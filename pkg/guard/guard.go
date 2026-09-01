package guard

import (
	"bytes"
	"container/heap"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
	"github.com/lenny-ts/caddy-analyzer/pkg/blocklist"
	"github.com/lenny-ts/caddy-analyzer/pkg/parser"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

// chainName is a dedicated iptables/ip6tables chain so that unban and
// expiry cleanup only ever touch rules this tool created.
const (
	chainName     = "CADDY_ANALYZER"
	commentMarker = "caddy-analyzer"
)

// iptablesTimeout bounds every firewall invocation so a stuck iptables
// (huge ruleset, lock contention, NFS-backed /etc) cannot freeze the guard.
var iptablesTimeout = 10 * time.Second

// runCmd runs bin with args, capturing stderr so failures carry the firewall's
// own diagnostic (e.g. "Permission denied", "Table does not exist") instead of
// a bare exit code. The *exec.ExitError is preserved via %w so callers can still
// use errors.As to inspect the exit code.
func runCmd(ctx context.Context, bin string, args ...string) error {
	c, cancel := context.WithTimeout(ctx, iptablesTimeout)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(c, bin, args...)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("%s %s: %w", bin, strings.Join(args, " "), err)
	}
	return nil
}

// Blocker is the interface for IP blocking backends. The guard domain uses
// only this interface — concrete implementations are adapters selected at
// startup (iptables, Docker DOCKER-USER chain, nftables, etc.).
type Blocker interface {
	Block(ip string) error
	Unblock(ip string) error
}

// ChainBlocker extends Blocker with chain lifecycle management.
// Implementations that manage a dedicated firewall chain should implement this.
type ChainBlocker interface {
	Blocker
	// EnsureChain creates the dedicated chain and jump rule if missing.
	EnsureChain() error
	// Validate checks that the chain and jump rule are correctly positioned.
	Validate() error
}

// GeoIPLookuper is the subset of *enrich.GeoIP used by the guard for
// country-block lookups. Defining it as an interface allows tests to
// inject a mock without a real mmdb file.
type GeoIPLookuper interface {
	Lookup(ip string) (types.GeoInfo, error)
}

type iptablesBlocker struct{}

func (iptablesBlocker) Block(ip string) error   { return BlockIP(ip) }
func (iptablesBlocker) Unblock(ip string) error { return UnblockIP(ip) }

// BinForIP returns the firewall binary matching the address family of ip.
func BinForIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed != nil {
		if parsed.To4() == nil {
			return "ip6tables"
		}
		return "iptables"
	}
	if _, ipnet, err := net.ParseCIDR(ip); err == nil {
		if ipnet.IP.To4() == nil {
			return "ip6tables"
		}
	}
	return "iptables"
}

func ensureChainAndJump(bin string) error {
	ctx := context.Background()
	if err := runCmd(ctx, bin, "-N", chainName); err != nil {
		// `iptables -N` exits 1 when the chain already exists, printing
		// "Chain already exists." to stderr. Only that case is benign; any
		// other exit-1 (permission denied, table missing, etc.) must surface.
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !strings.Contains(strings.ToLower(err.Error()), "already exists") {
			return err
		}
	}
	if err := runCmd(ctx, bin, "-C", "INPUT", "-j", chainName); err != nil {
		if err := runCmd(ctx, bin, "-A", "INPUT", "-j", chainName); err != nil {
			return err
		}
	}
	return nil
}

// BlockIP adds a DROP rule for ip inside the dedicated chain, tagged with
// the ownership comment. IPv6 addresses are routed to ip6tables. Idempotent:
// if the rule already exists (e.g. manual block while guard has already
// blocked the IP), it returns nil without adding a duplicate.
func BlockIP(ip string) error {
	bin := BinForIP(ip)
	if err := ensureChainAndJump(bin); err != nil {
		return fmt.Errorf("ensure chain: %w", err)
	}
	args := []string{chainName, "-s", ip, "-m", "comment", "--comment", commentMarker, "-j", "DROP"}
	if err := runCmd(context.Background(), bin, append([]string{"-C"}, args...)...); err == nil {
		return nil
	}
	return runCmd(context.Background(), bin, append([]string{"-A"}, args...)...)
}

// UnblockIP removes only the tagged DROP rule created by BlockIP.
func UnblockIP(ip string) error {
	bin := BinForIP(ip)
	return runCmd(context.Background(), bin, "-D", chainName, "-s", ip,
		"-m", "comment", "--comment", commentMarker, "-j", "DROP")
}

// ListBlockedIPs reports the IPs currently blocked by this tool.
func ListBlockedIPs() ([]string, error) {
	var ips []string
	anyRan := false
	for _, bin := range []string{"iptables", "ip6tables"} {
		ctx, cancel := context.WithTimeout(context.Background(), iptablesTimeout)
		out, err := exec.CommandContext(ctx, bin, "-S", chainName).Output()
		cancel()
		if err != nil {
			// *exec.ExitError means the binary ran but the chain
			// doesn't exist yet (fresh system) — benign, treat as
			// "no blocked IPs".
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				anyRan = true
				continue
			}
			// Binary not on PATH / not executable.
			continue
		}
		anyRan = true
		ips = append(ips, parseBlockedIPs(string(out))...)
	}
	if !anyRan {
		return nil, fmt.Errorf("%s not found on PATH", "iptables/ip6tables")
	}
	return ips, nil
}

// parseBlockedIPs extracts IPs from firewall rules belonging to this tool.
func parseBlockedIPs(output string) []string {
	var ips []string
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "-j DROP") || !strings.Contains(line, commentMarker) {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "-s" && i+1 < len(fields) {
				ip := strings.Split(fields[i+1], "/")[0]
				ip = strings.Trim(ip, "[]")
				if ip == "" || ip == "0.0.0.0" || ip == "::" {
					continue
				}
				ips = append(ips, ip)
				break
			}
		}
	}
	return ips
}

type Config struct {
	Limit               int
	AuthLimit           int
	NotFoundLimit       int
	Window              time.Duration
	BlockDuration       time.Duration
	DetectionConfidence int
	IPValidator         func(string) error
	OnAudit             func(action, ip, reason, duration string)
	OnError             func(error)
	StatePath           string
	NeverBlock          []string
	TrustForwarded      bool
	SubnetLimit         int
	AnomalyFactor       float64
	UARotationThreshold int
	CredStuffingLimit   int
	CustomPatterns      []analysis.DetectionPattern
	// Blocker is an optional firewall blocker. If nil, the real
	// iptables blocker is used. Tests should provide a fake blocker
	// so that loadState cleanup hits the fake, not real iptables.
	Blocker Blocker
	// FirewallBackend, if set, overrides Blocker and provides full
	// chain lifecycle management (EnsureChain, Validate). When set,
	// Blocker is ignored.
	FirewallBackend Blocker
	// BlocklistMgr, if non-nil, enables immediate blocking of IPs
	// found in any configured blocklist feed. The manager must have
	// been loaded (LoadAll or Refresh) before guard starts.
	BlocklistMgr *blocklist.Manager
	// BlocklistRefresh is the interval between automatic blocklist
	// refreshes in guard mode. If <= 0, no background refresh runs.
	BlocklistRefresh time.Duration
	// CountryBlock is a list of ISO country codes whose IPs are
	// blocked on sight. Requires GeoIP to be set.
	CountryBlock []string
	// GeoIP, if non-nil, is used for country-block lookups. If
	// CountryBlock is non-empty and GeoIP is nil, country-block is
	// silently disabled.
	GeoIP GeoIPLookuper
}

type expiryEntry struct {
	ip   string
	when time.Time
}

type expiryHeap []expiryEntry

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].when.Before(h[j].when) }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(x any)        { *h = append(*h, x.(expiryEntry)) }
func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

type Guard struct {
	mu             sync.Mutex
	blocked        map[string]bool
	blockedSubnets []*net.IPNet
	detector       *analysis.Detector
	engine         *analysis.Engine
	blocker        Blocker
	cfg            Config
	expCh          chan expiryEntry
	state          *stateFile
	expiries       map[string]time.Time
	allowlist      []*net.IPNet
	detectCounts   map[string]int
	initial        []expiryEntry
	sliding        *slidingCounters
	tickReqs       atomic.Int64
	ewmaRPS        float64
	ewmaInit       bool
	// saveState debounce: avoid O(n²) I/O under mass blocks by batching
	// saves to at most one per second.
	dirty    atomic.Bool
	lastSave time.Time
	saveMu   sync.Mutex
	saveGen  atomic.Int64
	// Blocklist and GeoIP for immediate block-on-match.
	blocklistMgr *blocklist.Manager
	countryBlock map[string]bool
	geoip        GeoIPLookuper
	// blocklistHits counts IPs blocked via blocklist or country-block
	// for stats reporting.
	blocklistHits atomic.Int64
	// pendingBlock is set by checkImmediateBlock and consumed by Run to
	// log the ban in terminal output.
	pendingBlock *Candidate
}

// ipBucket holds per-second counters for one IP.
type ipBucket struct {
	total    int64
	authFail int64
	notFound int64
}

// slidingCounters tracks per-IP, per-second buckets to implement a true
// sliding window rather than a tumbling one: an attacker cannot evade the
// limit by straddling a tick boundary. Buckets older than the window are
// evicted lazily during sum/expire.
type slidingCounters struct {
	mu      sync.Mutex
	window  time.Duration
	buckets map[string]map[int64]*ipBucket
	// subnetTotals tracks per-/24 per-second totals to detect distributed
	// scans (many IPs in one subnet, each below the per-IP limit).
	subnetTotals map[string]map[int64]int64
	// authFailPaths tracks path → set of IPs for 401/403 responses,
	// to detect distributed credential stuffing (many IPs, same login path).
	authFailPaths map[string]map[string]struct{}
}

func newSlidingCounters(window time.Duration) *slidingCounters {
	return &slidingCounters{
		window:        window,
		buckets:       make(map[string]map[int64]*ipBucket),
		subnetTotals:  make(map[string]map[int64]int64),
		authFailPaths: make(map[string]map[string]struct{}),
	}
}

func (sc *slidingCounters) add(ip string, ts time.Time, authFail, notFound bool, path string) {
	sec := ts.Unix()
	sc.mu.Lock()
	defer sc.mu.Unlock()
	m := sc.buckets[ip]
	if m == nil {
		m = make(map[int64]*ipBucket)
		sc.buckets[ip] = m
	}
	b := m[sec]
	if b == nil {
		b = &ipBucket{}
		m[sec] = b
	}
	b.total++
	if authFail {
		b.authFail++
		if path != "" {
			if sc.authFailPaths[path] == nil {
				sc.authFailPaths[path] = make(map[string]struct{})
			}
			sc.authFailPaths[path][ip] = struct{}{}
		}
	}
	if notFound {
		b.notFound++
	}
	if subnet := subnetKey(ip); subnet != "" {
		sm := sc.subnetTotals[subnet]
		if sm == nil {
			sm = make(map[int64]int64)
			sc.subnetTotals[subnet] = sm
		}
		sm[sec]++
	}
}

// subnetSum returns the total request count for a /24 within the window,
// evicting expired buckets in the process.
func (sc *slidingCounters) subnetSum(subnet string, now time.Time) int64 {
	cutoff := now.Add(-sc.window).Unix()
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sm := sc.subnetTotals[subnet]
	if sm == nil {
		return 0
	}
	var total int64
	for sec, n := range sm {
		if sec < cutoff {
			delete(sm, sec)
			continue
		}
		total += n
	}
	if len(sm) == 0 {
		delete(sc.subnetTotals, subnet)
	}
	return total
}

func (sc *slidingCounters) subnets() []string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	out := make([]string, 0, len(sc.subnetTotals))
	for s := range sc.subnetTotals {
		out = append(out, s)
	}
	return out
}

// subnetKey returns the /24 CIDR for an IPv4 address or the /64 CIDR for
// an IPv6 address, or "" for invalid addresses. Used for distributed-scan
// correlation so the subnet-limit feature covers both address families.
func subnetKey(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	if v4 := p.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	b := p.To16()
	return fmt.Sprintf("%x:%x:%x:%x::/64",
		uint16(b[0])<<8|uint16(b[1]),
		uint16(b[2])<<8|uint16(b[3]),
		uint16(b[4])<<8|uint16(b[5]),
		uint16(b[6])<<8|uint16(b[7]))
}

// credStuffingCandidates returns paths where >= limit distinct IPs failed
// auth (401/403) within the window. This catches distributed credential
// stuffing where each IP stays under --auth-limit but the same login path
// is hammered from many sources.
func (sc *slidingCounters) credStuffingCandidates(limit int) []credStuffingHit {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	var out []credStuffingHit
	for path, ips := range sc.authFailPaths {
		if len(ips) >= limit {
			out = append(out, credStuffingHit{Path: path, IPCount: len(ips)})
		}
	}
	return out
}

type credStuffingHit struct {
	Path    string
	IPCount int
}

// resetAuthFailPaths clears the credential-stuffing tracking map. Called
// at the end of each Tick so the map doesn't grow unbounded across windows.
func (sc *slidingCounters) resetAuthFailPaths() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.authFailPaths = make(map[string]map[string]struct{})
}

func (sc *slidingCounters) sum(ip string, now time.Time) (total, authFail, notFound int64) {
	cutoff := now.Add(-sc.window).Unix()
	sc.mu.Lock()
	defer sc.mu.Unlock()
	m := sc.buckets[ip]
	if m == nil {
		return 0, 0, 0
	}
	for sec, b := range m {
		if sec < cutoff {
			delete(m, sec)
			continue
		}
		total += b.total
		authFail += b.authFail
		notFound += b.notFound
	}
	return
}

func (sc *slidingCounters) expire(now time.Time) {
	cutoff := now.Add(-sc.window).Unix()
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for ip, m := range sc.buckets {
		for sec := range m {
			if sec < cutoff {
				delete(m, sec)
			}
		}
		if len(m) == 0 {
			delete(sc.buckets, ip)
		}
	}
}

func (sc *slidingCounters) ips() []string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	ips := make([]string, 0, len(sc.buckets))
	for ip := range sc.buckets {
		ips = append(ips, ip)
	}
	return ips
}

func New(cfg Config) *Guard {
	sf := newStateFile(cfg.StatePath)
	blocker := cfg.Blocker
	if cfg.FirewallBackend != nil {
		blocker = cfg.FirewallBackend
	} else if blocker == nil {
		blocker = iptablesBlocker{}
	}
	countryBlock := make(map[string]bool)
	for _, cc := range cfg.CountryBlock {
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if cc != "" {
			countryBlock[cc] = true
		}
	}
	g := &Guard{
		blocked:        make(map[string]bool),
		blockedSubnets: make([]*net.IPNet, 0),
		detector:       analysis.NewDetectorWithPatterns(cfg.CustomPatterns),
		engine:         analysis.New(types.Filters{}),
		blocker:        blocker,
		cfg:            cfg,
		expCh:          make(chan expiryEntry, 50000),
		state:          sf,
		expiries:       make(map[string]time.Time),
		allowlist:      parseCIDRList(cfg.NeverBlock),
		detectCounts:   make(map[string]int),
		sliding:        newSlidingCounters(cfg.Window),
		blocklistMgr:   cfg.BlocklistMgr,
		countryBlock:   countryBlock,
		geoip:          cfg.GeoIP,
	}
	if cfg.UARotationThreshold > 0 {
		g.detector.SetUARotationThreshold(cfg.UARotationThreshold)
	}
	// Ensure firewall chain exists and validate before loading state.
	// The firewall.Backend interface includes EnsureChain and Validate.
	if cb, ok := blocker.(interface {
		EnsureChain() error
		Validate() error
	}); ok {
		if err := cb.EnsureChain(); err != nil && cfg.OnError != nil {
			cfg.OnError(fmt.Errorf("firewall setup: %w", err))
		}
		if err := cb.Validate(); err != nil && cfg.OnError != nil {
			cfg.OnError(fmt.Errorf("firewall validation: %w", err))
		}
	}
	g.loadState()
	return g
}

func parseCIDRList(list []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				s += "/32"
			} else {
				s += "/128"
			}
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		nets = append(nets, ipnet)
	}
	return nets
}

func (g *Guard) isAllowlisted(ip string) bool {
	if len(g.allowlist) == 0 {
		return false
	}
	// Candidate IPs from the subnet-limit path are CIDRs (e.g.
	// "10.0.0.0/24"), not bare addresses. A bare net.ParseIP returns nil
	// for a CIDR string and the allowlist would be silently bypassed.
	// If the candidate is a CIDR, treat it as allowlisted when it is a
	// subset of any allowlist CIDR (covers both v4 and v6).
	if _, ipnet, err := net.ParseCIDR(ip); err == nil {
		for _, n := range g.allowlist {
			if cidrSubset(ipnet, n) {
				return true
			}
		}
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range g.allowlist {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// cidrSubset reports whether every address in a is contained in b. Used to
// honor the allowlist when the candidate is itself a subnet (distributed
// scan block via --subnet-limit).
func cidrSubset(a, b *net.IPNet) bool {
	// Different address families cannot overlap.
	if len(a.IP) != len(b.IP) {
		return false
	}
	// a ⊆ b iff b's mask is shorter or equal (broader) AND a's network
	// address, masked with b, equals b's network address.
	for i := range a.IP {
		if a.IP[i]&b.Mask[i] != b.IP[i]&b.Mask[i] {
			return false
		}
	}
	// a's mask must be at least as specific as b's (a ones >= b ones).
	aOnes, _ := a.Mask.Size()
	bOnes, _ := b.Mask.Size()
	return aOnes >= bOnes
}

func (g *Guard) loadState() {
	if g.state == nil {
		return
	}
	entries, err := g.state.load()
	if err != nil && g.cfg.OnError != nil {
		g.cfg.OnError(fmt.Errorf("load state %s: %w", g.state.path, err))
	}
	now := time.Now()
	for _, e := range entries {
		switch {
		case e.When.IsZero():
			// Permanent block: always restore, regardless of current duration.
			g.blocked[e.IP] = true
			// Recreate the firewall rule — iptables rules may have been
			// flushed while we were down (reboot, iptables -F, etc.).
			if err := g.blocker.Block(e.IP); err != nil && g.cfg.OnError != nil {
				g.cfg.OnError(fmt.Errorf("restore permanent block %s: %w", e.IP, err))
			}
		case g.cfg.BlockDuration <= 0:
			// Temporary blocks recorded under a previous run: running in
			// permanent mode now; preserve them as permanent to avoid
			// silently dropping firewall protection while we were down.
			g.blocked[e.IP] = true
			if err := g.blocker.Block(e.IP); err != nil && g.cfg.OnError != nil {
				g.cfg.OnError(fmt.Errorf("restore block %s: %w", e.IP, err))
			}
		case e.When.Before(now):
			// Ban expired while the daemon was down: clean up the rule.
			if err := g.blocker.Unblock(e.IP); err != nil && g.cfg.OnError != nil {
				g.cfg.OnError(fmt.Errorf("unblock expired %s: %w", e.IP, err))
			}
			if g.cfg.OnAudit != nil {
				g.cfg.OnAudit("unblock", e.IP, "expired during downtime", g.cfg.BlockDuration.String())
			}
		default:
			g.blocked[e.IP] = true
			// Recreate the firewall rule for still-valid temporary blocks.
			if err := g.blocker.Block(e.IP); err != nil && g.cfg.OnError != nil {
				g.cfg.OnError(fmt.Errorf("restore block %s: %w", e.IP, err))
			}
			g.expiries[e.IP] = e.When
			g.initial = append(g.initial, expiryEntry{ip: e.IP, when: e.When})
		}
	}
}

// saveStateDebounced marks the state dirty and flushes at most once per
// second to avoid O(n²) I/O when many IPs are blocked in a single tick.
func (g *Guard) saveStateDebounced() {
	g.saveMu.Lock()
	g.dirty.Store(true)
	g.saveGen.Add(1)
	g.saveMu.Unlock()
	g.mu.Lock()
	shouldFlush := time.Since(g.lastSave) > time.Second
	g.mu.Unlock()
	if shouldFlush {
		g.saveState()
	}
}

func (g *Guard) saveState() {
	if g.state == nil {
		return
	}
	g.saveMu.Lock()
	defer g.saveMu.Unlock()
	g.mu.Lock()
	entries := make([]stateEntry, 0, len(g.expiries))
	for ip, when := range g.expiries {
		entries = append(entries, stateEntry{IP: ip, When: when})
	}
	permanent := make([]stateEntry, 0)
	for ip := range g.blocked {
		if _, hasExp := g.expiries[ip]; !hasExp {
			permanent = append(permanent, stateEntry{IP: ip, When: time.Time{}})
		}
	}
	entries = append(entries, permanent...)
	g.lastSave = time.Now()
	g.mu.Unlock()
	genBefore := g.saveGen.Load()
	if err := g.state.saveEntries(entries); err != nil {
		g.dirty.Store(true)
		if g.cfg.OnError != nil {
			g.cfg.OnError(fmt.Errorf("save state: %w", err))
		}
		return
	}
	// Only clear dirty if no concurrent modification happened during
	// the file write. If saveGen advanced, another block marked the
	// state dirty since our snapshot — the next save will include it.
	if genBefore == g.saveGen.Load() {
		g.dirty.Store(false)
	}
}

func (g *Guard) SetBlocker(b Blocker) {
	g.blocker = b
}

// FlushState forces an immediate save of all blocked IPs to the state file.
// Called during graceful shutdown to ensure no data is lost.
func (g *Guard) FlushState() {
	g.dirty.Store(true)
	g.saveState()
}

// AddPermanentBlockToState records ip as a permanent block in the state
// file at path. Used by the block command so manual blocks survive guard
// restarts. Idempotent: if the IP is already tracked, it is a no-op.
func AddPermanentBlockToState(path, ip string) error {
	if path == "" {
		return nil
	}
	sf := newStateFile(path)
	entries, err := sf.load()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IP == ip {
			return nil
		}
	}
	entries = append(entries, stateEntry{IP: ip, When: time.Time{}})
	return sf.saveEntries(entries)
}

// RemoveBlockFromState removes ip from the state file at path. Used by the
// unban command so manual unbans are reflected in the guard's persisted
// state.
func RemoveBlockFromState(path, ip string) error {
	if path == "" {
		return nil
	}
	sf := newStateFile(path)
	entries, err := sf.load()
	if err != nil {
		return err
	}
	var out []stateEntry
	for _, e := range entries {
		if e.IP != ip {
			out = append(out, e)
		}
	}
	return sf.saveEntries(out)
}

func (g *Guard) IsBlocked(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.blocked[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range g.blockedSubnets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func (g *Guard) setBlocked(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blocked[ip] = true
}

func (g *Guard) removeBlocked(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.blocked, ip)
	// If ip is a CIDR (subnet block), also remove it from blockedSubnets so
	// IsBlocked stops matching individual hosts inside that subnet.
	if _, ipnet, err := net.ParseCIDR(ip); err == nil {
		for i, n := range g.blockedSubnets {
			if n.String() == ipnet.String() {
				g.blockedSubnets = append(g.blockedSubnets[:i], g.blockedSubnets[i+1:]...)
				break
			}
		}
	}
}

func (g *Guard) Count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.blocked)
}

func (g *Guard) Detector() *analysis.Detector {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.detector
}

func (g *Guard) Engine() *analysis.Engine {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.engine
}

func (g *Guard) Evaluate(line string) {
	entry, err := parser.Parse(line)
	if err != nil || entry == nil {
		return
	}
	le, ok := entry.(*types.LogEntry)
	if !ok {
		// Operational entries (config loads, TLS events, upstream
		// errors) are not HTTP requests and carry no RemoteIP/Status,
		// so they cannot feed the sliding window, detector, or engine.
		return
	}
	if g.cfg.TrustForwarded {
		if ip := le.EffectiveClientIP(true); ip != "" {
			le.RemoteIP = ip
		}
	}
	if g.IsBlocked(le.RemoteIP) {
		return
	}
	// Blocklist and country-block: immediate block on match. The
	// allowlist (--never-block) always wins over both — this is checked
	// inside checkImmediateBlock so an allowlisted IP is never blocked
	// by a feed or country rule.
	if g.checkImmediateBlock(le.RemoteIP) {
		return
	}
	g.tickReqs.Add(1)
	g.sliding.add(le.RemoteIP, time.Now(), le.Status == 401 || le.Status == 403, le.Status == 404, le.Path())
	if g.cfg.DetectionConfidence > 0 {
		for _, det := range g.detector.DetectAll(le) {
			if det.Confidence >= g.cfg.DetectionConfidence {
				g.mu.Lock()
				g.detectCounts[le.RemoteIP]++
				g.mu.Unlock()
				break
			}
		}
	} else {
		g.detector.Detect(le)
	}
	g.engine.Process(le)
}

// checkImmediateBlock returns true if ip matches the blocklist or a
// blocked country and was blocked. The allowlist is checked first:
// if ip is allowlisted, no immediate block is applied and false is
// returned. The block is applied inline (not deferred to Tick) so the
// IP is cut off before it can do more damage.
func (g *Guard) checkImmediateBlock(ip string) bool {
	if g.isAllowlisted(ip) {
		return false
	}
	if g.blocklistMgr != nil {
		if hit, source := g.blocklistMgr.Contains(ip); hit {
			c := &Candidate{IP: ip, Count: 1, Why: "blocklist: " + source}
			ctx, cancel := context.WithTimeout(context.Background(), iptablesTimeout)
			defer cancel()
			g.block(ctx, *c, time.Now())
			g.blocklistHits.Add(1)
			g.pendingBlock = c
			return true
		}
	}
	if g.geoip != nil && len(g.countryBlock) > 0 {
		info, err := g.geoip.Lookup(ip)
		if err == nil && info.CountryCode != "" && g.countryBlock[info.CountryCode] {
			c := &Candidate{IP: ip, Count: 1, Why: "country-block: " + info.CountryCode}
			ctx, cancel := context.WithTimeout(context.Background(), iptablesTimeout)
			defer cancel()
			g.block(ctx, *c, time.Now())
			g.blocklistHits.Add(1)
			g.pendingBlock = c
			return true
		}
	}
	return false
}

type Candidate struct {
	IP    string
	Count int64
	Why   string
}

func (g *Guard) Tick(ctx context.Context) []Candidate {
	now := time.Now()
	g.sliding.expire(now)

	var candidates []Candidate
	seen := make(map[string]bool)

	for _, ip := range g.sliding.ips() {
		if g.IsBlocked(ip) {
			continue
		}
		total, authFail, notFound := g.sliding.sum(ip, now)
		why := ""
		switch {
		case g.cfg.AuthLimit > 0 && authFail >= int64(g.cfg.AuthLimit):
			why = fmt.Sprintf("%d auth failures", authFail)
		case g.cfg.NotFoundLimit > 0 && notFound >= int64(g.cfg.NotFoundLimit):
			why = fmt.Sprintf("%d not found", notFound)
		case g.cfg.Limit > 0 && total >= int64(g.cfg.Limit):
			why = fmt.Sprintf("%d requests", total)
		}
		if why != "" {
			candidates = append(candidates, Candidate{ip, total, why})
			seen[ip] = true
		}
	}

	g.mu.Lock()
	for ip, count := range g.detectCounts {
		if g.blocked[ip] || seen[ip] {
			continue
		}
		seen[ip] = true
		candidates = append(candidates, Candidate{ip, int64(count), fmt.Sprintf("%d malicious request(s)", count)})
	}
	g.mu.Unlock()

	if g.cfg.SubnetLimit > 0 {
		for _, subnet := range g.sliding.subnets() {
			if g.IsBlocked(subnet) {
				continue
			}
			total := g.sliding.subnetSum(subnet, now)
			if total >= int64(g.cfg.SubnetLimit) {
				candidates = append(candidates, Candidate{subnet, total, fmt.Sprintf("%d requests from %s (distributed scan)", total, subnet)})
			}
		}
	}

	// Credential stuffing: alert when many distinct IPs fail auth on the same path.
	// Alert-only (audit log) — iptables blocks IPs, not paths.
	if g.cfg.CredStuffingLimit > 0 {
		for _, cs := range g.sliding.credStuffingCandidates(g.cfg.CredStuffingLimit) {
			if g.cfg.OnAudit != nil {
				g.cfg.OnAudit("cred_stuffing", "-", fmt.Sprintf("%d distinct IPs failing auth on %s", cs.IPCount, cs.Path), g.cfg.BlockDuration.String())
			}
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Count > candidates[j].Count
	})

	var blocked []Candidate
	for _, c := range candidates {
		if g.isAllowlisted(c.IP) {
			continue
		}
		if g.cfg.IPValidator != nil {
			if err := g.cfg.IPValidator(c.IP); err != nil {
				continue
			}
		}
		if g.block(ctx, c, now) {
			blocked = append(blocked, c)
		}
	}

	g.mu.Lock()
	g.detector = analysis.NewDetectorWithPatterns(g.cfg.CustomPatterns)
	if g.cfg.UARotationThreshold > 0 {
		g.detector.SetUARotationThreshold(g.cfg.UARotationThreshold)
	}
	g.engine = analysis.New(types.Filters{})
	g.engine.Stats().StartTime = now
	g.detectCounts = make(map[string]int)
	g.mu.Unlock()
	g.sliding.resetAuthFailPaths()

	g.detectAnomaly()

	// Flush any debounced state at the end of the tick so blocks from this
	// tick are persisted even under low block volume.
	if g.dirty.Load() {
		g.saveState()
	}

	return blocked
}

// detectAnomaly tracks request rate with an EWMA and fires an audit alert when
// the current window's RPS exceeds AnomalyFactor × baseline. This catches
// volumetric spikes / DDoS that per-IP thresholds miss. Alert-only: blocking
// individual hosts is the wrong tool for a distributed flood.
func (g *Guard) detectAnomaly() {
	reqs := g.tickReqs.Swap(0)
	if g.cfg.Window <= 0 {
		return
	}
	currentRPS := float64(reqs) / g.cfg.Window.Seconds()
	const alpha = 0.3
	const minBaseline = 1.0
	if !g.ewmaInit {
		g.ewmaRPS = currentRPS
		g.ewmaInit = true
		return
	}
	g.ewmaRPS = alpha*currentRPS + (1-alpha)*g.ewmaRPS
	if g.cfg.AnomalyFactor > 0 && g.ewmaRPS > minBaseline && currentRPS > g.cfg.AnomalyFactor*g.ewmaRPS {
		if g.cfg.OnAudit != nil {
			g.cfg.OnAudit("anomaly", "-",
				fmt.Sprintf("RPS spike: %.1f req/s vs %.1f baseline (%.1fx)", currentRPS, g.ewmaRPS, currentRPS/g.ewmaRPS),
				g.cfg.BlockDuration.String())
		}
	}
}

func (g *Guard) block(ctx context.Context, c Candidate, now time.Time) bool {
	g.setBlocked(c.IP)
	if err := g.blocker.Block(c.IP); err != nil {
		g.removeBlocked(c.IP)
		return false
	}
	// Track subnet blocks so IsBlocked short-circuits individual hosts in a
	// blocked /24 without re-evaluating them on every request.
	if _, ipnet, err := net.ParseCIDR(c.IP); err == nil {
		g.mu.Lock()
		g.blockedSubnets = append(g.blockedSubnets, ipnet)
		g.mu.Unlock()
	}
	if g.cfg.OnAudit != nil {
		dur := g.cfg.BlockDuration.String()
		if g.cfg.BlockDuration <= 0 {
			dur = "permanent"
		}
		g.cfg.OnAudit("block", c.IP, c.Why, dur)
	}
	if g.cfg.BlockDuration > 0 {
		expiry := now.Add(g.cfg.BlockDuration)
		g.mu.Lock()
		g.expiries[c.IP] = expiry
		g.mu.Unlock()
		select {
		case g.expCh <- expiryEntry{ip: c.IP, when: expiry}:
		case <-ctx.Done():
		}
	}
	g.saveStateDebounced()
	return true
}

func (g *Guard) runExpiryLoop(ctx context.Context) {
	var h expiryHeap
	for _, e := range g.initial {
		heap.Push(&h, e)
	}
	g.initial = nil
	var timer *time.Timer
	var timerC <-chan time.Time

	for {
		if timer != nil {
			timer.Stop()
			timer = nil
			timerC = nil
		}
		if h.Len() > 0 {
			d := time.Until(h[0].when)
			if d < 0 {
				d = 0
			}
			timer = time.NewTimer(d)
			timerC = timer.C
		}

		select {
		case e := <-g.expCh:
			heap.Push(&h, e)
		case <-timerC:
			now := time.Now()
			var requeue []expiryEntry
			for h.Len() > 0 && !h[0].when.After(now) {
				e := heap.Pop(&h).(expiryEntry)
				if err := g.blocker.Unblock(e.ip); err != nil {
					if g.cfg.OnError != nil {
						g.cfg.OnError(fmt.Errorf("unblock %s: %w", e.ip, err))
					}
					requeue = append(requeue, expiryEntry{ip: e.ip, when: now.Add(time.Minute)})
					continue
				}
				g.removeBlocked(e.ip)
				g.mu.Lock()
				delete(g.expiries, e.ip)
				g.mu.Unlock()
				if g.cfg.OnAudit != nil {
					g.cfg.OnAudit("unblock", e.ip, "block duration expired", g.cfg.BlockDuration.String())
				}
			}
			for _, e := range requeue {
				heap.Push(&h, e)
			}
			g.saveStateDebounced()
		case <-ctx.Done():
			// Final flush so the on-disk state reflects the latest expiries.
			if g.dirty.Load() {
				g.saveState()
			}
			return
		}
	}
}

func (g *Guard) Run(ctx context.Context, linesCh <-chan string, logf func(string, ...interface{})) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.runExpiryLoop(ctx)
	}()

	// Blocklist background refresh: periodically re-fetch all feeds so
	// new malicious networks are picked up without a manual refresh.
	if g.blocklistMgr != nil && g.cfg.BlocklistRefresh > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.runBlocklistRefresh(ctx, logf)
		}()
	}

	ticker := time.NewTicker(g.cfg.Window)
	defer ticker.Stop()

	for {
		select {
		case line, ok := <-linesCh:
			if !ok {
				cancel()
				wg.Wait()
				return
			}
			g.Evaluate(line)
			if c := g.pendingBlock; c != nil {
				g.pendingBlock = nil
				logf("[%s] + %s blocked (%s)\n", time.Now().Format("15:04:05"), c.IP, c.Why)
			}

		case <-ticker.C:
			blocked := g.Tick(ctx)
			now := time.Now()
			for _, c := range blocked {
				logf("[%s] + %s blocked (%s)\n", now.Format("15:04:05"), c.IP, c.Why)
			}

		case <-ctx.Done():
			wg.Wait()
			return
		}
	}
}

// runBlocklistRefresh re-fetches all blocklist feeds at the configured
// interval. Failures are logged via logf but do not stop the loop —
// the next tick will retry.
func (g *Guard) runBlocklistRefresh(ctx context.Context, logf func(string, ...interface{})) {
	ticker := time.NewTicker(g.cfg.BlocklistRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			statuses := g.blocklistMgr.Refresh()
			for _, st := range statuses {
				if st.Error != "" {
					logf("[blocklist] %s: %s\n", st.Name, st.Error)
				} else {
					logf("[blocklist] %s: %d entries refreshed\n", st.Name, st.Entries)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// BlocklistHits returns the number of IPs blocked via blocklist or
// country-block matching since the guard started.
func (g *Guard) BlocklistHits() int64 {
	return g.blocklistHits.Load()
}

// SetIPTablesTimeout overrides the per-invocation firewall command timeout.
// Call once at startup: runCmd reads this without synchronisation, so changing
// it while the guard is running is a data race.
//
// The timeout must be positive. A zero or negative value would make every
// invocation fail immediately with a context deadline, turning a tuning knob
// into an outage, so it is ignored.
func SetIPTablesTimeout(d time.Duration) {
	if d <= 0 {
		return
	}
	iptablesTimeout = d
}

// IPTablesTimeout reports the timeout currently in effect.
func IPTablesTimeout() time.Duration { return iptablesTimeout }
