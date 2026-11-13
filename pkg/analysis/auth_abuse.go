package analysis

import (
	"container/heap"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

const (
	DetBruteForce         DetectionType = "brute_force"
	DetCredentialStuffing DetectionType = "credential_stuffing"
	DetPasswordSpray      DetectionType = "password_spray"
)

// AuthThreshold configures evidence required within a rolling time window.
type AuthThreshold struct {
	Failures  int    `json:"failures"`
	Window    string `json:"window"`
	UniqueIPs int    `json:"unique_ips,omitempty"`
	UniqueUAs int    `json:"unique_uas,omitempty"`
}

// AuthAbuseConfig is opt-in. Block only applies to per-IP detections, never
// aggregate spraying: aggregate evidence does not identify an individual attacker.
type AuthAbuseConfig struct {
	Enabled            bool          `json:"enabled"`
	Block              bool          `json:"block,omitempty"`
	Endpoints          []string      `json:"endpoints"`
	FailureStatuses    []int         `json:"failure_statuses"`
	BruteForce         AuthThreshold `json:"brute_force"`
	CredentialStuffing AuthThreshold `json:"credential_stuffing"`
	PasswordSpray      AuthThreshold `json:"password_spray"`
}

type authKey struct{ host, path, ip string }
type authFailure struct {
	at     time.Time
	key    authKey
	status int
	ua     string
}

type authFailures []authFailure

func (h authFailures) Len() int           { return len(h) }
func (h authFailures) Less(i, j int) bool { return h[i].at.Before(h[j].at) }
func (h authFailures) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *authFailures) Push(x any)        { *h = append(*h, x.(authFailure)) }
func (h *authFailures) Pop() any {
	old := *h
	event := old[len(old)-1]
	old[len(old)-1] = authFailure{}
	*h = old[:len(old)-1]
	return event
}

type authEvidence struct {
	count    int
	ips, uas map[string]int
	statuses map[int]int
}

// Each scenario expires its own evidence and maintains counts incrementally.
// Heap ordering also supports out-of-order records without sorting each ingest.
type authWindow struct {
	duration  time.Duration
	aggregate bool
	events    authFailures
	counts    map[authKey]*authEvidence
}

func (w *authWindow) group(key authKey) authKey {
	if w.aggregate {
		key.ip = ""
	}
	return key
}

func (w *authWindow) adjust(e authFailure, delta int) {
	key := w.group(e.key)
	counts := w.counts[key]
	if counts == nil {
		counts = &authEvidence{ips: make(map[string]int), uas: make(map[string]int), statuses: make(map[int]int)}
		w.counts[key] = counts
	}
	counts.count += delta
	if counts.count == 0 {
		delete(w.counts, key)
		return
	}
	counts.ips[e.key.ip] += delta
	if counts.ips[e.key.ip] == 0 {
		delete(counts.ips, e.key.ip)
	}
	if e.ua != "" {
		counts.uas[e.ua] += delta
		if counts.uas[e.ua] == 0 {
			delete(counts.uas, e.ua)
		}
	}
	counts.statuses[e.status] += delta
	if counts.statuses[e.status] == 0 {
		delete(counts.statuses, e.status)
	}
}

// AuthAbuseDetector retains bounded failure evidence, independently of report
// and Guard reset cadence. Like Detector, it is used by a single ingest loop.
type AuthAbuseDetector struct {
	cfg     AuthAbuseConfig
	windows [3]*authWindow
	now     time.Time
}

// NewSession creates independent evidence storage with the validated settings.
func (d *AuthAbuseDetector) NewSession() *AuthAbuseDetector {
	if d == nil {
		return nil
	}
	copy := *d
	copy.now = time.Time{}
	for i, window := range d.windows {
		if window != nil {
			copy.windows[i] = &authWindow{duration: window.duration, aggregate: window.aggregate, counts: make(map[authKey]*authEvidence)}
		}
	}
	return &copy
}

// BlockingEnabled reports whether per-IP Guard blocking was explicitly enabled.
func (d *AuthAbuseDetector) BlockingEnabled() bool { return d != nil && d.cfg.Block }

// NewAuthAbuseDetector validates configuration and fills omitted defaults.
// A zero failure threshold explicitly disables that scenario.
func NewAuthAbuseDetector(cfg AuthAbuseConfig) (*AuthAbuseDetector, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.Endpoints == nil {
		cfg.Endpoints = []string{"/login", "/api/login", "/wp-login.php"}
	}
	if len(cfg.Endpoints) == 0 {
		return nil, fmt.Errorf("auth_abuse: endpoints must not be empty")
	}
	for _, path := range cfg.Endpoints {
		u, err := url.ParseRequestURI(path)
		if err != nil || u.Path != path || u.RawQuery != "" || path[0] != '/' {
			return nil, fmt.Errorf("auth_abuse: invalid endpoint %q (use an exact decoded path)", path)
		}
	}
	if cfg.FailureStatuses == nil {
		cfg.FailureStatuses = []int{401, 403}
	}
	if len(cfg.FailureStatuses) == 0 {
		return nil, fmt.Errorf("auth_abuse: failure_statuses must not be empty")
	}
	for _, status := range cfg.FailureStatuses {
		if status < 400 || status > 599 {
			return nil, fmt.Errorf("auth_abuse: failure status %d must be 400..599", status)
		}
	}
	// Entirely omitted scenarios get defaults; an explicit window with failures
	// set to zero disables the scenario.
	if cfg.BruteForce == (AuthThreshold{}) {
		cfg.BruteForce = AuthThreshold{Failures: 10, Window: "1m"}
	}
	if cfg.CredentialStuffing == (AuthThreshold{}) {
		cfg.CredentialStuffing = AuthThreshold{Failures: 20, Window: "1m", UniqueUAs: 5}
	}
	if cfg.PasswordSpray == (AuthThreshold{}) {
		cfg.PasswordSpray = AuthThreshold{Failures: 100, Window: "5m", UniqueIPs: 20}
	}
	d := &AuthAbuseDetector{cfg: cfg}
	for i, rule := range []AuthThreshold{cfg.BruteForce, cfg.CredentialStuffing, cfg.PasswordSpray} {
		if rule.Failures < 0 || rule.Failures > 100000 || rule.UniqueIPs < 0 || rule.UniqueUAs < 0 {
			return nil, fmt.Errorf("auth_abuse: invalid threshold")
		}
		window, err := time.ParseDuration(rule.Window)
		if err != nil || window <= 0 || window > 24*time.Hour {
			return nil, fmt.Errorf("auth_abuse: window must be positive and at most 24h")
		}
		if rule.Failures > 0 && ((i == 1 && (rule.UniqueUAs < 2 || rule.UniqueUAs > rule.Failures)) || (i == 2 && (rule.UniqueIPs < 2 || rule.UniqueIPs > rule.Failures))) {
			return nil, fmt.Errorf("auth_abuse: distinct client/UA threshold must be 2..failures")
		}
		if rule.Failures > 0 {
			d.windows[i] = &authWindow{duration: window, aggregate: i == 2, counts: make(map[authKey]*authEvidence)}
		}
	}
	return d, nil
}

// Observe uses log timestamps (not wall time) so offline reports remain useful.
// Late records are accepted only within the active event-time window.
func (d *AuthAbuseDetector) Observe(e *types.LogEntry) []Detection {
	if d == nil || e.Timestamp.IsZero() || net.ParseIP(e.RemoteIP) == nil {
		return nil
	}
	d.advance(e.Timestamp)
	path, err := url.PathUnescape(e.Path())
	if err != nil {
		return nil
	}
	if !slices.Contains(d.cfg.Endpoints, path) || !slices.Contains(d.cfg.FailureStatuses, e.Status) {
		return nil
	}
	key := authKey{strings.ToLower(e.Host), path, net.ParseIP(e.RemoteIP).String()}
	var out []Detection
	for i, window := range d.windows {
		// ponytail: at most 100k failures per enabled scenario; use an external
		// correlation store if campaigns exceed this in-memory evidence budget.
		if window == nil || !e.Timestamp.After(d.now.Add(-window.duration)) {
			continue
		}
		if len(window.events) < DefaultIPCap {
			event := authFailure{at: e.Timestamp, key: key, status: e.Status, ua: e.UserAgent}
			heap.Push(&window.events, event)
			window.adjust(event, 1)
		}
		if det := d.detection(i, key); det != nil {
			out = append(out, *det)
		}
	}
	return out
}

func (d *AuthAbuseDetector) advance(now time.Time) {
	if now.After(d.now) {
		d.now = now
	}
	for _, window := range d.windows {
		if window == nil {
			continue
		}
		cutoff := d.now.Add(-window.duration)
		for len(window.events) > 0 && !window.events[0].at.After(cutoff) {
			window.adjust(heap.Pop(&window.events).(authFailure), -1)
		}
	}
}

// Current returns per-IP detections still supported by live evidence.
func (d *AuthAbuseDetector) Current(now time.Time) []Detection {
	if d == nil {
		return nil
	}
	d.advance(now)
	var out []Detection
	for i, window := range d.windows[:2] {
		if window == nil {
			continue
		}
		for key := range window.counts {
			if det := d.detection(i, key); det != nil {
				out = append(out, *det)
			}
		}
	}
	return out
}

// ForgetIP consumes evidence after an IP or subnet ban, avoiding stale re-bans.
func (d *AuthAbuseDetector) ForgetIP(ip string) {
	if d == nil {
		return
	}
	_, subnet, _ := net.ParseCIDR(ip)
	if parsed := net.ParseIP(ip); parsed != nil {
		ip = parsed.String()
	}
	// ponytail: one bounded scan per successful ban; index heap positions if
	// mass-ban evidence removal becomes a measured bottleneck.
	for _, window := range d.windows {
		if window == nil {
			continue
		}
		window.events = slices.DeleteFunc(window.events, func(e authFailure) bool {
			if e.key.ip != ip && (subnet == nil || !subnet.Contains(net.ParseIP(e.key.ip))) {
				return false
			}
			window.adjust(e, -1)
			return true
		})
		heap.Init(&window.events)
	}
}

func (d *AuthAbuseDetector) detection(i int, key authKey) *Detection {
	window := d.windows[i]
	counts := window.counts[window.group(key)]
	rule := []AuthThreshold{d.cfg.BruteForce, d.cfg.CredentialStuffing, d.cfg.PasswordSpray}[i]
	if counts == nil || counts.count < rule.Failures || (i == 1 && len(counts.uas) < rule.UniqueUAs) || (i == 2 && len(counts.ips) < rule.UniqueIPs) {
		return nil
	}
	dt, ip, technique := DetBruteForce, key.ip, "T1110.001"
	if i == 1 {
		dt, technique = DetCredentialStuffing, "T1110.004"
	}
	if i == 2 {
		dt, ip, technique = DetPasswordSpray, "", "T1110.003"
	}
	codes := make([]int, 0, len(counts.statuses))
	for code := range counts.statuses {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	desc := fmt.Sprintf("Suspected %s: %d failures on %s%s in %s; %d IPs, %d User-Agents; status codes %v", dt, counts.count, key.host, key.path, window.duration, len(counts.ips), len(counts.uas), codes)
	return &Detection{Type: dt, IP: ip, URI: key.path, Desc: desc, Confidence: 7, Techniques: []string{technique}}
}
