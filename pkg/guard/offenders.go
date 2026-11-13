package guard

import (
	"crypto/sha256"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	DefaultBanResetAfter  = 30 * 24 * time.Hour
	DefaultMaxBanDuration = 7 * 24 * time.Hour
)

// Offender records successful automatic bans, independently of active bans.
// Separate files keep the existing blocked.json format safe for older binaries.
type Offender struct {
	IP          string    `json:"ip"`
	Offenses    int       `json:"offenses"`
	LastOffense time.Time `json:"last_offense"`
	BanUntil    time.Time `json:"ban_until"`
	ResetAt     time.Time `json:"reset_at"`
}

// ValidateBanEscalation checks the opt-in policy before starting the guard.
func ValidateBanEscalation(cfg Config) error {
	if !cfg.BanEscalation {
		return nil
	}
	if strings.TrimSpace(cfg.StatePath) == "" {
		return fmt.Errorf("--ban-escalation requires a non-empty --state-file")
	}
	if cfg.BlockDuration <= 0 {
		return fmt.Errorf("--ban-escalation requires --duration > 0")
	}
	if cfg.BanResetAfter < 0 || cfg.MaxBanDuration < 0 {
		return fmt.Errorf("ban reset period and maximum duration must be positive")
	}
	return nil
}

func offenderFile(statePath, ip string) (*stateFile, string, error) {
	if statePath == "" {
		return nil, "", fmt.Errorf("a non-empty --state-file is required")
	}
	if addr, err := netip.ParseAddr(ip); err == nil {
		ip = addr.Unmap().String()
	} else if prefix, err := netip.ParsePrefix(ip); err == nil {
		ip = prefix.Masked().String()
	} else {
		return nil, "", fmt.Errorf("invalid offender IP or CIDR %q", ip)
	}
	// Hash validated addresses so IPv6 and CIDRs are safe filenames on Windows too.
	name := fmt.Sprintf("%x.json", sha256.Sum256([]byte(ip)))
	return newStateFile(filepath.Join(statePath+".offenders", name)), ip, nil
}

// GetOffender returns nil for missing or expired history; it never touches a ban.
func GetOffender(statePath, ip string) (*Offender, error) {
	sf, ip, err := offenderFile(statePath, ip)
	if err != nil {
		return nil, err
	}
	var o Offender
	if err := sf.loadJSON(&o); err != nil {
		return nil, err
	}
	if o.IP == "" && o.Offenses == 0 {
		return nil, nil
	}
	if o.IP != ip || o.Offenses <= 0 || o.LastOffense.IsZero() || !o.ResetAt.After(o.LastOffense) || !o.BanUntil.After(o.LastOffense) {
		return nil, fmt.Errorf("invalid offender state for %s", ip)
	}
	if !time.Now().Before(o.ResetAt) {
		return nil, nil
	}
	return &o, nil
}

// ResetOffender forgets history, but leaves any active firewall ban untouched.
// The guard reads the record before each new ban, so resets also work while running.
func ResetOffender(statePath, ip string) error {
	sf, _, err := offenderFile(statePath, ip)
	if err != nil {
		return err
	}
	if err := os.Remove(sf.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ListOffenders returns unexpired history in address order.
func ListOffenders(statePath string) ([]Offender, error) {
	if statePath == "" {
		return nil, fmt.Errorf("a non-empty --state-file is required")
	}
	files, err := os.ReadDir(statePath + ".offenders")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var result []Offender
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") || file.IsDir() {
			continue
		}
		var o Offender
		sf := newStateFile(filepath.Join(statePath+".offenders", file.Name()))
		if err := sf.loadJSON(&o); err != nil {
			return nil, err
		}
		if o.IP == "" { // A concurrent reset may have removed the file.
			continue
		}
		current, err := GetOffender(statePath, o.IP)
		if err != nil {
			return nil, err
		}
		if current != nil {
			result = append(result, *current)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].IP < result[j].IP })
	return result, nil
}

func (g *Guard) nextOffense(ip string, now time.Time) (Offender, time.Duration, error) {
	_, key, err := offenderFile(g.cfg.StatePath, ip)
	if err != nil {
		return Offender{}, 0, err
	}
	previous, err := GetOffender(g.cfg.StatePath, ip)
	if err != nil {
		return Offender{}, 0, err
	}
	o := Offender{IP: key}
	if previous != nil {
		o = *previous
	}
	if g.cfg.DryRun {
		g.mu.Lock()
		if simulated, ok := g.dryOffenders[key]; ok {
			o = simulated
		}
		g.mu.Unlock()
	}
	if !now.Before(o.LastOffense.Add(g.cfg.BanResetAfter)) {
		o.Offenses = 0
	}
	if o.Offenses < math.MaxInt {
		o.Offenses++
	}
	duration := g.cfg.BlockDuration
	switch {
	case o.Offenses >= 4:
		duration = max(duration, 7*24*time.Hour)
	case o.Offenses == 3:
		duration = max(duration, 24*time.Hour)
	case o.Offenses == 2:
		duration = max(duration, time.Hour)
	}
	duration = min(duration, g.cfg.MaxBanDuration)
	o.LastOffense, o.BanUntil, o.ResetAt = now, now.Add(duration), now.Add(g.cfg.BanResetAfter)
	return o, duration, nil
}

func (g *Guard) recordOffense(o Offender) {
	if g.cfg.DryRun {
		g.mu.Lock()
		g.dryOffenders[o.IP] = o
		g.mu.Unlock()
		return
	}
	sf, _, err := offenderFile(g.cfg.StatePath, o.IP)
	if err == nil {
		err = sf.saveJSON(o)
	}
	if err != nil && g.cfg.OnError != nil {
		g.cfg.OnError(fmt.Errorf("save offender %s: %w", o.IP, err))
	}
}

// forgetOffense consumes evidence after a successful ban. Otherwise, a ban
// shorter than Window could expire and escalate again without any new request.
func (g *Guard) forgetOffense(ip string) {
	_, subnet, _ := net.ParseCIDR(ip)
	matches := func(key string) bool { return key == ip || subnet != nil && subnet.Contains(net.ParseIP(key)) }
	g.sliding.mu.Lock()
	if subnet == nil {
		delete(g.sliding.buckets, ip)
	} else {
		for key := range g.sliding.buckets {
			if matches(key) {
				delete(g.sliding.buckets, key)
			}
		}
	}
	delete(g.sliding.subnetTotals, ip)
	g.sliding.mu.Unlock()
	g.mu.Lock()
	if subnet == nil {
		delete(g.detectCounts, ip)
	} else {
		for key := range g.detectCounts {
			if matches(key) {
				delete(g.detectCounts, key)
			}
		}
	}
	g.mu.Unlock()
}

func (g *Guard) pruneOffenders(now time.Time) {
	if !g.cfg.BanEscalation {
		return
	}
	if g.cfg.DryRun {
		g.mu.Lock()
		for ip, o := range g.dryOffenders {
			if !now.Before(o.ResetAt) {
				delete(g.dryOffenders, ip)
			}
		}
		g.mu.Unlock()
		return
	}
	// ponytail: one file per offender; use an indexed store if directory scans dominate a window.
	files, err := os.ReadDir(g.cfg.StatePath + ".offenders")
	if os.IsNotExist(err) {
		return
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") || file.IsDir() {
			continue
		}
		sf := newStateFile(filepath.Join(g.cfg.StatePath+".offenders", file.Name()))
		var o Offender
		if loadErr := sf.loadJSON(&o); loadErr != nil {
			err = loadErr
			continue
		}
		if !o.ResetAt.IsZero() && (!now.Before(o.ResetAt) || !now.Before(o.LastOffense.Add(g.cfg.BanResetAfter))) {
			if removeErr := os.Remove(sf.path); removeErr != nil && !os.IsNotExist(removeErr) {
				err = removeErr
			}
		}
	}
	if err != nil && !os.IsNotExist(err) && g.cfg.OnError != nil {
		g.cfg.OnError(fmt.Errorf("prune offender history: %w", err))
	}
}
