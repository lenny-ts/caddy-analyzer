package analysis

import (
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
	status int
	ua     string
}

// AuthAbuseDetector retains bounded failure evidence, independently of report
// and Guard reset cadence. Like Detector, it is used by a single ingest loop.
type AuthAbuseDetector struct {
	cfg        AuthAbuseConfig
	windows    [3]time.Duration
	maxWindow  time.Duration
	maxSamples int
	samples    int
	now        time.Time
	pruned     time.Time
	failures   map[authKey][]authFailure
}

// NewSession creates independent evidence storage with the validated settings.
func (d *AuthAbuseDetector) NewSession() *AuthAbuseDetector {
	if d == nil {
		return nil
	}
	copy := *d
	copy.now, copy.pruned, copy.samples = time.Time{}, time.Time{}, 0
	copy.failures = make(map[authKey][]authFailure)
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
	d := &AuthAbuseDetector{cfg: cfg, failures: make(map[authKey][]authFailure)}
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
		d.windows[i] = window
		d.maxWindow = max(d.maxWindow, window)
		d.maxSamples = max(d.maxSamples, rule.Failures)
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
	if !slices.Contains(d.cfg.Endpoints, path) || !slices.Contains(d.cfg.FailureStatuses, e.Status) || !e.Timestamp.After(d.now.Add(-d.maxWindow)) {
		return nil
	}
	key := authKey{strings.ToLower(e.Host), path, net.ParseIP(e.RemoteIP).String()}
	events := d.failures[key]
	// ponytail: at most 100k failure samples across all clients; use an external
	// correlation store if campaigns exceed this in-memory evidence budget.
	if events == nil && len(d.failures) >= DefaultIPCap {
		return nil
	}
	if d.maxSamples == 0 {
		return nil
	}
	if d.samples >= DefaultIPCap {
		return nil
	}
	d.samples++
	events = append(events, authFailure{e.Timestamp, e.Status, e.UserAgent})
	slices.SortFunc(events, func(a, b authFailure) int { return a.at.Compare(b.at) })
	if len(events) > d.maxSamples {
		d.samples -= len(events) - d.maxSamples
		events = events[len(events)-d.maxSamples:]
	}
	d.failures[key] = events
	return d.detections(key, true)
}

func (d *AuthAbuseDetector) advance(now time.Time) {
	if now.After(d.now) {
		d.now = now
	}
	if d.now.Sub(d.pruned) < time.Second {
		return
	}
	cutoff := d.now.Add(-d.maxWindow)
	for key, events := range d.failures {
		before := len(events)
		events = slices.DeleteFunc(events, func(e authFailure) bool { return !e.at.After(cutoff) })
		d.samples -= before - len(events)
		if len(events) == 0 {
			delete(d.failures, key)
		} else {
			d.failures[key] = events
		}
	}
	d.pruned = d.now
}

// Current returns per-IP detections still supported by live evidence.
func (d *AuthAbuseDetector) Current(now time.Time) []Detection {
	if d == nil {
		return nil
	}
	d.advance(now)
	var out []Detection
	for key := range d.failures {
		out = append(out, d.detections(key, false)...)
	}
	return out
}

// ForgetIP consumes evidence after a successful ban, avoiding stale re-bans.
func (d *AuthAbuseDetector) ForgetIP(ip string) {
	if d == nil {
		return
	}
	for key, events := range d.failures {
		if key.ip == ip {
			d.samples -= len(events)
			delete(d.failures, key)
		}
	}
}

func (d *AuthAbuseDetector) detections(key authKey, spray bool) []Detection {
	// ponytail: aggregate checks scan retained evidence for this endpoint;
	// add rolling endpoint counters if profiling shows this dominates ingest.
	var out []Detection
	for i, rule := range []AuthThreshold{d.cfg.BruteForce, d.cfg.CredentialStuffing, d.cfg.PasswordSpray} {
		if rule.Failures == 0 || (i == 2 && !spray) {
			continue
		}
		count := 0
		ips, uas, statuses := map[string]bool{}, map[string]bool{}, map[int]bool{}
		cutoff := d.now.Add(-d.windows[i])
		evidence := d.failures
		if i != 2 {
			evidence = map[authKey][]authFailure{key: d.failures[key]}
		}
		for k, events := range evidence {
			if k.host != key.host || k.path != key.path || (i != 2 && k.ip != key.ip) {
				continue
			}
			for _, e := range events {
				if !e.at.After(cutoff) {
					continue
				}
				count++
				ips[k.ip] = true
				if e.ua != "" {
					uas[e.ua] = true
				}
				statuses[e.status] = true
			}
		}
		if count < rule.Failures || (i == 1 && len(uas) < rule.UniqueUAs) || (i == 2 && len(ips) < rule.UniqueIPs) {
			continue
		}
		dt, ip, technique := DetBruteForce, key.ip, "T1110.001"
		if i == 1 {
			dt, technique = DetCredentialStuffing, "T1110.004"
		}
		if i == 2 {
			dt, ip, technique = DetPasswordSpray, "", "T1110.003"
		}
		codes := make([]int, 0, len(statuses))
		for code := range statuses {
			codes = append(codes, code)
		}
		slices.Sort(codes)
		desc := fmt.Sprintf("Suspected %s: %d failures on %s%s in %s; %d IPs, %d User-Agents; status codes %v", dt, count, key.host, key.path, d.windows[i], len(ips), len(uas), codes)
		out = append(out, Detection{Type: dt, IP: ip, URI: key.path, Desc: desc, Confidence: 7, Techniques: []string{technique}})
	}
	return out
}
