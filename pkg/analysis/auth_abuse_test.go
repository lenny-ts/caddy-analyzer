package analysis

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestAuthAbuse(t *testing.T) {
	base := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name   string
		change func(int, *types.LogEntry)
		want   DetectionType
	}{
		{"brute force", nil, DetBruteForce},
		{"credential stuffing heuristic", func(i int, e *types.LogEntry) { e.UserAgent = fmt.Sprint(i) }, DetCredentialStuffing},
		{"distributed spraying", func(i int, e *types.LogEntry) { e.RemoteIP = fmt.Sprintf("203.0.113.%d", i+1) }, DetPasswordSpray},
		{"successful login traffic", func(_ int, e *types.LogEntry) { e.Status = 200 }, ""},
		{"login page visits", func(_ int, e *types.LogEntry) { e.Status = 302; e.Method = "GET" }, ""},
		{"unrelated forbidden endpoint", func(_ int, e *types.LogEntry) { e.URI = "/private" }, ""},
		{"slow failed logins", func(i int, e *types.LogEntry) { e.Timestamp = base.Add(time.Duration(i) * time.Minute) }, ""},
		{"separate endpoints", func(i int, e *types.LogEntry) {
			if i%2 == 0 {
				e.URI = "/api/login"
			}
		}, ""},
		{"separate hosts", func(i int, e *types.LogEntry) { e.Host = fmt.Sprint(i) }, ""},
		{"query strings share endpoint", func(i int, e *types.LogEntry) { e.URI = fmt.Sprintf("/login?next=%d", i) }, DetBruteForce},
		{"encoded endpoint", func(_ int, e *types.LogEntry) { e.URI = "/%6cogin" }, DetBruteForce},
		{"custom failure code", func(_ int, e *types.LogEntry) { e.Status = 429 }, DetBruteForce},
		{"invalid source", func(_ int, e *types.LogEntry) { e.RemoteIP = "not-an-ip" }, ""},
		{"missing timestamp", func(_ int, e *types.LogEntry) { e.Timestamp = time.Time{} }, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := AuthAbuseConfig{Enabled: true, FailureStatuses: []int{401, 403, 429},
				BruteForce:         AuthThreshold{Failures: 4, Window: "1m"},
				CredentialStuffing: AuthThreshold{Failures: 4, Window: "1m", UniqueUAs: 3},
				PasswordSpray:      AuthThreshold{Failures: 4, Window: "1m", UniqueIPs: 4}}
			auth, err := NewAuthAbuseDetector(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var found bool
			for i := 0; i < 4; i++ {
				e := &types.LogEntry{Timestamp: base.Add(time.Duration(i) * time.Second), RemoteIP: "203.0.113.10", Host: "example.com", URI: "/login", Method: "POST", Status: 401, UserAgent: "Browser"}
				if tt.change != nil {
					tt.change(i, e)
				}
				for _, det := range auth.Observe(e) {
					if i < 3 {
						t.Fatalf("premature detection: %+v", det)
					}
					if det.Type == tt.want {
						found = true
					}
					if tt.want == "" {
						t.Fatalf("legitimate traffic flagged: %+v", det)
					}
					if det.Type == DetPasswordSpray && det.IP != "" {
						t.Fatal("spray attributed to one IP")
					}
					if !strings.Contains(det.Desc, "status codes") || len(det.Techniques) != 1 {
						t.Fatalf("missing metadata: %+v", det)
					}
				}
			}
			if tt.want != "" && !found {
				t.Fatalf("missing %s", tt.want)
			}
			if got := auth.Current(base.Add(2 * time.Hour)); len(got) != 0 {
				t.Fatalf("expired evidence retained: %v", got)
			}
			for _, window := range auth.windows {
				if window != nil && (len(window.events) != 0 || len(window.counts) != 0) {
					t.Fatal("expired storage not reclaimed")
				}
			}
		})
	}
}

func TestAuthAbuseWindowAndReports(t *testing.T) {
	cfg := AuthAbuseConfig{Enabled: true, BruteForce: AuthThreshold{Failures: 3, Window: "1m"},
		PasswordSpray: AuthThreshold{Failures: 3, Window: "1m", UniqueIPs: 3}}
	auth, err := NewAuthAbuseDetector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	entry := func(ip string, offset time.Duration) *types.LogEntry {
		return &types.LogEntry{RemoteIP: ip, URI: "/login", Timestamp: base.Add(offset), Status: 401}
	}
	auth.Observe(entry("203.0.113.1", 0))
	auth.Observe(entry("203.0.113.1", time.Minute))
	if len(auth.Observe(entry("203.0.113.1", time.Minute+time.Second))) != 0 {
		t.Fatal("window included expired boundary")
	}
	if len(auth.Observe(entry("203.0.113.1", 30*time.Second))) == 0 {
		t.Fatal("in-window out-of-order evidence ignored")
	}
	if len(auth.Observe(entry("203.0.113.1", -time.Hour))) != 0 {
		t.Fatal("stale event emitted detection")
	}
	auth.ForgetIP("203.0.113.1")
	if len(auth.Current(base.Add(time.Minute+time.Second))) != 0 {
		t.Fatal("consumed evidence retained")
	}
	for _, window := range auth.NewSession().windows {
		if window != nil && (len(window.events) != 0 || len(window.counts) != 0) {
			t.Fatal("sessions share evidence")
		}
	}

	engine := New(types.Filters{})
	engine.SetDetector(NewDetectorWithPatterns(nil, auth.NewSession()))
	for i := 1; i <= 3; i++ {
		engine.Process(entry(fmt.Sprintf("203.0.113.%d", i), time.Duration(i)*time.Second))
	}
	if len(engine.Stats().SuspiciousDetections["aggregate"]) != 1 {
		t.Fatalf("spraying missing from report: %+v", engine.Stats().SuspiciousDetections)
	}
	if engine.Stats().SuspiciousIPs["203.0.113.3"] != 0 {
		t.Fatal("aggregate attack blamed on last client")
	}
	engine = New(types.Filters{})
	engine.SetDetector(NewDetectorWithPatterns(nil, auth.NewSession()))
	for i := 0; i < 3; i++ {
		e := entry("2001:db8:0:0:0:0:0:1", time.Duration(i)*time.Second)
		e.UserAgent = "sqlmap"
		engine.Process(e)
	}
	if len(engine.Stats().SuspiciousIPs) != 1 || engine.Stats().SuspiciousIPs["2001:db8:0:0:0:0:0:1"] != 3 {
		t.Fatalf("signature/auth IP aliases counted separately: %v", engine.Stats().SuspiciousIPs)
	}
}

func TestAuthAbuseConfig(t *testing.T) {
	for _, cfg := range []AuthAbuseConfig{
		{Enabled: true, Endpoints: []string{}},
		{Enabled: true, Endpoints: []string{""}},
		{Enabled: true, Endpoints: []string{"/login?x=1"}},
		{Enabled: true, FailureStatuses: []int{200}},
		{Enabled: true, FailureStatuses: []int{}},
		{Enabled: true, BruteForce: AuthThreshold{Failures: -1, Window: "1m"}},
		{Enabled: true, BruteForce: AuthThreshold{Failures: 1, Window: "0s"}},
		{Enabled: true, BruteForce: AuthThreshold{Failures: 1, Window: "25h"}},
		{Enabled: true, PasswordSpray: AuthThreshold{Failures: 2, Window: "1m", UniqueIPs: 3}},
		{Enabled: true, CredentialStuffing: AuthThreshold{Failures: 2, Window: "1m", UniqueUAs: 1}},
	} {
		if _, err := NewAuthAbuseDetector(cfg); err == nil {
			t.Errorf("accepted invalid config: %+v", cfg)
		}
	}
	if d, err := NewAuthAbuseDetector(AuthAbuseConfig{}); err != nil || d != nil {
		t.Fatal("disabled config must be inert")
	}
	d, err := NewAuthAbuseDetector(AuthAbuseConfig{Enabled: true})
	if err != nil || d == nil {
		t.Fatalf("defaults: %v", err)
	}
	now := time.Now()
	for i := 0; i < 200; i++ {
		d.Observe(&types.LogEntry{Timestamp: now, RemoteIP: "203.0.113.1", URI: "/login", Status: 401})
	}
	for _, window := range d.windows {
		if len(window.events) != 200 {
			t.Fatalf("live failures discarded: %d", len(window.events))
		}
	}
}

func TestAuthAbuseCustomEndpointAndDisabledRule(t *testing.T) {
	d, err := NewAuthAbuseDetector(AuthAbuseConfig{Enabled: true, Endpoints: []string{"/auth"},
		BruteForce:         AuthThreshold{Failures: 2, Window: "1m"},
		CredentialStuffing: AuthThreshold{Window: "1m"}, PasswordSpray: AuthThreshold{Window: "1m"}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, path := range []string{"/login", "/auth", "/auth"} {
		got := d.Observe(&types.LogEntry{Timestamp: now, RemoteIP: "203.0.113.1", URI: path, Status: 401})
		if path == "/login" && len(got) != 0 {
			t.Fatal("default endpoint still active")
		}
	}
	got := d.Current(now)
	if len(got) != 1 || got[0].Type != DetBruteForce {
		t.Fatalf("custom endpoint: %v", got)
	}
	d.advance(now.Add(2 * time.Minute))
	for _, window := range d.windows {
		if window != nil && (len(window.events) != 0 || len(window.counts) != 0) {
			t.Fatal("bounded evidence not reclaimed")
		}
	}
}

func TestAuthAbuseRetainsWindowDiversity(t *testing.T) {
	d, err := NewAuthAbuseDetector(AuthAbuseConfig{Enabled: true,
		BruteForce: AuthThreshold{Window: "1m"}, PasswordSpray: AuthThreshold{Window: "1m"},
		CredentialStuffing: AuthThreshold{Failures: 3, Window: "1m", UniqueUAs: 3}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var got []Detection
	for i, ua := range []string{"a", "b", "b", "b", "c"} {
		got = d.Observe(&types.LogEntry{Timestamp: now.Add(time.Duration(i) * time.Second),
			RemoteIP: "203.0.113.1", URI: "/login", Status: 401, UserAgent: ua})
	}
	if len(got) != 1 || got[0].Type != DetCredentialStuffing || !strings.Contains(got[0].Desc, "5 failures") {
		t.Fatalf("live diversity/counts lost: %+v", got)
	}
	d.ForgetIP("203.0.113.0/24")
	if got := d.Current(now.Add(5 * time.Second)); len(got) != 0 {
		t.Fatalf("subnet ban left stale evidence: %+v", got)
	}
}

func BenchmarkAuthAbuseDistributed(b *testing.B) {
	for _, clients := range []int{100, 10000} {
		b.Run(fmt.Sprint(clients), func(b *testing.B) {
			d, err := NewAuthAbuseDetector(AuthAbuseConfig{Enabled: true})
			if err != nil {
				b.Fatal(err)
			}
			now := time.Now()
			for i := 0; i < clients; i++ {
				d.Observe(&types.LogEntry{Timestamp: now, RemoteIP: fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255), URI: "/login", Status: 401})
			}
			entry := &types.LogEntry{Timestamp: now, RemoteIP: "203.0.113.1", URI: "/login", Status: 401}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				d.Observe(entry)
			}
		})
	}
}

func TestAuthAbuseScenarioExpiryAndBudget(t *testing.T) {
	d, err := NewAuthAbuseDetector(AuthAbuseConfig{Enabled: true,
		BruteForce:         AuthThreshold{Failures: 3, Window: "250ms"},
		CredentialStuffing: AuthThreshold{Failures: 3, Window: "500ms", UniqueUAs: 2},
		PasswordSpray:      AuthThreshold{Failures: 3, Window: "1s", UniqueIPs: 2}})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	var got []Detection
	for i, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.1", "203.0.113.1"} {
		status, ua := 401, "a"
		if i == 1 {
			status, ua = 403, "b"
		}
		if i == 3 {
			ua = "c"
		}
		got = d.Observe(&types.LogEntry{Timestamp: base.Add(time.Duration(i) * 100 * time.Millisecond), RemoteIP: ip, URI: "/login", Status: status, UserAgent: ua})
	}
	if len(got) != 2 || got[0].Type != DetCredentialStuffing || got[1].Type != DetPasswordSpray {
		t.Fatalf("scenario windows mixed: %+v", got)
	}
	if got := d.Current(base.Add(500 * time.Millisecond)); len(got) != 0 {
		t.Fatalf("credential window retained expired event: %+v", got)
	}
	d.advance(base.Add(1100 * time.Millisecond))
	counts := d.windows[2].counts[authKey{"", "/login", ""}]
	if counts.count != 2 || len(counts.ips) != 1 || len(counts.uas) != 2 || counts.statuses[403] != 0 {
		t.Fatalf("expired dimensions retained: %+v", counts)
	}
	session := d.NewSession()
	if len(session.windows[2].events) != 0 || len(d.windows[2].events) != 2 {
		t.Fatal("session storage not independent")
	}

	d, err = NewAuthAbuseDetector(AuthAbuseConfig{Enabled: true,
		BruteForce:         AuthThreshold{Failures: DefaultIPCap, Window: "1m"},
		CredentialStuffing: AuthThreshold{Window: "1m"}, PasswordSpray: AuthThreshold{Window: "1m"}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < DefaultIPCap+1; i++ {
		d.Observe(&types.LogEntry{Timestamp: base, RemoteIP: "203.0.113.1", URI: "/login", Status: 401})
	}
	if len(d.windows[0].events) != DefaultIPCap {
		t.Fatal("failure budget exceeded")
	}
	d.Observe(&types.LogEntry{Timestamp: base.Add(time.Minute), RemoteIP: "203.0.113.2", URI: "/login", Status: 401})
	if len(d.windows[0].events) != 1 || len(d.windows[0].counts) != 1 {
		t.Fatal("budget not reclaimed at expiry")
	}
}
