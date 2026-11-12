package guard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func escalationConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Limit: 1, Window: time.Minute, BlockDuration: 10 * time.Minute,
		BanEscalation: true, StatePath: filepath.Join(t.TempDir(), "blocked.json"),
		Blocker: newFakeBlocker(),
	}
}

func TestBanEscalationLevelsAndRestart(t *testing.T) {
	cfg := escalationConfig(t)
	g := New(cfg)
	now := time.Now()
	ip := "203.0.113.10"
	for i, want := range []time.Duration{10 * time.Minute, time.Hour, 24 * time.Hour, 168 * time.Hour, 168 * time.Hour} {
		if !g.block(context.Background(), Candidate{IP: ip, Why: "test"}, now) {
			t.Fatalf("offense %d did not block", i+1)
		}
		if got := g.expiries[ip].Sub(now); got != want {
			t.Fatalf("offense %d: duration %s, want %s", i+1, got, want)
		}
		g.FlushState()
		g = New(cfg)
		o, err := GetOffender(cfg.StatePath, ip)
		if err != nil || o == nil || o.Offenses != i+1 || !g.IsBlocked(ip) {
			t.Fatalf("restart lost ban/history: offender=%+v err=%v", o, err)
		}
		// Simulate the recorded expiry without sleeping for days.
		g.removeBlocked(ip)
		delete(g.expiries, ip)
		now = now.Add(want + time.Second)
	}
}

func TestEscalationCapResetAndLiveManualReset(t *testing.T) {
	cfg := escalationConfig(t)
	cfg.MaxBanDuration = 30 * time.Minute
	g := New(cfg)
	ip, now := "2001:db8::10", time.Now()
	for i, want := range []time.Duration{10 * time.Minute, 30 * time.Minute, 30 * time.Minute} {
		if !g.block(context.Background(), Candidate{IP: ip}, now) || g.expiries[ip].Sub(now) != want {
			t.Fatalf("offense %d did not respect cap", i+1)
		}
		g.removeBlocked(ip)
		delete(g.expiries, ip)
		now = now.Add(time.Hour)
	}
	if err := ResetOffender(cfg.StatePath, "2001:0db8::10"); err != nil {
		t.Fatal(err)
	}
	if !g.block(context.Background(), Candidate{IP: ip}, now) || g.expiries[ip].Sub(now) != 10*time.Minute {
		t.Fatal("manual reset was not seen by running guard")
	}
	if err := ResetOffender(cfg.StatePath, ip); err != nil || !g.IsBlocked(ip) {
		t.Fatal("reset must not remove an active ban", err)
	}
	if _, err := os.Stat(cfg.StatePath); err != nil {
		t.Fatal("reset removed ban state", err)
	}
}

func TestEscalationExpiryAndPruning(t *testing.T) {
	cfg := escalationConfig(t)
	cfg.BanResetAfter = time.Hour
	g := New(cfg)
	ip, now := "203.0.113.10", time.Now()
	if !g.block(context.Background(), Candidate{IP: ip}, now) {
		t.Fatal("first ban failed")
	}
	o, duration, err := g.nextOffense(ip, now.Add(time.Hour))
	if err != nil || o.Offenses != 1 || duration != cfg.BlockDuration {
		t.Fatalf("reset period ignored: %+v, %s, %v", o, duration, err)
	}
	g.pruneOffenders(now.Add(time.Hour))
	sf, _, _ := offenderFile(cfg.StatePath, ip)
	if _, err := os.Stat(sf.path); !os.IsNotExist(err) {
		t.Fatal("expired history was not removed", err)
	}
	if !g.IsBlocked(ip) {
		t.Fatal("history expiry must not alter an active ban")
	}
}

func TestEscalationRequiresFreshEvidence(t *testing.T) {
	for _, pattern := range []bool{false, true} {
		cfg := escalationConfig(t)
		cfg.DetectionConfidence = 8
		g := New(cfg)
		uri := "/api"
		if pattern {
			g.cfg.Limit = 0
			uri = "/search?id=1%27%20UNION%20SELECT%20username%20FROM%20users--"
		}
		g.Evaluate(caddyLine("203.0.113.10", uri, "GET", 200))
		if len(g.Tick(context.Background())) != 1 {
			t.Fatal("initial detection missing")
		}
		g.removeBlocked("203.0.113.10")
		delete(g.expiries, "203.0.113.10")
		if blocked := g.Tick(context.Background()); len(blocked) != 0 {
			t.Fatal("old evidence triggered a repeat offense", blocked)
		}
	}
}

func TestEscalationOnlyCountsSuccessfulUnprotectedBans(t *testing.T) {
	cfg := escalationConfig(t)
	cfg.NeverBlock = []string{"203.0.113.10"}
	g := New(cfg)
	if g.block(context.Background(), Candidate{IP: "203.0.113.10"}, time.Now()) {
		t.Fatal("allowlisted IP blocked")
	}
	cfg.Blocker.(*fakeBlocker).blockErr = errors.New("firewall unavailable")
	if g.block(context.Background(), Candidate{IP: "203.0.113.11"}, time.Now()) {
		t.Fatal("failed firewall ban counted")
	}
	offenders, err := ListOffenders(cfg.StatePath)
	if err != nil || len(offenders) != 0 {
		t.Fatal("failed/protected decisions created history", offenders, err)
	}
}

func TestEscalationDisabledAndDryRun(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg := escalationConfig(t)
		cfg.BanEscalation, cfg.DryRun = enabled, enabled
		g := New(cfg)
		for i := 0; i < 2; i++ {
			if !g.block(context.Background(), Candidate{IP: "203.0.113.10"}, time.Now()) {
				t.Fatal("ban failed")
			}
			if !enabled && time.Until(g.expiries["203.0.113.10"]) > cfg.BlockDuration {
				t.Fatal("disabled escalation changed duration")
			}
			g.removeBlocked("203.0.113.10")
			delete(g.expiries, "203.0.113.10")
		}
		if _, err := os.Stat(cfg.StatePath + ".offenders"); !os.IsNotExist(err) {
			t.Fatal("disabled/dry-run mode wrote history", err)
		}
		if enabled && g.dryOffenders["203.0.113.10"].Offenses != 2 {
			t.Fatal("dry-run did not simulate repeat offenses")
		}
	}
}

func TestOffenderStateValidationListingAndPermissions(t *testing.T) {
	cfg := escalationConfig(t)
	g := New(cfg)
	for _, ip := range []string{"203.0.113.12", "203.0.113.10/24"} {
		if !g.block(context.Background(), Candidate{IP: ip}, time.Now()) {
			t.Fatal("ban failed", ip)
		}
	}
	offenders, err := ListOffenders(cfg.StatePath)
	if err != nil || len(offenders) != 2 || offenders[0].IP != "203.0.113.0/24" {
		t.Fatal("unexpected offender listing", offenders, err)
	}
	sf, _, _ := offenderFile(cfg.StatePath, "203.0.113.12")
	if runtime.GOOS != "windows" {
		info, err := os.Stat(sf.path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("unsafe offender file permissions", err)
		}
	}
	if err := os.WriteFile(sf.path, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.nextOffense("203.0.113.12", time.Now()); err == nil {
		t.Fatal("corrupt history was silently overwritten")
	}
	g.removeBlocked("203.0.113.12")
	g.removeBlocked("203.0.113.10/24")
	var reported error
	g.cfg.OnError = func(err error) { reported = err }
	if !g.block(context.Background(), Candidate{IP: "203.0.113.12"}, time.Now()) || reported == nil {
		t.Fatal("corrupt history must not disable base firewall protection")
	}
	data, err := os.ReadFile(sf.path)
	if err != nil || string(data) != "{broken" {
		t.Fatal("corrupt history was overwritten", err)
	}
	if err := ResetOffender(cfg.StatePath, "../../escape"); err == nil {
		t.Fatal("invalid address accepted")
	}
}

func TestBanEscalationConfiguration(t *testing.T) {
	valid := escalationConfig(t)
	for _, mutate := range []func(*Config){
		func(c *Config) { c.StatePath = "" },
		func(c *Config) { c.BlockDuration = 0 },
		func(c *Config) { c.MaxBanDuration = -time.Second },
		func(c *Config) { c.BanResetAfter = -time.Second },
	} {
		cfg := valid
		mutate(&cfg)
		if err := ValidateBanEscalation(cfg); err == nil {
			t.Fatal("invalid escalation config accepted", cfg)
		}
		cfg.BanEscalation = false
		if err := ValidateBanEscalation(cfg); err != nil {
			t.Fatal("disabled escalation must preserve existing behavior", err)
		}
	}
}

func TestEscalationRunExpiryRequiresAnotherRequest(t *testing.T) {
	cfg := escalationConfig(t)
	cfg.Window, cfg.BlockDuration, cfg.MaxBanDuration = 100*time.Millisecond, 20*time.Millisecond, 40*time.Millisecond
	type event struct{ action, duration string }
	events := make(chan event, 16)
	cfg.OnAudit = func(action, _, _, duration string) { events <- event{action, duration} }
	g := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	lines := make(chan string, 8)
	done := make(chan struct{})
	go func() { g.Run(ctx, lines, func(string, ...interface{}) {}); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("guard did not stop")
		}
	})
	waitEvent := func(action, duration string) {
		t.Helper()
		select {
		case e := <-events:
			if e.action != action || (action == "block" && e.duration != duration) {
				t.Fatalf("event %+v, want %s %s", e, action, duration)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for", action)
		}
	}
	line := caddyLine("203.0.113.10", "/api", "GET", 200)
	lines <- line
	waitEvent("block", "20ms")
	waitEvent("unblock", "")
	select {
	case e := <-events:
		t.Fatal("old request triggered a new ban", e)
	case <-time.After(250 * time.Millisecond):
	}
	lines <- line
	waitEvent("block", "40ms")
	select {
	case e := <-events:
		if e.action != "unblock" || e.duration != "40ms" {
			t.Fatalf("unblock audit lost escalated duration: %+v", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for escalated ban expiry")
	}
}

func TestManualUnbanPreservesOffenderHistory(t *testing.T) {
	cfg := escalationConfig(t)
	g := New(cfg)
	ip := "203.0.113.10"
	if !g.block(context.Background(), Candidate{IP: ip}, time.Now()) {
		t.Fatal("ban failed")
	}
	if err := RemoveBlockFromState(cfg.StatePath, ip); err != nil {
		t.Fatal(err)
	}
	if o, err := GetOffender(cfg.StatePath, ip); err != nil || o == nil || o.Offenses != 1 {
		t.Fatal("manual unban lost history", o, err)
	}
	if err := ResetOffender(cfg.StatePath, ip); err != nil {
		t.Fatal(err)
	}
	if o, err := GetOffender(cfg.StatePath, ip); err != nil || o != nil {
		t.Fatal("explicit reset did not remove history", o, err)
	}
}
