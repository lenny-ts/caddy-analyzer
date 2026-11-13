package guard

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"testing"
	"time"
)

func TestGuardThresholdBanRequiresFreshTraffic(t *testing.T) {
	for _, escalation := range []bool{false, true} {
		mode := "default"
		if escalation {
			mode = "escalation"
		}
		for _, threshold := range []string{"requests", "auth", "notfound", "subnet"} {
			t.Run(mode+"/"+threshold, func(t *testing.T) {
				blocks := make(chan struct{}, 16)
				cfg := Config{
					Window: time.Minute, EvalInterval: 10 * time.Millisecond,
					BlockDuration: 50 * time.Millisecond, Blocker: newFakeBlocker(),
					BanEscalation: escalation, StatePath: filepath.Join(t.TempDir(), "blocked.json"),
					OnAudit: func(action, _, _, _ string) {
						if action == "block" {
							blocks <- struct{}{}
						}
					},
				}
				status := 200
				switch threshold {
				case "requests":
					cfg.Limit = 1
				case "auth":
					cfg.AuthLimit, status = 1, 401
				case "notfound":
					cfg.NotFoundLimit, status = 1, 404
				case "subnet":
					cfg.SubnetLimit = 1
				}
				g := New(cfg)
				lines := startGuardRunForEvalTest(t, g)
				lines <- caddyLine("203.0.113.10", "/api", "GET", status)
				select {
				case <-blocks:
				case <-time.After(2 * time.Second):
					t.Fatal("initial ban missing")
				}
				select {
				case <-blocks:
					t.Fatal("same traffic triggered another ban after expiry")
				case <-time.After(200 * time.Millisecond):
				}
			})
		}
	}
}

func TestGuardFailedThresholdBlockKeepsEvidenceForRetry(t *testing.T) {
	fb := newFakeBlocker()
	fb.blockErr = errors.New("firewall unavailable")
	g := New(Config{Limit: 1, Window: time.Minute, Blocker: fb})
	g.Evaluate(caddyLine("203.0.113.10", "/api", "GET", 200))
	if blocked := g.evaluate(context.Background(), time.Now()); len(blocked) != 0 {
		t.Fatal("failed firewall operation counted as a ban")
	}
	fb.blockErr = nil
	if blocked := g.evaluate(context.Background(), time.Now()); len(blocked) != 1 {
		t.Fatal("failed block consumed threshold evidence")
	}
}

type slowCadenceBlocker struct{ *fakeBlocker }

func (b slowCadenceBlocker) Block(ip string) error {
	time.Sleep(750 * time.Millisecond)
	return b.fakeBlocker.Block(ip)
}

func TestGuardLateWindowUsesActualElapsedTime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var start time.Time
	var elapsed time.Duration
	g := New(Config{
		Limit: 1, Window: time.Second, EvalInterval: time.Second,
		CredStuffingLimit: 1, Blocker: slowCadenceBlocker{newFakeBlocker()},
		OnAudit: func(action, _, _, _ string) {
			if action == "cred_stuffing" {
				elapsed = time.Since(start)
				cancel()
			}
		},
	})
	g.Evaluate(caddyLine("203.0.113.11", "/login", "POST", 401))
	done := make(chan struct{})
	start = time.Now()
	go func() {
		g.Run(ctx, make(chan string), func(string, ...interface{}) {})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("guard did not stop")
	}
	want := 1 / elapsed.Seconds()
	if math.Abs(g.ewmaRPS-want)/want > 0.05 {
		t.Fatalf("one request over %s: reported %.3f RPS, want %.3f", elapsed, g.ewmaRPS, want)
	}
}

func TestGuardAnomalyUsesFractionalSampleDuration(t *testing.T) {
	g := New(Config{Window: time.Second, Blocker: newFakeBlocker()})
	g.tickReqs.Store(7)
	g.detectAnomaly(1750 * time.Millisecond)
	if g.ewmaRPS != 4 {
		t.Fatalf("RPS = %v, want 7 / 1.75 = 4", g.ewmaRPS)
	}
}
