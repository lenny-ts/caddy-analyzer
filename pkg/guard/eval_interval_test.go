package guard

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Reproduce #124 with its real window, 404 threshold and default evaluation
// cadence. Stop once blocked rather than spending the full 20s on the scan.
func TestGuardIssue124Blocks404ScanBeforeBurstEnds(t *testing.T) {
	events := make(chan string, 1)
	g := New(Config{
		Limit: 100, AuthLimit: 10, NotFoundLimit: 50,
		Window: time.Minute, BlockDuration: 10 * time.Minute,
		Blocker: newFakeBlocker(),
		OnAudit: func(action, _, reason, _ string) {
			if action == "block" {
				events <- reason
			}
		},
	})
	start := time.Now()
	lines := startGuardRunForEvalTest(t, g)
	requests := time.NewTicker(20 * time.Second / 221)
	defer requests.Stop()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	sent := 0
	for {
		select {
		case <-requests.C:
			status := 404
			if sent < 5 {
				status = 200
			}
			sent++
			lines <- caddyLine("203.0.113.124", "/missing", "GET", status)
		case reason := <-events:
			elapsed := time.Since(start)
			if !strings.Contains(reason, "not found") || sent >= 221 || elapsed >= 20*time.Second {
				t.Fatalf("scan was not stopped promptly by the 404 threshold: %d requests, %s, %q", sent, elapsed, reason)
			}
			t.Logf("#124: blocked after %s, at request %d/221; %s; window=1m, default eval=1s", elapsed, sent, reason)
			return
		case <-deadline.C:
			t.Fatalf("404 scan still unblocked after 10s (%d requests); evaluation must not wait for the 1m window", sent)
		}
	}
}

func TestGuardEvalIntervalDefaultsAndClamping(t *testing.T) {
	for _, tt := range []struct {
		name                   string
		window, interval, want time.Duration
	}{
		{"default", time.Minute, 0, time.Second},
		{"short window", 50 * time.Millisecond, 0, 50 * time.Millisecond},
		{"explicit", time.Minute, 10 * time.Millisecond, 10 * time.Millisecond},
		{"capped", time.Second, 5 * time.Second, time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := New(Config{Window: tt.window, EvalInterval: tt.interval, Blocker: newFakeBlocker()})
			if got := g.evalInterval(); got != tt.want {
				t.Fatalf("evalInterval=%s, want %s", got, tt.want)
			}
		})
	}
}

func startGuardRunForEvalTest(t *testing.T, g *Guard) chan string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	linesCh := make(chan string, 16)
	done := make(chan struct{})
	go func() {
		g.Run(ctx, linesCh, func(string, ...interface{}) {})
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("Run did not stop after context cancel")
		}
	})
	return linesCh
}

func waitForGuardBlocked(t *testing.T, g *Guard, ip string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if g.IsBlocked(ip) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s was not blocked within %s", ip, timeout)
}

// TestGuardRunEvalIntervalBlocksBurstBeforeWindow exercises the incident:
// a short burst crosses the limit long before the 1m counting window ends.
// Run must evaluate at EvalInterval, not wait for the window ticker.
func TestGuardRunEvalIntervalBlocksBurstBeforeWindow(t *testing.T) {
	g := New(Config{
		Limit:         3,
		AuthLimit:     0,
		NotFoundLimit: 0,
		Window:        time.Minute,
		EvalInterval:  10 * time.Millisecond,
		IPValidator:   func(string) error { return nil },
		Blocker:       newFakeBlocker(),
	})
	linesCh := startGuardRunForEvalTest(t, g)

	for i := 0; i < 3; i++ {
		linesCh <- caddyLine("203.0.113.10", "/api", "GET", 200)
	}

	waitForGuardBlocked(t, g, "203.0.113.10", 3*time.Second)
}

// TestGuardRunEvalIntervalBlocksPatternBeforeWindow covers the same
// delayed-evaluation bug on the pattern-detection path.
func TestGuardRunEvalIntervalBlocksPatternBeforeWindow(t *testing.T) {
	g := New(Config{
		Limit:               0,
		AuthLimit:           0,
		NotFoundLimit:       0,
		Window:              time.Minute,
		EvalInterval:        10 * time.Millisecond,
		DetectionConfidence: 8,
		IPValidator:         func(string) error { return nil },
		Blocker:             newFakeBlocker(),
	})
	linesCh := startGuardRunForEvalTest(t, g)

	linesCh <- caddyLine("203.0.113.11", "/search?id=1%27%20UNION%20SELECT%20username%20FROM%20users--", "GET", 200)

	waitForGuardBlocked(t, g, "203.0.113.11", 3*time.Second)
}

// TestGuardRunResetsWindowOnWindowCadence verifies that the per-window reset
// follows the window deadline, not the evaluation ticker. With an evaluation
// interval larger than half the window, a tick-driven reset lands on the
// second tick (2×eval) instead of on the first window boundary (1×window).
func TestGuardRunResetsWindowOnWindowCadence(t *testing.T) {
	const (
		window       = time.Second
		evalInterval = 750 * time.Millisecond
	)
	g := New(Config{
		Window:       window,
		EvalInterval: evalInterval,
		IPValidator:  func(string) error { return nil },
		Blocker:      newFakeBlocker(),
	})

	start := time.Now()
	startGuardRunForEvalTest(t, g)

	prev := g.Engine()
	var resets []time.Time
	deadline := start.Add(3 * window)
	for time.Now().Before(deadline) && len(resets) < 2 {
		if eng := g.Engine(); eng != prev {
			resets = append(resets, time.Now())
			prev = eng
		}
		time.Sleep(time.Millisecond)
	}
	if len(resets) < 2 {
		t.Fatalf("expected 2 window resets within %s, got %d", 3*window, len(resets))
	}

	// The midpoint between one window and two evaluation ticks discriminates
	// window-cadence resets from tick-cadence resets.
	limit := (window + 2*evalInterval) / 2
	if first := resets[0].Sub(start); first >= limit {
		t.Fatalf("first reset after %s, want near %s (window cadence), not %s (tick cadence)", first, window, 2*evalInterval)
	}
	if gap := resets[1].Sub(resets[0]); gap >= limit {
		t.Fatalf("second reset gap %s, want near %s (window cadence), not %s (tick cadence)", gap, window, 2*evalInterval)
	}
}
