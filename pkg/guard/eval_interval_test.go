package guard

import (
	"context"
	"testing"
	"time"
)

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
