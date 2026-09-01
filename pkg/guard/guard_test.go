package guard

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

type fakeBlocker struct {
	mu       sync.Mutex
	blocked  map[string]bool
	blockErr error
}

func newFakeBlocker() *fakeBlocker {
	return &fakeBlocker{blocked: make(map[string]bool)}
}

func (f *fakeBlocker) Block(ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.blockErr != nil {
		return f.blockErr
	}
	f.blocked[ip] = true
	return nil
}

func (f *fakeBlocker) Unblock(ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.blocked, ip)
	return nil
}

func newTestGuard() *Guard {
	return New(Config{
		Limit:         100,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
	})
}

func TestGuardConcurrent(t *testing.T) {
	g := newTestGuard()
	g.SetBlocker(newFakeBlocker())

	var wg sync.WaitGroup
	const workers = 100
	const opsPerWorker = 200

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				ip := fmt.Sprintf("10.0.%d.%d", id, i%256)
				switch i % 4 {
				case 0:
					g.setBlocked(ip)
				case 1:
					g.IsBlocked(ip)
				case 2:
					g.removeBlocked(ip)
				case 3:
					g.Count()
				}
			}
		}(w)
	}

	wg.Wait()

	g2 := newTestGuard()
	g2.SetBlocker(newFakeBlocker())
	g2.setBlocked("192.168.1.1")
	g2.setBlocked("192.168.1.2")
	if !g2.IsBlocked("192.168.1.1") {
		t.Error("expected 192.168.1.1 to be blocked")
	}
	g2.removeBlocked("192.168.1.1")
	if g2.IsBlocked("192.168.1.1") {
		t.Error("expected 192.168.1.1 to be unblocked")
	}
	if g2.Count() != 1 {
		t.Errorf("expected count=1, got %d", g2.Count())
	}
}

func TestGuardEvaluateSkipsBlockedIP(t *testing.T) {
	g := newTestGuard()
	g.SetBlocker(newFakeBlocker())
	g.setBlocked("1.2.3.4")

	before := g.Engine().Count()
	g.Evaluate(caddyLine("1.2.3.4", "/test", "GET", 200))
	after := g.Engine().Count()

	if after != before {
		t.Errorf("blocked IP should be skipped, engine count changed from %d to %d", before, after)
	}
}

func caddyLine(ip, uri, method string, status int) string {
	return fmt.Sprintf(`{"level":"info","ts":1785148418.35,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"%s","proto":"HTTP/1.1","method":"%s","uri":"%s","headers":{"User-Agent":["Mozilla/5.0"]}},"status":%d}`, ip, method, uri, status)
}

func TestGuardEvaluateProcessesValidLine(t *testing.T) {
	g := newTestGuard()
	g.SetBlocker(newFakeBlocker())

	g.Evaluate(caddyLine("1.2.3.4", "/test", "GET", 200))

	if g.Engine().Count() != 1 {
		t.Errorf("expected engine count=1, got %d", g.Engine().Count())
	}
}

func TestGuardEvaluateSkipsInvalidJSON(t *testing.T) {
	g := newTestGuard()
	g.SetBlocker(newFakeBlocker())

	g.Evaluate(`not json at all`)

	if g.Engine().Count() != 0 {
		t.Errorf("expected engine count=0 for invalid JSON, got %d", g.Engine().Count())
	}
}

func TestGuardTickBlocksOnAuthThreshold(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.AuthLimit = 2

	for i := 0; i < 3; i++ {
		g.Evaluate(caddyLine("1.2.3.4", "/login", "POST", 401))
	}

	blocked := g.Tick(context.Background())

	if len(blocked) != 1 {
		t.Fatalf("expected 1 candidate blocked, got %d", len(blocked))
	}
	if blocked[0].IP != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4, got %s", blocked[0].IP)
	}
	if !g.IsBlocked("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be in blocked map")
	}
	if !fb.blocked["1.2.3.4"] {
		t.Error("expected fake blocker to have blocked 1.2.3.4")
	}
}

func TestGuardDryRunDoesNotCallBlockerOrPersist(t *testing.T) {
	fb := newFakeBlocker()
	statePath := t.TempDir() + "/blocked.json"
	if err := os.WriteFile(statePath, []byte("[]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var actions []string
	g := New(Config{
		Limit: 1, Window: time.Minute, BlockDuration: time.Hour,
		Blocker: fb, StatePath: statePath, DryRun: true,
		IPValidator: func(string) error { return nil },
		OnAudit:     func(action, ip, reason, duration string) { actions = append(actions, action) },
	})
	g.Evaluate(caddyLine("1.2.3.4", "/api", "GET", 200))
	if got := g.Tick(context.Background()); len(got) != 1 {
		t.Fatalf("expected one simulated block, got %d", len(got))
	}
	if len(fb.blocked) != 0 {
		t.Fatalf("dry-run called blocker: %v", fb.blocked)
	}
	if g.SessionBlocks() != 1 || !g.IsBlocked("1.2.3.4") {
		t.Fatalf("expected simulated block to be tracked")
	}
	if len(actions) != 1 || actions[0] != "would_block" {
		t.Fatalf("expected would_block audit event, got %v", actions)
	}
	data, err := os.ReadFile(statePath)
	if err != nil || string(data) != "[]\n" {
		t.Fatalf("dry-run changed state file: %q (%v)", data, err)
	}
}

func TestGuardTickBlocksOnNotFoundThreshold(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.NotFoundLimit = 3

	for i := 0; i < 4; i++ {
		g.Evaluate(caddyLine("5.6.7.8", "/nonexistent", "GET", 404))
	}

	blocked := g.Tick(context.Background())

	if len(blocked) != 1 {
		t.Fatalf("expected 1 candidate blocked, got %d", len(blocked))
	}
	if blocked[0].IP != "5.6.7.8" {
		t.Errorf("expected IP 5.6.7.8, got %s", blocked[0].IP)
	}
}

func TestGuardTickBlocksOnRequestLimit(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.Limit = 5

	for i := 0; i < 6; i++ {
		g.Evaluate(caddyLine("9.10.11.12", "/api", "GET", 200))
	}

	blocked := g.Tick(context.Background())

	if len(blocked) != 1 {
		t.Fatalf("expected 1 candidate blocked, got %d", len(blocked))
	}
	if blocked[0].IP != "9.10.11.12" {
		t.Errorf("expected IP 9.10.11.12, got %s", blocked[0].IP)
	}
}

func TestGuardTickSkipsAlreadyBlocked(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.Limit = 3

	for i := 0; i < 5; i++ {
		g.Evaluate(caddyLine("1.1.1.1", "/api", "GET", 200))
	}
	g.setBlocked("1.1.1.1")

	blocked := g.Tick(context.Background())

	if len(blocked) != 0 {
		t.Errorf("expected 0 candidates (already blocked), got %d", len(blocked))
	}
}

func TestGuardTickResetsDetectorAndEngine(t *testing.T) {
	g := newTestGuard()
	g.SetBlocker(newFakeBlocker())

	for i := 0; i < 3; i++ {
		g.Evaluate(caddyLine("1.2.3.4", "/api", "GET", 200))
	}
	if g.Engine().Count() != 3 {
		t.Fatalf("expected count=3 before tick, got %d", g.Engine().Count())
	}

	g.Tick(context.Background())

	if g.Engine().Count() != 0 {
		t.Errorf("expected count=0 after tick (reset), got %d", g.Engine().Count())
	}
}

func TestGuardBlockFailsRemovesFromBlocked(t *testing.T) {
	fb := newFakeBlocker()
	fb.blockErr = fmt.Errorf("iptables failed")
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.Limit = 1

	g.Evaluate(caddyLine("1.2.3.4", "/api", "GET", 200))

	blocked := g.Tick(context.Background())

	if len(blocked) != 0 {
		t.Errorf("expected 0 blocked (iptables failed), got %d", len(blocked))
	}
	if g.IsBlocked("1.2.3.4") {
		t.Error("IP should not be in blocked map when iptables fails")
	}
}

func TestGuardAuditOnBlock(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.Limit = 1

	var audits []struct {
		action, ip, reason, duration string
	}
	g.cfg.OnAudit = func(action, ip, reason, duration string) {
		audits = append(audits, struct {
			action, ip, reason, duration string
		}{action, ip, reason, duration})
	}
	g.cfg.BlockDuration = 0

	g.Evaluate(caddyLine("1.2.3.4", "/api", "GET", 200))
	g.Tick(context.Background())

	if len(audits) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(audits))
	}
	if audits[0].action != "block" || audits[0].ip != "1.2.3.4" {
		t.Errorf("unexpected audit: %+v", audits[0])
	}
	if audits[0].duration != "permanent" {
		t.Errorf("expected permanent duration, got %s", audits[0].duration)
	}
}

func TestGuardNeverBlockAllowlist(t *testing.T) {
	fb := newFakeBlocker()
	cfg := Config{
		Limit:         1,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		NeverBlock:    []string{"10.0.0.0/8", "192.168.1.1"},
	}
	g := New(cfg)
	g.SetBlocker(fb)

	g.Evaluate(caddyLine("10.0.0.5", "/api", "GET", 200))
	g.Tick(context.Background())

	if g.IsBlocked("10.0.0.5") {
		t.Error("10.0.0.5 should not be blocked (in 10.0.0.0/8 allowlist)")
	}
	if fb.blocked["10.0.0.5"] {
		t.Error("iptables should not have been called for allowlisted IP")
	}
}

func TestGuardNeverBlockSingleIP(t *testing.T) {
	fb := newFakeBlocker()
	cfg := Config{
		Limit:         1,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		NeverBlock:    []string{"192.168.1.1"},
	}
	g := New(cfg)
	g.SetBlocker(fb)

	g.Evaluate(caddyLine("192.168.1.1", "/api", "GET", 200))
	g.Tick(context.Background())

	if g.IsBlocked("192.168.1.1") {
		t.Error("192.168.1.1 should not be blocked (in allowlist)")
	}
}

func TestGuardNeverBlockDoesNotAffectOthers(t *testing.T) {
	fb := newFakeBlocker()
	cfg := Config{
		Limit:         1,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		NeverBlock:    []string{"10.0.0.0/8"},
	}
	g := New(cfg)
	g.SetBlocker(fb)

	g.Evaluate(caddyLine("8.8.8.8", "/api", "GET", 200))
	g.Tick(context.Background())

	if !g.IsBlocked("8.8.8.8") {
		t.Error("8.8.8.8 should be blocked (not in allowlist)")
	}
}

func TestGuardTickRejectsInvalidIP(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.Limit = 1
	g.cfg.IPValidator = func(ip string) error { return fmt.Errorf("invalid") }

	g.Evaluate(caddyLine("1.2.3.4", "/api", "GET", 200))

	blocked := g.Tick(context.Background())

	if len(blocked) != 0 {
		t.Errorf("expected 0 blocked (IP rejected), got %d", len(blocked))
	}
}

func TestGuardEvaluateDetectsSQLi(t *testing.T) {
	g := newTestGuard()
	g.SetBlocker(newFakeBlocker())

	g.Evaluate(caddyLine("1.2.3.4", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users", "GET", 200))

	ipStats := g.Detector().IPStats()
	stats := ipStats["1.2.3.4"]
	if stats == nil {
		t.Fatal("expected IP stats for 1.2.3.4")
	}
	if stats.Total != 1 {
		t.Errorf("expected 1 total detection, got %d", stats.Total)
	}
}

func TestGuardRunStopsOnContextCancel(t *testing.T) {
	g := newTestGuard()
	g.SetBlocker(newFakeBlocker())

	ctx, cancel := context.WithCancel(context.Background())
	linesCh := make(chan string, 1)

	done := make(chan struct{})
	go func() {
		g.Run(ctx, linesCh, func(string, ...interface{}) {})
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after context cancel")
	}
}

func TestGuardExpiryLoopUnblocksExpiredIPs(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.BlockDuration = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go g.runExpiryLoop(ctx)

	g.setBlocked("1.2.3.4")
	fb.blocked["1.2.3.4"] = true

	select {
	case g.expCh <- expiryEntry{ip: "1.2.3.4", when: time.Now().Add(20 * time.Millisecond)}:
	case <-time.After(time.Second):
		t.Fatal("timed out sending to expCh")
	}

	time.Sleep(100 * time.Millisecond)

	if g.IsBlocked("1.2.3.4") {
		t.Error("expected IP to be unblocked after expiry")
	}
	if fb.blocked["1.2.3.4"] {
		t.Error("expected fake blocker to have unblocked IP")
	}
}

func TestGuardExpiryLoopStopsOnContextCancel(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.BlockDuration = 1 * time.Hour

	ctx, cancel := context.WithCancel(context.Background())

	g.setBlocked("1.2.3.4")
	fb.blocked["1.2.3.4"] = true
	go g.runExpiryLoop(ctx)

	select {
	case g.expCh <- expiryEntry{ip: "1.2.3.4", when: time.Now().Add(1 * time.Hour)}:
	case <-time.After(time.Second):
		t.Fatal("timed out sending to expCh")
	}

	cancel()
	time.Sleep(50 * time.Millisecond)

	if !g.IsBlocked("1.2.3.4") {
		t.Error("IP should still be blocked — expiry loop should exit without unblocking on context cancel")
	}
	if _, ok := fb.blocked["1.2.3.4"]; !ok {
		t.Error("fake blocker should not have been unblocked on context cancel")
	}
}

func TestGuardTickBlocksOnPatternDetection(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.DetectionConfidence = 8

	g.Evaluate(caddyLine("1.2.3.4", "/search?id=1%27%20UNION%20SELECT%20username%20FROM%20users--", "GET", 200))

	blocked := g.Tick(context.Background())

	if len(blocked) != 1 {
		t.Fatalf("expected 1 candidate blocked via pattern detection, got %d", len(blocked))
	}
	if blocked[0].IP != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4, got %s", blocked[0].IP)
	}
	if !g.IsBlocked("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be blocked")
	}
	if !fb.blocked["1.2.3.4"] {
		t.Error("expected fake blocker to have blocked 1.2.3.4")
	}
}

func TestGuardDetectionConfidenceBelowThreshold(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.DetectionConfidence = 10
	g.cfg.Limit = 0
	g.cfg.AuthLimit = 0
	g.cfg.NotFoundLimit = 0

	// "UNION SELECT" is confidence 10; use a weaker signal that is
	// below the configured threshold to ensure it is not blocked.
	g.Evaluate(caddyLine("1.2.3.4", "/api?q=chr(65)", "GET", 200))

	blocked := g.Tick(context.Background())

	if len(blocked) != 0 {
		t.Fatalf("expected 0 blocked (confidence below threshold), got %d", len(blocked))
	}
	if g.IsBlocked("1.2.3.4") {
		t.Error("IP should not be blocked below confidence threshold")
	}
}

func TestGuardZeroThresholdsDisableBlocking(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.Limit = 0
	g.cfg.AuthLimit = 0
	g.cfg.NotFoundLimit = 0

	for i := 0; i < 3; i++ {
		g.Evaluate(caddyLine("1.2.3.4", "/login", "POST", 401))
	}

	blocked := g.Tick(context.Background())

	if len(blocked) != 0 {
		t.Fatalf("expected 0 blocked when all thresholds are disabled, got %d", len(blocked))
	}
}

func TestGuardDetectionCountsResetAfterTick(t *testing.T) {
	g := newTestGuard()
	g.SetBlocker(newFakeBlocker())
	g.cfg.DetectionConfidence = 8
	g.cfg.Limit = 0
	g.cfg.AuthLimit = 0
	g.cfg.NotFoundLimit = 0

	g.Evaluate(caddyLine("1.2.3.4", "/search?id=1%27%20UNION%20SELECT%20username%20FROM%20users--", "GET", 200))
	_ = g.Tick(context.Background())

	g.mu.Lock()
	count := g.detectCounts["1.2.3.4"]
	g.mu.Unlock()
	if count != 0 {
		t.Errorf("expected detect count reset to 0 after tick, got %d", count)
	}
}

// TestGuardSlidingWindowBlocksAcrossTickBoundary verifies that a true sliding
// window catches traffic that straddles a tick boundary, where a tumbling
// window would reset and let the attacker evade the limit.
func TestGuardSlidingWindowBlocksAcrossTickBoundary(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.Limit = 10
	g.cfg.AuthLimit = 0
	g.cfg.NotFoundLimit = 0

	// 6 requests, tick (resets engine/detector but NOT the sliding window),
	// then 5 more. Tumbling window: 6 then 5, neither >= 10. Sliding: 11 >= 10.
	for i := 0; i < 6; i++ {
		g.Evaluate(caddyLine("7.7.7.7", "/api", "GET", 200))
	}
	_ = g.Tick(context.Background())
	for i := 0; i < 5; i++ {
		g.Evaluate(caddyLine("7.7.7.7", "/api", "GET", 200))
	}
	blocked := g.Tick(context.Background())

	if len(blocked) != 1 {
		t.Fatalf("sliding window should block 7.7.7.7 across tick boundary, got %d blocked", len(blocked))
	}
	if blocked[0].IP != "7.7.7.7" {
		t.Errorf("expected 7.7.7.7, got %s", blocked[0].IP)
	}
}

// TestSlidingCountersExpiry verifies that buckets older than the window are
// evicted during sum, so past traffic does not count toward the limit. Uses
// controlled timestamps (the guard buckets at second granularity, appropriate
// for the >=1s windows used in production).
func TestSlidingCountersExpiry(t *testing.T) {
	sc := newSlidingCounters(2 * time.Second)
	base := time.Unix(1000, 0)
	sc.add("1.1.1.1", base, false, false, "")
	sc.add("1.1.1.1", base.Add(1*time.Second), false, false, "")

	// Window is 2s. At base+3s, the bucket at base (3s old) is expired;
	// the bucket at base+1s (2s old, on the cutoff boundary) is retained.
	total, _, _ := sc.sum("1.1.1.1", base.Add(3*time.Second))
	if total != 1 {
		t.Errorf("expected 1 after expiry, got %d", total)
	}

	// After full expiry, the IP is gone.
	sc.expire(base.Add(10 * time.Second))
	if ips := sc.ips(); len(ips) != 0 {
		t.Errorf("expected no IPs after full expiry, got %v", ips)
	}
}

// TestGuardSubnetLimitBlocksDistributedScan verifies that a /24 with many
// requests spread across IPs (each below the per-IP limit) is blocked as a
// whole when --subnet-limit is set.
func TestGuardSubnetLimitBlocksDistributedScan(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.Limit = 100
	g.cfg.SubnetLimit = 5

	// 6 distinct IPs in 9.9.9.0/24, 1 request each → no per-IP trip,
	// but /24 total = 6 >= 5.
	for i := 1; i <= 6; i++ {
		g.Evaluate(caddyLine(fmt.Sprintf("9.9.9.%d", i), "/api", "GET", 200))
	}
	blocked := g.Tick(context.Background())

	found := false
	for _, c := range blocked {
		if c.IP == "9.9.9.0/24" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 9.9.9.0/24 blocked, got %v", blocked)
	}
}

func TestCredStuffingCandidates(t *testing.T) {
	sc := newSlidingCounters(time.Minute)
	now := time.Now()
	sc.add("1.1.1.1", now, true, false, "/login")
	sc.add("2.2.2.2", now, true, false, "/login")
	sc.add("3.3.3.3", now, true, false, "/login")
	sc.add("4.4.4.4", now, true, false, "/admin")

	hits := sc.credStuffingCandidates(3)
	if len(hits) != 1 {
		t.Fatalf("expected 1 cred stuffing hit, got %d", len(hits))
	}
	if hits[0].Path != "/login" || hits[0].IPCount != 3 {
		t.Errorf("unexpected hit: %+v", hits[0])
	}

	hits2 := sc.credStuffingCandidates(5)
	if len(hits2) != 0 {
		t.Errorf("expected 0 hits with limit 5, got %d", len(hits2))
	}
}
