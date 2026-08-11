package guard

import (
	"context"
	"testing"
	"time"

	"github.com/L9Lenny/caddy-analyzer/pkg/blocklist"
	"github.com/L9Lenny/caddy-analyzer/pkg/types"
)

func newTestBlocklistMgr(t *testing.T, entries string) *blocklist.Manager {
	t.Helper()
	dir := t.TempDir()
	m, err := blocklist.NewManager([]blocklist.Source{
		{Name: "test", URL: "http://test.local"},
	}, dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.SetFetcher(func(url string) ([]byte, error) {
		return []byte(entries), nil
	})
	m.Refresh()
	return m
}

func TestGuardBlocklistImmediateBlock(t *testing.T) {
	fb := newFakeBlocker()
	mgr := newTestBlocklistMgr(t, "10.0.0.0/8\n")
	g := New(Config{
		Limit:         100,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		BlocklistMgr:  mgr,
	})
	g.SetBlocker(fb)

	g.Evaluate(caddyLine("10.1.2.3", "/test", "GET", 200))

	if !g.IsBlocked("10.1.2.3") {
		t.Error("expected 10.1.2.3 to be immediately blocked via blocklist")
	}
	if !fb.blocked["10.1.2.3"] {
		t.Error("expected fake blocker to have blocked 10.1.2.3")
	}
	if g.BlocklistHits() != 1 {
		t.Errorf("expected 1 blocklist hit, got %d", g.BlocklistHits())
	}
}

func TestGuardBlocklistNoHit(t *testing.T) {
	fb := newFakeBlocker()
	mgr := newTestBlocklistMgr(t, "10.0.0.0/8\n")
	g := New(Config{
		Limit:         100,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		BlocklistMgr:  mgr,
	})
	g.SetBlocker(fb)

	g.Evaluate(caddyLine("8.8.8.8", "/test", "GET", 200))

	if g.IsBlocked("8.8.8.8") {
		t.Error("8.8.8.8 should not be blocked")
	}
	if g.BlocklistHits() != 0 {
		t.Errorf("expected 0 blocklist hits, got %d", g.BlocklistHits())
	}
}

func TestGuardNeverBlockWinsOverBlocklist(t *testing.T) {
	fb := newFakeBlocker()
	mgr := newTestBlocklistMgr(t, "10.0.0.0/8\n")
	g := New(Config{
		Limit:         100,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		BlocklistMgr:  mgr,
		NeverBlock:    []string{"10.0.0.0/8"},
	})
	g.SetBlocker(fb)

	g.Evaluate(caddyLine("10.1.2.3", "/test", "GET", 200))

	if g.IsBlocked("10.1.2.3") {
		t.Error("10.1.2.3 should not be blocked (never-block wins)")
	}
	if g.BlocklistHits() != 0 {
		t.Errorf("expected 0 blocklist hits, got %d", g.BlocklistHits())
	}
}

type mockGeoIP struct {
	info map[string]types.GeoInfo
}

func (m *mockGeoIP) Lookup(ip string) (types.GeoInfo, error) {
	return m.info[ip], nil
}

func TestGuardCountryBlock(t *testing.T) {
	fb := newFakeBlocker()
	mgr := newTestBlocklistMgr(t, "")
	geo := &mockGeoIP{info: map[string]types.GeoInfo{
		"1.2.3.4": {CountryCode: "CN", CountryName: "China"},
	}}
	g := New(Config{
		Limit:         100,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		BlocklistMgr:  mgr,
		CountryBlock:  []string{"CN"},
		GeoIP:         geo,
	})
	g.SetBlocker(fb)

	g.Evaluate(caddyLine("1.2.3.4", "/test", "GET", 200))

	if !g.IsBlocked("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be blocked (country CN)")
	}
	if g.BlocklistHits() != 1 {
		t.Errorf("expected 1 blocklist hit, got %d", g.BlocklistHits())
	}
}

func TestGuardCountryBlockNoMatch(t *testing.T) {
	fb := newFakeBlocker()
	mgr := newTestBlocklistMgr(t, "")
	geo := &mockGeoIP{info: map[string]types.GeoInfo{
		"1.2.3.4": {CountryCode: "US", CountryName: "United States"},
	}}
	g := New(Config{
		Limit:         100,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		BlocklistMgr:  mgr,
		CountryBlock:  []string{"RU"},
		GeoIP:         geo,
	})
	g.SetBlocker(fb)

	g.Evaluate(caddyLine("1.2.3.4", "/test", "GET", 200))

	if g.IsBlocked("1.2.3.4") {
		t.Error("1.2.3.4 should not be blocked (country US, not RU)")
	}
}

func TestGuardNeverBlockWinsOverCountryBlock(t *testing.T) {
	fb := newFakeBlocker()
	mgr := newTestBlocklistMgr(t, "")
	geo := &mockGeoIP{info: map[string]types.GeoInfo{
		"1.2.3.4": {CountryCode: "CN", CountryName: "China"},
	}}
	g := New(Config{
		Limit:         100,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		BlocklistMgr:  mgr,
		CountryBlock:  []string{"CN"},
		GeoIP:         geo,
		NeverBlock:    []string{"1.2.3.4"},
	})
	g.SetBlocker(fb)

	g.Evaluate(caddyLine("1.2.3.4", "/test", "GET", 200))

	if g.IsBlocked("1.2.3.4") {
		t.Error("1.2.3.4 should not be blocked (never-block wins)")
	}
}

func TestGuardNoBlocklistMgr(t *testing.T) {
	fb := newFakeBlocker()
	g := New(Config{
		Limit:         100,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
	})
	g.SetBlocker(fb)

	g.Evaluate(caddyLine("10.1.2.3", "/test", "GET", 200))

	if g.IsBlocked("10.1.2.3") {
		t.Error("10.1.2.3 should not be blocked (no blocklist manager)")
	}
}

func TestGuardBlocklistAndCountryBothHit(t *testing.T) {
	fb := newFakeBlocker()
	mgr := newTestBlocklistMgr(t, "10.0.0.0/8\n")
	g := New(Config{
		Limit:         100,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		BlocklistMgr:  mgr,
		CountryBlock:  []string{"CN"},
	})
	g.SetBlocker(fb)

	g.Evaluate(caddyLine("10.1.2.3", "/test", "GET", 200))

	if !g.IsBlocked("10.1.2.3") {
		t.Error("expected 10.1.2.3 to be blocked")
	}
}

func TestGuardBlocklistRefreshInRun(t *testing.T) {
	fb := newFakeBlocker()
	dir := t.TempDir()
	mgr, err := blocklist.NewManager([]blocklist.Source{
		{Name: "test", URL: "http://test.local"},
	}, dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	mgr.SetFetcher(func(url string) ([]byte, error) {
		return []byte("10.0.0.0/8\n"), nil
	})
	mgr.Refresh()

	g := New(Config{
		Limit:            100,
		Window:           50 * time.Millisecond,
		BlockDuration:    0,
		IPValidator:      func(string) error { return nil },
		BlocklistMgr:     mgr,
		BlocklistRefresh: 10 * time.Millisecond,
	})
	g.SetBlocker(fb)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	linesCh := make(chan string, 1)
	linesCh <- caddyLine("10.1.2.3", "/test", "GET", 200)
	close(linesCh)

	logf := func(string, ...interface{}) {}
	g.Run(ctx, linesCh, logf)

	if !g.IsBlocked("10.1.2.3") {
		t.Error("expected 10.1.2.3 to be blocked")
	}
}
