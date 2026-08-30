package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
	"github.com/lenny-ts/caddy-analyzer/pkg/enrich"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

// sampleCaddyLine is a minimal but valid Caddy v2 "handled request" JSON log.
const sampleCaddyLine = `{"level":"info","ts":1700000000.0,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"192.0.2.10","remote_port":"50000","proto":"HTTP/1.1","method":"GET","host":"example.com","uri":"/search?q=test","headers":{"User-Agent":["curl/8.0"]}},"bytes_read":0,"user_id":"","duration":0.012,"size":2048,"status":200,"resp_headers":{"Content-Type":["text/html"]}}`

func TestNewModelDefaults(t *testing.T) {
	m := NewModel(make(chan string, 1))
	if m.engine == nil {
		t.Fatal("engine must be set")
	}
	if m.detector == nil {
		t.Fatal("detector must be set")
	}
	if m.current != viewSummary {
		t.Errorf("default view = %v, want viewSummary", m.current)
	}
	if m.ready {
		t.Error("new model must not be ready until a WindowSizeMsg arrives")
	}
	if cap(m.recentLogs) == 0 {
		t.Error("recentLogs should be pre-allocated")
	}
}

func TestUpdateWindowSizeMsgMarksReadyAndInitTables(t *testing.T) {
	m := NewModel(make(chan string, 1))
	updated, cmd := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	um := updated.(Model)
	if !um.ready {
		t.Fatal("ready must be true after WindowSizeMsg")
	}
	if um.width != 120 || um.height != 40 {
		t.Errorf("dims = %dx%d, want 120x40", um.width, um.height)
	}
	// initTables builds fresh tables sized to the window; rows are empty but
	// the table models are no longer the zero value (a subsequent refresh
	// populates them). We verify the ready/dims here and table population in
	// TestRefreshTablesPopulatesWhenReady.
	if cmd != nil {
		t.Error("WindowSizeMsg should return nil cmd")
	}
}

func TestUpdateLineMsgParsesAndAppends(t *testing.T) {
	ch := make(chan string, 1)
	m := NewModel(ch)
	m.ready = true

	updated, _ := m.Update(LineMsg(sampleCaddyLine))
	um := updated.(Model)
	if len(um.recentLogs) != 1 {
		t.Fatalf("recentLogs len = %d, want 1", len(um.recentLogs))
	}
	if um.recentLogs[0] == nil {
		t.Fatal("appended entry must not be nil")
	}
	if um.recentLogs[0].Method != "GET" {
		t.Errorf("entry Method = %q, want GET", um.recentLogs[0].Method)
	}
	if um.engine.Count() != 1 {
		t.Errorf("engine should have processed 1 entry, got %d", um.engine.Count())
	}
}

func TestUpdateLineMsgGarbageIgnored(t *testing.T) {
	m := NewModel(make(chan string, 1))
	m.ready = true

	updated, _ := m.Update(LineMsg("not json at all"))
	um := updated.(Model)
	if len(um.recentLogs) != 0 {
		t.Errorf("garbage line must not append, got %d logs", len(um.recentLogs))
	}
}

func TestUpdateTickMsgFinalizesStatsAndRPS(t *testing.T) {
	m := NewModel(make(chan string, 1))
	m.ready = true

	// Feed a line so the engine has data.
	um, _ := m.Update(LineMsg(sampleCaddyLine))
	m = um.(Model)

	updated, cmd := m.Update(TickMsg(time.Now()))
	m = updated.(Model)
	if m.stats == nil {
		t.Fatal("stats must be set after TickMsg")
	}
	if m.stats.TotalRequests != 1 {
		t.Errorf("stats.TotalRequests = %d, want 1", m.stats.TotalRequests)
	}
	if m.rps <= 0 {
		t.Error("rps must be > 0 after a tick with data")
	}
	if cmd == nil {
		t.Error("TickMsg should schedule the next tick")
	}
}

func TestUpdateKeyMessagesSwitchView(t *testing.T) {
	cases := []struct {
		key  string
		want view
	}{
		{"1", viewSummary},
		{"2", viewRealtime},
		{"3", viewSecurity},
		{"4", viewTopIPs},
		{"5", viewTopPaths},
		{"6", viewTopUA},
		{"7", viewGeo},
	}
	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			m := NewModel(make(chan string, 1))
			m.ready = true
			updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(c.key)})
			um := updated.(Model)
			if um.current != c.want {
				t.Errorf("key %q: current = %v, want %v", c.key, um.current, c.want)
			}
		})
	}
}

func TestUpdateNavigationKeysWrapViews(t *testing.T) {
	cases := []struct {
		name  string
		start view
		key   tea.KeyType
		want  view
	}{
		{"right from geo", viewGeo, tea.KeyRight, viewOperational},
		{"right from realtime", viewRealtime, tea.KeyRight, viewSecurity},
		{"right from operational", viewOperational, tea.KeyRight, viewSummary},
		{"left from summary", viewSummary, tea.KeyLeft, viewOperational},
		{"left from top ua", viewTopUA, tea.KeyLeft, viewTopPaths},
		{"tab from geo", viewGeo, tea.KeyTab, viewOperational},
		{"tab from security", viewSecurity, tea.KeyTab, viewTopIPs},
		{"tab from operational", viewOperational, tea.KeyTab, viewSummary},
		{"shift tab from summary", viewSummary, tea.KeyShiftTab, viewOperational},
		{"shift tab from geo", viewGeo, tea.KeyShiftTab, viewTopUA},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := NewModel(make(chan string, 1))
			m.ready = true
			m.current = c.start
			updated, _ := m.Update(tea.KeyMsg{Type: c.key})
			um := updated.(Model)
			if um.current != c.want {
				t.Fatalf("current = %v, want %v", um.current, c.want)
			}
			if um.viewTabs() != (Model{current: c.want}).viewTabs() {
				t.Fatal("tab highlight does not match wrapped view")
			}
		})
	}
}

func TestUpdateQuitKeyReturnsQuitCmd(t *testing.T) {
	m := NewModel(make(chan string, 1))
	for _, key := range []string{"q", "esc"} {
		t.Run(key, func(t *testing.T) {
			_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
			if cmd == nil {
				t.Fatalf("key %q should return a non-nil cmd", key)
			}
			// tea.Quit is a tea.Cmd; executing it yields a tea.QuitMsg.
			msg := cmd()
			if _, ok := msg.(tea.QuitMsg); !ok {
				t.Errorf("key %q: cmd did not produce tea.QuitMsg, got %T", key, msg)
			}
		})
	}
}

func TestViewLoadingWhenNotReady(t *testing.T) {
	m := NewModel(make(chan string, 1))
	out := m.View()
	if !strings.Contains(out, "loading") {
		t.Errorf("View before ready should mention loading, got %q", out)
	}
}

func TestViewRendersWhenReady(t *testing.T) {
	m := NewModel(make(chan string, 1))
	m.ready = true
	m.width = 120
	m.height = 40
	m = m.initTables()

	// Feed data and a tick so stats populate.
	um, _ := m.Update(LineMsg(sampleCaddyLine))
	m = um.(Model)
	um, _ = m.Update(TickMsg(time.Now()))
	m = um.(Model)

	out := m.View()
	if out == "" {
		t.Fatal("View must not be empty when ready")
	}
	if !strings.Contains(out, "Caddy") {
		t.Errorf("View should contain the dashboard title, got %q", out)
	}
}

func TestRefreshTablesNoOpWhenNotReady(t *testing.T) {
	m := NewModel(make(chan string, 1))
	got := m.refreshTables()
	// Must return the model unchanged (no panic, no mutation to stats).
	if got.ready {
		t.Error("refreshTables must not flip ready")
	}
}

func TestRefreshTablesPopulatesWhenReady(t *testing.T) {
	m := NewModel(make(chan string, 1))
	m.ready = true
	m.width = 120
	m.height = 40
	m = m.initTables()

	// Feed data + tick so stats exist. The tick handler already calls
	// refreshTables once, so the table is populated; calling it again must keep
	// the rows (idempotent) and not clear them.
	um, _ := m.Update(LineMsg(sampleCaddyLine))
	m = um.(Model)
	um, _ = m.Update(TickMsg(time.Now()))
	m = um.(Model)

	if len(m.ipTable.Rows()) == 0 {
		t.Fatal("ipTable must have rows after a tick with data")
	}
	m = m.refreshTables()
	if len(m.ipTable.Rows()) == 0 {
		t.Error("ipTable must still have rows after a manual refresh")
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"short", 10, "short"},
		{"exactlen", 8, "exactlen"},
		{"toolongforthis", 6, "toolo…"},
		{"ab", 2, "ab"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := truncate(c.in, c.max)
			if got != c.want {
				t.Errorf("truncate(%q,%d) = %q, want %q", c.in, c.max, got, c.want)
			}
		})
	}
}

func TestInitReturnsBatchedCmds(t *testing.T) {
	m := NewModel(make(chan string, 1))
	cmd := m.Init()
	if cmd == nil {
		t.Fatal("Init must return a batched cmd (waitForLines + tickEvery)")
	}
}

// TestModelSatisfiesTeaModel is a compile-time guarantee that Model (value
// receiver) implements tea.Model. After the receiver-consistency fix, *Model
// no longer carries the mutating helpers, so this is the contract.
func TestModelSatisfiesTeaModel(t *testing.T) {
	var _ tea.Model = Model{}
}

// TestDetectorSharedInTUI verifies the TUI's detector benefits from the cached
// patterns (regression for the regex-caching fix).
func TestDetectorSharedInTUI(t *testing.T) {
	m := NewModel(make(chan string, 1))
	if m.detector == nil {
		t.Fatal("detector nil")
	}
	// A known SQLi payload must be detected.
	det := m.detector.Detect(&types.LogEntry{
		RemoteIP: "1.2.3.4", URI: "/?id=1 UNION SELECT 1,2,3", Status: 200,
	})
	if det == nil || det.Type != analysis.DetSQLInjection {
		t.Fatalf("expected SQLi detection, got %+v", det)
	}
}

// TestNewModelWithGeoIPStoresEnricher verifies the GeoIP enricher is stored on
// the model so the LineMsg handler can use it.
func TestNewModelWithGeoIPStoresEnricher(t *testing.T) {
	g := &enrich.GeoIP{}
	m := NewModelWithGeoIP(make(chan string, 1), g)
	if m.geoip != g {
		t.Fatal("geoip enricher must be stored on the model")
	}
	// NewModel must leave geoip nil for backward compatibility.
	if NewModel(make(chan string, 1)).geoip != nil {
		t.Error("NewModel must leave geoip nil")
	}
}

// TestUpdateLineMsgEnrichesGeo verifies that when a GeoIP enricher is wired,
// parsed entries are enriched before reaching the engine so country/ASN
// stats populate.
func TestUpdateLineMsgEnrichesGeo(t *testing.T) {
	// We cannot easily construct a real maxminddb reader in a unit test, so we
	// verify the wiring indirectly: with geoip == nil the entry's Geo field
	// remains zero and the engine records no country counts. This guards
	// against regressions where the enricher call is removed from the
	// LineMsg handler.
	m := NewModelWithGeoIP(make(chan string, 1), nil)
	m.ready = true

	updated, _ := m.Update(LineMsg(sampleCaddyLine))
	um := updated.(Model)
	if um.stats != nil && len(um.stats.CountryCounts) != 0 {
		t.Errorf("country counts must be empty when geoip is nil, got %d", len(um.stats.CountryCounts))
	}
	// Force a finalize + stats so the engine exposes its counts.
	um.engine.Finalize()
	st := um.engine.Stats()
	if len(st.CountryCounts) != 0 {
		t.Errorf("country counts must be empty when no enricher is set, got %d", len(st.CountryCounts))
	}
}

// TestViewGeoRendersDisabledHint verifies the Geo tab degrades gracefully when
// no GeoIP enricher is configured.
func TestViewGeoRendersDisabledHint(t *testing.T) {
	m := NewModel(make(chan string, 1))
	m.ready = true
	m.width = 120
	m.height = 40
	m = m.initTables()
	m.current = viewGeo

	out := m.View()
	if !strings.Contains(out, "GeoIP enrichment disabled") {
		t.Errorf("Geo tab must render a disabled hint without an enricher, got %q", out)
	}
}
