package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestParseFormat(t *testing.T) {
	tests := []struct {
		in   string
		want Format
	}{
		{"json", FormatJSON},
		{"JSON", FormatJSON},
		{"csv", FormatCSV},
		{"html", FormatHTML},
		{"table", FormatTable},
		{"unknown", FormatTable},
		{"", FormatTable},
	}
	for _, tt := range tests {
		if got := ParseFormat(tt.in); got != tt.want {
			t.Errorf("ParseFormat(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestNewReportWithSections(t *testing.T) {
	engine := analysis.New(types.Filters{})
	sections := types.TopSections{Path: true, IP: true}
	r := NewReportWithSections(engine, FormatJSON, 5, sections)
	if r.format != FormatJSON || r.top != 5 || !r.sections.Path {
		t.Errorf("NewReportWithSections fields wrong: %+v", r)
	}
}

func TestReportSetters(t *testing.T) {
	engine := analysis.New(types.Filters{})
	r := NewReport(engine, FormatTable, 5)
	r.SetDetect(true)
	if !r.detect {
		t.Error("SetDetect(true) failed")
	}
	r.SetDefang(true)
	if !r.defang {
		t.Error("SetDefang(true) failed")
	}
	f := types.Filters{Method: "POST"}
	r.SetFilters(f)
	if r.filters.Method != "POST" {
		t.Error("SetFilters failed")
	}
}

func TestReportOutputs(t *testing.T) {
	engine := analysis.New(types.Filters{})
	engine.Process(&types.LogEntry{
		Method:     "GET",
		URI:        "/test",
		Host:       "localhost",
		RemoteIP:   "127.0.0.1",
		Status:     200,
		Size:       500,
		Duration:   0.002,
		Proto:      "HTTP/2.0",
		TLSVersion: "TLS 1.3",
	})
	engine.Finalize()

	tests := []struct {
		format   Format
		contains string
	}{
		{FormatTable, "CADDY LOG ANALYSIS REPORT"},
		{FormatJSON, `"total_requests": 1`},
		{FormatCSV, "total_requests,1"},
		{FormatHTML, "<!DOCTYPE html>"},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			var buf bytes.Buffer
			report := NewReport(engine, tt.format, 5)
			report.SetWriter(&buf)
			if err := report.Print(); err != nil {
				t.Fatalf("Print failed: %v", err)
			}

			out := buf.String()
			if !strings.Contains(out, tt.contains) {
				t.Errorf("expected output to contain %q, got:\n%s", tt.contains, out)
			}
		})
	}
}

func TestHTMLReportRendersGeographicHeatmap(t *testing.T) {
	engine := analysis.New(types.Filters{})
	engine.Process(&types.LogEntry{URI: "/", Status: 200, Size: 1, Geo: types.GeoInfo{City: "Rome", Latitude: 41.9, Longitude: 12.5}})
	engine.Finalize()

	var buf bytes.Buffer
	report := NewReport(engine, FormatHTML, 5)
	report.SetWriter(&buf)
	if err := report.Print(); err != nil {
		t.Fatalf("Print failed: %v", err)
	}
	if !strings.Contains(buf.String(), "Geographic Attack Heatmap") {
		t.Fatal("expected HTML report to contain geographic heatmap")
	}
}

func TestSafeCell(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "=SUM(A1:A2)", want: "'=SUM(A1:A2)"},
		{in: "+cmd", want: "'+cmd"},
		{in: "-2+3", want: "'-2+3"},
		{in: "@VALUE", want: "'@VALUE"},
		{in: "\tcmd", want: "'\tcmd"},
		{in: "\r\ncmd", want: "'\r\ncmd"},
		{in: "normal-path", want: "normal-path"},
		{in: "123", want: "123"},
		{in: "", want: ""},
		{in: "=UNION SELECT", want: "'=UNION SELECT"},
	}

	for _, tt := range tests {
		if got := SafeCell(tt.in); got != tt.want {
			t.Errorf("SafeCell(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSafeCellStripsANSIControls(t *testing.T) {
	in := "\x1b[31m=1+1\x1b[0m"
	got := SafeCell(in)
	want := "'=1+1"
	if got != want {
		t.Errorf("SafeCell(%q) = %q, want %q", in, got, want)
	}

	in = "/path\x1b]0;title\x07/seg"
	want = "/path/seg"
	if got := SafeCell(in); got != want {
		t.Errorf("SafeCell(%q) = %q, want %q", in, got, want)
	}
}

func TestCSVFormulaInjectionNeutralized(t *testing.T) {
	engine := analysis.New(types.Filters{})
	engine.Process(&types.LogEntry{
		Method:   "GET",
		URI:      "=HYPERLINK(http://evil.example)",
		RemoteIP: "1.2.3.4",
		Status:   200,
		Size:     1,
	})
	engine.Finalize()

	var buf bytes.Buffer
	report := NewReport(engine, FormatCSV, 5)
	report.SetWriter(&buf)
	if err := report.Print(); err != nil {
		t.Fatalf("Print failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "'=HYPERLINK") {
		t.Errorf("CSV output missing sanitized formula cell, got:\n%s", out)
	}
	if strings.Contains(out, "\n=HYPERLINK") || strings.Contains(out, ",=HYPERLINK") {
		t.Errorf("CSV output still contains raw formula injection, got:\n%s", out)
	}
}

func TestCSVANSIStripped(t *testing.T) {
	engine := analysis.New(types.Filters{})
	engine.Process(&types.LogEntry{
		Method:   "GET",
		URI:      "/x\x1b[31mred\x1b[0m",
		RemoteIP: "1.2.3.4",
		Status:   200,
		Size:     1,
	})
	engine.Finalize()

	var buf bytes.Buffer
	report := NewReport(engine, FormatCSV, 5)
	report.SetWriter(&buf)
	if err := report.Print(); err != nil {
		t.Fatalf("Print failed: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "\x1b") {
		t.Errorf("CSV output contains ANSI escape sequences, got:\n%s", out)
	}
	if !strings.Contains(out, "/xred") {
		t.Errorf("expected stripped path /xred in CSV, got:\n%s", out)
	}
}

func TestFmtOperationalEntryStripsANSIAndSortsExtras(t *testing.T) {
	e := &types.OperationalEntry{
		Timestamp: time.Date(2026, 8, 21, 12, 35, 4, 0, time.UTC),
		Level:     "error",
		Logger:    "http.log.error",
		Msg:       "dialing \x1b[31mupstream\x1b[0m",
		Extra: map[string]json.RawMessage{
			"zebra":    json.RawMessage(`"last"`),
			"upstream": json.RawMessage(`"10.0.0.6:8080"`),
			"alpha":    json.RawMessage(`"first"`),
		},
	}

	got := FmtOperationalEntry(e, false)
	for _, want := range []string{"ERROR", "[http.log.error]", "dialing upstream", "alpha=first upstream=10.0.0.6:8080 zebra=last"} {
		if !strings.Contains(got, want) {
			t.Errorf("FmtOperationalEntry output missing %q, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\x1b") {
		t.Errorf("FmtOperationalEntry output contains ANSI escapes from log data, got:\n%s", got)
	}

	defanged := FmtOperationalEntry(e, true)
	if !strings.Contains(defanged, "10[.]0[.]0[.]6") {
		t.Errorf("FmtOperationalEntry defang did not apply to extra values, got:\n%s", defanged)
	}
}

func TestCSVOperationalFormulaInjectionNeutralized(t *testing.T) {
	engine := analysis.New(types.Filters{})
	engine.Finalize()

	op := types.NewOperationalStats()
	op.TotalEvents = 2
	op.Errors = 1
	op.LevelCounts["error"] = 1
	op.LoggerCounts["=cmd|'/c calc'!A0"] = 1
	op.MsgCounts["\t=1+1"] = 1

	var buf bytes.Buffer
	report := NewReport(engine, FormatCSV, 5)
	report.SetOperationalStats(op)
	report.SetWriter(&buf)
	if err := report.Print(); err != nil {
		t.Fatalf("Print failed: %v", err)
	}

	out := buf.String()
	for _, raw := range []string{"\n=cmd", ",=cmd", "\n\t=", ",\t="} {
		if strings.Contains(out, raw) {
			t.Errorf("CSV operational section contains unsanitized formula payload %q, got:\n%s", raw, out)
		}
	}
	if !strings.Contains(out, "'=cmd") {
		t.Errorf("CSV output missing sanitized operational logger cell, got:\n%s", out)
	}
}

func TestFmtLogEntryStripsANSISignal(t *testing.T) {
	e := &types.LogEntry{
		Method:    "GET",
		URI:       "/good/\x1b[31mred\x1b[0m",
		RemoteIP:  "1.2.3.4",
		UserAgent: "UA",
		Status:    200,
		Size:      10,
		Duration:  0.001,
	}
	out := FmtLogEntry(e, false)
	if strings.Contains(out, "\x1b[31m") {
		t.Errorf("FmtLogEntry leaked ANSI escape from log data: %q", out)
	}
	if !strings.Contains(out, "/good/red") {
		t.Errorf("expected stripped path in FmtLogEntry, got %q", out)
	}
}

func TestDefangMap(t *testing.T) {
	if defangMap(nil) != nil {
		t.Error("nil map should return nil")
	}
	m := map[string]int64{"1.2.3.4": 5}
	out := defangMap(m)
	if _, ok := out["1[.]2[.]3[.]4"]; !ok {
		t.Errorf("expected defanged key, got %v", out)
	}
}

func TestDefangStringSliceMap(t *testing.T) {
	if defangStringSliceMap(nil) != nil {
		t.Error("nil map should return nil")
	}
	m := map[string][]string{"1.2.3.4": {"4.5.6.7"}}
	out := defangStringSliceMap(m)
	dk := "1[.]2[.]3[.]4"
	v, ok := out[dk]
	if !ok {
		t.Fatalf("expected defanged key %q, got %v", dk, out)
	}
	if len(v) != 1 || v[0] != "4[.]5[.]6[.]7" {
		t.Errorf("expected defanged value, got %v", v)
	}
}

func TestDefangDetectionMap(t *testing.T) {
	if defangDetectionMap(nil) != nil {
		t.Error("nil map should return nil")
	}
	m := map[string][]types.DetectionRecord{
		"1.2.3.4": {{Type: "scan", Desc: "hit 9.9.9.9", URI: "/p"}},
	}
	out := defangDetectionMap(m)
	dk := "1[.]2[.]3[.]4"
	v, ok := out[dk]
	if !ok || len(v) != 1 {
		t.Fatalf("expected 1 defanged entry, got %v", out)
	}
	if v[0].Desc != "hit 9[.]9[.]9[.]9" || v[0].URI != "/p" {
		t.Errorf("unexpected defanged record: %+v", v[0])
	}
}

// TestActiveFiltersRendersEveryFilter pins that each filter field reaches the
// "Filters:" header line. Five of them (--max-latency, --min-size, --max-size,
// --level, --ops-only) used to be silently dropped, so a report produced with
// them looked identical to one produced without.
func TestActiveFiltersRendersEveryFilter(t *testing.T) {
	tests := []struct {
		name    string
		filters types.Filters
		want    string
	}{
		{"max-latency", types.Filters{MaxLatency: 1.5}, "--max-latency 1500ms"},
		{"min-size", types.Filters{MinSize: 1024}, "--min-size 1.00 KB"},
		{"max-size", types.Filters{MaxSize: 1048576}, "--max-size 1.00 MB"},
		{"level single", types.Filters{Level: []string{"error"}}, "--level error"},
		{"level repeated", types.Filters{Level: []string{"error", "warn"}}, "--level error,warn"},
		{"ops-only", types.Filters{OpsOnly: true}, "--ops-only"},
		// Regressions on the blocks that already worked.
		{"slow", types.Filters{MinLatency: 0.5}, "--slow 500ms"},
		{"grep", types.Filters{GrepPattern: "wp-admin"}, "--grep wp-admin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReport(analysis.New(types.Filters{}), FormatTable, 5)
			r.SetFilters(tt.filters)
			got := r.activeFilters()
			for _, s := range got {
				if s == tt.want {
					return
				}
			}
			t.Errorf("activeFilters() = %v, missing %q", got, tt.want)
		})
	}
}

// TestActiveFiltersZeroValuesAreOmitted guards the other direction: an unset
// filter must not appear. --ops-only is a bool and the rest are compared
// against zero, so a `>= 0` typo would print every flag on every report.
func TestActiveFiltersZeroValuesAreOmitted(t *testing.T) {
	r := NewReport(analysis.New(types.Filters{}), FormatTable, 5)
	r.SetFilters(types.Filters{})
	if got := r.activeFilters(); len(got) != 0 {
		t.Errorf("activeFilters() on empty Filters = %v, want none", got)
	}
}

// TestActiveFiltersCombined checks the five new blocks coexist with the old
// ones in one report, which is how they are actually used.
func TestActiveFiltersCombined(t *testing.T) {
	r := NewReport(analysis.New(types.Filters{}), FormatTable, 5)
	r.SetFilters(types.Filters{
		MinLatency: 0.1,
		MaxLatency: 1,
		MinSize:    1024,
		MaxSize:    1024 * 1024,
		Level:      []string{"error", "warn"},
		OpsOnly:    true,
		Method:     "POST",
	})
	got := strings.Join(r.activeFilters(), ", ")
	for _, want := range []string{
		"--method POST", "--slow 100ms", "--max-latency 1000ms",
		"--min-size 1.00 KB", "--max-size 1.00 MB", "--level error,warn", "--ops-only",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("activeFilters() = %q, missing %q", got, want)
		}
	}
}
