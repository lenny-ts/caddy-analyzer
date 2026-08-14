package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

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
