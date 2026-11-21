package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestReportShowsSkippedLines(t *testing.T) {
	engine := analysis.New(types.Filters{})
	engine.Process(&types.LogEntry{Method: "GET", URI: "/", Host: "localhost", RemoteIP: "127.0.0.1", Status: 200})
	engine.Stats().SkippedLines = 2
	engine.Finalize()

	tests := []struct {
		format Format
		want   string
	}{
		{FormatTable, "Skipped Lines (too long):"},
		{FormatJSON, `"skipped_lines": 2`},
		{FormatCSV, "skipped_lines,2"},
	}
	for _, tt := range tests {
		var buf bytes.Buffer
		report := NewReport(engine, tt.format, 5)
		report.SetWriter(&buf)
		if err := report.Print(); err != nil {
			t.Fatalf("format %v: Print returned %v", tt.format, err)
		}
		if !strings.Contains(buf.String(), tt.want) {
			t.Errorf("format %v: output does not contain %q:\n%s", tt.format, tt.want, buf.String())
		}
	}
}
