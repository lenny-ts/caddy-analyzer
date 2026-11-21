package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/reader"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestCountTotalLinesSkipsOversizedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	content := append([]byte("one\n"), bytes.Repeat([]byte("a"), reader.MaxLineSize+1)...)
	content = append(content, []byte("\ntwo\nthree\n")...)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	got := countTotalLines([]types.LogSource{{Type: types.SourceFile, Path: path}})
	if got != 3 {
		t.Fatalf("countTotalLines() = %d, want 3", got)
	}
}

func TestReportWhenEveryLineIsOversized(t *testing.T) {
	dir := t.TempDir()
	path, report := filepath.Join(dir, "access.log"), filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), reader.MaxLineSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	format, output, noDownload := flagFormat, flagOutput, flagNoAutoDL
	t.Cleanup(func() { flagFormat, flagOutput, flagNoAutoDL = format, output, noDownload })
	flagFormat, flagOutput, flagNoAutoDL = "json", report, true
	if err := runOnceMode(context.Background(), []types.LogSource{{Type: types.SourceFile, Path: path}}, types.Filters{}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		SkippedLines int `json:"skipped_lines"`
	}
	if err := json.Unmarshal(b, &result); err != nil || result.SkippedLines != 1 {
		t.Fatalf("skipped_lines = %d, decode error %v", result.SkippedLines, err)
	}
}
