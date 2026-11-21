package cmd

import (
	"bytes"
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
