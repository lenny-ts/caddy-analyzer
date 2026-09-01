package cmd

import (
	"context"
	"os"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestProcessParsedLinesPreservesInputOrder(t *testing.T) {
	lines := make(chan string, 3)
	lines <- `{"level":"info","ts":1,"msg":"first"}`
	lines <- `{"level":"info","ts":2,"msg":"second"}`
	lines <- `{"level":"info","ts":3,"msg":"third"}`
	close(lines)

	var got []string
	processParsedLines(context.Background(), lines, 4, func(entry types.Entry, err error) {
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		op, ok := entry.(*types.OperationalEntry)
		if !ok {
			t.Fatalf("entry type = %T, want operational entry", entry)
		}
		got = append(got, op.Msg)
	})

	want := []string{"first", "second", "third"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("result %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCountTotalLinesForLocalSources(t *testing.T) {
	path := t.TempDir() + "/access.log"
	if err := os.WriteFile(path, []byte("one\ntwo\nthree\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := countTotalLines([]types.LogSource{{Type: types.SourceFile, Path: path}})
	if got != 3 {
		t.Fatalf("countTotalLines() = %d, want 3", got)
	}
}
