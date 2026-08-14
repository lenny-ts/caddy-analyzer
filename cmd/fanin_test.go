package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

// TestFanInFollowMultipleSources verifies the multi-source fan-in: lines from
// ALL sources must be delivered, not just the first one. This is the regression
// test for the bug where runFollowMode/runTail iterated sources sequentially
// and blocked forever on the first follow reader (which only closes on
// ctx.Done), silently dropping every subsequent source.
func TestFanInFollowMultipleSources(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a.log")
	f2 := filepath.Join(dir, "b.log")
	if err := os.WriteFile(f1, []byte("a1\na2\na3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte("b1\nb2\nb3\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sources := []types.LogSource{
		{Type: types.SourceFile, Path: f1},
		{Type: types.SourceFile, Path: f2},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := fanInFollow(ctx, sources)

	// Collect until we have all 6 lines or time out. Follow readers deliver
	// existing content first, so all 6 should arrive quickly.
	got := make(map[string]bool)
	deadline := time.After(2 * time.Second)
	for len(got) < 6 {
		select {
		case line, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed before collecting all lines; got %d: %v", len(got), got)
			}
			got[line] = true
		case <-deadline:
			t.Fatalf("timeout: collected %d/%d lines: %v", len(got), 6, got)
		}
	}

	// Cancel and confirm the merged channel closes.
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("channel should be closed after context cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("channel did not close after context cancellation")
	}

	// The fix's whole point: lines from BOTH sources must be present. Before
	// the fix only f1's lines ("a*") would arrive.
	for _, want := range []string{"a1", "a2", "a3", "b1", "b2", "b3"} {
		if !got[want] {
			t.Errorf("missing line %q from fan-in; got %v", want, got)
		}
	}
}

// TestFanInFollowBadSourceSkipped ensures a failing source does not abort the
// fan-in: remaining sources must still be delivered.
func TestFanInFollowBadSourceSkipped(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.log")
	if err := os.WriteFile(good, []byte("g1\ng2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sources := []types.LogSource{
		{Type: types.SourceFile, Path: filepath.Join(dir, "does-not-exist.log")},
		{Type: types.SourceFile, Path: good},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := fanInFollow(ctx, sources)

	got := make(map[string]bool)
	deadline := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case line, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed early; got %v", got)
			}
			got[line] = true
		case <-deadline:
			t.Fatalf("timeout: got %v", got)
		}
	}

	if !got["g1"] || !got["g2"] {
		t.Errorf("expected g1 and g2 from the good source; got %v", got)
	}
}
