package reader

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileReaderKeepsAvailableFiles(t *testing.T) {
	dir := t.TempDir()
	valid, missing := filepath.Join(dir, "valid.log"), filepath.Join(dir, "missing.log")
	if err := os.WriteFile(valid, []byte("valid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &FileReader{paths: []string{missing, valid}}
	lines, err := r.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if line := <-lines; line != "valid" {
		t.Fatalf("got %q, want valid", line)
	}
	for range lines {
	}
	if !os.IsNotExist(r.Err()) {
		t.Fatalf("expected missing file error, got %v", r.Err())
	}
}

func TestParallelFollowCancellation(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"first.log", "second.log"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, nil, 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	r := &FileReader{paths: paths, follow: true}
	ctx, cancel := context.WithCancel(context.Background())
	lines, err := r.Read(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	for range lines {
	}
	if err := r.Err(); err != nil {
		t.Fatalf("cancellation reported as a read error: %v", err)
	}
}
