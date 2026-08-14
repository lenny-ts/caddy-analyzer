package reader

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func readLineTimeout(t *testing.T, ch <-chan string, timeout time.Duration) (string, bool) {
	t.Helper()
	select {
	case line, ok := <-ch:
		return line, ok
	case <-time.After(timeout):
		return "", false
	}
}

func TestFileReaderReadsAllLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	content := "line1\nline2\nline3\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	r := FromSource(types.LogSource{Type: types.SourceFile, Path: path})
	ctx := context.Background()
	lines, err := r.Read(ctx)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	var got []string
	for line := range lines {
		got = append(got, line)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(got), got)
	}
	if got[0] != "line1" || got[2] != "line3" {
		t.Errorf("unexpected lines: %v", got)
	}
}

func TestFileReaderGlobExpansion(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.log"), []byte("a\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.log"), []byte("b\n"), 0644); err != nil {
		t.Fatal(err)
	}

	pattern := filepath.Join(dir, "*.log")
	r := FromSource(types.LogSource{Type: types.SourceFile, Path: pattern})
	ctx := context.Background()
	lines, err := r.Read(ctx)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	seen := map[string]bool{}
	for line := range lines {
		seen[line] = true
	}
	if !seen["a"] || !seen["b"] {
		t.Errorf("glob expansion did not read both files, got %v", seen)
	}
}

func TestFileReaderFollowAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("line1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := FromSourceFollow(types.LogSource{Type: types.SourceFile, Path: path})
	lines, err := r.Read(ctx)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if line, ok := readLineTimeout(t, lines, 2*time.Second); !ok || line != "line1" {
		t.Fatalf("expected initial line1, got %q ok=%v", line, ok)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("line2\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if line, ok := readLineTimeout(t, lines, 2*time.Second); !ok || line != "line2" {
		t.Fatalf("expected appended line2, got %q ok=%v", line, ok)
	}
}

func TestFileReaderFollowRotation(t *testing.T) {
	// Windows cannot rename a file that another handle has open (no
	// FILE_SHARE_DELETE on os.Open), so the rename-while-open rotation
	// pattern used here is Unix-only. The reader still detects truncation
	// (size < pos) and replacement on all platforms.
	if runtime.GOOS == "windows" {
		t.Skip("rename of an open file is not supported on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("old1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := FromSourceFollow(types.LogSource{Type: types.SourceFile, Path: path})
	lines, err := r.Read(ctx)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if line, ok := readLineTimeout(t, lines, 2*time.Second); !ok || line != "old1" {
		t.Fatalf("expected old1, got %q ok=%v", line, ok)
	}

	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new1\nnew2\n"), 0644); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"new1", "new2"} {
		line, ok := readLineTimeout(t, lines, 3*time.Second)
		if !ok || line != want {
			t.Fatalf("expected %s after rotation, got %q ok=%v", want, line, ok)
		}
	}
}

func TestParseSourceSchemes(t *testing.T) {
	tests := []struct {
		raw  string
		want types.LogSource
	}{
		{"-", types.LogSource{Type: types.SourceStdin}},
		{"/var/log/caddy/access.log", types.LogSource{Type: types.SourceFile, Path: "/var/log/caddy/access.log"}},
		{"docker://my-caddy", types.LogSource{Type: types.SourceDocker, Path: "my-caddy"}},
		{"k8s://my-pod", types.LogSource{Type: types.SourceK8s, Path: "my-pod"}},
		{"journalctl://caddy", types.LogSource{Type: types.SourceJournalctl, Path: "caddy"}},
	}
	for _, tt := range tests {
		got := ParseSource(tt.raw)
		if got.Type != tt.want.Type || got.Path != tt.want.Path {
			t.Errorf("ParseSource(%q) = %+v, want %+v", tt.raw, got, tt.want)
		}
	}
}

func TestStdinReaderName(t *testing.T) {
	r := &StdinReader{}
	if !strings.Contains(r.Name(), "stdin") {
		t.Errorf("unexpected name %q", r.Name())
	}
}
