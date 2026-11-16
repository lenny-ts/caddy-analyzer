//go:build !windows

package guard

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAllowlistReloadFIFOLeavesLastGoodList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.txt")
	writeAllowlistFile(t, path, "203.0.113.7\n")
	g := New(Config{NeverBlockFile: path, Blocker: newFakeBlocker()})
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- g.reloadAllowlist() }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("expected non-regular file error, got %v", err)
		}
		if !g.isAllowlisted("203.0.113.7") {
			t.Fatal("failed reload lost the last good allowlist")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("allowlist reload hung on FIFO")
	}
}
