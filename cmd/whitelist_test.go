package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestWhitelistInit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")
	whitelistFile = path

	// Init should create the file.
	if err := initWhitelist(); err != nil {
		t.Fatalf("initWhitelist: %v", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("whitelist file not created")
	}

	// Init again should be idempotent (file already exists).
	if err := initWhitelist(); err != nil {
		t.Fatalf("initWhitelist idempotent: %v", err)
	}
}

func TestWhitelistAddAndList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")
	whitelistFile = path

	// Init first.
	if err := initWhitelist(); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Add entries.
	if err := addWhitelist([]string{"10.0.0.0/8", "192.168.1.1"}); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Load and verify.
	entries, err := loadWhitelist()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %v", len(entries), entries)
	}
	if entries[0] != "10.0.0.0/8" {
		t.Errorf("entries[0] = %q, want 10.0.0.0/8", entries[0])
	}
	if entries[1] != "192.168.1.1" {
		t.Errorf("entries[1] = %q, want 192.168.1.1", entries[1])
	}

	// Add duplicate — should not duplicate.
	if err := addWhitelist([]string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("add dup: %v", err)
	}
	entries, _ = loadWhitelist()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries after dup, got %d", len(entries))
	}
}

func TestWhitelistRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")
	whitelistFile = path

	initWhitelist()
	addWhitelist([]string{"10.0.0.0/8", "192.168.1.1", "172.16.0.0/12"})

	// Remove one.
	if err := removeWhitelist([]string{"192.168.1.1"}); err != nil {
		t.Fatalf("remove: %v", err)
	}

	entries, _ := loadWhitelist()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries after remove, got %d: %v", len(entries), entries)
	}
	for _, e := range entries {
		if e == "192.168.1.1" {
			t.Error("192.168.1.1 should have been removed")
		}
	}
}

func TestWhitelistLoadEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")
	whitelistFile = path

	// No file — should return empty, no error.
	entries, err := loadWhitelist()
	if err != nil {
		t.Fatalf("load non-existent: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestWhitelistLoadComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")
	whitelistFile = path

	content := `# This is a comment
10.0.0.0/8
  # indented comment
192.168.1.1

# trailing comment
`
	os.WriteFile(path, []byte(content), 0600)

	entries, err := loadWhitelist()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %v", len(entries), entries)
	}
}

func TestWhitelistPath(t *testing.T) {
	// Default path.
	old := whitelistFile
	defer func() { whitelistFile = old }()

	whitelistFile = "/etc/caddy-analyzer/whitelist.txt"
	if got := WhitelistPath(); got != "/etc/caddy-analyzer/whitelist.txt" {
		t.Errorf("WhitelistPath() = %q", got)
	}

	// Empty.
	whitelistFile = ""
	if got := WhitelistPath(); got != "" {
		t.Errorf("WhitelistPath() empty = %q", got)
	}
}

func TestWhitelistAddSkipsInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")
	whitelistFile = path

	initWhitelist()

	// Add mix of valid and invalid.
	err := addWhitelist([]string{"10.0.0.0/8", "not-an-ip", "192.168.1.1"})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	entries, _ := loadWhitelist()
	for _, e := range entries {
		if strings.Contains(e, "not-an-ip") {
			t.Error("invalid IP should not be in whitelist")
		}
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 valid entries, got %d: %v", len(entries), entries)
	}
}

func TestWhitelistReplacementUsesAtomicRename(t *testing.T) {
	statOpen := func(t *testing.T, path string) os.FileInfo {
		t.Helper()
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		defer func() { _ = f.Close() }()
		info, err := f.Stat()
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		return info
	}
	for _, tc := range []struct {
		name string
		op   func() error
	}{
		{name: "add", op: func() error { return addWhitelist([]string{"198.51.100.7"}) }},
		{name: "remove", op: func() error { return removeWhitelist([]string{"10.0.0.1"}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "whitelist.txt")
			whitelistFile = path
			if err := os.WriteFile(path, []byte("10.0.0.1\n"), 0600); err != nil {
				t.Fatalf("seed whitelist: %v", err)
			}
			before := statOpen(t, path)
			if err := tc.op(); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			after := statOpen(t, path)
			if os.SameFile(before, after) {
				t.Fatalf("%s rewrote the whitelist in place; a reload can observe a torn file", tc.name)
			}
		})
	}
}

func TestWhitelistReloadDuringReplacementKeepsLastGoodList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")
	whitelistFile = path

	// Seed exactly what removeWhitelist writes, plus enough entries to widen
	// the replacement window. A reload that opens the path mid-write sees a
	// different size, which means it did not get the last good list.
	var seed strings.Builder
	seed.WriteString("# caddy-analyzer whitelist\n")
	seed.WriteString("# IPs and CIDRs listed here will NEVER be blocked by the guard daemon.\n")
	seed.WriteString("# One entry per line. Lines starting with # are comments.\n")
	seed.WriteString("203.0.113.7\n")
	for i := 0; i < 200_000; i++ {
		fmt.Fprintf(&seed, "10.%d.%d.%d\n", i>>16&255, i>>8&255, i&255)
	}
	lastGood := []byte(seed.String())
	if err := os.WriteFile(path, lastGood, 0600); err != nil {
		t.Fatalf("seed whitelist: %v", err)
	}

	stop := make(chan struct{})
	torn := make(chan struct{}, 1)
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				info, err := os.Stat(path)
				if err != nil {
					continue
				}
				if info.Size() == int64(len(lastGood)) {
					continue
				}
				select {
				case torn <- struct{}{}:
				default:
				}
				return
			}
		}()
	}

	for i := 0; i < 10; i++ {
		if err := removeWhitelist([]string{"198.51.100.99"}); err != nil {
			t.Fatalf("remove: %v", err)
		}
	}
	close(stop)
	readers.Wait()

	select {
	case <-torn:
		entries, err := loadWhitelist()
		if err != nil {
			t.Fatalf("reload during replacement failed: %v", err)
		}
		for _, e := range entries {
			if e == "203.0.113.7" {
				t.Fatal("reload during replacement observed a partially written whitelist")
			}
		}
		t.Fatal("reload during replacement lost the retained whitelist entry")
	default:
	}
}
