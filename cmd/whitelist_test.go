package cmd

import (
	"os"
	"path/filepath"
	"strings"
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
