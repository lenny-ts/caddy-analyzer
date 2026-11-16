package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunGuardRejectsInvalidWhitelistAtStartup(t *testing.T) {
	oldFile, oldWhitelist := guardNeverBlockFile, whitelistFile
	oldDryRun, oldNoBlocklist, oldProtectSelf := guardDryRun, guardNoBlocklist, guardProtectSelf
	oldBackend := guardFirewallBackend
	oldAuditLog, oldNotify := guardAuditLog, guardNotify
	t.Cleanup(func() {
		guardNeverBlockFile, whitelistFile = oldFile, oldWhitelist
		guardDryRun, guardNoBlocklist, guardProtectSelf = oldDryRun, oldNoBlocklist, oldProtectSelf
		guardFirewallBackend = oldBackend
		guardAuditLog, guardNotify = oldAuditLog, oldNotify
	})
	dir := t.TempDir()
	log := filepath.Join(dir, "access.log")
	if err := os.WriteFile(log, nil, 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "whitelist.txt")
	if err := os.WriteFile(path, []byte("203.0.113.7\nnot-an-ip\n"), 0600); err != nil {
		t.Fatal(err)
	}
	guardDryRun, guardNoBlocklist, guardProtectSelf = true, true, false
	guardAuditLog = ""
	// If validation is bypassed, stop before any firewall or network access.
	guardFirewallBackend = "review-invalid"
	whitelistFile = path
	for _, explicit := range []bool{true, false} {
		guardNeverBlockFile = ""
		if explicit {
			guardNeverBlockFile = path
		}
		err := runGuard(nil, []string{log})
		if err == nil || !strings.Contains(err.Error(), "invalid IP or CIDR") {
			t.Errorf("explicit=%v: expected whitelist validation failure, got %v", explicit, err)
		}
	}
}

func TestRunGuardInvalidDuration(t *testing.T) {
	old := guardDuration
	defer func() { guardDuration = old }()

	guardDuration = "abc"
	err := runGuard(nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid duration, got nil")
	}
}

func TestRunGuardInvalidWindow(t *testing.T) {
	old := guardWindow
	defer func() { guardWindow = old }()

	guardWindow = "xyz"
	err := runGuard(nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid window, got nil")
	}
}

func TestGuardDryRunFlag(t *testing.T) {
	flag := guardCmd.Flags().Lookup("dry-run")
	if flag == nil {
		t.Fatal("expected --dry-run flag")
	}
	if flag.DefValue != "false" {
		t.Fatalf("expected dry-run default false, got %s", flag.DefValue)
	}
}

func TestGuardProtectSelfDefault(t *testing.T) {
	flag := guardCmd.Flags().Lookup("protect-self")
	if flag == nil || flag.DefValue != "true" {
		t.Fatal("guard must protect server IPs by default")
	}
}

// TestRunGuardRequiresRoot: when not running as root, guard must refuse to
// start with a clear error so the user does not believe protection is
// active while every BlockIP silently fails.
func TestRunGuardRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test only meaningful when not root")
	}
	oldDur, oldWin := guardDuration, guardWindow
	defer func() { guardDuration, guardWindow = oldDur, oldWin }()
	guardDuration = "10m"
	guardWindow = "1m"

	err := runGuard(nil, nil)
	if err == nil {
		t.Fatal("expected root error, got nil")
	}
}
