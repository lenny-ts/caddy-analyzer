package cmd

import (
	"os"
	"testing"
)

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
