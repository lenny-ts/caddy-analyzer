package selfupdate

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ExecutablePath resolves the absolute path of the running binary,
// resolving symlinks so the replacement lands where the real file lives
// (e.g. Homebrew shims, /usr/local/bin links).
func ExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve running binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Abs(exe)
}

// CheckWritable probes whether the current user may create files in
// destDir before anything is downloaded, turning a late permission error
// into an early actionable message.
func CheckWritable(destDir string) error {
	probe := filepath.Join(destDir, ".caddy-analyze-update-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("cannot write to %s: %w\n"+
			"Re-run with sudo (the destination is likely root-owned), or install to a user directory instead:\n"+
			"  sudo caddy-analyze update\n"+
			"  caddy-analyze update --install-dir ~/.local/bin", destDir, err)
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return nil
}

// ReplaceBinary atomically moves newBin over target. On POSIX a rename in
// the same directory is atomic and safe while the old file executes. On
// Windows a running .exe cannot be overwritten, so the live image is
// renamed out of the way first and rolled back if anything fails.
func ReplaceBinary(newBin, target string) error {
	if runtime.GOOS == "windows" {
		old := target + ".old"
		_ = os.Remove(old) // leftover from a previous update
		if err := os.Rename(target, old); err != nil {
			return fmt.Errorf("move running executable aside: %w", err)
		}
		if err := os.Rename(newBin, target); err != nil {
			if rbErr := os.Rename(old, target); rbErr != nil {
				return fmt.Errorf("install new binary: %w (rollback also failed: %s; original saved as %s)", err, rbErr.Error(), old)
			}
			return fmt.Errorf("install new binary: %w", err)
		}
		if rmErr := os.Remove(old); rmErr != nil {
			fmt.Fprintf(os.Stderr, "note: could not delete %s; it can be removed manually\n", old)
		}
		return nil
	}

	if info, err := os.Stat(target); err == nil {
		if err := os.Chmod(newBin, info.Mode().Perm()); err != nil {
			return fmt.Errorf("preserve file mode: %w", err)
		}
	}

	if err := os.Rename(newBin, target); err != nil {
		return fmt.Errorf("replace %s: %w", target, err)
	}
	return nil
}
