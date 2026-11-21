//go:build !windows

package cmd

import (
	"os"
	"syscall"
)

func lockWhitelistFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}
