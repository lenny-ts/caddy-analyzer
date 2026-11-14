//go:build !windows

package doctor

import "syscall"

// canWriteDir reports whether the current process may write inside an existing
// directory. It is a permission check only; no file or directory is created.
func canWriteDir(path string) bool {
	const wOK = 2
	return syscall.Access(path, wOK) == nil
}
