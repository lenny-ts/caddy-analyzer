//go:build windows

package doctor

import "syscall"

// canWriteDir reports whether the current process may write inside an existing
// directory. It opens the directory for write access (with backup semantics)
// and closes the handle immediately, so nothing is created or modified.
func canWriteDir(path string) bool {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	h, err := syscall.CreateFile(
		p,
		syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return false
	}
	_ = syscall.CloseHandle(h)
	return true
}
