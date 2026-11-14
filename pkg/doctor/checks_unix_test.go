//go:build !windows

package doctor

import (
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCaddyChecksFIFOLogDoesNotHang(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "access.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	done := make(chan []Check, 1)
	go func() {
		done <- caddyChecks(Env{
			AccessLog: fifo,
			LookPath:  func(string) (string, error) { return "", errors.New("not found") },
		})
	}()

	select {
	case checks := <-done:
		logCheck := checkByID(t, checks, "caddy.access_log")
		if logCheck.Status != StatusFail || !logCheck.Critical {
			t.Errorf("FIFO log check = %+v", logCheck)
		}
		if !strings.Contains(logCheck.Message, "regular file") {
			t.Errorf("FIFO log message = %s", logCheck.Message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("caddyChecks hung on FIFO access log")
	}
}
