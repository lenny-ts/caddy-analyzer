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

func TestGeoIPCheckFIFODoesNotHang(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "GeoIP.mmdb")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}
	done := make(chan Check, 1)
	go func() { done <- geoIPCheck(Env{GeoIPDB: fifo}) }()
	select {
	case check := <-done:
		if check.Status != StatusWarn || !strings.Contains(check.Message, "regular file") {
			t.Fatalf("FIFO GeoIP check = %+v", check)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GeoIP check hung on FIFO")
	}
}

func TestBlocklistCacheFIFODoesNotHang(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "feed.json"), 0600); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}
	done := make(chan Check, 1)
	go func() { done <- blocklistCacheCheck(Env{BlocklistCacheDir: dir}) }()
	select {
	case check := <-done:
		if check.Status != StatusWarn {
			t.Fatalf("FIFO cache check = %+v", check)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocklist cache check hung on FIFO")
	}
}
