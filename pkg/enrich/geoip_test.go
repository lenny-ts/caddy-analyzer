package enrich

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestUserHomeDirResolvesNonEmpty asserts the cross-platform home lookup
// returns a usable directory on the host running the tests (it must not
// silently degrade to "" the way os.Getenv("HOME") does on Windows).
func TestUserHomeDirResolvesNonEmpty(t *testing.T) {
	home := userHomeDir()
	if home == "" {
		t.Fatalf("userHomeDir() returned empty; expected a resolved home directory on %s", runtime.GOOS)
	}
	if info, err := os.Stat(home); err != nil || !info.IsDir() {
		t.Fatalf("userHomeDir()=%q is not an accessible directory: %v", home, err)
	}
}

// TestGeoIPSearchPathsPrependUserHome asserts the home-based search paths are
// built from userHomeDir() rather than the raw HOME env var, so they resolve
// on Windows where HOME is typically unset.
func TestGeoIPSearchPathsPrependUserHome(t *testing.T) {
	home := userHomeDir()
	wantCountry := []string{
		filepath.Join(home, ".config", "caddy-analyzer", "GeoIP.mmdb"),
		filepath.Join(home, ".config", "caddy-analyzer", "GeoLite2-Country.mmdb"),
		filepath.Join(home, ".config", "caddy-analyzer", "dbip-country-lite.mmdb"),
	}
	for _, want := range wantCountry {
		if !containsPath(geoIPSearchPaths, want) {
			t.Errorf("geoIPSearchPaths missing %q; got %v", want, geoIPSearchPaths)
		}
	}

	wantASN := []string{
		filepath.Join(home, ".config", "caddy-analyzer", "GeoLite2-ASN.mmdb"),
		filepath.Join(home, ".config", "caddy-analyzer", "dbip-asn-lite.mmdb"),
	}
	for _, want := range wantASN {
		if !containsPath(geoIPASNSearchPaths, want) {
			t.Errorf("geoIPASNSearchPaths missing %q; got %v", want, geoIPASNSearchPaths)
		}
	}
}

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}
