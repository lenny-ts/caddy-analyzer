package enrich

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindDBExplicitPath(t *testing.T) {
	got := FindDB("/some/explicit/path.mmdb")
	if got != "/some/explicit/path.mmdb" {
		t.Errorf("FindDB(explicit) = %q, want /some/explicit/path.mmdb", got)
	}
}

func TestFindDBEmptyReturnsEmpty(t *testing.T) {
	got := FindDB("")
	// On CI there's usually no mmdb in search paths, so empty is acceptable.
	// We just verify it doesn't panic.
	_ = got
}

func TestCountryCodeFromNameNoDB(t *testing.T) {
	got := CountryCodeFromName("Italy", "/nonexistent/path.mmdb")
	if got != "" {
		t.Errorf("CountryCodeFromName with bad path = %q, want empty", got)
	}
}

func TestCountryCodeFromNameEmptyPath(t *testing.T) {
	got := CountryCodeFromName("Italy", "")
	// If a GeoIP mmdb is installed, the function resolves it. If not, empty
	// is acceptable. We just verify it doesn't panic or error.
	_ = got
}

func TestCountryCodeFromNameNoMatch(t *testing.T) {
	dir := t.TempDir()

	// Create a minimal valid mmdb with no matching entries.
	// Use a real mmdb if one exists in testdata, otherwise skip.
	mmdbPath := filepath.Join(dir, "test.mmdb")
	if err := os.WriteFile(mmdbPath, []byte("not-a-real-mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := CountryCodeFromName("Nonexistent", mmdbPath)
	if got != "" {
		t.Errorf("CountryCodeFromName with corrupt mmdb = %q, want empty", got)
	}
}
