package enrich

import (
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

// TestGeoIPAsyncLoadingReturnsEmpty verifies that a GeoIP in the loading
// state (as returned by NewGeoIPAsync before the download completes)
// returns a zero GeoInfo from Lookup without error, so callers can use
// the enricher immediately without blocking on the download.
func TestGeoIPAsyncLoadingReturnsEmpty(t *testing.T) {
	g := &GeoIP{
		cache:   make(map[string]geoCacheEntry),
		loading: true,
	}
	if !g.Loading() {
		t.Fatal("Loading() = false, want true")
	}
	info, err := g.Lookup("8.8.8.8")
	if err != nil {
		t.Fatalf("Lookup during loading returned error: %v", err)
	}
	if info != (types.GeoInfo{}) {
		t.Fatalf("Lookup during loading = %+v, want zero GeoInfo", info)
	}
}

// TestGeoIPAsyncCloseDuringLoading verifies that Close marks the GeoIP
// as closed so a racing backgroundLoad releases its freshly opened
// databases instead of swapping them into a discarded enricher. After
// Close, Loading() is false and Lookup still returns empty.
func TestGeoIPAsyncCloseDuringLoading(t *testing.T) {
	g := &GeoIP{
		cache:   make(map[string]geoCacheEntry),
		loading: true,
	}
	if err := g.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if g.Loading() {
		t.Fatal("Loading() = true after Close, want false")
	}
	g.mu.RLock()
	closed := g.closed
	g.mu.RUnlock()
	if !closed {
		t.Fatal("closed = false after Close, want true")
	}
	info, err := g.Lookup("8.8.8.8")
	if err != nil {
		t.Fatalf("Lookup after Close: %v", err)
	}
	if info != (types.GeoInfo{}) {
		t.Fatalf("Lookup after Close = %+v, want zero GeoInfo", info)
	}
}

// TestNewGeoIPAsyncNoDownloadReturnsError verifies that when
// auto-download is disabled and no mmdb is on disk, NewGeoIPAsync
// returns an error rather than a loading proxy.
func TestNewGeoIPAsyncNoDownloadReturnsError(t *testing.T) {
	old := autoDownload
	oldPaths := geoIPSearchPaths
	oldASNPaths := geoIPASNSearchPaths
	defer func() {
		autoDownload = old
		geoIPSearchPaths = oldPaths
		geoIPASNSearchPaths = oldASNPaths
	}()
	autoDownload = false
	geoIPSearchPaths = []string{"/nonexistent/GeoIP.mmdb"}
	geoIPASNSearchPaths = []string{"/nonexistent/GeoLite2-ASN.mmdb"}
	_, err := NewGeoIPAsync("")
	if err == nil {
		t.Fatal("NewGeoIPAsync with no DB and auto-download disabled: expected error, got nil")
	}
}
