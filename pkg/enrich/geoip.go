package enrich

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"github.com/L9Lenny/caddy-analyzer/pkg/types"
)

const (
	geoCacheTTL     = 24 * time.Hour
	geoCacheMaxSize = 50000

	// dbipCountryURL is the DB-IP country-lite mmdb download URL.
	dbipCountryURL = "https://download.dbip.com/dbip-country-lite.mmdb"
	// dbipASNURL is the DB-IP ASN-lite mmdb download URL.
	dbipASNURL = "https://download.dbip.com/dbip-asn-lite.mmdb"
)

// autoDownload controls whether NewGeoIP auto-downloads the DB-IP lite
// mmdb when no file is found. Enabled by default; can be disabled via
// SetAutoDownload(false).
var autoDownload = true

// GeoIP enriches IP addresses with country and ASN data from a MaxMind or
// DB-IP mmdb file. The same reader handles both country-only and
// country+ASN databases; ASN is populated only when the ASN database
// (or a combined db containing ASN fields) is available.
//
// Lookups are cached with a TTL to avoid repeated mmdb reads for the
// same IP in long-running guard sessions. The cache is bounded to
// geoCacheMaxSize entries; when full, expired entries are evicted first,
// then the oldest entry.
type GeoIP struct {
	countryDB *maxminddb.Reader
	asnDB     *maxminddb.Reader
	mu        sync.RWMutex
	cacheMu   sync.Mutex
	cache     map[string]geoCacheEntry
	path      string
}

type geoCacheEntry struct {
	info types.GeoInfo
	time time.Time
}

// countryRecord matches the MaxMind/DB-IP country mmdb schema.
type countryRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
}

// asnRecordMaxMind matches the MaxMind GeoLite2-ASN schema.
type asnRecordMaxMind struct {
	ASN uint   `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

// asnRecordDBIP matches the DB-IP ASN lite schema.
type asnRecordDBIP struct {
	ASN uint   `maxminddb:"as_number"`
	Org string `maxminddb:"as_organization"`
}

// GeoIPSearchPaths are the locations checked (in order) for an mmdb
// file when no explicit path is given. The first existing file wins.
var geoIPSearchPaths = []string{
	"GeoIP.mmdb",
	"dbip-country-lite.mmdb",
	"dbip-city-lite.mmdb",
	filepath.Join(os.Getenv("HOME"), ".config", "caddy-analyzer", "GeoIP.mmdb"),
	filepath.Join(os.Getenv("HOME"), ".config", "caddy-analyzer", "dbip-country-lite.mmdb"),
	"/var/lib/caddy-analyzer/GeoIP.mmdb",
	"/usr/share/GeoIP/GeoIP.mmdb",
	"/usr/share/GeoIP/dbip-country-lite.mmdb",
}

// geoIPASNSearchPaths are checked for a separate ASN database.
var geoIPASNSearchPaths = []string{
	"GeoLite2-ASN.mmdb",
	"dbip-asn-lite.mmdb",
	filepath.Join(os.Getenv("HOME"), ".config", "caddy-analyzer", "GeoLite2-ASN.mmdb"),
	filepath.Join(os.Getenv("HOME"), ".config", "caddy-analyzer", "dbip-asn-lite.mmdb"),
	"/var/lib/caddy-analyzer/GeoLite2-ASN.mmdb",
	"/usr/share/GeoIP/GeoLite2-ASN.mmdb",
}

// SetAutoDownload enables or disables automatic download of the DB-IP
// lite mmdb when no GeoIP file is found. Must be called before NewGeoIP.
func SetAutoDownload(enabled bool) {
	autoDownload = enabled
}

// userConfigDir returns the directory where auto-downloaded mmdb files
// are stored (~/.config/caddy-analyzer/).
func userConfigDir() (string, error) {
	dir := filepath.Join(os.Getenv("HOME"), ".config", "caddy-analyzer")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create config dir %s: %w", dir, err)
	}
	return dir, nil
}

// downloadFile downloads url to dest with a 5-minute timeout.
func downloadFile(url, dest string) (retErr error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "caddy-analyzer/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %s", url, resp.Status)
	}
	out, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("create %s: %w", dest, err)
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("close %s: %w", dest, cerr)
		}
	}()
	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	return nil
}

// autoDownloadGeoIP downloads the DB-IP country-lite and ASN-lite mmdb
// files to the user config directory and returns their paths.
func autoDownloadGeoIP() (countryPath, asnPath string, err error) {
	dir, err := userConfigDir()
	if err != nil {
		return "", "", err
	}
	countryPath = filepath.Join(dir, "dbip-country-lite.mmdb")
	asnPath = filepath.Join(dir, "dbip-asn-lite.mmdb")

	if _, e := os.Stat(countryPath); e != nil {
		fmt.Fprintf(os.Stderr, "Auto-downloading DB-IP country-lite mmdb to %s...\n", countryPath)
		if err := downloadFile(dbipCountryURL, countryPath); err != nil {
			return "", "", fmt.Errorf("auto-download GeoIP: %w", err)
		}
		fmt.Fprintf(os.Stderr, "  done.\n")
	}

	if _, e := os.Stat(asnPath); e != nil {
		fmt.Fprintf(os.Stderr, "Auto-downloading DB-IP ASN-lite mmdb to %s...\n", asnPath)
		if err := downloadFile(dbipASNURL, asnPath); err != nil {
			// ASN is optional; country-only is still useful.
			fmt.Fprintf(os.Stderr, "  warning: ASN download failed: %v\n", err)
			return countryPath, "", nil
		}
		fmt.Fprintf(os.Stderr, "  done.\n")
	}
	return countryPath, asnPath, nil
}

// NewGeoIP opens the mmdb file at path. If path is empty, auto-discovers
// the first matching file in geoIPSearchPaths. If no file is found and
// auto-download is enabled, downloads the DB-IP lite mmdb to
// ~/.config/caddy-analyzer/ and opens it.
func NewGeoIP(path string) (*GeoIP, error) {
	if path != "" {
		return openGeoIP(path, "")
	}

	countryPath, ok := findFirst(geoIPSearchPaths)
	if !ok {
		if autoDownload {
			cp, ap, err := autoDownloadGeoIP()
			if err != nil {
				return nil, err
			}
			return openGeoIP(cp, ap)
		}
		return nil, fmt.Errorf("no GeoIP mmdb file found; pass --geoip-db or place a file in one of: %v", geoIPSearchPaths)
	}
	asnPath, _ := findFirst(geoIPASNSearchPaths)
	return openGeoIP(countryPath, asnPath)
}

func openGeoIP(countryPath, asnPath string) (*GeoIP, error) {
	cdb, err := maxminddb.Open(countryPath)
	if err != nil {
		return nil, fmt.Errorf("open geoip db %s: %w", countryPath, err)
	}
	g := &GeoIP{
		countryDB: cdb,
		cache:     make(map[string]geoCacheEntry),
		path:      countryPath,
	}
	if asnPath != "" {
		adb, err := maxminddb.Open(asnPath)
		if err == nil {
			g.asnDB = adb
		}
	}
	return g, nil
}

// findFirst returns the first path in the list that exists as a file.
func findFirst(paths []string) (string, bool) {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, true
		}
	}
	return "", false
}

// Close releases the mmdb file handles.
func (g *GeoIP) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	var err error
	if g.countryDB != nil {
		err = g.countryDB.Close()
	}
	if g.asnDB != nil {
		if e := g.asnDB.Close(); e != nil {
			err = e
		}
	}
	return err
}

// Path returns the path to the country mmdb file.
func (g *GeoIP) Path() string {
	return g.path
}

// Lookup returns GeoInfo for the given IP. For private/loopback IPs
// returns a zero-value GeoInfo without hitting the database. Results
// are cached for geoCacheTTL.
func (g *GeoIP) Lookup(ip string) (types.GeoInfo, error) {
	if IsPrivateOrLoopback(ip) {
		return types.GeoInfo{}, nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return types.GeoInfo{}, fmt.Errorf("invalid IP: %s", ip)
	}

	if info, ok := g.cacheGet(ip); ok {
		return info, nil
	}

	info, err := g.lookupUncached(parsed)
	if err != nil {
		return types.GeoInfo{}, err
	}
	g.cachePut(ip, info)
	return info, nil
}

func (g *GeoIP) lookupUncached(ip net.IP) (types.GeoInfo, error) {
	var info types.GeoInfo

	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.countryDB != nil {
		var rec countryRecord
		if err := g.countryDB.Lookup(ip, &rec); err != nil {
			return info, fmt.Errorf("country lookup: %w", err)
		}
		info.CountryCode = rec.Country.ISOCode
		if name, ok := rec.Country.Names["en"]; ok {
			info.CountryName = name
		}
	}

	if g.asnDB != nil {
		var asnMaxMind asnRecordMaxMind
		if err := g.asnDB.Lookup(ip, &asnMaxMind); err == nil && asnMaxMind.ASN > 0 {
			info.ASN = asnMaxMind.ASN
			info.ASNOrg = asnMaxMind.Org
		} else {
			var asnDBIP asnRecordDBIP
			if err := g.asnDB.Lookup(ip, &asnDBIP); err == nil && asnDBIP.ASN > 0 {
				info.ASN = asnDBIP.ASN
				info.ASNOrg = asnDBIP.Org
			}
		}
	}

	return info, nil
}

func (g *GeoIP) cacheGet(ip string) (types.GeoInfo, bool) {
	g.cacheMu.Lock()
	defer g.cacheMu.Unlock()
	e, ok := g.cache[ip]
	if !ok {
		return types.GeoInfo{}, false
	}
	if time.Since(e.time) >= geoCacheTTL {
		delete(g.cache, ip)
		return types.GeoInfo{}, false
	}
	return e.info, true
}

func (g *GeoIP) cachePut(ip string, info types.GeoInfo) {
	g.cacheMu.Lock()
	defer g.cacheMu.Unlock()
	if len(g.cache) >= geoCacheMaxSize {
		g.evictExpired()
	}
	if len(g.cache) >= geoCacheMaxSize {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range g.cache {
			if oldestKey == "" || v.time.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.time
			}
		}
		delete(g.cache, oldestKey)
	}
	g.cache[ip] = geoCacheEntry{info: info, time: time.Now()}
}

func (g *GeoIP) evictExpired() {
	now := time.Now()
	for k, e := range g.cache {
		if now.Sub(e.time) >= geoCacheTTL {
			delete(g.cache, k)
		}
	}
}
