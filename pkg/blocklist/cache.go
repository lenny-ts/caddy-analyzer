package blocklist

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/yl2chen/cidranger"
)

// cacheFile is the on-disk representation of a fetched blocklist.
type cacheFile struct {
	Entries   []string  `json:"entries"`
	FetchedAt time.Time `json:"fetched_at"`
}

// ensureCacheDir creates the cache directory if it does not exist.
func ensureCacheDir(dir string) error {
	if dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0750)
}

func cachePath(dir, name string) string {
	return filepath.Join(dir, name+".json")
}

// writeCache serialises the entries and timestamp to a per-source JSON
// file in the cache directory.
func (m *Manager) writeCache(src Source, entries []net.IPNet, fetchedAt time.Time) error {
	if m.cacheDir == "" {
		return nil
	}
	cf := cacheFile{
		Entries:   make([]string, len(entries)),
		FetchedAt: fetchedAt,
	}
	for i, e := range entries {
		cf.Entries[i] = e.String()
	}
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	path := cachePath(m.cacheDir, src.Name)
	return os.WriteFile(path, data, 0o600)
}

// loadFromCache populates the ranger and status for a source from its
// on-disk cache file. If the file is missing, the source is marked as
// not loaded. If the cache is older than cacheTTL, the source is marked
// stale so Contains() skips it and the user is warned to refresh.
func (m *Manager) loadFromCache(src Source) {
	path := cachePath(m.cacheDir, src.Name)
	data, err := os.ReadFile(path)
	if err != nil {
		st := SourceStatus{
			Name:  src.Name,
			URL:   src.URL,
			Error: "no cache; run 'caddy-analyze blocklist refresh'",
		}
		m.statuses[src.Name] = st
		return
	}
	var cf cacheFile
	if err := json.Unmarshal(data, &cf); err != nil {
		st := SourceStatus{
			Name:  src.Name,
			URL:   src.URL,
			Error: fmt.Sprintf("cache parse: %v", err),
		}
		m.statuses[src.Name] = st
		return
	}
	ranger := cidranger.NewPCTrieRanger()
	for _, s := range cf.Entries {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		_ = ranger.Insert(cidranger.NewBasicRangerEntry(*ipnet))
	}
	m.rangers[src.Name] = ranger
	stale := time.Since(cf.FetchedAt) >= cacheTTL
	st := SourceStatus{
		Name:      src.Name,
		URL:       src.URL,
		Entries:   len(cf.Entries),
		FetchedAt: cf.FetchedAt,
		Stale:     stale,
	}
	if stale {
		st.Error = "cache stale; run 'caddy-analyze blocklist refresh'"
	}
	m.statuses[src.Name] = st
}

func removeCacheFile(dir, name string) error {
	if dir == "" {
		return nil
	}
	path := cachePath(dir, name)
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
