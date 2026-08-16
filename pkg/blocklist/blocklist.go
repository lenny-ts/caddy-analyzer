package blocklist

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/yl2chen/cidranger"
)

// cacheTTL is how long a fetched blocklist remains valid before it
// is considered stale. Per design decision: 7 days. A stale source is
// disabled with a warning rather than silently served or silently dropped.
const cacheTTL = 7 * 24 * time.Hour

// fetchTimeout bounds each HTTP download so a slow or unresponsive
// feed cannot block the refresh loop indefinitely.
const fetchTimeout = 30 * time.Second

// userAgent identifies the tool in blocklist fetch requests. Some
// feeds (Spamhaus in particular) reject empty or generic UA strings.
const userAgent = "caddy-analyzer/1.0 (+https://github.com/lenny-ts/caddy-analyzer)"

// Source describes a single blocklist feed.
type Source struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Format string `json:"format,omitempty"`
}

// SourceStatus reports the state of one source after a refresh or load.
type SourceStatus struct {
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Entries   int       `json:"entries"`
	FetchedAt time.Time `json:"fetched_at"`
	Error     string    `json:"error,omitempty"`
	Stale     bool      `json:"stale,omitempty"`
}

// Stats summarises the manager's current state.
type Stats struct {
	Sources []SourceStatus `json:"sources"`
	Total   int            `json:"total_entries"`
	Active  int            `json:"active_sources"`
}

// DefaultSources are the blocklist feeds enabled out of the box.
// The user can disable them with --no-default-blocklists and/or add
// custom sources via --blocklist-config.
var DefaultSources = []Source{
	{Name: "spamhaus-drop", URL: "https://www.spamhaus.org/drop/drop.txt"},
	{Name: "firehol-level1", URL: "https://iplists.firehol.org/files/firehol_level1.netset"},
	{Name: "cins-army", URL: "http://cinsscore.com/list/ci-badguys.txt"},
	{Name: "tor-exit-nodes", URL: "https://check.torproject.org/torbulkexitlist"},
}

// Manager coordinates fetching, caching, and lookups across multiple
// blocklist sources. It is safe for concurrent use. The CIDR trie
// (cidranger) provides O(log n) IP containment checks for both IPv4
// and IPv6.
type Manager struct {
	mu        sync.RWMutex
	sources   []Source
	cacheDir  string
	rangers   map[string]cidranger.Ranger
	statuses  map[string]SourceStatus
	userAgent string
	httpFetch func(url string) ([]byte, error)
}

// NewManager creates a Manager with the given sources and cache directory.
// If sources is nil, DefaultSources are used. The cache directory is
// created if it does not exist.
func NewManager(sources []Source, cacheDir string) (*Manager, error) {
	if len(sources) == 0 {
		sources = DefaultSources
	}
	m := &Manager{
		sources:   sources,
		cacheDir:  cacheDir,
		rangers:   make(map[string]cidranger.Ranger),
		statuses:  make(map[string]SourceStatus),
		userAgent: userAgent,
		httpFetch: defaultFetcher,
	}
	if err := ensureCacheDir(cacheDir); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	return m, nil
}

// SetFetcher injects a custom fetch function. Used in tests to avoid
// real HTTP calls.
func (m *Manager) SetFetcher(fn func(url string) ([]byte, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.httpFetch = fn
}

// Sources returns the configured source list.
func (m *Manager) Sources() []Source {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Source, len(m.sources))
	copy(out, m.sources)
	return out
}

// LoadAll loads every source from the on-disk cache without fetching.
// Sources whose cache is missing or stale are marked accordingly in
// their status. This is called at startup so guard can use blocklists
// immediately if they were previously refreshed.
func (m *Manager) LoadAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, src := range m.sources {
		m.loadFromCache(src)
	}
}

// Refresh downloads every source, parses it, stores the entries in a
// cidranger trie, and writes the result to the on-disk cache. A source
// that fails to fetch or parse is logged in its status but does not
// abort the overall refresh.
func (m *Manager) Refresh() []SourceStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	var statuses []SourceStatus
	for _, src := range m.sources {
		statuses = append(statuses, m.refreshSource(src))
	}
	return statuses
}

func (m *Manager) refreshSource(src Source) SourceStatus {
	body, err := m.httpFetch(src.URL)
	if err != nil {
		st := SourceStatus{
			Name:  src.Name,
			URL:   src.URL,
			Error: fmt.Sprintf("fetch: %v", err),
		}
		m.statuses[src.Name] = st
		return st
	}
	entries := parseEntries(body)
	ranger := cidranger.NewPCTrieRanger()
	for _, e := range entries {
		_ = ranger.Insert(cidranger.NewBasicRangerEntry(e))
	}
	m.rangers[src.Name] = ranger
	now := time.Now().UTC()
	st := SourceStatus{
		Name:      src.Name,
		URL:       src.URL,
		Entries:   len(entries),
		FetchedAt: now,
	}
	m.statuses[src.Name] = st
	_ = m.writeCache(src, entries, now)
	return st
}

// Contains reports whether ip is present in any active (non-stale) source.
func (m *Manager) Contains(ip string) (bool, string) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, src := range m.sources {
		ranger, ok := m.rangers[src.Name]
		if !ok {
			continue
		}
		st := m.statuses[src.Name]
		if st.Stale || st.Entries == 0 {
			continue
		}
		contained, err := ranger.Contains(parsed)
		if err == nil && contained {
			return true, src.Name
		}
	}
	return false, ""
}

// ListSources returns the status of every source.
func (m *Manager) ListSources() []SourceStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]SourceStatus, 0, len(m.sources))
	for _, src := range m.sources {
		st := m.statuses[src.Name]
		st.Name = src.Name
		st.URL = src.URL
		out = append(out, st)
	}
	return out
}

// Stats returns an aggregate summary of all sources.
func (m *Manager) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var s Stats
	for _, src := range m.sources {
		st := m.statuses[src.Name]
		st.Name = src.Name
		st.URL = src.URL
		s.Sources = append(s.Sources, st)
		s.Total += st.Entries
		if !st.Stale && st.Entries > 0 && st.Error == "" {
			s.Active++
		}
	}
	return s
}

// AddSource appends a new source to the manager's source list.
func (m *Manager) AddSource(src Source) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.sources {
		if existing.Name == src.Name {
			return
		}
	}
	m.sources = append(m.sources, src)
}

// RemoveSource drops a source from the manager's source list and
// clears its trie and status.
func (m *Manager) RemoveSource(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := -1
	for i, s := range m.sources {
		if s.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false
	}
	m.sources = append(m.sources[:idx], m.sources[idx+1:]...)
	delete(m.rangers, name)
	delete(m.statuses, name)
	_ = removeCacheFile(m.cacheDir, name)
	return true
}
