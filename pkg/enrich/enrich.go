package enrich

import (
	"net"
	"sync"
	"time"
)

// Reputation represents the threat-intel reputation of an IP address.
type Reputation struct {
	IP         string
	Source     string
	Score      int // 0-100 confidence that this IP is malicious
	Malicious  bool
	Categories []string // e.g., "brute-force", "scanner", "botnet"
	Country    string
	ISP        string
	UsageType  string // e.g., "datacenter", "isp", "tor"
	Reports    int    // number of abuse reports
	FetchedAt  time.Time
}

// Enricher looks up the reputation of an IP from external threat-intel feeds.
type Enricher interface {
	Lookup(ip string) (*Reputation, error)
	Name() string
}

// Cache wraps an Enricher with a TTL-based cache so repeated lookups for
// the same IP don't hit the API. IP indicators expire after 30 days per
// threat-intel best practice; the default TTL is configurable. The cache
// is bounded to maxEntries to prevent unbounded memory growth in
// long-running guard sessions.
type Cache struct {
	inner      Enricher
	ttl        time.Duration
	mu         sync.Mutex
	store      map[string]cacheEntry
	maxEntries int
}

type cacheEntry struct {
	rep  *Reputation
	time time.Time
}

const defaultMaxEntries = 10000

// NewCache wraps an Enricher with a TTL cache.
func NewCache(inner Enricher, ttl time.Duration) *Cache {
	return &Cache{
		inner:      inner,
		ttl:        ttl,
		store:      make(map[string]cacheEntry),
		maxEntries: defaultMaxEntries,
	}
}

func (c *Cache) Lookup(ip string) (*Reputation, error) {
	c.mu.Lock()
	if e, ok := c.store[ip]; ok && time.Since(e.time) < c.ttl {
		if e.rep != nil {
			rep := *e.rep
			c.mu.Unlock()
			return &rep, nil
		}
		c.mu.Unlock()
		return nil, nil
	}
	c.mu.Unlock()

	rep, err := c.inner.Lookup(ip)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	if len(c.store) >= c.maxEntries {
		c.evictExpired()
	}
	if len(c.store) >= c.maxEntries {
		for k := range c.store {
			delete(c.store, k)
			break
		}
	}
	c.store[ip] = cacheEntry{rep: rep, time: time.Now()}
	c.mu.Unlock()
	return rep, nil
}

func (c *Cache) evictExpired() {
	now := time.Now()
	for k, e := range c.store {
		if now.Sub(e.time) >= c.ttl {
			delete(c.store, k)
		}
	}
}

func (c *Cache) Name() string { return c.inner.Name() }

// IsPrivateOrLoopback returns true for IPs that should not be enriched
// (RFC1918, loopback, link-local). These never have external reputation.
func IsPrivateOrLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsPrivate() || parsed.IsLoopback() ||
		parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() ||
		parsed.IsUnspecified() || parsed.IsMulticast()
}

// MultiEnricher combines multiple enrichers, returning the first non-nil
// reputation (first-source-wins). This lets you stack multiple threat-intel
// sources without duplicating lookups: the cache prevents redundant API calls.
type MultiEnricher struct {
	sources []Enricher
}

func NewMultiEnricher(sources ...Enricher) *MultiEnricher {
	return &MultiEnricher{sources: sources}
}

func (m *MultiEnricher) Lookup(ip string) (*Reputation, error) {
	for _, s := range m.sources {
		rep, err := s.Lookup(ip)
		if err == nil && rep != nil {
			return rep, nil
		}
	}
	return nil, nil
}

func (m *MultiEnricher) Name() string {
	return "multi"
}
