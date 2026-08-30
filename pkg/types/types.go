package types

import (
	"encoding/json"
	"math"
	"net"
	"strings"
	"time"
)

// durationHistogram is a fixed-memory streaming histogram for latency
// percentiles. It uses log10-spaced buckets (100 per decade) covering 1µs to
// ~10s, giving O(1) per insert and O(buckets) per percentile query with
// <2.5% relative error — suitable for multi-million-line logs where storing
// every duration would cost ~80MB and an O(n log n) sort.
type durationHistogram struct {
	buckets [1000]uint64
	total   uint64
	min     float64
	max     float64
	hasData bool
}

// histBucketIndex maps a duration (seconds) to a bucket index in [0, 999].
// Bucket 0 = [1µs, ~1.023µs), bucket 100 = [10µs, ~10.23µs), etc.
func histBucketIndex(d float64) int {
	if d <= 1e-6 {
		return 0
	}
	idx := int(100 * math.Log10(d*1e6))
	if idx < 0 {
		return 0
	}
	if idx > 999 {
		return 999
	}
	return idx
}

// histBucketLower returns the lower bound (seconds) of bucket i.
func histBucketLower(i int) float64 {
	if i <= 0 {
		return 0
	}
	return math.Pow(10, float64(i)/100) * 1e-6
}

func (h *durationHistogram) add(d float64) {
	if !h.hasData {
		h.min = d
		h.max = d
		h.hasData = true
	} else {
		if d < h.min {
			h.min = d
		}
		if d > h.max {
			h.max = d
		}
	}
	h.buckets[histBucketIndex(d)]++
	h.total++
}

// percentile returns the estimated p-th percentile (0-100) from the histogram.
func (h *durationHistogram) percentile(p float64) float64 {
	if h.total == 0 {
		return 0
	}
	target := uint64(math.Ceil(p / 100 * float64(h.total)))
	var cum uint64
	for i := 0; i < 1000; i++ {
		cum += h.buckets[i]
		if cum >= target {
			// Linear interpolation inside the bucket between lower and upper.
			lower := histBucketLower(i)
			upper := histBucketLower(i + 1)
			if i == 0 {
				lower = h.min
			}
			if i == 999 {
				upper = h.max
			}
			bucketCount := h.buckets[i]
			if bucketCount <= 1 {
				return (lower + upper) / 2
			}
			prev := cum - bucketCount
			frac := float64(target-prev-1) / float64(bucketCount)
			if frac < 0 {
				frac = 0
			}
			return lower + frac*(upper-lower)
		}
	}
	return h.max
}

type LogEntry struct {
	Timestamp     time.Time
	Level         string
	Logger        string
	Method        string
	URI           string
	Host          string
	RemoteAddr    string
	RemoteIP      string
	Proto         string
	UserAgent     string
	Referer       string
	RefererDomain string
	Status        int
	Size          int64
	Duration      float64
	Raw           string
	TLSVersion    string
	TLSCipher     string
	TLSServerName string
	IsBot         bool
	BotName       string
	Browser       string
	OS            string
	ContentType   string
	ForwardedFor  []string
	RealIP        string
	Authorization string
	Geo           GeoInfo
}

// Entry is a marker interface implemented by all parsed log entry types.
// Parse returns an Entry; callers type-switch on the concrete type
// (*LogEntry for HTTP access logs, *OperationalEntry for server/runtime
// logs) to dispatch to the appropriate pipeline.
type Entry interface {
	entry()
}

func (*LogEntry) entry() {}

// OperationalEntry represents a non-HTTP Caddy log line: server startup,
// TLS events, admin API activity, upstream errors, config reloads, etc.
// These are the entries Caddy's global/default logger emits alongside (or
// instead of) access logs.
type OperationalEntry struct {
	Timestamp time.Time
	Level     string // info, warn, error, debug
	Logger    string // "tls", "http", "admin", "" (top-level)
	Msg       string // "using provided configuration", "dialing upstream", ...
	Raw       string
	// Extra holds all JSON fields not covered by the typed fields above
	// (upstream, error, config_file, etc.). Values are the raw JSON tokens
	// so callers can decode them lazily.
	Extra map[string]json.RawMessage
}

func (*OperationalEntry) entry() {}

// EffectiveLevel returns the entry's level, defaulting to "info" when
// the level field is empty (Caddy omits it for info-level messages).
func (e *OperationalEntry) EffectiveLevel() string {
	if e.Level == "" {
		return "info"
	}
	return e.Level
}

// GeoInfo holds GeoIP enrichment data for a single IP. Populated by the
// GeoIP enricher from a DB-IP / MaxMind mmdb file. Zero-value means the
// IP was not enriched (private/loopback, db missing, or lookup miss).
type GeoInfo struct {
	CountryCode string // ISO 3166-1 alpha-2, e.g. "US", "DE"
	CountryName string // Human-readable, e.g. "United States"
	ASN         uint   // Autonomous System Number
	ASNOrg      string // ASNOrganization, e.g. "AS15169 Google LLC"
}

// EffectiveClientIP returns the IP to attribute the request to when a
// deployment sits behind a trusted reverse proxy / CDN. When trustForwarded
// is true, the LAST public (non-RFC1918 / non-loopback) address in
// X-Forwarded-For is preferred, falling back to X-Real-IP, then RemoteIP.
//
// The last hop is the one added by the trusted reverse proxy immediately
// upstream of Caddy; the first hop is client-controlled and must NOT be
// trusted, otherwise an attacker can spoof it to evade rate limits or to
// get a third party banned by the guard.
//
// When trustForwarded is false the direct RemoteIP is returned unchanged.
func (e *LogEntry) EffectiveClientIP(trustForwarded bool) string {
	if !trustForwarded {
		return e.RemoteIP
	}
	// Iterate from the last hop backwards: the rightmost public address is
	// the one added by the trusted proxy immediately upstream. Earlier hops
	// are client-controlled and would allow spoofing.
	for i := len(e.ForwardedFor) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(e.ForwardedFor[i])
		if hop == "" {
			continue
		}
		if isPublicIP(hop) {
			return hop
		}
	}
	if e.RealIP != "" && isPublicIP(e.RealIP) {
		return e.RealIP
	}
	return e.RemoteIP
}

func isPublicIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	return true
}

type SourceType string

const (
	SourceFile       SourceType = "file"
	SourceStdin      SourceType = "stdin"
	SourceDocker     SourceType = "docker"
	SourceK8s        SourceType = "k8s"
	SourceJournalctl SourceType = "journalctl"
)

type LogSource struct {
	Type      SourceType
	Path      string
	Namespace string
}

type Filters struct {
	From       time.Time
	To         time.Time
	HasFrom    bool
	HasTo      bool
	Status     []int
	Method     string
	PathGlob   string
	Host       string
	MinLatency float64
	MaxLatency float64
	MinSize    int64
	MaxSize    int64
	RemoteIP   string
	ExcludeIP  string
	// Country/ASN allow-deny lists, populated from --country,
	// --exclude-country, --asn and --exclude-asn. Country codes are
	// normalized to uppercase at flag parse time; ASNs must be positive.
	// They read the Geo-enriched entry, so callers must enrich before
	// matching (see cmd.geoFiltersActive). Unresolved entries (private IP
	// or mmdb miss: empty country code, ASN 0) fail allowlists and pass
	// denylists.
	Country        []string
	ExcludeCountry []string
	ASN            []int
	ExcludeASN     []int
	Only2xx        bool
	Only3xx        bool
	Only4xx        bool
	Only5xx        bool
	ErrorsOnly     bool
	NoBots         bool
	BotsOnly       bool
	GrepPattern    string
	Compact        bool
	TrustForwarded bool
	// Level filters operational entries by level (info, warn, error,
	// debug). Empty slice = accept all levels.
	Level []string
	// OpsOnly, when true, suppresses HTTP entries entirely so only
	// operational events are processed/displayed.
	OpsOnly bool
}

type TopField string

const (
	TopPath       TopField = "path"
	TopMethod     TopField = "method"
	TopStatus     TopField = "status"
	TopHost       TopField = "host"
	TopRemoteAddr TopField = "remote_addr"
	TopUserAgent  TopField = "user_agent"
	TopRemoteIP   TopField = "remote_ip"
	TopCountry    TopField = "country"
	TopASN        TopField = "asn"
)

type Stats struct {
	TotalRequests    int64
	StatusCounts     map[int]int64
	MethodCounts     map[string]int64
	PathCounts       map[string]int64
	HostCounts       map[string]int64
	RemoteAddrCounts map[string]int64
	RemoteIPCounts   map[string]int64
	UserAgentCounts  map[string]int64
	ProtoCounts      map[string]int64
	TLSVersionCounts map[string]int64
	BotCounts        map[string]int64
	RefererCounts    map[string]int64
	PathBytesMap     map[string]int64
	IPBytesMap       map[string]int64
	// CountryCounts and ASNCounts are populated by the GeoIP enricher
	// when a mmdb file is available. Keys are ISO country codes (e.g.
	// "US") and ASN strings (e.g. "AS15169") respectively.
	CountryCounts map[string]int64
	ASNCounts     map[string]int64
	// CountryNames maps ISO country codes (e.g. "IT") to human-readable
	// names (e.g. "Italy") for display. Populated by the GeoIP enricher
	// alongside CountryCounts.
	CountryNames map[string]string
	// PathErrorCounts tracks 5xx responses per path. Used by the diff
	// engine to surface NEW error paths (paths that errored in target but
	// were absent or healthy in baseline) rather than any new path.
	PathErrorCounts map[string]int64
	HumanRequests   int64
	BotRequests     int64
	TotalBytes      int64
	DurationSum     float64
	MaxDuration     float64
	MinDuration     float64
	Percentile50    float64
	Percentile95    float64
	Percentile99    float64
	StartTime       time.Time
	EndTime         time.Time
	Errors          int64
	ParseErrors     int64
	Status2xx       int64
	Status3xx       int64
	Status4xx       int64
	Status5xx       int64

	// MaxCardinality bounds the number of distinct keys tracked in the
	// string-keyed counters (PathCounts, HostCounts, RemoteIPCounts,
	// UserAgentCounts, ...). 0 = unlimited. When the cap is reached, new
	// keys are dropped (existing keys keep accumulating) so memory is
	// bounded on huge-cardinality logs.
	MaxCardinality int

	SuspiciousIPs        map[string]int64
	SuspiciousDetails    map[string][]string
	SuspiciousDetections map[string][]DetectionRecord

	durHist durationHistogram
}

// DetectionRecord is the JSON-serializable form of a single detection.
type DetectionRecord struct {
	Type       string `json:"type"`
	Desc       string `json:"description"`
	Confidence int    `json:"confidence"`
	Method     string `json:"method"`
	URI        string `json:"uri"`
	Status     int    `json:"status"`
}

type CountItem struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

type CountIntItem struct {
	Key   int   `json:"key"`
	Count int64 `json:"count"`
}

type TopSections struct {
	Path    bool
	IP      bool
	UA      bool
	Method  bool
	Status  bool
	Host    bool
	Country bool
	ASN     bool
}

func DefaultTopSections() TopSections {
	return TopSections{Path: true, IP: true, UA: true, Method: true, Status: true, Host: true, Country: true, ASN: true}
}

func (e *LogEntry) Path() string {
	if idx := strings.Index(e.URI, "?"); idx >= 0 {
		return e.URI[:idx]
	}
	return e.URI
}

func NewStats() *Stats {
	return &Stats{
		StatusCounts:         make(map[int]int64),
		MethodCounts:         make(map[string]int64),
		PathCounts:           make(map[string]int64),
		HostCounts:           make(map[string]int64),
		RemoteAddrCounts:     make(map[string]int64),
		RemoteIPCounts:       make(map[string]int64),
		UserAgentCounts:      make(map[string]int64),
		ProtoCounts:          make(map[string]int64),
		TLSVersionCounts:     make(map[string]int64),
		BotCounts:            make(map[string]int64),
		RefererCounts:        make(map[string]int64),
		PathBytesMap:         make(map[string]int64),
		IPBytesMap:           make(map[string]int64),
		PathErrorCounts:      make(map[string]int64),
		SuspiciousIPs:        make(map[string]int64),
		SuspiciousDetails:    make(map[string][]string),
		SuspiciousDetections: make(map[string][]DetectionRecord),
		CountryCounts:        make(map[string]int64),
		ASNCounts:            make(map[string]int64),
		CountryNames:         make(map[string]string),
		MinDuration:          1<<63 - 1,
	}
}

// IncStrCount increments a string-keyed counter, respecting MaxCardinality.
// New keys are dropped once the cap is reached; existing keys always increment.
func (s *Stats) IncStrCount(m map[string]int64, key string) {
	if _, ok := m[key]; ok {
		m[key]++
		return
	}
	if s.MaxCardinality > 0 && len(m) >= s.MaxCardinality {
		return
	}
	m[key] = 1
}

// AddStrBytes adds bytes to a string-keyed byte counter, respecting
// MaxCardinality. New keys are dropped once the cap is reached; existing
// keys always accumulate.
func (s *Stats) AddStrBytes(m map[string]int64, key string, n int64) {
	if _, ok := m[key]; ok {
		m[key] += n
		return
	}
	if s.MaxCardinality > 0 && len(m) >= s.MaxCardinality {
		return
	}
	m[key] = n
}

func (s *Stats) AddDuration(d float64) {
	s.durHist.add(d)
}

func (s *Stats) ComputePercentiles() {
	s.Percentile50 = s.durHist.percentile(50)
	s.Percentile95 = s.durHist.percentile(95)
	s.Percentile99 = s.durHist.percentile(99)
}

// OperationalStats holds aggregate counters for non-HTTP Caddy log entries.
// Populated by the OperationalEngine and read by the output formatters when
// operational events are present.
type OperationalStats struct {
	TotalEvents  int64
	LevelCounts  map[string]int64 // info, warn, error, debug
	LoggerCounts map[string]int64 // "tls", "http", "admin", ""
	MsgCounts    map[string]int64
	StartTime    time.Time
	EndTime      time.Time
	Errors       int64 // count of level == "error"
	ParseErrors  int64
}

func NewOperationalStats() *OperationalStats {
	return &OperationalStats{
		LevelCounts:  make(map[string]int64),
		LoggerCounts: make(map[string]int64),
		MsgCounts:    make(map[string]int64),
	}
}
