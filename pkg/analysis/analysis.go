package analysis

import (
	"container/list"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

const compiledPatternCacheCap = 1024

type lruCache[V any] struct {
	mu    sync.Mutex
	cap   int
	items map[string]*list.Element
	order *list.List
}

type lruCacheEntry[V any] struct {
	key   string
	value V
}

func newLRUCache[V any](cap int) *lruCache[V] {
	return &lruCache[V]{cap: cap, items: make(map[string]*list.Element), order: list.New()}
}

func (c *lruCache[V]) getOrCreate(key string, create func() V) V {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[key]; ok {
		c.order.MoveToBack(elem)
		return elem.Value.(lruCacheEntry[V]).value
	}
	value := create()
	elem := c.order.PushBack(lruCacheEntry[V]{key: key, value: value})
	c.items[key] = elem
	if c.cap > 0 && c.order.Len() > c.cap {
		oldest := c.order.Front()
		delete(c.items, oldest.Value.(lruCacheEntry[V]).key)
		c.order.Remove(oldest)
	}
	return value
}

// grepCache caches compiled grep patterns across entries so a multi-million-line
// log does not recompile the same regex per row. Patterns that are not valid
// regex fall back to case-insensitive substring matching.
var grepCache = newLRUCache[grepMatcher](compiledPatternCacheCap)

type grepMatcher struct {
	re  *regexp.Regexp
	lit string
}

func grepCompile(pattern string) grepMatcher {
	return grepCache.getOrCreate(pattern, func() grepMatcher {
		var gm grepMatcher
		if re, err := regexp.Compile("(?i)" + pattern); err == nil {
			gm.re = re
		} else {
			gm.lit = strings.ToLower(pattern)
		}
		return gm
	})
}

func (gm grepMatcher) match(target string) bool {
	if gm.re != nil {
		return gm.re.MatchString(target)
	}
	return strings.Contains(strings.ToLower(target), gm.lit)
}

type Engine struct {
	filters  types.Filters
	entries  int
	stats    *types.Stats
	detector *Detector
}

func New(filters types.Filters) *Engine {
	return &Engine{
		filters: filters,
		stats:   types.NewStats(),
	}
}

// NewFromStats creates an engine backed by an already finalized snapshot.
// It is used by baseline comparisons; the snapshot is never mutated by the
// comparison itself.
func NewFromStats(filters types.Filters, stats *types.Stats) *Engine {
	if stats == nil {
		stats = types.NewStats()
	}
	return &Engine{filters: filters, entries: int(stats.TotalRequests), stats: stats}
}

func (e *Engine) SetDetector(d *Detector) {
	e.detector = d
}

func (e *Engine) Process(entry *types.LogEntry) {
	if !e.match(entry) {
		return
	}

	if e.detector != nil {
		if dets := e.detector.DetectAll(entry); len(dets) > 0 {
			e.stats.SuspiciousIPs[entry.RemoteIP]++
			for _, det := range dets {
				detail := fmt.Sprintf("[%s] %s %s → %s", det.Type, det.Desc, entry.Method, entry.Path())
				if len(e.stats.SuspiciousDetails[entry.RemoteIP]) < 10 {
					e.stats.SuspiciousDetails[entry.RemoteIP] = append(e.stats.SuspiciousDetails[entry.RemoteIP], detail)
				}
				if len(e.stats.SuspiciousDetections[entry.RemoteIP]) < 50 {
					e.stats.SuspiciousDetections[entry.RemoteIP] = append(e.stats.SuspiciousDetections[entry.RemoteIP], types.DetectionRecord{
						Type:       string(det.Type),
						Desc:       det.Desc,
						Confidence: det.Confidence,
						Method:     entry.Method,
						URI:        entry.URI,
						Status:     entry.Status,
					})
				}
			}
		}
	}

	e.entries++
	s := e.stats
	s.TotalRequests++

	if !entry.Timestamp.IsZero() {
		if s.StartTime.IsZero() || entry.Timestamp.Before(s.StartTime) {
			s.StartTime = entry.Timestamp
		}
		if entry.Timestamp.After(s.EndTime) {
			s.EndTime = entry.Timestamp
		}
	}

	s.StatusCounts[entry.Status]++
	s.IncStrCount(s.MethodCounts, entry.Method)
	s.IncStrCount(s.PathCounts, entry.Path())
	s.IncStrCount(s.HostCounts, entry.Host)
	s.IncStrCount(s.RemoteAddrCounts, entry.RemoteAddr)
	s.IncStrCount(s.UserAgentCounts, entry.UserAgent)
	s.TotalBytes += entry.Size
	s.AddStrBytes(s.PathBytesMap, entry.Path(), entry.Size)

	if entry.Proto != "" {
		s.ProtoCounts[entry.Proto]++
	}
	if entry.TLSVersion != "" {
		s.TLSVersionCounts[entry.TLSVersion]++
	} else {
		s.TLSVersionCounts["Plain HTTP"]++
	}

	if entry.IsBot {
		s.BotRequests++
		botName := entry.BotName
		if botName == "" {
			botName = "Unknown Bot"
		}
		s.IncStrCount(s.BotCounts, botName)
	} else {
		s.HumanRequests++
	}

	if entry.RefererDomain != "" {
		s.IncStrCount(s.RefererCounts, entry.RefererDomain)
	}

	if entry.RemoteIP != "" {
		s.IncStrCount(s.RemoteIPCounts, entry.RemoteIP)
		s.AddStrBytes(s.IPBytesMap, entry.RemoteIP, entry.Size)
	}

	if entry.Geo.CountryCode != "" {
		s.IncStrCount(s.CountryCounts, entry.Geo.CountryCode)
		if entry.Geo.CountryName != "" {
			s.CountryNames[entry.Geo.CountryCode] = entry.Geo.CountryName
		}
	}
	if entry.Geo.City != "" {
		s.IncStrCount(s.CityCounts, entry.Geo.City)
		s.CityLocations[entry.Geo.City] = types.GeoLocation{Latitude: entry.Geo.Latitude, Longitude: entry.Geo.Longitude, Timezone: entry.Geo.Timezone}
	}
	if entry.Geo.ASN > 0 {
		s.IncStrCount(s.ASNCounts, fmt.Sprintf("AS%d", entry.Geo.ASN))
	}

	if entry.Status >= 500 {
		s.Errors++
		s.IncStrCount(s.PathErrorCounts, entry.Path())
	}
	switch {
	case entry.Status >= 200 && entry.Status < 300:
		s.Status2xx++
	case entry.Status >= 300 && entry.Status < 400:
		s.Status3xx++
	case entry.Status >= 400 && entry.Status < 500:
		s.Status4xx++
	case entry.Status >= 500:
		s.Status5xx++
	}

	s.DurationSum += entry.Duration
	if entry.Duration > 0 {
		if entry.Duration > s.MaxDuration {
			s.MaxDuration = entry.Duration
		}
		if entry.Duration < s.MinDuration {
			s.MinDuration = entry.Duration
		}
	}
	s.AddDuration(entry.Duration)
}

func (e *Engine) Finalize() {
	e.stats.ComputePercentiles()
}

func (e *Engine) Stats() *types.Stats {
	return e.stats
}

func (e *Engine) Count() int {
	return e.entries
}

func (e *Engine) AvgDuration() float64 {
	if e.entries == 0 {
		return 0
	}
	return e.stats.DurationSum / float64(e.entries)
}

func (e *Engine) RPS() float64 {
	if e.stats.EndTime.IsZero() || e.stats.StartTime.IsZero() {
		return 0
	}
	elapsed := e.stats.EndTime.Sub(e.stats.StartTime).Seconds()
	if elapsed == 0 {
		return 0
	}
	return float64(e.entries) / elapsed
}

func TopN(m map[string]int64, n int) []types.CountItem {
	var items []types.CountItem
	for k, v := range m {
		if k == "" {
			continue
		}
		items = append(items, types.CountItem{Key: k, Count: v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Key < items[j].Key
	})
	if n > 0 && len(items) > n {
		items = items[:n]
	}
	return items
}

func TopNInt(m map[int]int64, n int) []types.CountIntItem {
	var items []types.CountIntItem
	for k, v := range m {
		items = append(items, types.CountIntItem{Key: k, Count: v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Key < items[j].Key
	})
	if n > 0 && len(items) > n {
		items = items[:n]
	}
	return items
}

func (e *Engine) match(entry *types.LogEntry) bool {
	return MatchEntry(entry, e.filters)
}

type DiffResult struct {
	BaseRequests    int64    `json:"base_requests"`
	CurrRequests    int64    `json:"curr_requests"`
	RequestsDelta   int64    `json:"requests_delta"`
	RequestsPct     float64  `json:"requests_pct"`
	BaseRPS         float64  `json:"base_rps"`
	CurrRPS         float64  `json:"curr_rps"`
	RPSDelta        float64  `json:"rps_delta"`
	BaseErrors      int64    `json:"base_errors"`
	CurrErrors      int64    `json:"curr_errors"`
	ErrorsDelta     int64    `json:"errors_delta"`
	BaseAvgDuration float64  `json:"base_avg_duration"`
	CurrAvgDuration float64  `json:"curr_avg_duration"`
	AvgDurDelta     float64  `json:"avg_dur_delta"`
	NewErrorPaths   []string `json:"new_error_paths"`
}

func CompareStats(baseEngine, currEngine *Engine) DiffResult {
	b := baseEngine.Stats()
	c := currEngine.Stats()

	bReq := b.TotalRequests
	cReq := c.TotalRequests
	reqDelta := cReq - bReq
	reqPct := float64(0)
	if bReq > 0 {
		reqPct = float64(reqDelta) / float64(bReq) * 100
	}

	bRPS := baseEngine.RPS()
	cRPS := currEngine.RPS()
	bAvgDur := baseEngine.AvgDuration()
	cAvgDur := currEngine.AvgDuration()

	// New error paths: paths that produced 5xx errors in the target but
	// did NOT produce 5xx in the baseline. Previously this surfaced any
	// new path regardless of status, which was misleading.
	var newErrPaths []string
	for path, errCount := range c.PathErrorCounts {
		if errCount <= 0 {
			continue
		}
		if baseErr, ok := b.PathErrorCounts[path]; !ok || baseErr == 0 {
			newErrPaths = append(newErrPaths, path)
		}
	}
	sort.Strings(newErrPaths)
	if len(newErrPaths) > 10 {
		newErrPaths = newErrPaths[:10]
	}

	return DiffResult{
		BaseRequests:    bReq,
		CurrRequests:    cReq,
		RequestsDelta:   reqDelta,
		RequestsPct:     reqPct,
		BaseRPS:         bRPS,
		CurrRPS:         cRPS,
		RPSDelta:        cRPS - bRPS,
		BaseErrors:      b.Errors,
		CurrErrors:      c.Errors,
		ErrorsDelta:     c.Errors - b.Errors,
		BaseAvgDuration: bAvgDur,
		CurrAvgDuration: cAvgDur,
		AvgDurDelta:     cAvgDur - bAvgDur,
		NewErrorPaths:   newErrPaths,
	}
}

func MatchEntry(entry *types.LogEntry, filters types.Filters) bool {
	if filters.HasFrom && entry.Timestamp.Before(filters.From) {
		return false
	}
	if filters.HasTo && entry.Timestamp.After(filters.To) {
		return false
	}
	if len(filters.Status) > 0 {
		found := false
		for _, s := range filters.Status {
			if entry.Status == s {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if filters.Method != "" && !strings.EqualFold(entry.Method, filters.Method) {
		return false
	}
	if filters.PathGlob != "" && !matchGlob(filters.PathGlob, entry.Path()) {
		return false
	}
	if filters.Host != "" && !strings.Contains(strings.ToLower(entry.Host), strings.ToLower(filters.Host)) {
		return false
	}
	if filters.MinLatency > 0 && entry.Duration < filters.MinLatency {
		return false
	}
	if filters.MaxLatency > 0 && entry.Duration > filters.MaxLatency {
		return false
	}
	if filters.MinSize > 0 && entry.Size < filters.MinSize {
		return false
	}
	if filters.MaxSize > 0 && entry.Size > filters.MaxSize {
		return false
	}
	if filters.Only2xx && (entry.Status < 200 || entry.Status >= 300) {
		return false
	}
	if filters.Only3xx && (entry.Status < 300 || entry.Status >= 400) {
		return false
	}
	if filters.Only4xx && (entry.Status < 400 || entry.Status >= 500) {
		return false
	}
	if filters.Only5xx && entry.Status < 500 {
		return false
	}
	if filters.ErrorsOnly && entry.Status < 500 {
		return false
	}
	if filters.NoBots && entry.IsBot {
		return false
	}
	if filters.BotsOnly && !entry.IsBot {
		return false
	}
	if filters.RemoteIP != "" && !ipMatch(filters.RemoteIP, entry.RemoteIP) {
		return false
	}
	if filters.ExcludeIP != "" && ipMatch(filters.ExcludeIP, entry.RemoteIP) {
		return false
	}
	// Geo-based filters read the enriched entry (see types.Filters).
	if len(filters.Country) > 0 && !containsString(filters.Country, entry.Geo.CountryCode) {
		return false
	}
	if len(filters.ExcludeCountry) > 0 && containsString(filters.ExcludeCountry, entry.Geo.CountryCode) {
		return false
	}
	if len(filters.ASN) > 0 && !containsInt(filters.ASN, int(entry.Geo.ASN)) {
		return false
	}
	if len(filters.ExcludeASN) > 0 && containsInt(filters.ExcludeASN, int(entry.Geo.ASN)) {
		return false
	}
	if filters.GrepPattern != "" {
		target := entry.URI + " " + entry.UserAgent + " " + entry.RemoteIP + " " + entry.Host
		if !grepCompile(filters.GrepPattern).match(target) {
			return false
		}
	}
	return true
}

func ipMatch(pattern, ip string) bool {
	if pattern == "" || ip == "" {
		return pattern == ip
	}
	if strings.Contains(pattern, "/") {
		prefix, err := netip.ParsePrefix(pattern)
		if err != nil {
			return false
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return false
		}
		return prefix.Contains(addr)
	}
	return pattern == ip
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func containsInt(list []int, v int) bool {
	for _, n := range list {
		if n == v {
			return true
		}
	}
	return false
}

// globCache caches compiled glob patterns so a multi-million-line log does
// not recompile the same glob per row.
var globCache = newLRUCache[*regexp.Regexp](compiledPatternCacheCap)

func matchGlob(pattern, s string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	re := globCache.getOrCreate(pattern, func() *regexp.Regexp { return compileGlob(pattern) })
	if re != nil {
		return re.MatchString(s)
	}
	return s == pattern
}

// compileGlob converts a glob pattern into a case-insensitive anchored regex.
// `*` matches any sequence (including `/`), `?` matches any single char.
// Returns nil if the pattern cannot be compiled as a regex (caller falls back
// to exact match).
func compileGlob(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?i)^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}
