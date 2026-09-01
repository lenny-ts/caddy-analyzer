package analysis

import (
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestEngineAggregatesCityWithoutSchemaKnowledge(t *testing.T) {
	engine := New(types.Filters{})
	engine.Process(&types.LogEntry{Geo: types.GeoInfo{City: "Rome", Latitude: 41.9, Longitude: 12.5, Timezone: "Europe/Rome"}})
	engine.Process(&types.LogEntry{Geo: types.GeoInfo{City: "Rome", Latitude: 41.9, Longitude: 12.5, Timezone: "Europe/Rome"}})
	engine.Process(&types.LogEntry{Geo: types.GeoInfo{City: "Berlin", Latitude: 52.5, Longitude: 13.4}})

	stats := engine.Stats()
	if stats.CityCounts["Rome"] != 2 || stats.CityCounts["Berlin"] != 1 {
		t.Fatalf("city counts = %#v", stats.CityCounts)
	}
	if got := TopN(stats.CityCounts, 1); len(got) != 1 || got[0].Key != "Rome" {
		t.Fatalf("top city = %#v", got)
	}
	if got := stats.CityLocations["Rome"]; got.Latitude != 41.9 || got.Timezone != "Europe/Rome" {
		t.Fatalf("Rome location = %#v", got)
	}
}

func TestLRUCacheEvictsLeastRecentlyUsed(t *testing.T) {
	c := newLRUCache[string](2)
	created := 0
	makeValue := func(value string) func() string {
		return func() string { created++; return value }
	}
	c.getOrCreate("a", makeValue("a"))
	c.getOrCreate("b", makeValue("b"))
	c.getOrCreate("a", makeValue("unexpected"))
	c.getOrCreate("c", makeValue("c"))
	if got := c.getOrCreate("a", makeValue("unexpected")); got != "a" {
		t.Fatalf("recent entry was evicted: %q", got)
	}
	if got := c.getOrCreate("b", makeValue("b2")); got != "b2" {
		t.Fatalf("least recent entry was retained: %q", got)
	}
	if created != 4 {
		t.Fatalf("create calls = %d, want 4", created)
	}
}

func TestEngineProcessing(t *testing.T) {
	engine := New(types.Filters{})

	now := time.Now()
	entries := []*types.LogEntry{
		{
			Timestamp:  now,
			Method:     "GET",
			URI:        "/index.html",
			Host:       "example.com",
			RemoteIP:   "1.1.1.1",
			Status:     200,
			Size:       1000,
			Duration:   0.005,
			Proto:      "HTTP/2.0",
			TLSVersion: "TLS 1.3",
		},
		{
			Timestamp:  now.Add(time.Second),
			Method:     "POST",
			URI:        "/api/data",
			Host:       "example.com",
			RemoteIP:   "1.1.1.1",
			Status:     500,
			Size:       500,
			Duration:   0.010,
			Proto:      "HTTP/2.0",
			TLSVersion: "TLS 1.3",
		},
		{
			Timestamp: now.Add(2 * time.Second),
			Method:    "GET",
			URI:       "/index.html",
			Host:      "example.com",
			RemoteIP:  "2.2.2.2",
			Status:    200,
			Size:      1000,
			Duration:  0.002,
			Proto:     "HTTP/1.1",
			IsBot:     true,
			BotName:   "Googlebot",
		},
	}

	for _, e := range entries {
		engine.Process(e)
	}
	engine.Finalize()

	stats := engine.Stats()
	if stats.TotalRequests != 3 {
		t.Errorf("expected 3 requests, got %d", stats.TotalRequests)
	}
	if stats.Status2xx != 2 {
		t.Errorf("expected 2 status 2xx, got %d", stats.Status2xx)
	}
	if stats.Status5xx != 1 {
		t.Errorf("expected 1 status 5xx, got %d", stats.Status5xx)
	}
	if stats.TotalBytes != 2500 {
		t.Errorf("expected 2500 bytes, got %d", stats.TotalBytes)
	}
	if stats.HumanRequests != 2 {
		t.Errorf("expected 2 human requests, got %d", stats.HumanRequests)
	}
	if stats.BotRequests != 1 {
		t.Errorf("expected 1 bot request, got %d", stats.BotRequests)
	}

	topPaths := TopN(stats.PathCounts, 10)
	if len(topPaths) == 0 || topPaths[0].Key != "/index.html" || topPaths[0].Count != 2 {
		t.Errorf("unexpected top path: %v", topPaths)
	}
}

func TestEngineFilterStatus(t *testing.T) {
	filters := types.Filters{
		Status: []int{500},
	}
	engine := New(filters)

	now := time.Now()
	engine.Process(&types.LogEntry{Timestamp: now, Status: 200, Method: "GET", URI: "/"})
	engine.Process(&types.LogEntry{Timestamp: now, Status: 500, Method: "GET", URI: "/"})

	if engine.Count() != 1 {
		t.Errorf("expected 1 entry matching filter, got %d", engine.Count())
	}
}

func TestMatchEntryGrepRegex(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		uri     string
		want    bool
	}{
		{"literal substring", "/api/v1", "/api/v1/users", true},
		{"regex alternation", "/api/(v[23]|beta)", "/api/v2/users", true},
		{"regex no match", "/api/(v[23]|beta)", "/api/v1/users", false},
		{"invalid regex falls back to substring", "[invalid(", "[invalid(", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &types.LogEntry{URI: tt.uri, Method: "GET"}
			got := MatchEntry(entry, types.Filters{GrepPattern: tt.pattern})
			if got != tt.want {
				t.Errorf("MatchEntry grep %q on %q = %v, want %v", tt.pattern, tt.uri, got, tt.want)
			}
		})
	}
}

func TestAvgDuration(t *testing.T) {
	e := New(types.Filters{})
	if got := e.AvgDuration(); got != 0 {
		t.Errorf("empty engine AvgDuration = %v, want 0", got)
	}
	e.entries = 2
	e.stats.DurationSum = 10.0
	if got := e.AvgDuration(); got != 5.0 {
		t.Errorf("AvgDuration = %v, want 5.0", got)
	}
}

func TestRPS(t *testing.T) {
	e := New(types.Filters{})
	if got := e.RPS(); got != 0 {
		t.Errorf("empty engine RPS = %v, want 0", got)
	}
	e.entries = 10
	e.stats.StartTime = time.Now().Add(-2 * time.Second)
	e.stats.EndTime = time.Now()
	if rps := e.RPS(); rps <= 0 {
		t.Errorf("RPS = %v, want > 0", rps)
	}
	// zero elapsed → 0
	e.stats.StartTime = e.stats.EndTime
	if got := e.RPS(); got != 0 {
		t.Errorf("zero-elapsed RPS = %v, want 0", got)
	}
}

func TestTopNInt(t *testing.T) {
	m := map[int]int64{1: 30, 2: 10, 3: 20}
	items := TopNInt(m, 2)
	if len(items) != 2 || items[0].Key != 1 || items[0].Count != 30 {
		t.Errorf("TopNInt = %v", items)
	}
	// n=0 → all
	all := TopNInt(m, 0)
	if len(all) != 3 {
		t.Errorf("TopNInt(0) = %d items, want 3", len(all))
	}
}

func TestCompareStats(t *testing.T) {
	base := New(types.Filters{})
	base.entries = 100
	base.stats.TotalRequests = 100
	base.stats.StartTime = time.Now().Add(-10 * time.Second)
	base.stats.EndTime = time.Now()
	base.stats.Errors = 5
	base.stats.DurationSum = 50.0
	base.stats.PathErrorCounts = map[string]int64{"/old": 1}

	curr := New(types.Filters{})
	curr.entries = 150
	curr.stats.TotalRequests = 150
	curr.stats.StartTime = time.Now().Add(-10 * time.Second)
	curr.stats.EndTime = time.Now()
	curr.stats.Errors = 8
	curr.stats.DurationSum = 90.0
	curr.stats.PathErrorCounts = map[string]int64{"/old": 1, "/new": 3}

	diff := CompareStats(base, curr)
	if diff.BaseRequests != 100 || diff.CurrRequests != 150 {
		t.Errorf("requests base=%d curr=%d", diff.BaseRequests, diff.CurrRequests)
	}
	if diff.RequestsDelta != 50 {
		t.Errorf("delta = %d, want 50", diff.RequestsDelta)
	}
	if diff.ErrorsDelta != 3 {
		t.Errorf("errors delta = %d, want 3", diff.ErrorsDelta)
	}
	if len(diff.NewErrorPaths) != 1 || diff.NewErrorPaths[0] != "/new" {
		t.Errorf("new error paths = %v, want [/new]", diff.NewErrorPaths)
	}

	// zero base → 0 pct
	emptyBase := New(types.Filters{})
	diff0 := CompareStats(emptyBase, curr)
	if diff0.RequestsPct != 0 {
		t.Errorf("pct with zero base = %v, want 0", diff0.RequestsPct)
	}
}

func TestIPMatch(t *testing.T) {
	tests := []struct {
		pattern, ip string
		want        bool
	}{
		{"", "", true},
		{"", "1.1.1.1", false},
		{"1.1.1.1", "1.1.1.1", true},
		{"1.1.1.1", "2.2.2.2", false},
		{"10.0.0.0/8", "10.1.2.3", true},
		{"10.0.0.0/8", "11.1.2.3", false},
		{"invalid/", "1.1.1.1", false},
		{"10.0.0.0/8", "notanip", false},
	}
	for _, tt := range tests {
		if got := ipMatch(tt.pattern, tt.ip); got != tt.want {
			t.Errorf("ipMatch(%q, %q) = %v, want %v", tt.pattern, tt.ip, got, tt.want)
		}
	}
}

func TestMatchGlob(t *testing.T) {
	if !matchGlob("*", "/anything") {
		t.Error("matchGlob(*) should be true")
	}
	if !matchGlob("", "/anything") {
		t.Error("matchGlob('') should be true")
	}
	if !matchGlob("/api/*", "/api/v1/users") {
		t.Error("glob /api/* should match /api/v1/users")
	}
	if matchGlob("/api/*", "/admin/login") {
		t.Error("glob /api/* should not match /admin/login")
	}
	if !matchGlob("/api/?", "/api/x") {
		t.Error("glob /api/? should match /api/x")
	}
	// exact fallback when pattern has no glob chars and regex fails —
	// exercise the cache path too
	if !matchGlob("/api/v1", "/api/v1") {
		t.Error("exact glob should match")
	}
}

func TestCompileGlob(t *testing.T) {
	re := compileGlob("/api/*")
	if re == nil {
		t.Fatal("expected non-nil regex")
	}
	if !re.MatchString("/api/v1") {
		t.Error("compiled glob should match")
	}
}

func TestSetDetector(t *testing.T) {
	e := New(types.Filters{})
	d := NewDetector()
	e.SetDetector(d)
	if e.detector == nil {
		t.Error("detector not set")
	}
}

func TestUARotationThreshold(t *testing.T) {
	d := NewDetector()
	d.SetUARotationThreshold(5)
	if got := d.UARotationThreshold(); got != 5 {
		t.Errorf("threshold = %d, want 5", got)
	}
	d.SetUARotationThreshold(0)
	if got := d.UARotationThreshold(); got <= 0 {
		t.Errorf("threshold reset = %d, want > 0", got)
	}
}

func TestMatchEntryGeoFilters(t *testing.T) {
	tests := []struct {
		name    string
		filters types.Filters
		geo     types.GeoInfo
		want    bool
	}{
		{
			name:    "country allowlist hit",
			filters: types.Filters{Country: []string{"IT", "US"}},
			geo:     types.GeoInfo{CountryCode: "IT"},
			want:    true,
		},
		{
			name:    "country allowlist miss",
			filters: types.Filters{Country: []string{"IT"}},
			geo:     types.GeoInfo{CountryCode: "DE"},
			want:    false,
		},
		{
			name:    "country allowlist drops unresolved",
			filters: types.Filters{Country: []string{"IT"}},
			geo:     types.GeoInfo{},
			want:    false,
		},
		{
			name:    "country denylist drops match",
			filters: types.Filters{ExcludeCountry: []string{"CN", "RU"}},
			geo:     types.GeoInfo{CountryCode: "RU"},
			want:    false,
		},
		{
			name:    "country denylist keeps other",
			filters: types.Filters{ExcludeCountry: []string{"CN"}},
			geo:     types.GeoInfo{CountryCode: "US"},
			want:    true,
		},
		{
			name:    "country denylist keeps unresolved",
			filters: types.Filters{ExcludeCountry: []string{"CN"}},
			geo:     types.GeoInfo{},
			want:    true,
		},
		{
			name:    "asn allowlist hit",
			filters: types.Filters{ASN: []int{12345, 67890}},
			geo:     types.GeoInfo{ASN: 67890},
			want:    true,
		},
		{
			name:    "asn allowlist drops unresolved (ASN 0)",
			filters: types.Filters{ASN: []int{12345}},
			geo:     types.GeoInfo{},
			want:    false,
		},
		{
			name:    "asn denylist drops match",
			filters: types.Filters{ExcludeASN: []int{15169}},
			geo:     types.GeoInfo{ASN: 15169},
			want:    false,
		},
		{
			name:    "asn denylist keeps unresolved (ASN 0)",
			filters: types.Filters{ExcludeASN: []int{15169}},
			geo:     types.GeoInfo{},
			want:    true,
		},
		{
			name:    "country and asn AND-combined, both hit",
			filters: types.Filters{Country: []string{"US"}, ASN: []int{15169}},
			geo:     types.GeoInfo{CountryCode: "US", ASN: 15169},
			want:    true,
		},
		{
			name:    "country and asn AND-combined, asn misses",
			filters: types.Filters{Country: []string{"US"}, ExcludeASN: []int{15169}},
			geo:     types.GeoInfo{CountryCode: "US", ASN: 15169},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &types.LogEntry{Status: 200}
			entry.Geo = tt.geo
			if got := MatchEntry(entry, tt.filters); got != tt.want {
				t.Errorf("MatchEntry geo = %v, want %v", got, tt.want)
			}
		})
	}
}
