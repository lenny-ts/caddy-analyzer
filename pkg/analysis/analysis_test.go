package analysis

import (
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

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
