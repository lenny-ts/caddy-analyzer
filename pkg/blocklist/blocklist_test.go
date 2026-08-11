package blocklist

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExtractEntry(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"1.2.3.0/24", "1.2.3.0/24"},
		{"1.2.3.0/24 ; SBL123456", "1.2.3.0/24"},
		{"1.2.3.0/24;SBL123456", "1.2.3.0/24"},
		{"1.2.3.4", "1.2.3.4/32"},
		{"::1", "::1/128"},
		{"  1.2.3.4  ", "1.2.3.4/32"},
		{"# comment", ""},
		{"", ""},
		{"  # indented comment", ""},
		{"2001:db8::/32", "2001:db8::/32"},
		{"2001:db8::1 # inline", "2001:db8::1/128"},
		{"foo bar", ""},
		{"1.2.3.4 # comment with # hash", "1.2.3.4/32"},
	}
	for _, tt := range tests {
		got := extractEntry(tt.line)
		if got != tt.want {
			t.Errorf("extractEntry(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestParseEntries(t *testing.T) {
	body := []byte(`# header comment
1.2.3.0/24 ; SBL123456
5.6.7.8
# another comment

2001:db8::/32
9.10.11.12/32
invalid line
`)
	entries := parseEntries(body)
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d: %v", len(entries), entries)
	}
	want := []string{"1.2.3.0/24", "5.6.7.8/32", "2001:db8::/32", "9.10.11.12/32"}
	for i, e := range entries {
		if e.String() != want[i] {
			t.Errorf("entry %d = %s, want %s", i, e.String(), want[i])
		}
	}
}

func TestParseEntriesEmpty(t *testing.T) {
	entries := parseEntries([]byte(""))
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseEntriesTorFormat(t *testing.T) {
	body := []byte("1.1.1.1\n2.2.2.2\n3.3.3.3\n")
	entries := parseEntries(body)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	for _, e := range entries {
		ones, bits := e.Mask.Size()
		if ones != 32 || bits != 32 {
			t.Errorf("expected /32 for bare IPv4, got %s", e.String())
		}
	}
}

func TestManagerRefreshAndContains(t *testing.T) {
	tmp := t.TempDir()
	src := []Source{
		{Name: "test", URL: "http://example.com/list.txt"},
	}
	m, err := NewManager(src, tmp)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.SetFetcher(func(url string) ([]byte, error) {
		return []byte("10.0.0.0/8\n192.168.1.1\n2001:db8::/32\n"), nil
	})
	statuses := m.Refresh()
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].Entries != 3 {
		t.Fatalf("expected 3 entries, got %d", statuses[0].Entries)
	}
	if statuses[0].Error != "" {
		t.Fatalf("unexpected error: %s", statuses[0].Error)
	}

	tests := []struct {
		ip      string
		wantHit bool
	}{
		{"10.1.2.3", true},
		{"192.168.1.1", true},
		{"2001:db8::1", true},
		{"8.8.8.8", false},
		{"172.16.0.1", false},
	}
	for _, tt := range tests {
		hit, _ := m.Contains(tt.ip)
		if hit != tt.wantHit {
			t.Errorf("Contains(%s) = %v, want %v", tt.ip, hit, tt.wantHit)
		}
	}
}

func TestManagerContainsReturnsSource(t *testing.T) {
	tmp := t.TempDir()
	src := []Source{
		{Name: "src-a", URL: "http://a"},
		{Name: "src-b", URL: "http://b"},
	}
	m, err := NewManager(src, tmp)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.SetFetcher(func(url string) ([]byte, error) {
		if url == "http://a" {
			return []byte("10.0.0.0/8\n"), nil
		}
		return []byte("172.16.0.0/12\n"), nil
	})
	m.Refresh()

	hit, source := m.Contains("10.1.1.1")
	if !hit || source != "src-a" {
		t.Errorf("expected hit from src-a, got %v %s", hit, source)
	}
	hit, source = m.Contains("172.16.1.1")
	if !hit || source != "src-b" {
		t.Errorf("expected hit from src-b, got %v %s", hit, source)
	}
	hit, _ = m.Contains("8.8.8.8")
	if hit {
		t.Error("expected no hit for 8.8.8.8")
	}
}

func TestManagerLoadFromCache(t *testing.T) {
	tmp := t.TempDir()
	src := []Source{{Name: "cached", URL: "http://example.com"}}
	m1, err := NewManager(src, tmp)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m1.SetFetcher(func(url string) ([]byte, error) {
		return []byte("10.0.0.0/8\n192.168.1.0/24\n"), nil
	})
	m1.Refresh()

	m2, err := NewManager(src, tmp)
	if err != nil {
		t.Fatalf("NewManager m2: %v", err)
	}
	m2.SetFetcher(func(url string) ([]byte, error) {
		t.Fatal("should not fetch on LoadAll")
		return nil, nil
	})
	m2.LoadAll()

	hit, _ := m2.Contains("10.1.1.1")
	if !hit {
		t.Error("expected cached hit for 10.1.1.1")
	}
	hit, _ = m2.Contains("192.168.1.50")
	if !hit {
		t.Error("expected cached hit for 192.168.1.50")
	}
}

func TestManagerLoadFromCacheMissing(t *testing.T) {
	tmp := t.TempDir()
	src := []Source{{Name: "noexist", URL: "http://example.com"}}
	m, err := NewManager(src, tmp)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.LoadAll()

	statuses := m.ListSources()
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].Error == "" {
		t.Error("expected error for missing cache")
	}
	hit, _ := m.Contains("1.2.3.4")
	if hit {
		t.Error("expected no hit for uncached source")
	}
}

func TestManagerStaleCache(t *testing.T) {
	tmp := t.TempDir()
	src := []Source{{Name: "stale", URL: "http://example.com"}}

	cf := cacheFile{
		Entries:   []string{"10.0.0.0/8"},
		FetchedAt: time.Now().Add(-(cacheTTL + time.Hour)),
	}
	data, _ := json.Marshal(cf)
	_ = os.WriteFile(filepath.Join(tmp, "stale.json"), data, 0640)

	m, err := NewManager(src, tmp)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.LoadAll()

	statuses := m.ListSources()
	if !statuses[0].Stale {
		t.Error("expected stale=true")
	}
	hit, _ := m.Contains("10.1.1.1")
	if hit {
		t.Error("stale source should not produce hits")
	}
}

func TestManagerRefreshError(t *testing.T) {
	tmp := t.TempDir()
	src := []Source{{Name: "fail", URL: "http://down.example.com"}}
	m, err := NewManager(src, tmp)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.SetFetcher(func(url string) ([]byte, error) {
		return nil, &net.OpError{Op: "get", Err: errFakeNetworkError{}}
	})
	statuses := m.Refresh()
	if statuses[0].Error == "" {
		t.Error("expected error in status")
	}
	hit, _ := m.Contains("1.2.3.4")
	if hit {
		t.Error("expected no hit for failed source")
	}
}

func TestManagerAddRemoveSource(t *testing.T) {
	tmp := t.TempDir()
	m, err := NewManager(nil, tmp)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if len(m.Sources()) != len(DefaultSources) {
		t.Fatalf("expected %d default sources, got %d", len(DefaultSources), len(m.Sources()))
	}
	m.AddSource(Source{Name: "custom", URL: "http://custom"})
	if len(m.Sources()) != len(DefaultSources)+1 {
		t.Fatalf("expected %d sources after add, got %d", len(DefaultSources)+1, len(m.Sources()))
	}
	m.AddSource(Source{Name: "custom", URL: "http://dup"})
	if len(m.Sources()) != len(DefaultSources)+1 {
		t.Error("duplicate add should be a no-op")
	}
	if !m.RemoveSource("custom") {
		t.Error("RemoveSource should return true for existing source")
	}
	if m.RemoveSource("custom") {
		t.Error("RemoveSource should return false for non-existing source")
	}
}

func TestManagerStats(t *testing.T) {
	tmp := t.TempDir()
	src := []Source{
		{Name: "a", URL: "http://a"},
		{Name: "b", URL: "http://b"},
	}
	m, err := NewManager(src, tmp)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.SetFetcher(func(url string) ([]byte, error) {
		switch url {
		case "http://a":
			return []byte("10.0.0.0/8\n11.0.0.0/8\n"), nil
		case "http://b":
			return []byte("172.16.0.0/12\n"), nil
		}
		return nil, nil
	})
	m.Refresh()
	stats := m.Stats()
	if stats.Total != 3 {
		t.Errorf("expected 3 total entries, got %d", stats.Total)
	}
	if stats.Active != 2 {
		t.Errorf("expected 2 active sources, got %d", stats.Active)
	}
}

func TestManagerContainsInvalidIP(t *testing.T) {
	tmp := t.TempDir()
	m, err := NewManager(nil, tmp)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	hit, _ := m.Contains("not-an-ip")
	if hit {
		t.Error("expected false for invalid IP")
	}
}

func TestDefaultSources(t *testing.T) {
	if len(DefaultSources) < 5 {
		t.Fatalf("expected at least 5 default sources, got %d", len(DefaultSources))
	}
	names := map[string]bool{}
	for _, s := range DefaultSources {
		if s.Name == "" || s.URL == "" {
			t.Error("default source has empty name or URL")
		}
		names[s.Name] = true
	}
	expected := []string{"spamhaus-drop", "spamhaus-edrop", "firehol-level1", "cins-army", "tor-exit-nodes"}
	for _, e := range expected {
		if !names[e] {
			t.Errorf("missing default source: %s", e)
		}
	}
}

type errFakeNetworkError struct{}

func (errFakeNetworkError) Error() string { return "network unreachable" }
