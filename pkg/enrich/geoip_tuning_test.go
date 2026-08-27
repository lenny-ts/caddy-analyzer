package enrich

import (
	"testing"
	"time"
)

func TestSetGeoCacheTTL(t *testing.T) {
	original := GeoCacheTTL()
	t.Cleanup(func() { geoCacheTTL = original })

	tests := []struct {
		name string
		set  time.Duration
		want time.Duration
	}{
		{"shorter ttl", time.Hour, time.Hour},
		{"longer ttl", 72 * time.Hour, 72 * time.Hour},
		{"zero disables caching", 0, 0},
		{"negative is ignored", -time.Second, time.Hour},
	}

	// Sequential on purpose: the negative case asserts the *previous* value
	// survived, which is what "ignored" has to mean.
	geoCacheTTL = original
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "negative is ignored" {
				SetGeoCacheTTL(time.Hour)
			}
			SetGeoCacheTTL(tt.set)
			if got := GeoCacheTTL(); got != tt.want {
				t.Errorf("SetGeoCacheTTL(%v) -> %v, want %v", tt.set, got, tt.want)
			}
		})
	}
}

func TestSetGeoCacheMaxSize(t *testing.T) {
	original := GeoCacheMaxSize()
	t.Cleanup(func() { geoCacheMaxSize = original })

	for _, tt := range []struct {
		name string
		set  int
		want int
	}{
		{"smaller", 100, 100},
		{"larger", 1_000_000, 1_000_000},
		{"zero disables caching", 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			SetGeoCacheMaxSize(tt.set)
			if got := GeoCacheMaxSize(); got != tt.want {
				t.Errorf("SetGeoCacheMaxSize(%d) -> %d, want %d", tt.set, got, tt.want)
			}
		})
	}

	SetGeoCacheMaxSize(100)
	SetGeoCacheMaxSize(-1)
	if got := GeoCacheMaxSize(); got != 100 {
		t.Errorf("a negative size must be ignored, got %d", got)
	}
}

// TestGeoCacheDefaultsAreUnchanged pins the defaults the issue asks not to
// change: the goal is configurability, not new behaviour for anyone who sets
// nothing.
func TestGeoCacheDefaultsAreUnchanged(t *testing.T) {
	if GeoCacheTTL() != 24*time.Hour {
		t.Errorf("default TTL = %v, want 24h", GeoCacheTTL())
	}
	if GeoCacheMaxSize() != 50000 {
		t.Errorf("default max size = %d, want 50000", GeoCacheMaxSize())
	}
}
