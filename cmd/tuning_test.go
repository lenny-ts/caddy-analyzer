package cmd

import (
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/config"
	"github.com/lenny-ts/caddy-analyzer/pkg/enrich"
	"github.com/lenny-ts/caddy-analyzer/pkg/guard"
)

func restoreTuning(t *testing.T) {
	t.Helper()
	ttl, size, timeout := enrich.GeoCacheTTL(), enrich.GeoCacheMaxSize(), guard.IPTablesTimeout()
	t.Cleanup(func() {
		enrich.SetGeoCacheTTL(ttl)
		enrich.SetGeoCacheMaxSize(size)
		guard.SetIPTablesTimeout(timeout)
	})
}

func TestApplyTuningFromConfig(t *testing.T) {
	restoreTuning(t)

	cfg := &config.Config{Tuning: &config.TuningConfig{
		GeoCacheTTL:     "1h",
		GeoCacheSize:    100,
		IPTablesTimeout: "45s",
	}}
	if err := applyTuning(cfg, false, false, false); err != nil {
		t.Fatalf("applyTuning: %v", err)
	}

	if got := enrich.GeoCacheTTL(); got != time.Hour {
		t.Errorf("ttl = %v, want 1h", got)
	}
	if got := enrich.GeoCacheMaxSize(); got != 100 {
		t.Errorf("size = %d, want 100", got)
	}
	if got := guard.IPTablesTimeout(); got != 45*time.Second {
		t.Errorf("iptables timeout = %v, want 45s", got)
	}
}

// TestApplyTuningFlagsBeatConfig is the precedence the issue specifies.
func TestApplyTuningFlagsBeatConfig(t *testing.T) {
	restoreTuning(t)

	cfg := &config.Config{Tuning: &config.TuningConfig{
		GeoCacheTTL:     "1h",
		GeoCacheSize:    100,
		IPTablesTimeout: "45s",
	}}
	flagGeoCacheTTL, flagGeoCacheSize, flagIPTablesTimeout = 2*time.Hour, 200, 90*time.Second
	t.Cleanup(func() { flagGeoCacheTTL, flagGeoCacheSize, flagIPTablesTimeout = 0, 0, 0 })

	if err := applyTuning(cfg, true, true, true); err != nil {
		t.Fatalf("applyTuning: %v", err)
	}

	if got := enrich.GeoCacheTTL(); got != 2*time.Hour {
		t.Errorf("ttl = %v, want the flag's 2h", got)
	}
	if got := enrich.GeoCacheMaxSize(); got != 200 {
		t.Errorf("size = %d, want the flag's 200", got)
	}
	if got := guard.IPTablesTimeout(); got != 90*time.Second {
		t.Errorf("iptables timeout = %v, want the flag's 90s", got)
	}
}

// TestApplyTuningLeavesDefaultsAlone: no config and no flags set must not move
// anything, so an existing install behaves identically.
func TestApplyTuningLeavesDefaultsAlone(t *testing.T) {
	restoreTuning(t)
	before := [3]any{enrich.GeoCacheTTL(), enrich.GeoCacheMaxSize(), guard.IPTablesTimeout()}

	if err := applyTuning(nil, false, false, false); err != nil {
		t.Fatalf("applyTuning: %v", err)
	}

	after := [3]any{enrich.GeoCacheTTL(), enrich.GeoCacheMaxSize(), guard.IPTablesTimeout()}
	if before != after {
		t.Errorf("tuning changed with nothing set: %v -> %v", before, after)
	}
}

func TestApplyTuningRejectsBadValues(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		ttl, size   bool
		iptables    bool
		flagTTL     time.Duration
		flagSize    int
		flagTimeout time.Duration
		wantErr     string
	}{
		{
			name:    "unparseable config ttl",
			cfg:     &config.Config{Tuning: &config.TuningConfig{GeoCacheTTL: "banana"}},
			wantErr: "tuning.geo_cache_ttl",
		},
		{
			name:    "negative config ttl",
			cfg:     &config.Config{Tuning: &config.TuningConfig{GeoCacheTTL: "-1h"}},
			wantErr: "must not be negative",
		},
		{
			name:    "negative config size",
			cfg:     &config.Config{Tuning: &config.TuningConfig{GeoCacheSize: -1}},
			wantErr: "must not be negative",
		},
		{
			name:    "zero config iptables timeout",
			cfg:     &config.Config{Tuning: &config.TuningConfig{IPTablesTimeout: "0s"}},
			wantErr: "must be positive",
		},
		{
			name:    "negative flag ttl",
			ttl:     true,
			flagTTL: -time.Second,
			wantErr: "--geo-cache-ttl",
		},
		{
			name:     "negative flag size",
			size:     true,
			flagSize: -1,
			wantErr:  "--geo-cache-size",
		},
		{
			name:        "zero flag iptables timeout",
			iptables:    true,
			flagTimeout: 0,
			wantErr:     "--iptables-timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreTuning(t)
			flagGeoCacheTTL, flagGeoCacheSize, flagIPTablesTimeout = tt.flagTTL, tt.flagSize, tt.flagTimeout
			t.Cleanup(func() { flagGeoCacheTTL, flagGeoCacheSize, flagIPTablesTimeout = 0, 0, 0 })

			err := applyTuning(tt.cfg, tt.ttl, tt.size, tt.iptables)
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tt.wantErr)
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || len(haystack) >= len(needle) &&
		(haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
