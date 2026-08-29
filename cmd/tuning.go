package cmd

import (
	"fmt"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/config"
	"github.com/lenny-ts/caddy-analyzer/pkg/enrich"
	"github.com/lenny-ts/caddy-analyzer/pkg/guard"
)

// Operational tuning, formerly compile-time constants (#25). The defaults here
// must match the package defaults exactly: applyTuning only overrides a value
// when the flag was actually set, and "was it set" is asked of cobra rather
// than inferred by comparing against the default -- passing --geo-cache-ttl 24h
// explicitly should still count as a deliberate choice.
var (
	flagGeoCacheTTL     time.Duration
	flagGeoCacheSize    int
	flagIPTablesTimeout time.Duration
)

// applyTuning resolves flag > config file > default and pushes the result into
// the packages that own the values. Called once, before any command runs.
//
// Precedence is applied by writing the config file first and the flags second,
// so a flag always wins without either layer having to know about the other.
func applyTuning(cfg *config.Config, geoTTLSet, geoSizeSet, iptablesSet bool) error {
	if cfg != nil && cfg.Tuning != nil {
		t := cfg.Tuning
		if t.GeoCacheTTL != "" {
			d, err := time.ParseDuration(t.GeoCacheTTL)
			if err != nil {
				return fmt.Errorf("config tuning.geo_cache_ttl %q: %w", t.GeoCacheTTL, err)
			}
			if d < 0 {
				return fmt.Errorf("config tuning.geo_cache_ttl %q must not be negative", t.GeoCacheTTL)
			}
			enrich.SetGeoCacheTTL(d)
		}
		if t.GeoCacheSize != 0 {
			if t.GeoCacheSize < 0 {
				return fmt.Errorf("config tuning.geo_cache_size %d must not be negative", t.GeoCacheSize)
			}
			enrich.SetGeoCacheMaxSize(t.GeoCacheSize)
		}
		if t.IPTablesTimeout != "" {
			d, err := time.ParseDuration(t.IPTablesTimeout)
			if err != nil {
				return fmt.Errorf("config tuning.iptables_timeout %q: %w", t.IPTablesTimeout, err)
			}
			if d <= 0 {
				return fmt.Errorf("config tuning.iptables_timeout %q must be positive", t.IPTablesTimeout)
			}
			guard.SetIPTablesTimeout(d)
		}
	}

	if geoTTLSet {
		if flagGeoCacheTTL < 0 {
			return fmt.Errorf("--geo-cache-ttl must not be negative")
		}
		enrich.SetGeoCacheTTL(flagGeoCacheTTL)
	}
	if geoSizeSet {
		if flagGeoCacheSize < 0 {
			return fmt.Errorf("--geo-cache-size must not be negative")
		}
		enrich.SetGeoCacheMaxSize(flagGeoCacheSize)
	}
	if iptablesSet {
		// Rejected rather than ignored: a non-positive timeout makes every
		// firewall invocation fail on a context deadline, so silently keeping
		// the default would hide a typo that looks like it took effect.
		if flagIPTablesTimeout <= 0 {
			return fmt.Errorf("--iptables-timeout must be positive")
		}
		guard.SetIPTablesTimeout(flagIPTablesTimeout)
	}
	return nil
}
