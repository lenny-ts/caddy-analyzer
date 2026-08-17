package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lenny-ts/caddy-analyzer/pkg/blocklist"
)

type Config struct {
	Source    string `json:"source,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	// Blocklist configuration. When present, the guard and blocklist
	// subcommand read these settings automatically so the user does
	// not need to pass --blocklist-config / --no-default-blocklists on
	// every invocation.
	Blocklist *BlocklistConfig `json:"blocklist,omitempty"`
}

// BlocklistConfig holds the persistent blocklist preferences. It can
// be embedded directly in the main config.json or in a standalone file
// referenced by --blocklist-config.
type BlocklistConfig struct {
	// NoDefaults disables the built-in default feeds (Spamhaus, FireHOL,
	// CINS, Tor). When true, only CustomSources are used.
	NoDefaults bool `json:"no_defaults,omitempty"`
	// CustomSources is a list of additional blocklist feeds. These are
	// appended to the defaults (unless NoDefaults is true).
	CustomSources []blocklist.Source `json:"custom_sources,omitempty"`
	// RemoveSources is a list of source names to remove from the
	// configuration. Applied after defaults + custom sources.
	RemoveSources []string `json:"remove_sources,omitempty"`
}

func DefaultConfigPath() (string, error) {
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		xdg = filepath.Join(home, ".config")
	}
	dir := filepath.Join(xdg, "caddy-analyzer")
	return filepath.Join(dir, "config.json"), nil
}

func LocalConfigPath() string {
	return "caddy-analyzer.json"
}

func Load() (*Config, string, error) {
	paths := []string{LocalConfigPath()}

	defPath, err := DefaultConfigPath()
	if err == nil {
		paths = append(paths, defPath)
	}

	for _, p := range paths {
		cfg, err := loadFile(p)
		if err == nil {
			return cfg, p, nil
		}
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "warning: config %s: %v\n", p, err)
		}
	}

	return nil, "", nil
}

func CreateDefault(path string) error {
	cfg := Config{Source: "/var/log/caddy/access.log"}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func loadFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	return &cfg, nil
}

// LoadBlocklistFile reads a standalone blocklist config JSON file. This
// supports the --blocklist-config flag which can point to a file
// containing just a BlocklistConfig object (or an array of Source).
func LoadBlocklistFile(path string) (*BlocklistConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Try as a full BlocklistConfig object first.
	var bc BlocklistConfig
	if err := json.Unmarshal(data, &bc); err == nil && (len(bc.CustomSources) > 0 || bc.NoDefaults || len(bc.RemoveSources) > 0) {
		return &bc, nil
	}
	// Fall back to an array of Source.
	var srcs []blocklist.Source
	if err := json.Unmarshal(data, &srcs); err != nil {
		return nil, fmt.Errorf("expected BlocklistConfig object or Source array: %w", err)
	}
	return &BlocklistConfig{CustomSources: srcs}, nil
}

// ResolveSources returns the final source list after applying defaults,
// custom sources, and removals. Returns an error if the result is empty.
func (bc *BlocklistConfig) ResolveSources() ([]blocklist.Source, error) {
	if bc == nil {
		return blocklist.DefaultSources, nil
	}
	var sources []blocklist.Source
	if !bc.NoDefaults {
		sources = append(sources, blocklist.DefaultSources...)
	}
	sources = append(sources, bc.CustomSources...)
	if len(bc.RemoveSources) > 0 {
		remove := make(map[string]bool, len(bc.RemoveSources))
		for _, name := range bc.RemoveSources {
			remove[name] = true
		}
		filtered := sources[:0]
		for _, s := range sources {
			if !remove[s.Name] {
				filtered = append(filtered, s)
			}
		}
		sources = filtered
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no sources configured")
	}
	return sources, nil
}
