package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/blocklist"
)

func resetBlocklistFlags() {
	blocklistNoDefaults = false
	blocklistConfigFiles = nil
	blocklistRemoveSources = nil
	blocklistConfigFormat = "table"
}

func TestBuildSourcesDefaults(t *testing.T) {
	resetBlocklistFlags()
	srcs, err := buildSources()
	if err != nil {
		t.Fatalf("buildSources: %v", err)
	}
	if len(srcs) != len(blocklist.DefaultSources) {
		t.Errorf("expected %d default sources, got %d", len(blocklist.DefaultSources), len(srcs))
	}
}

func TestBuildSourcesNoDefaults(t *testing.T) {
	resetBlocklistFlags()
	blocklistNoDefaults = true
	_, err := buildSources()
	if err == nil {
		t.Fatal("expected error when no defaults and no config files")
	}
}

func TestBuildSourcesConfigFile(t *testing.T) {
	resetBlocklistFlags()
	defer resetBlocklistFlags()

	dir := t.TempDir()
	path := filepath.Join(dir, "extra.json")
	srcs := []blocklist.Source{
		{Name: "custom1", URL: "https://example.com/list1.txt"},
		{Name: "custom2", URL: "https://example.com/list2.txt"},
	}
	data, _ := json.Marshal(srcs)
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
	blocklistConfigFiles = []string{path}
	got, err := buildSources()
	if err != nil {
		t.Fatalf("buildSources: %v", err)
	}
	total := len(blocklist.DefaultSources) + 2
	if len(got) != total {
		t.Errorf("expected %d sources (defaults + 2 custom), got %d", total, len(got))
	}
}

func TestBuildSourcesConfigFileOnly(t *testing.T) {
	resetBlocklistFlags()
	defer resetBlocklistFlags()

	dir := t.TempDir()
	path := filepath.Join(dir, "extra.json")
	srcs := []blocklist.Source{
		{Name: "custom1", URL: "https://example.com/list1.txt"},
	}
	data, _ := json.Marshal(srcs)
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
	blocklistNoDefaults = true
	blocklistConfigFiles = []string{path}
	got, err := buildSources()
	if err != nil {
		t.Fatalf("buildSources: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 source, got %d", len(got))
	}
}

func TestBuildSourcesRemove(t *testing.T) {
	resetBlocklistFlags()
	defer resetBlocklistFlags()

	blocklistRemoveSources = []string{"tor-exit-nodes", "cins-army"}
	got, err := buildSources()
	if err != nil {
		t.Fatalf("buildSources: %v", err)
	}
	expected := len(blocklist.DefaultSources) - 2
	if len(got) != expected {
		t.Errorf("expected %d sources after removing 2, got %d", expected, len(got))
	}
	for _, s := range got {
		if s.Name == "tor-exit-nodes" || s.Name == "cins-army" {
			t.Errorf("source %q should have been removed", s.Name)
		}
	}
}

func TestBuildSourcesConfigFileMissing(t *testing.T) {
	resetBlocklistFlags()
	defer resetBlocklistFlags()

	blocklistNoDefaults = true
	blocklistConfigFiles = []string{"/nonexistent/path/file.json"}
	_, err := buildSources()
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestBlocklistRefreshFakeSource(t *testing.T) {
	resetBlocklistFlags()
	defer resetBlocklistFlags()

	dir := t.TempDir()
	path := filepath.Join(dir, "src.json")
	srcs := []blocklist.Source{
		{Name: "test-local", URL: "http://test.local"},
	}
	data, _ := json.Marshal(srcs)
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
	blocklistNoDefaults = true
	blocklistConfigFiles = []string{path}
	blocklistCacheDir = filepath.Join(dir, "cache")

	mgr, err := blocklist.NewManager(srcs, blocklistCacheDir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	mgr.SetFetcher(func(url string) ([]byte, error) {
		return []byte("10.0.0.0/8\n192.168.1.0/24\n"), nil
	})
	statuses := mgr.Refresh()
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].Error != "" {
		t.Errorf("expected no error, got %s", statuses[0].Error)
	}
	if statuses[0].Entries != 2 {
		t.Errorf("expected 2 entries, got %d", statuses[0].Entries)
	}
	hit, source := mgr.Contains("10.1.2.3")
	if !hit {
		t.Error("expected 10.1.2.3 to be in blocklist")
	}
	if source != "test-local" {
		t.Errorf("expected source test-local, got %s", source)
	}
}

func TestBuildSourcesFromConfigFile(t *testing.T) {
	resetBlocklistFlags()
	defer resetBlocklistFlags()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "caddy-analyzer.json")
	cfgData := `{
		"blocklist": {
			"no_defaults": true,
			"custom_sources": [{"name":"from-cfg","url":"http://example.com"}]
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(cfgData), 0640); err != nil {
		t.Fatal(err)
	}

	// Change working directory so config.Load() finds the file.
	wd, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(wd) }()

	srcs, err := buildSources()
	if err != nil {
		t.Fatalf("buildSources: %v", err)
	}
	if len(srcs) != 1 {
		t.Fatalf("expected 1 source from config file, got %d", len(srcs))
	}
	if srcs[0].Name != "from-cfg" {
		t.Errorf("expected from-cfg, got %s", srcs[0].Name)
	}
}

func TestBuildSourcesCLIFlagOverridesConfigFile(t *testing.T) {
	resetBlocklistFlags()
	defer resetBlocklistFlags()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "caddy-analyzer.json")
	cfgData := `{
		"blocklist": {
			"no_defaults": false
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(cfgData), 0640); err != nil {
		t.Fatal(err)
	}

	wd, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(wd) }()

	// CLI flag should override config file's no_defaults=false
	blocklistNoDefaults = true
	_, err := buildSources()
	if err == nil {
		t.Fatal("expected error: no defaults + no custom = empty")
	}
}
