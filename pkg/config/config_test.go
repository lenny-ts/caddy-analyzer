package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/L9Lenny/caddy-analyzer/pkg/blocklist"
)

func TestCreateDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions not supported on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "config.json")

	if err := CreateDefault(path); err != nil {
		t.Fatalf("CreateDefault failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("config file not created: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected perm 0600, got %v", info.Mode().Perm())
	}

	cfg, err := loadFile(path)
	if err != nil {
		t.Fatalf("loadFile failed: %v", err)
	}
	if cfg.Source != "/var/log/caddy/access.log" {
		t.Errorf("expected source /var/log/caddy/access.log, got %q", cfg.Source)
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := loadFile("/nonexistent/path/config.json")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

func TestLoadFileInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{invalid json"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err := loadFile(path)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestLoadReturnsNilWhenNoConfig(t *testing.T) {
	dir := t.TempDir()
	localPath := filepath.Join(dir, "caddy-analyzer.json")
	defPath := filepath.Join(dir, "config", "config.json")

	origLocal := LocalConfigPath()
	defer func() { _ = os.Symlink(origLocal, origLocal) }()
	_ = localPath
	_ = defPath

	cfg, p, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config when no files exist, got %+v", cfg)
	}
	if p != "" {
		t.Errorf("expected empty path, got %q", p)
	}
}

func TestLoadLocalConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-analyzer.json")
	data := `{"source": "/custom/path.log"}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, err := loadFile(path)
	if err != nil {
		t.Fatalf("loadFile failed: %v", err)
	}
	if cfg.Source != "/custom/path.log" {
		t.Errorf("expected /custom/path.log, got %q", cfg.Source)
	}
}

func TestLoadLocalConfigWithNamespace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-analyzer.json")
	data := `{"source": "k8s://my-pod", "namespace": "production"}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, err := loadFile(path)
	if err != nil {
		t.Fatalf("loadFile failed: %v", err)
	}
	if cfg.Source != "k8s://my-pod" {
		t.Errorf("expected k8s://my-pod, got %q", cfg.Source)
	}
	if cfg.Namespace != "production" {
		t.Errorf("expected namespace production, got %q", cfg.Namespace)
	}
}

func TestConfigNamespaceOmittedWhenEmpty(t *testing.T) {
	cfg := Config{Source: "/var/log/caddy/access.log"}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if strings.Contains(string(data), "namespace") {
		t.Errorf("empty namespace must be omitted from JSON, got %s", data)
	}
}

func TestDefaultConfigPath(t *testing.T) {
	path, err := DefaultConfigPath()
	if err != nil {
		t.Fatalf("DefaultConfigPath failed: %v", err)
	}
	if path == "" {
		t.Error("expected non-empty path")
	}
}

func TestLocalConfigPath(t *testing.T) {
	if LocalConfigPath() != "caddy-analyzer.json" {
		t.Error("expected caddy-analyzer.json")
	}
}

func TestResolveSourcesDefaults(t *testing.T) {
	bc := &BlocklistConfig{}
	srcs, err := bc.ResolveSources()
	if err != nil {
		t.Fatalf("ResolveSources: %v", err)
	}
	if len(srcs) != len(blocklist.DefaultSources) {
		t.Errorf("expected %d sources, got %d", len(blocklist.DefaultSources), len(srcs))
	}
}

func TestResolveSourcesNoDefaults(t *testing.T) {
	bc := &BlocklistConfig{NoDefaults: true}
	_, err := bc.ResolveSources()
	if err == nil {
		t.Error("expected error when no defaults and no custom sources")
	}
}

func TestResolveSourcesCustomOnly(t *testing.T) {
	custom := []blocklist.Source{{Name: "custom", URL: "http://example.com"}}
	bc := &BlocklistConfig{NoDefaults: true, CustomSources: custom}
	srcs, err := bc.ResolveSources()
	if err != nil {
		t.Fatalf("ResolveSources: %v", err)
	}
	if len(srcs) != 1 {
		t.Fatalf("expected 1 source, got %d", len(srcs))
	}
	if srcs[0].Name != "custom" {
		t.Errorf("expected custom, got %s", srcs[0].Name)
	}
}

func TestResolveSourcesRemove(t *testing.T) {
	bc := &BlocklistConfig{RemoveSources: []string{"tor-exit-nodes", "cins-army"}}
	srcs, err := bc.ResolveSources()
	if err != nil {
		t.Fatalf("ResolveSources: %v", err)
	}
	expected := len(blocklist.DefaultSources) - 2
	if len(srcs) != expected {
		t.Errorf("expected %d sources, got %d", expected, len(srcs))
	}
	for _, s := range srcs {
		if s.Name == "tor-exit-nodes" || s.Name == "cins-army" {
			t.Errorf("source %q should have been removed", s.Name)
		}
	}
}

func TestResolveSourcesNilReceiver(t *testing.T) {
	var bc *BlocklistConfig
	srcs, err := bc.ResolveSources()
	if err != nil {
		t.Fatalf("ResolveSources: %v", err)
	}
	if len(srcs) != len(blocklist.DefaultSources) {
		t.Errorf("expected %d defaults for nil receiver, got %d", len(blocklist.DefaultSources), len(srcs))
	}
}

func TestLoadBlocklistFileSourceArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sources.json")
	data := `[{"name":"custom","url":"http://example.com"}]`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	bc, err := LoadBlocklistFile(path)
	if err != nil {
		t.Fatalf("LoadBlocklistFile: %v", err)
	}
	if len(bc.CustomSources) != 1 {
		t.Fatalf("expected 1 custom source, got %d", len(bc.CustomSources))
	}
	if bc.CustomSources[0].Name != "custom" {
		t.Errorf("expected custom, got %s", bc.CustomSources[0].Name)
	}
}

func TestLoadBlocklistFileFullObject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.json")
	data := `{"no_defaults":true,"custom_sources":[{"name":"x","url":"http://x"}],"remove_sources":["y"]}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	bc, err := LoadBlocklistFile(path)
	if err != nil {
		t.Fatalf("LoadBlocklistFile: %v", err)
	}
	if !bc.NoDefaults {
		t.Error("expected NoDefaults=true")
	}
	if len(bc.CustomSources) != 1 {
		t.Errorf("expected 1 custom source, got %d", len(bc.CustomSources))
	}
	if len(bc.RemoveSources) != 1 || bc.RemoveSources[0] != "y" {
		t.Errorf("expected remove [y], got %v", bc.RemoveSources)
	}
}

func TestLoadBlocklistFileMissing(t *testing.T) {
	_, err := LoadBlocklistFile("/nonexistent/path/file.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadBlocklistFileInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadBlocklistFile(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestConfigLoadWithBlocklist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-analyzer.json")
	data := `{
		"source": "/var/log/caddy/access.log",
		"blocklist": {
			"no_defaults": true,
			"custom_sources": [{"name":"x","url":"http://x"}]
		}
	}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadFile(path)
	if err != nil {
		t.Fatalf("loadFile: %v", err)
	}
	if cfg.Blocklist == nil {
		t.Fatal("expected non-nil Blocklist")
	}
	if !cfg.Blocklist.NoDefaults {
		t.Error("expected NoDefaults=true")
	}
	if len(cfg.Blocklist.CustomSources) != 1 {
		t.Errorf("expected 1 custom source, got %d", len(cfg.Blocklist.CustomSources))
	}
	srcs, err := cfg.Blocklist.ResolveSources()
	if err != nil {
		t.Fatalf("ResolveSources: %v", err)
	}
	if len(srcs) != 1 {
		t.Errorf("expected 1 resolved source, got %d", len(srcs))
	}
}

func TestConfigBlocklistOmittedWhenNil(t *testing.T) {
	cfg := Config{Source: "/var/log/caddy/access.log"}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(data), "blocklist") {
		t.Errorf("nil blocklist should be omitted, got %s", data)
	}
}
