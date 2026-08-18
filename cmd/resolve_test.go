package cmd

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

// TestResolveSourcesWithExplicitArgs verifies that explicit source
// arguments are parsed and returned without consulting config or stdin.
func TestResolveSourcesWithExplicitArgs(t *testing.T) {
	sources, err := resolveSources([]string{"/var/log/caddy/access.log"})
	if err != nil {
		t.Fatalf("resolveSources: %v", err)
	}
	if len(sources) != 1 || sources[0].Type != types.SourceFile || sources[0].Path != "/var/log/caddy/access.log" {
		t.Fatalf("unexpected sources: %+v", sources)
	}
}

// TestResolveSourcesWithConfigFile verifies that a caddy-analyzer.json
// in the working directory is picked up when no explicit args are given.
func TestResolveSourcesWithConfigFile(t *testing.T) {
	dir := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origWd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	cfg := map[string]string{"source": "/var/log/caddy/access.log"}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile("caddy-analyzer.json", data, 0o600); err != nil {
		t.Fatal(err)
	}
	sources, err := resolveSources(nil)
	if err != nil {
		t.Fatalf("resolveSources: %v", err)
	}
	if len(sources) != 1 || sources[0].Path != "/var/log/caddy/access.log" {
		t.Fatalf("unexpected sources: %+v", sources)
	}
}

// TestRunWatchRejectsStdinSource verifies that --watch refuses a stdin
// source immediately with a clear error instead of starting a dashboard
// that races bubbletea for fd 0 and never receives log lines.
func TestRunWatchRejectsStdinSource(t *testing.T) {
	err := runWatch(context.Background(), []types.LogSource{{Type: types.SourceStdin}})
	if err == nil {
		t.Fatal("runWatch with SourceStdin: expected error, got nil")
	}
}
