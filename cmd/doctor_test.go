package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/doctor"
	"github.com/spf13/cobra"
)

func TestDoctorReportsInvalidTuningAsJSON(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("PATH", dir)
	if err := os.WriteFile(filepath.Join(dir, "caddy-analyzer.json"),
		[]byte(`{"tuning":{"geo_cache_ttl":"invalid"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	oldJSON := doctorJSON
	t.Cleanup(func() { doctorJSON = oldJSON })
	doctorJSON = true
	var output bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&output)
	err := runDoctor(cmd, nil)
	if !errors.Is(err, doctor.ErrCritical) {
		t.Fatalf("expected critical failure, got %v", err)
	}
	var report doctor.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON report: %v: %s", err, output.String())
	}
	for _, group := range report.Groups {
		for _, check := range group.Checks {
			if check.ID == "runtime.configuration" && check.Status == doctor.StatusFail && check.Critical {
				return
			}
		}
	}
	t.Fatal("configuration failure missing from JSON report")
}

func TestDoctorCommandRegistered(t *testing.T) {
	found, _, err := rootCmd.Find([]string{"doctor"})
	if err != nil {
		t.Fatalf("find doctor command: %v", err)
	}
	if found != doctorCmd {
		t.Fatal("doctor command is not registered on the root command")
	}
	if flag := doctorCmd.Flags().Lookup("json"); flag == nil {
		t.Fatal("doctor command must expose --json")
	}
}

func TestDoctorDefaults(t *testing.T) {
	if flag := doctorCmd.Flags().Lookup("state-file"); flag == nil || flag.DefValue != defaultDoctorStateFile {
		t.Fatalf("unexpected state-file default: %+v", flag)
	}
	if flag := doctorCmd.Flags().Lookup("cache-dir"); flag == nil || flag.DefValue != defaultBlocklistCacheDir() {
		t.Fatalf("unexpected cache-dir default: %+v", flag)
	}
}
