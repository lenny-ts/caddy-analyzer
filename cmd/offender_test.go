package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBanResetAfterDuration(t *testing.T) {
	for _, value := range []string{"30d", "720h", "1.5d", "1m"} {
		duration, err := parseBanResetAfter(value)
		if err != nil || duration <= 0 {
			t.Fatalf("%q: %s, %v", value, duration, err)
		}
		if value == "30d" && duration != 30*24*time.Hour {
			t.Fatal("days parsed incorrectly")
		}
	}
	for _, value := range []string{"0", "-1d", "abc", "10000000d", "1d2h"} {
		if _, err := parseBanResetAfter(value); err == nil {
			t.Fatalf("accepted invalid period %q", value)
		}
	}
}

func TestOffenderCommands(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	for _, args := range [][]string{
		{"guard", "offenders", "--state-file", path},
		{"guard", "offender", "reset", "203.0.113.10", "--state-file", path},
	} {
		cmd, remaining, err := rootCmd.Find(args)
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		cmd.SetOut(&output)
		defer cmd.SetOut(nil)
		if err := cmd.ParseFlags(remaining); err != nil {
			t.Fatal(err)
		}
		defer cmd.Flags().Set("state-file", "/var/lib/caddy-analyzer/blocked.json")
		if err := cmd.RunE(cmd, cmd.Flags().Args()); err != nil {
			t.Fatal(err)
		}
		if cmd.Name() == "offenders" && strings.TrimSpace(output.String()) != "[]" {
			t.Fatal("empty list must be JSON []", output.String())
		}
	}
	if flag := unbanCmd.Flags().Lookup("reset-offenses"); flag == nil || flag.DefValue != "false" {
		t.Fatal("manual unban must preserve history by default")
	}
	if flag := guardCmd.Flags().Lookup("ban-escalation"); flag == nil || flag.DefValue != "false" {
		t.Fatal("escalation must be opt-in")
	}
}

func TestGuardRejectsInvalidEscalationOptions(t *testing.T) {
	oldEnabled, oldReset, oldMax := guardBanEscalation, guardBanResetAfter, guardMaxBanDuration
	oldDuration, oldState := guardDuration, guardStateFile
	t.Cleanup(func() {
		guardBanEscalation, guardBanResetAfter, guardMaxBanDuration = oldEnabled, oldReset, oldMax
		guardDuration, guardStateFile = oldDuration, oldState
	})
	for _, mutate := range []func(){
		func() { guardDuration = "0" },
		func() { guardStateFile = "" },
		func() { guardBanResetAfter = "0" },
		func() { guardMaxBanDuration = 0 },
	} {
		guardBanEscalation, guardBanResetAfter, guardMaxBanDuration = true, "30d", 168*time.Hour
		guardDuration, guardStateFile = "10m", "state.json"
		mutate()
		if err := runGuard(nil, nil); err == nil || !strings.Contains(err.Error(), "--") {
			t.Fatal("invalid escalation options were not rejected before startup", err)
		}
	}
}
