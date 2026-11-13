package guard

import (
	"context"
	"testing"
	"time"
)

func TestAuditBanDurationSurvivesRestartAndHistoryReset(t *testing.T) {
	cfg := escalationConfig(t)
	ip, now := "203.0.113.10", time.Now()
	g := New(cfg)
	g.recordOffense(Offender{
		IP: ip, Offenses: 1, LastOffense: now.Add(-time.Hour),
		BanUntil: now.Add(-time.Minute), ResetAt: now.Add(24 * time.Hour),
	})
	if !g.block(context.Background(), Candidate{IP: ip}, now) {
		t.Fatal("repeat-offender ban failed")
	}
	g.FlushState()
	entries, err := newStateFile(cfg.StatePath).load()
	if err != nil || len(entries) != 1 || entries[0].Duration != time.Hour {
		t.Fatal("effective duration was not persisted", entries, err)
	}
	if err := ResetOffender(cfg.StatePath, ip); err != nil {
		t.Fatal(err)
	}
	// Changing the base duration and resetting history must not rewrite an active ban.
	cfg.BlockDuration = 5 * time.Minute
	for _, name := range []string{"restored expiry", "expired offline"} {
		t.Run(name, func(t *testing.T) {
			offline := name == "expired offline"
			entry := entries[0]
			if offline {
				entry.When = time.Now().Add(-time.Minute)
			} else {
				entry.When = time.Now().Add(time.Hour)
			}
			if err := newStateFile(cfg.StatePath).saveEntries([]stateEntry{entry}); err != nil {
				t.Fatal(err)
			}
			events := make(chan string, 4)
			cfg.OnAudit = func(action, _, _, duration string) {
				if action == "unblock" {
					events <- duration
				}
			}
			restored := New(cfg)
			if !offline {
				if restored.banDurations[ip] != time.Hour {
					t.Fatal("restart lost effective duration")
				}
				// Drive the restored expiry immediately without waiting an hour.
				past := time.Now().Add(-time.Second)
				restored.initial[0].when = past
				restored.expiries[ip] = past
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() { restored.runExpiryLoop(ctx); close(done) }()
				t.Cleanup(func() { cancel(); <-done })
			}
			select {
			case duration := <-events:
				if duration != "1h0m0s" {
					t.Fatalf("unblock duration %s, want the original 1h ban (offline=%v)", duration, offline)
				}
			case <-time.After(time.Second):
				t.Fatal("missing unblock audit event")
			}
		})
	}
}

func TestAuditLegacyBanDurationFallback(t *testing.T) {
	cfg := escalationConfig(t)
	entry := stateEntry{IP: "203.0.113.10", When: time.Now().Add(-time.Minute)}
	if err := newStateFile(cfg.StatePath).saveEntries([]stateEntry{entry}); err != nil {
		t.Fatal(err)
	}
	var duration string
	cfg.OnAudit = func(action, _, _, value string) {
		if action == "unblock" {
			duration = value
		}
	}
	New(cfg)
	if duration != "10m0s" {
		t.Fatalf("legacy fallback duration = %q, want 10m0s", duration)
	}
}
