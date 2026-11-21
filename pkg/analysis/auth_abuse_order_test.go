package analysis

import (
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestAuthAbuseEqualTimestampKeepsRecentEvidence(t *testing.T) {
	d, err := NewAuthAbuseDetector(AuthAbuseConfig{Enabled: true,
		BruteForce: AuthThreshold{Failures: 2, Window: "1m"}})
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	record := func(ip string) {
		d.Observe(&types.LogEntry{Timestamp: ts, RemoteIP: ip, URI: "/login", Status: 401})
	}
	for i := 0; i < DefaultIPCap; i++ {
		record("192.0.2.1")
	}
	record("192.0.2.2")
	record("192.0.2.2")
	record("192.0.2.3")
	for _, det := range d.Current(ts) {
		if det.Type == DetBruteForce && det.IP == "192.0.2.2" {
			return
		}
	}
	t.Fatal("recent evidence at an equal timestamp was evicted before older arrivals")
}
