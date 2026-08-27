package guard

import (
	"testing"
	"time"
)

func TestSetIPTablesTimeout(t *testing.T) {
	original := IPTablesTimeout()
	t.Cleanup(func() { iptablesTimeout = original })

	for _, tt := range []struct {
		name string
		set  time.Duration
		want time.Duration
	}{
		{"raised for a huge ruleset", 60 * time.Second, 60 * time.Second},
		{"lowered for a test environment", time.Second, time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			SetIPTablesTimeout(tt.set)
			if got := IPTablesTimeout(); got != tt.want {
				t.Errorf("SetIPTablesTimeout(%v) -> %v, want %v", tt.set, got, tt.want)
			}
		})
	}
}

// TestSetIPTablesTimeoutRejectsNonPositive is the one that matters: zero or
// negative would make every firewall invocation fail on a context deadline,
// turning a tuning knob into an outage.
func TestSetIPTablesTimeoutRejectsNonPositive(t *testing.T) {
	original := IPTablesTimeout()
	t.Cleanup(func() { iptablesTimeout = original })

	SetIPTablesTimeout(30 * time.Second)
	for _, bad := range []time.Duration{0, -time.Second, -time.Hour} {
		SetIPTablesTimeout(bad)
		if got := IPTablesTimeout(); got != 30*time.Second {
			t.Errorf("SetIPTablesTimeout(%v) must be ignored, got %v", bad, got)
		}
	}
}

func TestIPTablesTimeoutDefaultIsUnchanged(t *testing.T) {
	if IPTablesTimeout() != 10*time.Second {
		t.Errorf("default = %v, want 10s", IPTablesTimeout())
	}
}
