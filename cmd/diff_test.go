package cmd

import "testing"

func TestFormatDurationDeltaZero(t *testing.T) {
	if got, want := formatDurationDelta(0), "N/A"; got != want {
		t.Fatalf("formatDurationDelta(0) = %q, want %q", got, want)
	}
}
