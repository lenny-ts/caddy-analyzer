package cmd

import (
	"strings"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/output"
)

// stripANSI removes the SGR sequences lipgloss adds so assertions can be made
// on the text alone, whether or not the test process is attached to a TTY.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// TestFormatDurationDeltaZero pins the deliberate divergence from
// output.FormatDuration: a zero delta is "no change", not "no data".
func TestFormatDurationDeltaZero(t *testing.T) {
	got := stripANSI(formatDurationDelta(0))
	if got != "0ms" {
		t.Errorf("formatDurationDelta(0) = %q, want %q", got, "0ms")
	}
	// The reason the literal exists: routing zero through FormatDuration
	// would print "N/A", which reads as a missing measurement.
	if na := output.FormatDuration(0); na != "N/A" {
		t.Fatalf("output.FormatDuration(0) = %q, want %q — if this changed, "+
			"revisit whether formatDurationDelta still needs its own zero case", na, "N/A")
	}
}

// TestFormatDurationDeltaZeroMatchesSiblings pins that all three delta
// formatters agree on an unstyled, literal zero.
func TestFormatDurationDeltaZeroMatchesSiblings(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"formatDeltaInt", formatDeltaInt(0), "0"},
		{"formatDeltaFloat", formatDeltaFloat(0, "req/s"), "0 req/s"},
		{"formatDurationDelta", formatDurationDelta(0), "0ms"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s zero case = %q, want %q (unstyled)", tt.name, tt.got, tt.want)
			}
		})
	}
}

// TestFormatDurationDeltaSigned covers the non-zero branches: a slower run is
// signed "+" and a faster one "-", and the magnitude is formatted by
// FormatDuration in both directions.
func TestFormatDurationDeltaSigned(t *testing.T) {
	tests := []struct {
		name string
		in   float64
		want string
	}{
		{"slower by 1ms", 0.001, "+1.00ms"},
		{"slower by 1s", 1, "+1.00s"},
		{"faster by 1ms", -0.001, "-1.00ms"},
		{"faster by 1s", -1, "-1.00s"},
		{"slower, sub-millisecond", 0.0000005, "+0\xc2\xb5s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripANSI(formatDurationDelta(tt.in)); got != tt.want {
				t.Errorf("formatDurationDelta(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestFormatDurationDeltaNegativeIsNotNA guards the bug the "-" branch exists
// to avoid: FormatDuration returns "N/A" for anything non-positive, so a
// faster run must have its magnitude negated before formatting.
func TestFormatDurationDeltaNegativeIsNotNA(t *testing.T) {
	got := stripANSI(formatDurationDelta(-0.5))
	if strings.Contains(got, "N/A") {
		t.Errorf("formatDurationDelta(-0.5) = %q, want a signed duration, not N/A", got)
	}
}
