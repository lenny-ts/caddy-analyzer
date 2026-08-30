package cmd

import (
	"testing"
	"time"
)

// TestParseTimeAbsolute covers the RFC3339 branch, which is tried first and
// returns the instant verbatim.
func TestParseTimeAbsolute(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"2026-07-27T14:57:24Z", "2026-07-27T14:57:24Z"},
		{"2026-07-27T14:57:24+02:00", "2026-07-27T12:57:24Z"},
		{"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseTime(tt.in)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.in, err)
			}
			if got.UTC().Format(time.RFC3339) != tt.want {
				t.Errorf("parseTime(%q) = %s, want %s",
					tt.in, got.UTC().Format(time.RFC3339), tt.want)
			}
		})
	}
}

// TestParseTimeRelative covers the four duration units. The result is measured
// against a `now` sampled just before the call, so the assertion is on the
// offset rather than on an absolute instant; tolerance absorbs the gap between
// the two clock reads.
func TestParseTimeRelative(t *testing.T) {
	const tolerance = 5 * time.Second

	tests := []struct {
		in   string
		want time.Duration
	}{
		{"30s", 30 * time.Second},
		{"5m", 5 * time.Minute},
		{"1h", time.Hour},
		{"2d", 48 * time.Hour},
		{"0s", 0},
		{"0d", 0},
		{"90m", 90 * time.Minute},
		{"365d", 365 * 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			before := time.Now()
			got, err := parseTime(tt.in)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.in, err)
			}
			ago := before.Sub(got)
			if diff := ago - tt.want; diff < -tolerance || diff > tolerance {
				t.Errorf("parseTime(%q) is %v ago, want %v (off by %v)",
					tt.in, ago, tt.want, diff)
			}
		})
	}
}

// TestParseTimeRelativeIsInThePast pins the sign: a relative value means "N
// ago", so the result must never be in the future. A dropped minus in the
// switch would still satisfy the magnitude check above.
func TestParseTimeRelativeIsInThePast(t *testing.T) {
	for _, in := range []string{"1s", "1m", "1h", "1d"} {
		t.Run(in, func(t *testing.T) {
			got, err := parseTime(in)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", in, err)
			}
			if !got.Before(time.Now()) {
				t.Errorf("parseTime(%q) = %v, want an instant in the past", in, got)
			}
		})
	}
}

// TestParseTimeErrors covers every rejection path, including the empty string
// — which reached `s[len(s)-1:]` and panicked with "slice bounds out of range
// [-1:]" before parseTime grew its empty guard. Both call sites in
// buildFilters() are behind an `if flag != ""` check, so it was never
// reachable from the CLI, but the function is no longer one refactor away
// from panicking.
func TestParseTimeErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"unknown unit", "5w"},
		{"unknown unit uppercase", "5M"},
		{"bare number, no unit", "5"},
		{"unit only", "m"},
		{"single char digit", "5"},
		{"single char letter", "d"},
		{"negative", "-5m"},
		{"negative days", "-1d"},
		{"not a number", "abcm"},
		{"float", "1.5h"},
		{"whitespace", " 5m"},
		{"trailing space", "5m "},
		{"incomplete RFC3339", "2026-07-27"},
		{"words", "yesterday"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTime(tt.in)
			if err == nil {
				t.Fatalf("parseTime(%q) expected an error, got %v", tt.in, got)
			}
			if !got.IsZero() {
				t.Errorf("parseTime(%q) returned %v alongside its error, want the zero Time",
					tt.in, got)
			}
		})
	}
}
