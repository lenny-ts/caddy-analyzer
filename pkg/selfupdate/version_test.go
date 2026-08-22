package selfupdate

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"0.5.0", "v0.5.0", 0},           // tag prefix tolerated
		{"0.5.0", "0.5.0", 0},            // identical
		{"0.5.1", "0.5.0", 1},            // patch newer
		{"0.5.0", "0.5.1", -1},           // patch older
		{"0.10.0", "0.9.0", 1},           // numeric, not lexicographic
		{"1.0.0", "0.9.9", 1},            // major
		{"2.1.0", "2.0.100", 1},          // minor
		{"0.5.0", "0.5.0-dev", 1},        // release beats dev suffix
		{"0.5.0-dev", "0.5.0", -1},       // dev suffix sorts lower
		{"0.5.0-rc.1", "0.5.0-rc.2", -1}, // pre-release ordering
		{"dev", "0.1.0", -1},             // unparsable is oldest
		{"", "v0.1.0", -1},
		{"garbage", "", 0}, // two unparsable are equal
		{"0.4.1-dev", "v0.5.0", -1},
	}
	for _, tt := range tests {
		if got := CompareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestNormalizeVersion(t *testing.T) {
	for _, in := range []string{"dev", "", "garbage"} {
		if got := NormalizeVersion(in); got != "dev" {
			t.Errorf("NormalizeVersion(%q) = %q, want dev", in, got)
		}
	}
	if got := NormalizeVersion("0.5.0"); got != "0.5.0" {
		t.Errorf("NormalizeVersion(0.5.0) = %q", got)
	}
}

func TestSameRelease(t *testing.T) {
	if !SameRelease("0.5.0", "v0.5.0") {
		t.Error(`SameRelease("0.5.0", "v0.5.0") = false`)
	}
	if SameRelease("0.4.1", "v0.5.0") {
		t.Error(`SameRelease("0.4.1", "v0.5.0") = true`)
	}
	if SameRelease("dev", "v0.5.0") {
		t.Error("dev build must never equal a release")
	}
}
