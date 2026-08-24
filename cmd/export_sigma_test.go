package cmd

import (
	"regexp"
	"testing"

	"github.com/google/uuid"
)

// uuidPattern matches the canonical 8-4-4-4-12 lowercase UUID string format
// that Sigma rule id fields expect.
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func TestSigmaUUIDFormat(t *testing.T) {
	got := sigmaUUID("Excessive 4xx Errors from Single IP")
	if !uuidPattern.MatchString(got) {
		t.Fatalf("sigmaUUID returned %q, expected canonical UUIDv5 format", got)
	}
}

func TestSigmaUUIDIsUUIDv5(t *testing.T) {
	got := sigmaUUID("Excessive 4xx Errors from Single IP")
	u, err := uuid.Parse(got)
	if err != nil {
		t.Fatalf("sigmaUUID returned %q which is not a valid UUID: %v", got, err)
	}
	if u.Version() != 5 {
		t.Fatalf("sigmaUUID returned UUID version %d, expected version 5 (SHA-1)", u.Version())
	}
}

func TestSigmaUUIDDeterministic(t *testing.T) {
	title := "Geo-based Anomaly Detection"
	first := sigmaUUID(title)
	for i := 0; i < 5; i++ {
		if got := sigmaUUID(title); got != first {
			t.Fatalf("sigmaUUID is not deterministic: got %q, want %q", got, first)
		}
	}
}

func TestSigmaUUIDDistinctForDifferentTitles(t *testing.T) {
	a := sigmaUUID("Rule A")
	b := sigmaUUID("Rule B")
	if a == b {
		t.Fatalf("expected distinct UUIDs for distinct titles, both were %q", a)
	}
}

func TestSigmaUUIDMatchesNamespaceDerivation(t *testing.T) {
	title := "Excessive 4xx Errors from Single IP"
	want := uuid.NewSHA1(sigmaNamespace, []byte("caddy-analyzer:sigma:"+title)).String()
	if got := sigmaUUID(title); got != want {
		t.Fatalf("sigmaUUID = %q, want %q", got, want)
	}
}
