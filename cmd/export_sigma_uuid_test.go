package cmd

import (
	"regexp"
	"testing"
)

// TestUUIDV5MatchesRFC4122Vector checks the implementation against the worked
// example published with the specification, so a hand-rolled UUIDv5 is not
// taken on trust.
func TestUUIDV5MatchesRFC4122Vector(t *testing.T) {
	const want = "886313e1-3b8a-5372-9b90-0c9aee199e5d"
	if got := uuidV5(uuidNamespaceDNS, "python.org"); got != want {
		t.Fatalf("uuidV5(DNS, %q) = %q, want %q", "python.org", got, want)
	}
}

func TestSigmaNamespaceIsWellFormed(t *testing.T) {
	ns, err := parseUUID(sigmaNamespace)
	if err != nil {
		t.Fatalf("sigmaNamespace does not parse: %v", err)
	}
	// sigmaUUID panics on a malformed constant, so this is the guard that
	// turns that into a test failure instead.
	if _ = ns; sigmaUUID("anything") == "" {
		t.Fatal("sigmaUUID returned an empty string")
	}
}

// TestSigmaNamespaceIsDerivedFromTheProjectName pins how the constant was
// produced. It must never change: a published rule carries its UUID forever.
func TestSigmaNamespaceIsDerivedFromTheProjectName(t *testing.T) {
	if got := uuidV5(uuidNamespaceDNS, "caddy-analyzer"); got != sigmaNamespace {
		t.Fatalf("sigmaNamespace = %q, but uuidV5(DNS, %q) = %q — the constant "+
			"must stay pinned to its derivation", sigmaNamespace, "caddy-analyzer", got)
	}
}

var uuidV5Pattern = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// TestSigmaUUIDIsAVersion5UUID is what the change is for: the previous MD5
// output had the canonical 8-4-4-4-12 shape but carried no version or variant
// bits, so it was not a UUID at all -- a Sigma consumer validating the field
// would reject it.
func TestSigmaUUIDIsAVersion5UUID(t *testing.T) {
	titles := []string{
		"Caddy: burst of 4xx from a single IP",
		"Caddy: sustained 5xx",
		"", // a rule with no title must still produce a valid UUID
		"unicode título — with punctuation",
	}
	for _, title := range titles {
		got := sigmaUUID(title)
		if !uuidV5Pattern.MatchString(got) {
			t.Errorf("sigmaUUID(%q) = %q, which is not a version-5 UUID", title, got)
		}
	}
}

func TestSigmaUUIDIsStableAcrossCalls(t *testing.T) {
	const title = "Caddy: burst of 4xx from a single IP"
	if a, b := sigmaUUID(title), sigmaUUID(title); a != b {
		t.Fatalf("sigmaUUID is not deterministic: %q then %q", a, b)
	}
}

func TestSigmaUUIDDistinguishesTitles(t *testing.T) {
	if sigmaUUID("rule one") == sigmaUUID("rule two") {
		t.Fatal("two different titles produced the same UUID")
	}
}

func TestParseUUIDRejectsMalformedInput(t *testing.T) {
	for _, bad := range []string{
		"",
		"not-a-uuid",
		"a64194cb-8d9e-5cf8-a2c3", // too short
		"a64194cb-8d9e-5cf8-a2c3-a0ddce730456-extra", // too long
		"g64194cb-8d9e-5cf8-a2c3-a0ddce730456",       // non-hex
	} {
		if _, err := parseUUID(bad); err == nil {
			t.Errorf("parseUUID(%q) returned no error", bad)
		}
	}
}

func TestParseUUIDAcceptsTheCanonicalForm(t *testing.T) {
	u, err := parseUUID("a64194cb-8d9e-5cf8-a2c3-a0ddce730456")
	if err != nil {
		t.Fatalf("parseUUID rejected a canonical UUID: %v", err)
	}
	if u[0] != 0xa6 || u[15] != 0x56 {
		t.Fatalf("parseUUID decoded the wrong bytes: %x", u)
	}
}
