package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
)

func TestRulesTest(t *testing.T) {
	previous := customPatterns
	t.Cleanup(func() { customPatterns = previous })
	customPatterns = []analysis.DetectionPattern{
		{Type: "example", Pattern: "review me", Description: "Local test rule", Source: "uri", Confidence: 8},
		{Type: "raw_example", Pattern: "%41", Description: "Raw query test rule", Source: "uri", Confidence: 8},
		{Type: "custom_header", Pattern: "x-review: marker", Description: "Header test rule", Source: "header", Confidence: 7},
		{Type: "secret_header", Pattern: "private-test-value", Description: "Sensitive header test", Source: "header", Confidence: 7},
	}
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"URI", []string{"/review me"}, []string{`Source: "uri"`, `Matched: "review me"`, "Rule: EXAMPLE-", "Severity: high"}},
		{"encoded query", []string{"--url", "https://example.org/search?q=Review%20Me"}, []string{
			`Source: "query string"`, `raw URI -> "/search?q=Review%20Me"`, `URL decode -> "/search?q=Review Me"`, `Matched: "review me"`,
		}},
		{"encoded separator in path", []string{"/search%3Ftag?q=review%20me"}, []string{`Source: "query string"`}},
		{"raw query after Unicode path", []string{"/İ?%41"}, []string{`Source: "query string"`, `Matched: "%41"`}},
		{"built-in header", []string{"--header", "user-agent: sqlmap"}, []string{`Source: "user_agent"`, "Rule: SCANNER-", "MITRE ATT&CK:"}},
		{"custom header", []string{"--header", "X-Review: Marker"}, []string{`Source: "header: X-Review"`, `raw header -> "X-Review: Marker"`}},
		{"redacted header", []string{"--header", "Authorization: private-test-value"}, []string{`Matched: "[redacted]"`}},
		{"no match", []string{"/"}, []string{"No detection rules matched."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newRulesTestCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetArgs(tc.args)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(out.String(), want) {
					t.Errorf("missing %q in:\n%s", want, &out)
				}
			}
			if strings.Contains(out.String(), "private-test-value") {
				t.Fatal("explanation disclosed the Authorization value")
			}
		})
	}
}
