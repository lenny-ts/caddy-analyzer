package cmd

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
)

var exportSigmaCmd = &cobra.Command{
	Use:   "export-sigma [output-file]",
	Short: "Export detection rules as Sigma YAML",
	Long: `Export all detection categories as Sigma rules in YAML format.

Sigma is a vendor-agnostic detection rule format. The exported rules can be
imported into Splunk, Elastic, Sigma-compatible SIEMs, or validated with
'sigma check'. Each rule includes MITRE ATT&CK technique tags.

Output:
  - Without arguments: writes to stdout
  - With a file argument: writes all rules to that file (YAML multi-document)

Examples:
  caddy-analyze export-sigma
  caddy-analyze export-sigma rules.yml
  caddy-analyze export-sigma - | sigma check
`,
	Args: cobra.MaximumNArgs(1),
	RunE: runExportSigma,
}

func init() {
	rootCmd.AddCommand(exportSigmaCmd)
}

func runExportSigma(cmd *cobra.Command, args []string) error {
	rules := analysis.ExportSigmaInfo()

	var w io.Writer = os.Stdout
	if len(args) == 1 && args[0] != "-" && args[0] != "" {
		f, err := os.Create(args[0])
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	for i, r := range rules {
		if i > 0 {
			if _, err := fmt.Fprintln(w, "---"); err != nil {
				return err
			}
		}
		if err := writeSigmaRule(w, r); err != nil {
			return err
		}
	}
	return nil
}

func writeSigmaRule(w io.Writer, r analysis.SigmaRuleInfo) error {
	uuid := sigmaUUID(r.Title)
	level := analysis.SigmaLevel(r.MaxConfidence)

	writef := func(format string, args ...any) error {
		_, err := fmt.Fprintf(w, format, args...)
		return err
	}

	if err := writef("title: %s\n", yamlEscape(r.Title)); err != nil {
		return err
	}
	if err := writef("id: %s\n", uuid); err != nil {
		return err
	}
	if err := writef("status: experimental\n"); err != nil {
		return err
	}
	if err := writef("description: %s\n", yamlEscape(r.Description)); err != nil {
		return err
	}
	if err := writef("logsource:\n"); err != nil {
		return err
	}
	if err := writef("    product: caddy\n"); err != nil {
		return err
	}
	if err := writef("    service: access\n"); err != nil {
		return err
	}

	if err := writef("detection:\n"); err != nil {
		return err
	}
	var conds []string
	if len(r.URIPatterns) > 0 {
		if err := writef("    selection_uri:\n"); err != nil {
			return err
		}
		for _, p := range r.URIPatterns {
			if err := writef("        uri|re: %s\n", yamlEscape(p)); err != nil {
				return err
			}
		}
		conds = append(conds, "selection_uri")
	}
	if len(r.UAPatterns) > 0 {
		if err := writef("    selection_ua:\n"); err != nil {
			return err
		}
		for _, p := range r.UAPatterns {
			if err := writef("        user_agent|re: %s\n", yamlEscape(p)); err != nil {
				return err
			}
		}
		conds = append(conds, "selection_ua")
	}
	if len(r.AuthPatterns) > 0 {
		if err := writef("    selection_auth:\n"); err != nil {
			return err
		}
		for _, p := range r.AuthPatterns {
			if err := writef("        authorization|re: %s\n", yamlEscape(p)); err != nil {
				return err
			}
		}
		conds = append(conds, "selection_auth")
	}
	if len(r.RawPatterns) > 0 {
		if err := writef("    selection_raw:\n"); err != nil {
			return err
		}
		for _, p := range r.RawPatterns {
			if err := writef("        raw_uri|re: %s\n", yamlEscape(p)); err != nil {
				return err
			}
		}
		conds = append(conds, "selection_raw")
	}

	if len(conds) > 0 {
		if err := writef("    condition: %s\n", strings.Join(conds, " or ")); err != nil {
			return err
		}
	} else {
		if err := writef("    condition: selection\n"); err != nil {
			return err
		}
	}

	if err := writef("fields:\n"); err != nil {
		return err
	}
	for _, f := range []string{"client_ip", "uri", "status", "method", "user_agent", "host"} {
		if err := writef("    - %s\n", f); err != nil {
			return err
		}
	}

	if len(r.FalsePositives) > 0 {
		if err := writef("falsepositives:\n"); err != nil {
			return err
		}
		for _, fp := range r.FalsePositives {
			if err := writef("    - %s\n", yamlEscape(fp)); err != nil {
				return err
			}
		}
	}

	if err := writef("level: %s\n", level); err != nil {
		return err
	}

	if len(r.Techniques) > 0 {
		if err := writef("tags:\n"); err != nil {
			return err
		}
		for _, t := range r.Techniques {
			if err := writef("    - attack.%s\n", t); err != nil {
				return err
			}
		}
	}

	return nil
}

// uuidNamespaceDNS is the DNS namespace from RFC 4122 Appendix C.
var uuidNamespaceDNS = [16]byte{
	0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
}

// sigmaNamespace is the namespace every Sigma rule UUID is derived under.
//
// Derived once, deterministically, as uuidV5(uuidNamespaceDNS,
// "caddy-analyzer"), and hardcoded thereafter. It must never change: a rule
// that has been published carries its UUID forever, and rederiving the
// namespace would silently reissue every rule under a new identity.
const sigmaNamespace = "a64194cb-8d9e-5cf8-a2c3-a0ddce730456"

// uuidV5 implements RFC 4122 section 4.3: SHA-1 over the namespace bytes
// followed by the name, truncated to 16 bytes, with the version and variant
// bits overwritten.
//
// Written against crypto/sha1 rather than taking a dependency on
// github.com/google/uuid, which would add a module for twelve lines. The
// implementation is checked against the RFC's own worked example in
// TestUUIDV5MatchesRFC4122Vector.
//
// SHA-1 is used because RFC 4122 specifies it for version 5; this is a naming
// scheme, not a security property.
func uuidV5(namespace [16]byte, name string) string {
	h := sha1.New()
	h.Write(namespace[:])
	h.Write([]byte(name))

	var u [16]byte
	copy(u[:], h.Sum(nil))
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant

	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// parseUUID reads the canonical 8-4-4-4-12 hex form.
func parseUUID(s string) ([16]byte, error) {
	var u [16]byte
	hexOnly := strings.ReplaceAll(s, "-", "")
	if len(hexOnly) != 32 {
		return u, fmt.Errorf("not a UUID: %q", s)
	}
	b, err := hex.DecodeString(hexOnly)
	if err != nil {
		return u, fmt.Errorf("not a UUID: %q: %w", s, err)
	}
	copy(u[:], b)
	return u, nil
}

func sigmaUUID(title string) string {
	// The namespace is a compile-time constant in canonical form, so this
	// cannot fail; TestSigmaNamespaceIsWellFormed proves it.
	ns, err := parseUUID(sigmaNamespace)
	if err != nil {
		panic("sigmaNamespace is not a valid UUID: " + err.Error())
	}
	return uuidV5(ns, "caddy-analyzer:sigma:"+title)
}

func yamlEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
