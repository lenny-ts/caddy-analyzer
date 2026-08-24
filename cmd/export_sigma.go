package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
)

// sigmaNamespace is the fixed namespace UUID used to derive deterministic
// UUIDv5 identifiers for exported Sigma rules. It is generated once and must
// never change, otherwise existing rules would receive new UUIDs on every run.
var sigmaNamespace = uuid.MustParse("d17af9d5-d714-40a0-a935-8bc80b980109")

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
			if err := writef("        uri|re: %s\n", yamlQuote(p)); err != nil {
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
			if err := writef("        user_agent|re: %s\n", yamlQuote(p)); err != nil {
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
			if err := writef("        authorization|re: %s\n", yamlQuote(p)); err != nil {
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
			if err := writef("        raw_uri|re: %s\n", yamlQuote(p)); err != nil {
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

func sigmaUUID(title string) string {
	return uuid.NewSHA1(sigmaNamespace, []byte("caddy-analyzer:sigma:"+title)).String()
}

func yamlEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func yamlQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
