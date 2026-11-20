package cmd

import (
	"fmt"
	"io"
	"net/textproto"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
	"github.com/lenny-ts/caddy-analyzer/pkg/output"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func init() {
	rules := &cobra.Command{Use: "rules", Short: "Inspect detection rule matches"}
	rules.AddCommand(newRulesTestCmd())
	rootCmd.AddCommand(rules)
}

func newRulesTestCmd() *cobra.Command {
	var address string
	var headers []string
	cmd := &cobra.Command{
		Use:   "test [request-target]",
		Short: "Test detection rules against one local request (no network requests)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			entry := types.LogEntry{Headers: make(map[string][]string)}
			switch {
			case cmd.Flags().Changed("url"):
				if len(args) != 0 {
					return fmt.Errorf("use either a request-target or --url, not both")
				}
				u, err := url.Parse(address)
				if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
					return fmt.Errorf("--url requires a valid absolute HTTP or HTTPS URL")
				}
				entry.URI = u.RequestURI()
			case len(args) > 0:
				entry.URI = args[0]
			case len(headers) == 0:
				return fmt.Errorf("provide a request-target, --url or --header")
			default:
				entry.URI = "/"
			}
			for _, header := range headers {
				name, value, ok := strings.Cut(header, ":")
				name = textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(name))
				if !ok || name == "" || strings.ContainsAny(header, "\r\n\x00") ||
					strings.ContainsFunc(name, func(r rune) bool {
						return !strings.ContainsRune("!#$%&'*+-.^_`|~", r) &&
							!(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
					}) {
					return fmt.Errorf("--header requires Name: Value")
				}
				entry.Headers[name] = append(entry.Headers[name], strings.TrimSpace(value))
			}
			for name, values := range entry.Headers {
				switch name {
				case "User-Agent":
					entry.UserAgent = values[0]
				case "Authorization":
					entry.Authorization = values[0][:min(500, len(values[0]))]
				}
			}
			w := cmd.OutOrStdout()
			det := analysis.NewDetectorWithPatterns(customPatterns)
			det.SetExplain(func(x analysis.Explanation) { printDetectionExplanation(w, x, flagDefang) })
			if len(det.DetectAll(&entry)) == 0 {
				fmt.Fprintln(w, "No detection rules matched.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&address, "url", "", "Absolute HTTP or HTTPS URL; test its request target")
	cmd.Flags().StringArrayVar(&headers, "header", nil, "Request header as Name: Value (repeatable)")
	return cmd
}

func printDetectionExplanation(w io.Writer, x analysis.Explanation, defang bool) {
	value := func(s string) string {
		if defang {
			return output.Defang(s)
		}
		return s
	}
	fmt.Fprintf(w, "Detection: %q\n", x.Detection.Type)
	if x.RuleID != "" {
		fmt.Fprintf(w, "Rule: %s\n", x.RuleID)
	}
	fmt.Fprintf(w, "Reason: %q\nConfidence: %d/10\nSeverity: %s\nSource: %q\n",
		value(x.Detection.Desc), x.Detection.Confidence, analysis.SigmaLevel(x.Detection.Confidence), x.Source)
	if x.RuleID != "" {
		fmt.Fprintf(w, "Matched: %q\nNormalization:\n", value(x.Matched))
		for _, stage := range x.Stages {
			fmt.Fprintf(w, "  %s -> %q\n", stage.Name, value(stage.Value))
		}
	}
	if len(x.Detection.Techniques) != 0 {
		fmt.Fprintf(w, "MITRE ATT&CK: %q\n", strings.Join(x.Detection.Techniques, ", "))
	}
	fmt.Fprintln(w)
}
