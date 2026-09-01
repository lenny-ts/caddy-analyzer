package cmd

import (
	"context"
	"fmt"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
	"github.com/lenny-ts/caddy-analyzer/pkg/enrich"
	"github.com/lenny-ts/caddy-analyzer/pkg/output"
	"github.com/lenny-ts/caddy-analyzer/pkg/parser"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

var (
	styleTail2xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	styleTail3xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("81")).Bold(true)
	styleTail4xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true)
	styleTail5xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styleTailDim  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleTailIP   = lipgloss.NewStyle().Foreground(lipgloss.Color("141"))
	styleTailPath = lipgloss.NewStyle().Foreground(lipgloss.Color("255"))

	// IP colors by severity — the IP itself changes color to signal danger
	styleIPCritical = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styleIPHigh     = lipgloss.NewStyle().Foreground(lipgloss.Color("160")).Bold(true)
	styleIPMedium   = lipgloss.NewStyle().Foreground(lipgloss.Color("172"))
	styleIPLow      = lipgloss.NewStyle().Foreground(lipgloss.Color("100"))

	// Threat type suffix — dim arrow + colored types
	styleThreatArrow = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleThreatCrit  = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styleThreatHigh  = lipgloss.NewStyle().Foreground(lipgloss.Color("160")).Bold(true)
	styleThreatMed   = lipgloss.NewStyle().Foreground(lipgloss.Color("172"))
	styleThreatLow   = lipgloss.NewStyle().Foreground(lipgloss.Color("100"))
)

var tailDetectLabels = map[analysis.DetectionType]string{
	analysis.DetSQLInjection:   "SQLi",
	analysis.DetNoSQLi:         "NoSQLi",
	analysis.DetXSS:            "XSS",
	analysis.DetPathTraversal:  "LFI",
	analysis.DetLog4j:          "Log4j",
	analysis.DetRCE:            "RCE",
	analysis.DetSSRF:           "SSRF",
	analysis.DetSSTI:           "SSTI",
	analysis.DetXXE:            "XXE",
	analysis.DetLFIWrapper:     "WRAP",
	analysis.DetCRLFInjection:  "CRLF",
	analysis.DetLDAPInjection:  "LDAP",
	analysis.DetXPathInjection: "XPath",
	analysis.DetProtoPollution: "Proto",
	analysis.DetSSIInjection:   "SSI",
	analysis.DetGraphQL:        "GQL",
	analysis.DetOpenRedirect:   "Redir",
	analysis.DetWPProbe:        "WP",
	analysis.DetCGIProbe:       "CGI",
	analysis.DetSensitiveFile:  "Secret",
	analysis.DetAdminProbe:     "Admin",
	analysis.DetScanner:        "SCAN",
	analysis.DetJWTAbuse:       "JWT",
	analysis.DetBeaconing:      "Beacon",
	analysis.DetObjectEnum:     "Enum",
	analysis.DetUARotation:     "UARot",
}

var tailDetect bool

var tailCmd = &cobra.Command{
	Use:          "tail [source...]",
	Short:        "Stream and colorize Caddy access logs in real time",
	RunE:         runTail,
	SilenceUsage: true,
}

func init() {
	rootCmd.AddCommand(tailCmd)
	tailCmd.Flags().BoolVarP(&tailDetect, "detect", "d", false, "Highlight suspicious entries inline (SQLi, XSS, scanners, etc.)")
}

func runTail(cmd *cobra.Command, args []string) error {
	sources, err := resolveSources(args)
	if err != nil {
		return err
	}

	filters, err := buildFilters()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var det *analysis.Detector
	if tailDetect {
		det = newDetector()
	}

	// Only spin up GeoIP when geo-based filters need it: enriching before
	// matching is required for --country/--asn, but a plain tail must not
	// trigger an mmdb auto-download.
	var geoip *enrich.GeoIP
	if geoFiltersActive(filters) {
		geoip = newGeoIPEnricher()
		if geoip != nil {
			defer func() { _ = geoip.Close() }()
		}
	}

	for line := range fanInFollow(ctx, sources) {
		entry, err := parser.Parse(line)
		if err != nil || entry == nil {
			continue
		}
		switch e := entry.(type) {
		case *types.LogEntry:
			if filters.OpsOnly {
				continue
			}
			applyForwarded(e, filters)
			enrichGeoIP(e, geoip)
			if !analysis.MatchEntry(e, filters) {
				continue
			}
			if err := printColorizedLog(e, det); err != nil {
				break
			}
		case *types.OperationalEntry:
			if !analysis.MatchOperational(e, filters) {
				continue
			}
			if err := printColorizedOperational(e); err != nil {
				break
			}
		}
	}
	return nil
}

func printColorizedLog(e *types.LogEntry, det *analysis.Detector) error {
	timeStr := styleTailDim.Render(e.Timestamp.Format("15:04:05"))
	statusStr := formatStatus(e.Status)
	methodStr := lipgloss.NewStyle().Bold(true).Render(e.Method)
	pathStr := e.Path()
	ipStr := e.RemoteIP
	if flagDefang {
		pathStr = output.Defang(pathStr)
		ipStr = output.Defang(ipStr)
	}
	pathStr = styleTailPath.Render(pathStr)
	sizeStr := output.FormatBytes(e.Size)
	durStr := output.FormatDuration(e.Duration)

	uaInfo := ""
	if e.IsBot {
		uaInfo = fmt.Sprintf(" [%s]", lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("🤖 "+e.BotName))
	} else if e.Browser != "" || e.OS != "" {
		uaInfo = fmt.Sprintf(" [%s/%s]", e.OS, e.Browser)
	}

	geoInfo := ""
	if e.Geo.CountryCode != "" {
		geoInfo = fmt.Sprintf(" [%s]", e.Geo.CountryCode)
	}

	// Run detection
	var dets []analysis.Detection
	if det != nil {
		dets = det.DetectAll(e)
	}

	// Determine IP color and threat suffix based on max confidence
	ipStyled := styleTailIP.Render(ipStr)
	threatSuffix := ""
	if len(dets) > 0 {
		var labels []string
		maxConf := 0
		seen := make(map[analysis.DetectionType]bool)
		for _, d := range dets {
			if seen[d.Type] {
				continue
			}
			seen[d.Type] = true
			if label, ok := tailDetectLabels[d.Type]; ok {
				labels = append(labels, label)
			}
			if d.Confidence > maxConf {
				maxConf = d.Confidence
			}
		}

		var ipStyle, threatStyle lipgloss.Style
		switch {
		case maxConf >= 9:
			ipStyle = styleIPCritical
			threatStyle = styleThreatCrit
		case maxConf >= 7:
			ipStyle = styleIPHigh
			threatStyle = styleThreatHigh
		case maxConf >= 5:
			ipStyle = styleIPMedium
			threatStyle = styleThreatMed
		default:
			ipStyle = styleIPLow
			threatStyle = styleThreatLow
		}
		ipStyled = ipStyle.Render(ipStr)

		if len(labels) > 0 {
			arrow := styleThreatArrow.Render(" → ")
			threatSuffix = arrow + threatStyle.Render(strings.Join(labels, " · "))
		}
	}

	_, err := fmt.Printf("%s  %s  %s %s  (%s, %s) - %s%s%s%s\n",
		timeStr, statusStr, methodStr, pathStr, sizeStr, durStr, ipStyled, geoInfo, uaInfo, threatSuffix)
	return err
}

func formatStatus(s int) string {
	str := fmt.Sprintf("%d", s)
	switch {
	case s >= 200 && s < 300:
		return styleTail2xx.Render(str + " OK")
	case s >= 300 && s < 400:
		return styleTail3xx.Render(str + " REDIR")
	case s >= 400 && s < 500:
		return styleTail4xx.Render(str + " WARN")
	case s >= 500:
		return styleTail5xx.Render(str + " ERR")
	default:
		return str
	}
}

func printColorizedOperational(e *types.OperationalEntry) error {
	timeStr := styleTailDim.Render(e.Timestamp.Format("15:04:05"))

	var lvlStr string
	switch e.Level {
	case "error":
		lvlStr = styleTail5xx.Render("ERROR")
	case "warn":
		lvlStr = styleTail4xx.Render("WARN ")
	case "debug":
		lvlStr = styleTailDim.Render("DEBUG")
	default:
		lvlStr = styleTail3xx.Render("INFO ")
	}

	loggerStr := ""
	if e.Logger != "" {
		loggerStr = styleTailIP.Render("[" + e.Logger + "]")
	}

	msgStr := e.Msg
	if flagDefang {
		msgStr = output.Defang(msgStr)
	}

	// Show up to 3 extra fields inline for context (upstream target,
	// error message, config path, etc.). Sort keys for deterministic
	// output — Go randomizes map iteration order.
	keys := make([]string, 0, len(e.Extra))
	for k := range e.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var extras []string
	for _, k := range keys {
		vs := strings.Trim(string(e.Extra[k]), `"`)
		if flagDefang {
			vs = output.Defang(vs)
		}
		extras = append(extras, fmt.Sprintf("%s=%s", k, vs))
		if len(extras) >= 3 {
			break
		}
	}
	extraStr := ""
	if len(extras) > 0 {
		extraStr = styleTailDim.Render(" " + strings.Join(extras, " "))
	}

	_, err := fmt.Printf("%s  %s  %s  %s%s\n", timeStr, lvlStr, loggerStr, msgStr, extraStr)
	return err
}
