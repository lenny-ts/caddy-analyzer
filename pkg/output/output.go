package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatCSV   Format = "csv"
	FormatHTML  Format = "html"
)

var (
	styleHeader = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99"))
	styleLabel  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
	styleOK     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleWarn   = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	styleError  = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	styleInfo   = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
	styleDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleBar    = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))

	styleList2xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	styleList3xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("81")).Bold(true)
	styleList4xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true)
	styleList5xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styleListDim  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleListIP   = lipgloss.NewStyle().Foreground(lipgloss.Color("141"))
	styleListPath = lipgloss.NewStyle().Foreground(lipgloss.Color("255"))
)

func ParseFormat(s string) Format {
	switch strings.ToLower(s) {
	case "json":
		return FormatJSON
	case "csv":
		return FormatCSV
	case "html":
		return FormatHTML
	default:
		return FormatTable
	}
}

type Report struct {
	engine   *analysis.Engine
	opStats  *types.OperationalStats
	format   Format
	top      int
	sections types.TopSections
	writer   io.Writer
	detect   bool
	defang   bool
	filters  types.Filters
}

func NewReport(engine *analysis.Engine, format Format, top int) *Report {
	return &Report{
		engine:   engine,
		format:   format,
		top:      top,
		sections: types.DefaultTopSections(),
		writer:   os.Stdout,
	}
}

func NewReportWithSections(engine *analysis.Engine, format Format, top int, sections types.TopSections) *Report {
	return &Report{
		engine:   engine,
		format:   format,
		top:      top,
		sections: sections,
		writer:   os.Stdout,
	}
}

func (r *Report) SetWriter(w io.Writer) {
	r.writer = w
}

func (r *Report) SetDetect(d bool) {
	r.detect = d
}

func (r *Report) SetDefang(d bool) {
	r.defang = d
}

func (r *Report) SetFilters(f types.Filters) {
	r.filters = f
}

func (r *Report) SetOperationalStats(s *types.OperationalStats) {
	r.opStats = s
}

func (r *Report) activeFilters() []string {
	var f []string
	if r.filters.HasFrom {
		f = append(f, "--from "+r.filters.From.Format(time.RFC3339))
	}
	if r.filters.HasTo {
		f = append(f, "--to "+r.filters.To.Format(time.RFC3339))
	}
	if len(r.filters.Status) > 0 {
		strs := make([]string, len(r.filters.Status))
		for i, s := range r.filters.Status {
			strs[i] = fmt.Sprintf("%d", s)
		}
		f = append(f, "--status "+strings.Join(strs, ","))
	}
	if r.filters.Method != "" {
		f = append(f, "--method "+r.filters.Method)
	}
	if r.filters.PathGlob != "" {
		f = append(f, "--path "+r.filters.PathGlob)
	}
	if r.filters.Host != "" {
		f = append(f, "--host "+r.filters.Host)
	}
	if r.filters.RemoteIP != "" {
		f = append(f, "--ip "+r.filters.RemoteIP)
	}
	if r.filters.ExcludeIP != "" {
		f = append(f, "--exclude-ip "+r.filters.ExcludeIP)
	}
	if r.filters.Only2xx {
		f = append(f, "--2xx")
	}
	if r.filters.Only3xx {
		f = append(f, "--3xx")
	}
	if r.filters.Only4xx {
		f = append(f, "--4xx")
	}
	if r.filters.Only5xx {
		f = append(f, "--5xx")
	}
	if r.filters.ErrorsOnly {
		f = append(f, "--errors-only")
	}
	if r.filters.NoBots {
		f = append(f, "--no-bots")
	}
	if r.filters.BotsOnly {
		f = append(f, "--bots-only")
	}
	if r.filters.MinLatency > 0 {
		f = append(f, "--slow "+fmt.Sprintf("%.0fms", r.filters.MinLatency*1000))
	}
	if r.filters.GrepPattern != "" {
		f = append(f, "--grep "+r.filters.GrepPattern)
	}
	return f
}

func (r *Report) Print() error {
	if r.defang {
		s := r.engine.Stats()
		orig := statsMaps{
			remoteIPCounts:       s.RemoteIPCounts,
			remoteAddrCounts:     s.RemoteAddrCounts,
			ipBytesMap:           s.IPBytesMap,
			suspiciousIPs:        s.SuspiciousIPs,
			suspiciousDetails:    s.SuspiciousDetails,
			suspiciousDetections: s.SuspiciousDetections,
		}
		s.RemoteIPCounts = defangMap(s.RemoteIPCounts)
		s.RemoteAddrCounts = defangMap(s.RemoteAddrCounts)
		s.IPBytesMap = defangMap(s.IPBytesMap)
		s.SuspiciousIPs = defangMap(s.SuspiciousIPs)
		s.SuspiciousDetails = defangStringSliceMap(s.SuspiciousDetails)
		s.SuspiciousDetections = defangDetectionMap(s.SuspiciousDetections)
		defer func() {
			s.RemoteIPCounts = orig.remoteIPCounts
			s.RemoteAddrCounts = orig.remoteAddrCounts
			s.IPBytesMap = orig.ipBytesMap
			s.SuspiciousIPs = orig.suspiciousIPs
			s.SuspiciousDetails = orig.suspiciousDetails
			s.SuspiciousDetections = orig.suspiciousDetections
		}()
	}
	switch r.format {
	case FormatJSON:
		return r.printJSON()
	case FormatCSV:
		return r.printCSV()
	case FormatHTML:
		return r.printHTML()
	default:
		return r.printTable()
	}
}

type statsMaps struct {
	remoteIPCounts       map[string]int64
	remoteAddrCounts     map[string]int64
	ipBytesMap           map[string]int64
	suspiciousIPs        map[string]int64
	suspiciousDetails    map[string][]string
	suspiciousDetections map[string][]types.DetectionRecord
}

func defangMap(m map[string]int64) map[string]int64 {
	if m == nil {
		return m
	}
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[Defang(k)] = v
	}
	return out
}

func defangStringSliceMap(m map[string][]string) map[string][]string {
	if m == nil {
		return m
	}
	out := make(map[string][]string, len(m))
	for k, v := range m {
		dv := make([]string, len(v))
		for i, s := range v {
			dv[i] = Defang(s)
		}
		out[Defang(k)] = dv
	}
	return out
}

func defangDetectionMap(m map[string][]types.DetectionRecord) map[string][]types.DetectionRecord {
	if m == nil {
		return m
	}
	out := make(map[string][]types.DetectionRecord, len(m))
	for k, v := range m {
		dv := make([]types.DetectionRecord, len(v))
		for i, r := range v {
			r.URI = Defang(r.URI)
			r.Desc = Defang(r.Desc)
			dv[i] = r
		}
		out[Defang(k)] = dv
	}
	return out
}

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	if err != nil {
		e.err = err
	}
	return n, err
}

func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func IsTerminal(w io.Writer) bool {
	return isTerminalWriter(w)
}

func stripANSI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x1b {
			i++
			if i >= len(s) {
				break
			}
			switch s[i] {
			case '[': // CSI: consume parameters and final byte
				for i+1 < len(s) {
					i++
					if s[i] >= 0x40 && s[i] <= 0x7e {
						break
					}
				}
			case ']': // OSC: consume until BEL
				for i+1 < len(s) {
					i++
					if s[i] == 0x07 {
						break
					}
				}
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func csvSafe(s string) string {
	if s == "" {
		return s
	}
	// Tab and CR at position 0 are formula triggers in some spreadsheets.
	if s[0] == '\t' || s[0] == '\r' {
		return "'" + s
	}
	// Defeat formula injection in spreadsheet apps (Excel, LibreOffice,
	// Google Sheets): any cell whose first non-whitespace byte is one of
	// the formula trigger characters gets a single-quote prefix. Trim left
	// first so leading spaces cannot smuggle a "=" past the check.
	trimmed := strings.TrimLeft(s, " \t\r\n")
	if len(trimmed) == 0 {
		return s
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return "'" + s
	}
	return s
}

func SafeCell(s string) string {
	return csvSafe(stripANSI(s))
}

func (r *Report) printTable() error {
	s := r.engine.Stats()
	total := s.TotalRequests
	useColor := r.useColor()

	ew := &errWriter{w: r.writer}

	if r.detect {
		return r.printDetectTable(s, total, useColor, ew)
	}

	if useColor {
		_, _ = fmt.Fprintln(ew, styleHeader.Render("CADDY LOG ANALYSIS REPORT"))
		_, _ = fmt.Fprintln(ew, styleDim.Render(strings.Repeat("=", 45)))
	} else {
		_, _ = fmt.Fprintln(ew, "CADDY LOG ANALYSIS REPORT")
		_, _ = fmt.Fprintln(ew, strings.Repeat("=", 45))
	}
	if filters := r.activeFilters(); len(filters) > 0 {
		if useColor {
			_, _ = fmt.Fprintf(ew, "%s %s\n", styleInfo.Render("Filters:"), strings.Join(filters, "  "))
		} else {
			_, _ = fmt.Fprintf(ew, "Filters: %s\n", strings.Join(filters, "  "))
		}
	}
	_, _ = fmt.Fprintln(ew)

	w := tabwriter.NewWriter(ew, 0, 0, 3, ' ', 0)

	duration := "N/A"
	if !s.EndTime.IsZero() && !s.StartTime.IsZero() {
		duration = s.EndTime.Sub(s.StartTime).Round(time.Second).String()
	}

	label := "Period:"
	if useColor {
		label = styleLabel.Render("Period:")
	}
	_, _ = fmt.Fprintf(w, "%s\t%s — %s (%s)\n", label, formatTime(s.StartTime), formatTime(s.EndTime), duration)

	label = "Total Requests:"
	if useColor {
		label = styleLabel.Render("Total Requests:")
	}
	_, _ = fmt.Fprintf(w, "%s\t%d\n", label, total)

	label = "Requests/sec:"
	if useColor {
		label = styleLabel.Render("Requests/sec:")
	}
	_, _ = fmt.Fprintf(w, "%s\t%.2f\n\n", label, r.engine.RPS())

	statusLabel := "Status Codes Breakdown"
	if useColor {
		statusLabel = styleLabel.Render("Status Codes Breakdown")
	}
	_, _ = fmt.Fprintf(w, "%s:\n", statusLabel)

	renderLabel := func(style lipgloss.Style, text string) string {
		if useColor {
			return style.Render(text)
		}
		return text
	}

	_, _ = fmt.Fprintf(w, "  %s\t%d (%.1f%%)\t%s\n", renderLabel(styleOK, "2xx Success:"), s.Status2xx, Pct(s.Status2xx, total), renderBarGraph(s.Status2xx, total, 15, useColor))
	_, _ = fmt.Fprintf(w, "  %s\t%d (%.1f%%)\t%s\n", renderLabel(styleInfo, "3xx Redirect:"), s.Status3xx, Pct(s.Status3xx, total), renderBarGraph(s.Status3xx, total, 15, useColor))
	_, _ = fmt.Fprintf(w, "  %s\t%d (%.1f%%)\t%s\n", renderLabel(styleWarn, "4xx Client Err:"), s.Status4xx, Pct(s.Status4xx, total), renderBarGraph(s.Status4xx, total, 15, useColor))
	_, _ = fmt.Fprintf(w, "  %s\t%d (%.1f%%)\t%s\n", renderLabel(styleError, "5xx Server Err:"), s.Status5xx, Pct(s.Status5xx, total), renderBarGraph(s.Status5xx, total, 15, useColor))

	errStyle := styleOK
	if s.Errors > 0 {
		errStyle = styleError
	}
	_, _ = fmt.Fprintf(w, "  %s\t%d (%.1f%%)\n\n", renderLabel(errStyle, "Total Errors (5xx):"), s.Errors, Pct(s.Errors, total))

	szLabel := "Response Size & Bandwidth"
	if useColor {
		szLabel = styleLabel.Render("Response Size & Bandwidth")
	}
	_, _ = fmt.Fprintf(w, "%s:\n", szLabel)
	_, _ = fmt.Fprintf(w, "  %s\t%s\n", "Total Transferred:", FormatBytes(s.TotalBytes))
	_, _ = fmt.Fprintf(w, "  %s\t%s\n\n", "Avg Response Size:", FormatBytes(AvgSize(s.TotalBytes, total)))

	durLabel := "Duration & Latency"
	if useColor {
		durLabel = styleLabel.Render("Duration & Latency")
	}
	_, _ = fmt.Fprintf(w, "%s:\n", durLabel)
	_, _ = fmt.Fprintf(w, "  %s\t%s\n", "Avg Latency:", FormatDuration(r.engine.AvgDuration()))
	_, _ = fmt.Fprintf(w, "  %s\t%s\n", "Min Latency:", FormatDuration(s.MinDuration))
	_, _ = fmt.Fprintf(w, "  %s\t%s\n", "Max Latency:", FormatDuration(s.MaxDuration))
	_, _ = fmt.Fprintf(w, "  %s\t%s\n", "P50 Latency:", FormatDuration(s.Percentile50))
	_, _ = fmt.Fprintf(w, "  %s\t%s\n", "P95 Latency:", FormatDuration(s.Percentile95))
	_, _ = fmt.Fprintf(w, "  %s\t%s\n\n", "P99 Latency:", FormatDuration(s.Percentile99))

	botLabel := "Traffic & User-Agent Classification"
	if useColor {
		botLabel = styleLabel.Render("Traffic & User-Agent Classification")
	}
	_, _ = fmt.Fprintf(w, "%s:\n", botLabel)
	_, _ = fmt.Fprintf(w, "  %s\t%d (%.1f%%)\n", "Human Requests:", s.HumanRequests, Pct(s.HumanRequests, total))
	_, _ = fmt.Fprintf(w, "  %s\t%d (%.1f%%)\n\n", "Bot / Crawler Requests:", s.BotRequests, Pct(s.BotRequests, total))

	if s.ParseErrors > 0 {
		_, _ = fmt.Fprintf(w, "%s\t%d\n\n", renderLabel(styleError, "Parse Errors:"), s.ParseErrors)
	}

	if r.top > 0 {
		if r.sections.Path {
			title := fmt.Sprintf("Top %d Paths", r.top)
			if useColor {
				title = styleLabel.Render(title)
			}
			_, _ = fmt.Fprintf(w, "%s:\n", title)
			printTopNWithBar(w, analysis.TopN(s.PathCounts, r.top), total, useColor)
		}
		if r.sections.IP {
			_, _ = fmt.Fprintf(w, "\n")
			title := fmt.Sprintf("Top %d Remote IPs", r.top)
			if useColor {
				title = styleLabel.Render(title)
			}
			_, _ = fmt.Fprintf(w, "%s:\n", title)
			printTopNWithBar(w, analysis.TopN(s.RemoteIPCounts, r.top), total, useColor)
		}
		if r.sections.UA {
			_, _ = fmt.Fprintf(w, "\n")
			title := fmt.Sprintf("Top %d User Agents", r.top)
			if useColor {
				title = styleLabel.Render(title)
			}
			_, _ = fmt.Fprintf(w, "%s:\n", title)
			printTopNWithBar(w, analysis.TopN(s.UserAgentCounts, r.top), total, useColor)
		}
		if r.sections.Method {
			_, _ = fmt.Fprintf(w, "\n")
			title := fmt.Sprintf("Top %d Methods", r.top)
			if useColor {
				title = styleLabel.Render(title)
			}
			_, _ = fmt.Fprintf(w, "%s:\n", title)
			printTopNWithBar(w, analysis.TopN(s.MethodCounts, r.top), total, useColor)
		}
		if r.sections.Status {
			_, _ = fmt.Fprintf(w, "\n")
			title := fmt.Sprintf("Top %d Status Codes", r.top)
			if useColor {
				title = styleLabel.Render(title)
			}
			_, _ = fmt.Fprintf(w, "%s:\n", title)
			printTopIntN(w, analysis.TopNInt(s.StatusCounts, r.top))
		}
		if r.sections.Host {
			_, _ = fmt.Fprintf(w, "\n")
			title := fmt.Sprintf("Top %d Hosts", r.top)
			if useColor {
				title = styleLabel.Render(title)
			}
			_, _ = fmt.Fprintf(w, "%s:\n", title)
			printTopNWithBar(w, analysis.TopN(s.HostCounts, r.top), total, useColor)
		}
		if r.sections.Country && len(s.CountryCounts) > 0 {
			_, _ = fmt.Fprintf(w, "\n")
			title := fmt.Sprintf("Top %d Countries", r.top)
			if useColor {
				title = styleLabel.Render(title)
			}
			_, _ = fmt.Fprintf(w, "%s:\n", title)
			printTopNWithBar(w, renameItems(analysis.TopN(s.CountryCounts, r.top), s.CountryNames), total, useColor)
		}
		if r.sections.ASN && len(s.ASNCounts) > 0 {
			_, _ = fmt.Fprintf(w, "\n")
			title := fmt.Sprintf("Top %d Autonomous Systems", r.top)
			if useColor {
				title = styleLabel.Render(title)
			}
			_, _ = fmt.Fprintf(w, "%s:\n", title)
			printTopNWithBar(w, analysis.TopN(s.ASNCounts, r.top), total, useColor)
		}
	}

	r.printOperationalTable(w, useColor)

	if err := w.Flush(); err != nil {
		return err
	}
	return ew.err
}

func (r *Report) printOperationalTable(w *tabwriter.Writer, useColor bool) {
	if r.opStats == nil || r.opStats.TotalEvents == 0 {
		return
	}
	op := r.opStats

	_, _ = fmt.Fprintf(w, "\n")
	label := "Operational Events"
	if useColor {
		label = styleLabel.Render(label)
	}
	_, _ = fmt.Fprintf(w, "%s:\n", label)
	_, _ = fmt.Fprintf(w, "  %s\t%d\n", "Total Events:", op.TotalEvents)
	if op.Errors > 0 {
		errLabel := "Errors:"
		if useColor {
			errLabel = styleError.Render("Errors:")
		}
		_, _ = fmt.Fprintf(w, "  %s\t%d\n", errLabel, op.Errors)
	}

	// Level breakdown
	for _, lvl := range []string{"error", "warn", "info", "debug"} {
		if c, ok := op.LevelCounts[lvl]; ok && c > 0 {
			lvlLabel := lvl + ":"
			if useColor {
				switch lvl {
				case "error":
					lvlLabel = styleError.Render(lvlLabel)
				case "warn":
					lvlLabel = styleWarn.Render(lvlLabel)
				case "info":
					lvlLabel = styleOK.Render(lvlLabel)
				default:
					lvlLabel = styleDim.Render(lvlLabel)
				}
			}
			_, _ = fmt.Fprintf(w, "  %s\t%d\n", lvlLabel, c)
		}
	}

	// Top loggers
	if len(op.LoggerCounts) > 0 {
		_, _ = fmt.Fprintf(w, "\n")
		logLabel := "Top Loggers"
		if useColor {
			logLabel = styleLabel.Render(logLabel)
		}
		_, _ = fmt.Fprintf(w, "%s:\n", logLabel)
		printTopNWithBar(w, analysis.TopN(op.LoggerCounts, r.top), op.TotalEvents, useColor)
	}

	// Top messages
	if len(op.MsgCounts) > 0 {
		_, _ = fmt.Fprintf(w, "\n")
		msgLabel := "Top Messages"
		if useColor {
			msgLabel = styleLabel.Render(msgLabel)
		}
		_, _ = fmt.Fprintf(w, "%s:\n", msgLabel)
		printTopNWithBar(w, analysis.TopN(op.MsgCounts, r.top), op.TotalEvents, useColor)
	}
	_, _ = fmt.Fprintf(w, "\n")
}

func (r *Report) printDetectTable(s *types.Stats, total int64, useColor bool, ew *errWriter) error {
	if useColor {
		_, _ = fmt.Fprintln(ew, styleHeader.Render("SECURITY THREAT INSPECTION REPORT"))
		_, _ = fmt.Fprintln(ew, styleDim.Render(strings.Repeat("=", 50)))
	} else {
		_, _ = fmt.Fprintln(ew, "SECURITY THREAT INSPECTION REPORT")
		_, _ = fmt.Fprintln(ew, strings.Repeat("=", 50))
	}
	_, _ = fmt.Fprintln(ew)

	w := tabwriter.NewWriter(ew, 0, 0, 3, ' ', 0)

	duration := "N/A"
	if !s.EndTime.IsZero() && !s.StartTime.IsZero() {
		duration = s.EndTime.Sub(s.StartTime).Round(time.Second).String()
	}

	label := "Period:"
	if useColor {
		label = styleLabel.Render("Period:")
	}
	_, _ = fmt.Fprintf(w, "%s\t%s — %s (%s)\n", label, formatTime(s.StartTime), formatTime(s.EndTime), duration)

	label = "Total Analyzed:"
	if useColor {
		label = styleLabel.Render("Total Analyzed:")
	}
	_, _ = fmt.Fprintf(w, "%s\t%d requests\n\n", label, total)

	if len(s.SuspiciousIPs) > 0 {
		alertLabel := fmt.Sprintf("[ALERT] THREAT ALERTS DETECTED (%d suspicious IPs)", len(s.SuspiciousIPs))
		if useColor {
			alertLabel = styleError.Render(alertLabel)
		}
		_, _ = fmt.Fprintf(w, "%s\n", alertLabel)

		_, _ = fmt.Fprintf(w, "Top Offending IPs:\n")
		items := analysis.TopN(s.SuspiciousIPs, 10)
		for _, item := range items {
			ipLine := fmt.Sprintf("  - %-18s %d malicious requests", stripANSI(item.Key), item.Count)
			if useColor {
				ipLine = styleError.Render(ipLine)
			}
			_, _ = fmt.Fprintf(w, "%s\n", ipLine)
			if details, ok := s.SuspiciousDetails[item.Key]; ok && len(details) > 0 {
				for _, d := range details {
					detailLine := fmt.Sprintf("       %s", stripANSI(d))
					if useColor {
						detailLine = styleWarn.Render(detailLine)
					}
					_, _ = fmt.Fprintf(w, "%s\n", detailLine)
				}
			}
		}
		_, _ = fmt.Fprintf(w, "\nHint: Run 'sudo caddy-analyze guard' to auto-block malicious IPs via iptables\n")
	} else {
		cleanMsg := fmt.Sprintf("[OK] CLEAN: 0 security threats or scanner probes detected across %d requests", total)
		if useColor {
			cleanMsg = styleOK.Render(cleanMsg)
		}
		_, _ = fmt.Fprintf(w, "%s\n", cleanMsg)
	}

	if err := w.Flush(); err != nil {
		return err
	}
	return ew.err
}

func (r *Report) useColor() bool {
	return r.format == FormatTable && isTerminalWriter(r.writer)
}

func renderBarGraph(count, total int64, width int, useColor bool) string {
	if total <= 0 || count <= 0 {
		return strings.Repeat("░", width)
	}
	ratio := float64(count) / float64(total)
	filled := int(ratio * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 1 && count > 0 {
		filled = 1
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	if useColor {
		return styleBar.Render(bar)
	}
	return bar
}

func printTopNWithBar(w io.Writer, items []types.CountItem, total int64, useColor bool) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, item := range items {
		bar := renderBarGraph(item.Count, total, 12, useColor)
		_, _ = fmt.Fprintf(tw, "  %d.\t%-35s\t(%d)\t%s\n", i+1, stripANSI(item.Key), item.Count, bar)
	}
	_ = tw.Flush()
}

func (r *Report) printJSON() error {
	s := r.engine.Stats()
	total := s.TotalRequests

	data := map[string]interface{}{
		"total_requests": total,
		"period": map[string]interface{}{
			"start": s.StartTime,
			"end":   s.EndTime,
		},
		"filters":             r.activeFilters(),
		"requests_per_second": r.engine.RPS(),
		"status_codes": map[string]interface{}{
			"2xx":     s.Status2xx,
			"3xx":     s.Status3xx,
			"4xx":     s.Status4xx,
			"5xx":     s.Status5xx,
			"errors":  s.Errors,
			"by_code": s.StatusCounts,
		},
		"traffic": map[string]interface{}{
			"human": s.HumanRequests,
			"bot":   s.BotRequests,
		},
		"response_size": map[string]int64{
			"total": s.TotalBytes,
			"avg":   AvgSize(s.TotalBytes, total),
		},
		"duration": map[string]float64{
			"avg": r.engine.AvgDuration(),
			"min": s.MinDuration,
			"max": s.MaxDuration,
			"p50": s.Percentile50,
			"p95": s.Percentile95,
			"p99": s.Percentile99,
		},
		"parse_errors": s.ParseErrors,
	}

	if r.detect && len(s.SuspiciousIPs) > 0 {
		data["suspicious_ips"] = analysis.TopN(s.SuspiciousIPs, 20)
		data["suspicious_details"] = s.SuspiciousDetails
		data["detections"] = s.SuspiciousDetections
	}

	if r.top > 0 {
		if r.sections.Path {
			data["top_paths"] = analysis.TopN(s.PathCounts, r.top)
		}
		if r.sections.IP {
			data["top_ips"] = analysis.TopN(s.RemoteIPCounts, r.top)
		}
		if r.sections.UA {
			data["top_user_agents"] = analysis.TopN(s.UserAgentCounts, r.top)
		}
		if r.sections.Method {
			data["top_methods"] = analysis.TopN(s.MethodCounts, r.top)
		}
		if r.sections.Status {
			data["top_statuses"] = analysis.TopNInt(s.StatusCounts, r.top)
		}
		if r.sections.Host {
			data["top_hosts"] = analysis.TopN(s.HostCounts, r.top)
		}
		if r.sections.Country && len(s.CountryCounts) > 0 {
			data["top_countries"] = analysis.TopN(s.CountryCounts, r.top)
		}
		if r.sections.ASN && len(s.ASNCounts) > 0 {
			data["top_asns"] = analysis.TopN(s.ASNCounts, r.top)
		}
	}

	if r.opStats != nil && r.opStats.TotalEvents > 0 {
		data["operational"] = map[string]interface{}{
			"total_events":   r.opStats.TotalEvents,
			"errors":         r.opStats.Errors,
			"level_counts":   r.opStats.LevelCounts,
			"logger_counts":  analysis.TopN(r.opStats.LoggerCounts, r.top),
			"message_counts": analysis.TopN(r.opStats.MsgCounts, r.top),
		}
	}

	enc := json.NewEncoder(r.writer)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func (r *Report) printCSV() error {
	s := r.engine.Stats()
	total := s.TotalRequests

	ew := &errWriter{w: r.writer}
	w := csv.NewWriter(ew)

	write := func(row []string) {
		for i, cell := range row {
			row[i] = SafeCell(cell)
		}
		_ = w.Write(row)
	}
	writeSection := func(header []string) {
		_ = w.Write(nil)
		write(header)
	}
	writePair := func(k, v string) {
		write([]string{k, v})
	}

	write([]string{"metric", "value"})
	for _, fl := range r.activeFilters() {
		writePair("filter", fl)
	}
	writePair("total_requests", fmt.Sprintf("%d", total))
	writePair("rps", fmt.Sprintf("%.2f", r.engine.RPS()))
	writePair("avg_duration_seconds", fmt.Sprintf("%.6f", r.engine.AvgDuration()))
	writePair("status_2xx", fmt.Sprintf("%d", s.Status2xx))
	writePair("status_3xx", fmt.Sprintf("%d", s.Status3xx))
	writePair("status_4xx", fmt.Sprintf("%d", s.Status4xx))
	writePair("status_5xx", fmt.Sprintf("%d", s.Status5xx))
	writePair("errors", fmt.Sprintf("%d", s.Errors))
	writePair("human_requests", fmt.Sprintf("%d", s.HumanRequests))
	writePair("bot_requests", fmt.Sprintf("%d", s.BotRequests))
	writePair("total_bytes", fmt.Sprintf("%d", s.TotalBytes))
	writePair("parse_errors", fmt.Sprintf("%d", s.ParseErrors))
	writePair("duration_p50", fmt.Sprintf("%.6f", s.Percentile50))
	writePair("duration_p95", fmt.Sprintf("%.6f", s.Percentile95))
	writePair("duration_p99", fmt.Sprintf("%.6f", s.Percentile99))

	if r.detect && len(s.SuspiciousIPs) > 0 {
		writeSection([]string{"suspicious_ips:ip", "count"})
		for _, item := range analysis.TopN(s.SuspiciousIPs, 20) {
			writePair(item.Key, fmt.Sprintf("%d", item.Count))
			if details, ok := s.SuspiciousDetails[item.Key]; ok {
				for _, d := range details {
					writePair(item.Key+":detail", d)
				}
			}
		}
	}

	if r.top > 0 {
		if r.sections.Path {
			writeSection([]string{"top_paths:path", "count"})
			for _, item := range analysis.TopN(s.PathCounts, r.top) {
				writePair(item.Key, fmt.Sprintf("%d", item.Count))
			}
		}
		if r.sections.IP {
			writeSection([]string{"top_ips:ip", "count"})
			for _, item := range analysis.TopN(s.RemoteIPCounts, r.top) {
				writePair(item.Key, fmt.Sprintf("%d", item.Count))
			}
		}
		if r.sections.Country && len(s.CountryCounts) > 0 {
			writeSection([]string{"top_countries:country", "count"})
			for _, item := range analysis.TopN(s.CountryCounts, r.top) {
				writePair(item.Key, fmt.Sprintf("%d", item.Count))
			}
		}
		if r.sections.ASN && len(s.ASNCounts) > 0 {
			writeSection([]string{"top_asns:asn", "count"})
			for _, item := range analysis.TopN(s.ASNCounts, r.top) {
				writePair(item.Key, fmt.Sprintf("%d", item.Count))
			}
		}
	}

	if r.opStats != nil && r.opStats.TotalEvents > 0 {
		writeSection([]string{"operational:metric", "value"})
		writePair("op_total_events", fmt.Sprintf("%d", r.opStats.TotalEvents))
		writePair("op_errors", fmt.Sprintf("%d", r.opStats.Errors))
		for _, lvl := range []string{"error", "warn", "info", "debug"} {
			if c, ok := r.opStats.LevelCounts[lvl]; ok && c > 0 {
				writePair("op_level:"+lvl, fmt.Sprintf("%d", c))
			}
		}
		writeSection([]string{"operational_loggers:logger", "count"})
		for _, item := range analysis.TopN(r.opStats.LoggerCounts, r.top) {
			writePair(item.Key, fmt.Sprintf("%d", item.Count))
		}
		writeSection([]string{"operational_messages:message", "count"})
		for _, item := range analysis.TopN(r.opStats.MsgCounts, r.top) {
			writePair(item.Key, fmt.Sprintf("%d", item.Count))
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return ew.err
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(time.RFC3339)
}

// Pct returns n as a percentage of total (0 if total is 0). Shared between the
// report formatter and the TUI dashboard so the percentage math stays in one
// place.
func Pct(n, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

// AvgSize returns the average response size given a total byte count and a
// request count (0 if count is 0). Shared between the report formatter and the
// TUI dashboard.
func AvgSize(total int64, count int64) int64 {
	if count == 0 {
		return 0
	}
	return total / count
}

func FormatBytes(b int64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%d B", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.2f KB", float64(b)/1024)
	case b < 1024*1024*1024:
		return fmt.Sprintf("%.2f MB", float64(b)/(1024*1024))
	default:
		return fmt.Sprintf("%.2f GB", float64(b)/(1024*1024*1024))
	}
}

func FormatDuration(d float64) string {
	if d <= 0 || d >= 1e18 {
		return "N/A"
	}
	switch {
	case d < 0.001:
		return fmt.Sprintf("%.0f\xc2\xb5s", d*1_000_000)
	case d < 1:
		return fmt.Sprintf("%.2fms", d*1000)
	case d < 60:
		return fmt.Sprintf("%.2fs", d)
	default:
		return fmt.Sprintf("%.1fm", d/60)
	}
}

func printTopIntN(w io.Writer, items []types.CountIntItem) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, item := range items {
		_, _ = fmt.Fprintf(tw, "  %d.\t%d\t(%d)\n", i+1, item.Key, item.Count)
	}
	_ = tw.Flush()
}

func TopFieldAnalysis(engine *analysis.Engine, field types.TopField, n int, w io.Writer) {
	s := engine.Stats()

	switch field {
	case types.TopPath:
		printTop(w, "Paths", analysis.TopN(s.PathCounts, n))
	case types.TopMethod:
		printTop(w, "Methods", analysis.TopN(s.MethodCounts, n))
	case types.TopStatus:
		printTopInt(w, "Status Codes", analysis.TopNInt(s.StatusCounts, n))
	case types.TopHost:
		printTop(w, "Hosts", analysis.TopN(s.HostCounts, n))
	case types.TopRemoteAddr:
		printTop(w, "Remote Addresses", analysis.TopN(s.RemoteAddrCounts, n))
	case types.TopRemoteIP:
		printTop(w, "Remote IPs", analysis.TopN(s.RemoteIPCounts, n))
	case types.TopUserAgent:
		printTop(w, "User Agents", analysis.TopN(s.UserAgentCounts, n))
	case types.TopCountry:
		printTop(w, "Countries", renameItems(analysis.TopN(s.CountryCounts, n), s.CountryNames))
	case types.TopASN:
		printTop(w, "Autonomous Systems", analysis.TopN(s.ASNCounts, n))
	}
}

func printTop(w io.Writer, title string, items []types.CountItem) {
	if len(items) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "Top %s:\n", title)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, item := range items {
		_, _ = fmt.Fprintf(tw, "  %d.\t%s\t(%d)\n", i+1, stripANSI(item.Key), item.Count)
	}
	_ = tw.Flush()
}

// RenameCountryItems returns a copy of items with keys replaced by their
// human-readable name from names when available; keys without a name
// entry are left unchanged. Used to display country names (e.g.
// "Italy") instead of ISO codes (e.g. "IT") in text output.
func RenameCountryItems(items []types.CountItem, names map[string]string) []types.CountItem {
	return renameItems(items, names)
}

// renameItems returns a copy of items with keys replaced by their
// human-readable name from names when available; keys without a name
// entry are left unchanged. Used to display country names (e.g.
// "Italy") instead of ISO codes (e.g. "IT") in text output.
func renameItems(items []types.CountItem, names map[string]string) []types.CountItem {
	out := make([]types.CountItem, len(items))
	for i, it := range items {
		if name, ok := names[it.Key]; ok && name != "" {
			out[i] = types.CountItem{Key: name, Count: it.Count}
		} else {
			out[i] = it
		}
	}
	return out
}

func listStatus(s int) string {
	str := fmt.Sprintf("%d", s)
	switch {
	case s >= 200 && s < 300:
		return styleList2xx.Render(str + " OK")
	case s >= 300 && s < 400:
		return styleList3xx.Render(str + " REDIR")
	case s >= 400 && s < 500:
		return styleList4xx.Render(str + " WARN")
	case s >= 500:
		return styleList5xx.Render(str + " ERR")
	default:
		return str
	}
}

func FmtLogEntry(e *types.LogEntry, defang bool) string {
	timeStr := styleListDim.Render(e.Timestamp.Format("15:04:05"))
	statusStr := listStatus(e.Status)
	methodStr := lipgloss.NewStyle().Bold(true).Render(stripANSI(e.Method))
	pathStr := stripANSI(e.Path())
	ipStr := stripANSI(e.RemoteIP)
	if defang {
		pathStr = Defang(pathStr)
		ipStr = Defang(ipStr)
	}
	pathStr = styleListPath.Render(pathStr)
	ipStr = styleListIP.Render(ipStr)

	uaInfo := ""
	if e.IsBot {
		uaInfo = fmt.Sprintf(" [%s]", lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("Bot "+stripANSI(e.BotName)))
	} else if e.Browser != "" || e.OS != "" {
		uaInfo = fmt.Sprintf(" [%s/%s]", stripANSI(e.OS), stripANSI(e.Browser))
	}

	return fmt.Sprintf("%s  %s  %s %s  (%s, %s) - %s%s",
		timeStr, statusStr, methodStr, pathStr, FormatBytes(e.Size), FormatDuration(e.Duration), ipStr, uaInfo)
}

func HasEntryFilters(f types.Filters) bool {
	return len(f.Status) > 0 || f.Method != "" || f.PathGlob != "" || f.Host != "" ||
		f.RemoteIP != "" || f.ExcludeIP != "" || f.Only2xx || f.Only3xx || f.Only4xx || f.Only5xx ||
		f.ErrorsOnly || f.NoBots || f.BotsOnly || f.MinLatency > 0 || f.MaxLatency > 0 ||
		f.MinSize > 0 || f.MaxSize > 0 || f.GrepPattern != ""
}

func PrintLogEntries(entries []*types.LogEntry, w io.Writer, defang bool) {
	for _, e := range entries {
		if e != nil {
			_, _ = fmt.Fprintln(w, FmtLogEntry(e, defang))
		}
	}
}

// FmtOperationalEntry renders one non-HTTP log event for filter-driven
// listings, mirroring the tail format: time, level, logger, message, and
// up to 3 extra fields with sorted keys for deterministic output.
func FmtOperationalEntry(e *types.OperationalEntry, defang bool) string {
	timeStr := styleListDim.Render(e.Timestamp.Format("15:04:05"))
	lvlStr := styleDim.Render(strings.ToUpper(e.EffectiveLevel()))
	switch e.EffectiveLevel() {
	case "error":
		lvlStr = styleError.Render("ERROR")
	case "warn":
		lvlStr = styleWarn.Render("WARN")
	case "info":
		lvlStr = styleOK.Render("INFO")
	}

	loggerStr := ""
	if e.Logger != "" {
		loggerStr = styleListDim.Render("[" + stripANSI(e.Logger) + "]  ")
	}
	msgStr := stripANSI(e.Msg)
	if defang {
		msgStr = Defang(msgStr)
	}

	keys := make([]string, 0, len(e.Extra))
	for k := range e.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var extras []string
	for _, k := range keys {
		vs := strings.Trim(string(e.Extra[k]), `"`)
		if defang {
			vs = Defang(vs)
		}
		extras = append(extras, fmt.Sprintf("%s=%s", k, vs))
		if len(extras) >= 3 {
			break
		}
	}
	extraStr := ""
	if len(extras) > 0 {
		extraStr = styleListDim.Render("  " + strings.Join(extras, " "))
	}

	return fmt.Sprintf("%s  %s  %s%s%s", timeStr, lvlStr, loggerStr, msgStr, extraStr)
}

func PrintOperationalEntries(entries []*types.OperationalEntry, w io.Writer, defang bool) {
	for _, e := range entries {
		if e != nil {
			_, _ = fmt.Fprintln(w, FmtOperationalEntry(e, defang))
		}
	}
}

func printTopInt(w io.Writer, title string, items []types.CountIntItem) {
	if len(items) == 0 {
		return
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})

	_, _ = fmt.Fprintf(w, "Top %s:\n", title)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, item := range items {
		_, _ = fmt.Fprintf(tw, "  %d.\t%d\t(%d)\n", i+1, item.Key, item.Count)
	}
	_ = tw.Flush()
}
