package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
	"github.com/lenny-ts/caddy-analyzer/pkg/enrich"
	"github.com/lenny-ts/caddy-analyzer/pkg/output"
	"github.com/lenny-ts/caddy-analyzer/pkg/parser"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

type TickMsg time.Time
type LineMsg string
type StreamEndMsg struct{}

type view int

const (
	viewSummary view = iota
	viewRealtime
	viewSecurity
	viewTopIPs
	viewTopPaths
	viewTopUA
	viewGeo
)

type Model struct {
	engine      *analysis.Engine
	detector    *analysis.Detector
	linesCh     chan string
	ready       bool
	width       int
	height      int
	current     view
	stats       *types.Stats
	rps         float64
	recentLogs  []*types.LogEntry
	windowStart time.Time

	ipTable      table.Model
	pathTable    table.Model
	countryTable table.Model
	asnTable     table.Model
	uaItems      []types.CountItem

	geoip *enrich.GeoIP
}

var (
	styleTitle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99"))
	styleLabel    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
	styleOK       = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleWarn     = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	styleError    = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	styleInfo     = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
	styleHelp     = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleActive   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99")).Underline(true)
	styleTail2xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	styleTail3xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("81")).Bold(true)
	styleTail4xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true)
	styleTail5xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styleTailDim  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleTailIP   = lipgloss.NewStyle().Foreground(lipgloss.Color("141"))
	styleTailPath = lipgloss.NewStyle().Foreground(lipgloss.Color("255"))
)

func NewModel(linesCh chan string) Model {
	return NewModelWithGeoIP(linesCh, nil)
}

// NewModelWithGeoIP returns a Model wired to enrich every parsed entry with
// the given GeoIP enricher before it reaches the analysis engine. Pass nil
// to disable GeoIP (equivalent to NewModel).
func NewModelWithGeoIP(linesCh chan string, g *enrich.GeoIP) Model {
	det := analysis.NewDetector()
	eng := analysis.New(types.Filters{})
	eng.SetDetector(det)

	return Model{
		engine:      eng,
		detector:    det,
		linesCh:     linesCh,
		current:     viewSummary,
		recentLogs:  make([]*types.LogEntry, 0, 20),
		windowStart: time.Now(),
		geoip:       g,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		waitForLines(m.linesCh),
		tickEvery(2*time.Second),
	)
}

func waitForLines(ch chan string) tea.Cmd {
	return func() tea.Msg {
		line, ok := <-ch
		if !ok {
			return StreamEndMsg{}
		}
		return LineMsg(line)
	}
}

func tickEvery(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		m = m.initTables()
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "1":
			m.current = viewSummary
		case "2":
			m.current = viewRealtime
		case "3":
			m.current = viewSecurity
		case "4":
			m.current = viewTopIPs
			m = m.refreshTables()
		case "5":
			m.current = viewTopPaths
			m = m.refreshTables()
		case "6":
			m.current = viewTopUA
		case "7":
			m.current = viewGeo
			m = m.refreshTables()
		case "tab", "right":
			if m.current < viewGeo {
				m.current++
				m = m.refreshTables()
			}
		case "shift+tab", "left":
			if m.current > viewSummary {
				m.current--
				m = m.refreshTables()
			}
		case "r":
			eng := analysis.New(types.Filters{})
			eng.SetDetector(m.detector)
			m.engine = eng
			m.stats = nil
			m.recentLogs = make([]*types.LogEntry, 0, 20)
			m.windowStart = time.Now()
		}

	case LineMsg:
		line := string(msg)
		entry, err := parser.Parse(line)
		if err == nil && entry != nil {
			if m.geoip != nil && entry.RemoteIP != "" {
				if info, lerr := m.geoip.Lookup(entry.RemoteIP); lerr == nil {
					entry.Geo = info
				}
			}
			m.engine.Process(entry)
			if len(m.recentLogs) >= 15 {
				m.recentLogs = m.recentLogs[1:]
			}
			m.recentLogs = append(m.recentLogs, entry)
		}
		return m, waitForLines(m.linesCh)

	case StreamEndMsg:
		return m, tea.Quit

	case TickMsg:
		// Auto-reset the engine every 5 minutes so the dashboard does not
		// accumulate unbounded maps over multi-hour sessions.
		if time.Since(m.windowStart) > 5*time.Minute {
			eng := analysis.New(types.Filters{})
			eng.SetDetector(m.detector)
			m.engine = eng
			m.stats = nil
			m.recentLogs = make([]*types.LogEntry, 0, 20)
			m.windowStart = time.Now()
		}
		m.engine.Finalize()
		s := m.engine.Stats()
		m.stats = s
		elapsed := s.EndTime.Sub(s.StartTime).Seconds()
		if elapsed <= 0 {
			elapsed = 2
		}
		m.rps = float64(s.TotalRequests) / elapsed
		m.uaItems = analysis.TopN(s.UserAgentCounts, 15)
		m = m.refreshTables()

		return m, tickEvery(2 * time.Second)
	}

	return m, nil
}

func (m Model) initTables() Model {
	columns := []table.Column{
		{Title: "#", Width: 4},
		{Title: "IP", Width: 18},
		{Title: "Requests", Width: 10},
	}

	m.ipTable = table.New(
		table.WithColumns(columns),
		table.WithFocused(false),
		table.WithHeight(max(1, min(15, m.height-10))),
	)

	pathCols := []table.Column{
		{Title: "#", Width: 4},
		{Title: "Path", Width: 40},
		{Title: "Requests", Width: 10},
	}

	m.pathTable = table.New(
		table.WithColumns(pathCols),
		table.WithFocused(false),
		table.WithHeight(max(1, min(15, m.height-10))),
	)

	countryCols := []table.Column{
		{Title: "#", Width: 4},
		{Title: "Country", Width: 26},
		{Title: "Requests", Width: 10},
	}
	m.countryTable = table.New(
		table.WithColumns(countryCols),
		table.WithFocused(false),
		table.WithHeight(max(1, min(12, m.height-14))),
	)

	asnCols := []table.Column{
		{Title: "#", Width: 4},
		{Title: "ASN", Width: 30},
		{Title: "Requests", Width: 10},
	}
	m.asnTable = table.New(
		table.WithColumns(asnCols),
		table.WithFocused(false),
		table.WithHeight(max(1, min(12, m.height-14))),
	)
	return m
}

func (m Model) refreshTables() Model {
	if !m.ready || m.stats == nil {
		return m
	}

	s := m.stats

	ips := analysis.TopN(s.RemoteIPCounts, 20)
	var ipRows []table.Row
	for i, ip := range ips {
		ipRows = append(ipRows, table.Row{
			fmt.Sprintf("%d", i+1),
			ip.Key,
			fmt.Sprintf("%d", ip.Count),
		})
	}
	m.ipTable.SetRows(ipRows)

	paths := analysis.TopN(s.PathCounts, 20)
	var pathRows []table.Row
	for i, p := range paths {
		pathRows = append(pathRows, table.Row{
			fmt.Sprintf("%d", i+1),
			truncate(p.Key, 38),
			fmt.Sprintf("%d", p.Count),
		})
	}
	m.pathTable.SetRows(pathRows)

	countries := analysis.TopN(s.CountryCounts, 15)
	var countryRows []table.Row
	for i, c := range countries {
		name := c.Key
		if display, ok := s.CountryNames[c.Key]; ok && display != "" {
			name = display
		}
		countryRows = append(countryRows, table.Row{
			fmt.Sprintf("%d", i+1),
			truncate(name, 24),
			fmt.Sprintf("%d", c.Count),
		})
	}
	m.countryTable.SetRows(countryRows)

	asns := analysis.TopN(s.ASNCounts, 15)
	var asnRows []table.Row
	for i, a := range asns {
		asnRows = append(asnRows, table.Row{
			fmt.Sprintf("%d", i+1),
			truncate(a.Key, 28),
			fmt.Sprintf("%d", a.Count),
		})
	}
	m.asnTable.SetRows(asnRows)
	return m
}

func (m Model) View() string {
	if !m.ready {
		return " ⚡ Caddy Dashboard — loading...\n"
	}

	var b strings.Builder

	b.WriteString(styleTitle.Render("⚡ Caddy Live Dashboard"))
	b.WriteString(styleHelp.Render("  [q] quit  [1-7] tabs  [tab] next  [r] reset"))
	b.WriteString("\n")
	b.WriteString(styleDimLine())
	b.WriteString("\n\n")

	switch m.current {
	case viewSummary:
		m.renderSummary(&b)
	case viewRealtime:
		m.renderRealtime(&b)
	case viewSecurity:
		m.renderSecurity(&b)
	case viewTopIPs:
		m.renderIPs(&b)
	case viewTopPaths:
		m.renderPaths(&b)
	case viewTopUA:
		m.renderUA(&b)
	case viewGeo:
		m.renderGeo(&b)
	}

	b.WriteString("\n")
	b.WriteString(m.viewTabs())

	return b.String()
}

func (m Model) viewTabs() string {
	tabs := []string{"Summary", "Realtime", "Security", "Top IPs", "Top Paths", "User Agents", "Geo"}
	var parts []string
	for i, t := range tabs {
		if view(i) == m.current {
			parts = append(parts, styleActive.Render(t))
		} else {
			parts = append(parts, t)
		}
	}
	return styleHelp.Render(" [") + strings.Join(parts, styleHelp.Render(" | ")) + styleHelp.Render("]")
}

func (m Model) renderSummary(b *strings.Builder) {
	s := m.stats
	if s == nil {
		fmt.Fprintf(b, "  Waiting for data...\n")
		return
	}

	total := s.TotalRequests

	fmt.Fprintf(b, "  %s %d\n", styleLabel.Render("Total Requests:"), total)
	fmt.Fprintf(b, "  %s %.1f\n\n", styleLabel.Render("Requests/sec:"), m.rps)

	fmt.Fprintf(b, "  %s:\n", styleLabel.Render("Status Codes"))
	fmt.Fprintf(b, "    2xx Success: %s\n", styleOK.Render(fmt.Sprintf("%d (%.1f%%)", s.Status2xx, output.Pct(s.Status2xx, total))))
	fmt.Fprintf(b, "    3xx Redir:   %s\n", styleInfo.Render(fmt.Sprintf("%d (%.1f%%)", s.Status3xx, output.Pct(s.Status3xx, total))))
	fmt.Fprintf(b, "    4xx Client:  %s\n", styleWarn.Render(fmt.Sprintf("%d (%.1f%%)", s.Status4xx, output.Pct(s.Status4xx, total))))
	fmt.Fprintf(b, "    5xx Server:  %s\n\n", styleError.Render(fmt.Sprintf("%d (%.1f%%)", s.Status5xx, output.Pct(s.Status5xx, total))))
	fmt.Fprintf(b, "  %s %s\n", styleLabel.Render("Response Size:"), output.FormatBytes(s.TotalBytes))
	fmt.Fprintf(b, "  %s %s\n\n", styleLabel.Render("Avg Size:"), output.FormatBytes(output.AvgSize(s.TotalBytes, total)))

	fmt.Fprintf(b, "  %s:\n", styleLabel.Render("Latency Percentiles"))
	if s.MinDuration < 1<<62 {
		fmt.Fprintf(b, "    Min: %s\n", output.FormatDuration(s.MinDuration))
	}
	fmt.Fprintf(b, "    Avg: %s\n", output.FormatDuration(s.DurationSum/float64(max(s.TotalRequests, 1))))
	fmt.Fprintf(b, "    Max: %s\n", output.FormatDuration(s.MaxDuration))
	fmt.Fprintf(b, "    P50: %s\n", output.FormatDuration(s.Percentile50))
	fmt.Fprintf(b, "    P95: %s\n", output.FormatDuration(s.Percentile95))
}

func (m Model) renderRealtime(b *strings.Builder) {
	fmt.Fprintf(b, "  %s:\n\n", styleLabel.Render("Live Log Stream"))
	if len(m.recentLogs) == 0 {
		fmt.Fprintf(b, "  Waiting for log events...\n")
		return
	}
	for _, e := range m.recentLogs {
		if e == nil {
			continue
		}
		timeStr := styleTailDim.Render(e.Timestamp.Format("15:04:05"))
		statusStr := tuiFormatStatus(e.Status)
		methodStr := lipgloss.NewStyle().Bold(true).Render(e.Method)
		pathStr := styleTailPath.Render(e.Path())
		ipStr := styleTailIP.Render(e.RemoteIP)
		sizeStr := output.FormatBytes(e.Size)
		durStr := output.FormatDuration(e.Duration)

		uaInfo := ""
		if e.IsBot {
			uaInfo = fmt.Sprintf(" [%s]", lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("🤖 "+e.BotName))
		} else if e.Browser != "" || e.OS != "" {
			uaInfo = fmt.Sprintf(" [%s/%s]", e.OS, e.Browser)
		}

		fmt.Fprintf(b, "  %s  %s  %s %s  (%s, %s) - %s%s\n",
			timeStr, statusStr, methodStr, pathStr, sizeStr, durStr, ipStr, uaInfo)
	}
}

func tuiFormatStatus(s int) string {
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

func (m Model) renderSecurity(b *strings.Builder) {
	if m.stats == nil || len(m.stats.SuspiciousIPs) == 0 {
		fmt.Fprintf(b, "  %s\n  No suspicious activities detected.\n", styleOK.Render("🛡️ Security Status: CLEAR"))
		return
	}
	fmt.Fprintf(b, "  %s:\n\n", styleError.Render("🚨 Detected Suspicious Activity"))
	items := analysis.TopN(m.stats.SuspiciousIPs, 15)
	for i, item := range items {
		fmt.Fprintf(b, "  %d. ⚠️ IP %-18s (%d suspicious requests)\n", i+1, item.Key, item.Count)
	}
}

func (m Model) renderIPs(b *strings.Builder) {
	if m.stats == nil {
		return
	}
	fmt.Fprintf(b, "  %s\n\n", styleLabel.Render("Top Remote IPs"))
	b.WriteString(m.ipTable.View())
}

func (m Model) renderPaths(b *strings.Builder) {
	if m.stats == nil {
		return
	}
	fmt.Fprintf(b, "  %s\n\n", styleLabel.Render("Top Paths"))
	b.WriteString(m.pathTable.View())
}

func (m Model) renderUA(b *strings.Builder) {
	if len(m.uaItems) == 0 {
		return
	}
	fmt.Fprintf(b, "  %s\n\n", styleLabel.Render("Top User Agents"))
	for i, item := range m.uaItems {
		fmt.Fprintf(b, "  %d. %-40s %d\n", i+1, truncate(item.Key, 38), item.Count)
	}
}

func (m Model) renderGeo(b *strings.Builder) {
	if m.geoip == nil && (m.stats == nil || (len(m.stats.CountryCounts) == 0 && len(m.stats.ASNCounts) == 0)) {
		fmt.Fprintf(b, "  %s\n", styleWarn.Render("GeoIP enrichment disabled"))
		fmt.Fprintf(b, "  Pass --geoip-db (or let auto-download run) to populate country/ASN stats.\n")
		return
	}
	if m.stats == nil {
		fmt.Fprintf(b, "  Waiting for data...\n")
		return
	}

	fmt.Fprintf(b, "  %s\n\n", styleLabel.Render("Top Countries"))
	b.WriteString(m.countryTable.View())
	fmt.Fprintf(b, "\n\n  %s\n\n", styleLabel.Render("Top ASN"))
	b.WriteString(m.asnTable.View())
}

func truncate(s string, n int) string {
	if n <= 1 {
		return "…"
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func styleDimLine() string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("236")).Render(strings.Repeat("━", 60))
}
