package output

import (
	"fmt"
	"html"
	"strings"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func (r *Report) printHTML() error {
	s := r.engine.Stats()
	total := s.TotalRequests

	var topPaths, topIPs, topUAs, topMethods, topCountries, topASNs []types.CountItem
	if r.top > 0 {
		topPaths = analysis.TopN(s.PathCounts, r.top)
		topIPs = analysis.TopN(s.RemoteIPCounts, r.top)
		topUAs = analysis.TopN(s.UserAgentCounts, r.top)
		topMethods = analysis.TopN(s.MethodCounts, r.top)
		topCountries = analysis.TopN(s.CountryCounts, r.top)
		topASNs = analysis.TopN(s.ASNCounts, r.top)
	}
	topProtos := analysis.TopN(s.ProtoCounts, 5)
	topTLS := analysis.TopN(s.TLSVersionCounts, 5)
	topBots := analysis.TopN(s.BotCounts, 5)
	topReferers := analysis.TopN(s.RefererCounts, 5)
	topPathBytes := analysis.TopN(s.PathBytesMap, 5)
	suspicious := analysis.TopN(s.SuspiciousIPs, 20)

	out := generateHTMLReport(s, total, r.engine.RPS(), r.engine.AvgDuration(),
		topPaths, topIPs, topUAs, topMethods, topCountries, topASNs, topProtos, topTLS, topBots, topReferers, topPathBytes, suspicious, r.detect, r.activeFilters(), s.SuspiciousDetails)

	// Inject operational events card before </body> if present
	if r.opStats != nil && r.opStats.TotalEvents > 0 {
		op := generateOperationalHTML(r.opStats, r.top)
		out = strings.Replace(out, "</body>", op+"</body>", 1)
	}

	_, err := fmt.Fprint(r.writer, out)
	return err
}

func generateHTMLReport(
	s *types.Stats,
	total int64,
	rps float64,
	avgDur float64,
	topPaths, topIPs, _, _, topCountries, topASNs, topProtos, topTLS, _, _, _, suspicious []types.CountItem,
	detect bool,
	activeFilters []string,
	suspiciousDetails map[string][]string,
) string {
	errPct := float64(0)
	if total > 0 {
		errPct = float64(s.Errors) / float64(total) * 100
	}
	botPct := float64(0)
	if total > 0 {
		botPct = float64(s.BotRequests) / float64(total) * 100
	}

	durationStr := "N/A"
	if !s.EndTime.IsZero() && !s.StartTime.IsZero() {
		durationStr = s.EndTime.Sub(s.StartTime).String()
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>caddy-analyzer report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace, sans-serif;
            background: #111111;
            color: #d1d5db;
            line-height: 1.5;
            padding: 1.5rem;
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            border-bottom: 1px solid #282828;
            padding-bottom: 1rem;
            margin-bottom: 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
        }

        h1 {
            font-size: 1.4rem;
            font-weight: 700;
            color: #ffffff;
            font-family: monospace;
        }

        .meta {
            color: #888888;
            font-size: 0.85rem;
            font-family: monospace;
        }

        .grid-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 0.75rem;
            margin-bottom: 1.5rem;
        }

        .stat-card {
            background: #181818;
            border: 1px solid #282828;
            border-radius: 4px;
            padding: 0.85rem 1rem;
        }

        .stat-label {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #888888;
            font-weight: 600;
        }

        .stat-value {
            font-size: 1.5rem;
            font-weight: 700;
            margin-top: 0.2rem;
            color: #58a6ff;
            font-family: monospace;
        }

        .stat-card.danger .stat-value { color: #f85149; }
        .stat-card.success .stat-value { color: #3fb950; }

        .grid-main {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
            gap: 1.25rem;
        }

        .card {
            background: #181818;
            border: 1px solid #282828;
            border-radius: 4px;
            padding: 1.25rem;
        }

        .card h2 {
            font-size: 0.95rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
            border-bottom: 1px solid #282828;
            padding-bottom: 0.4rem;
            color: #ffffff;
            font-family: monospace;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }

        table {
            width: 100%%;
            border-collapse: collapse;
            font-size: 0.85rem;
            font-family: monospace;
        }

        th, td {
            text-align: left;
            padding: 0.45rem 0.5rem;
            border-bottom: 1px solid #222222;
        }

        th {
            color: #888888;
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
        }

        td.count {
            text-align: right;
            font-weight: 600;
            color: #58a6ff;
        }

        td.bar-cell {
            width: 30%%;
        }

        .progress-bar {
            background: #222222;
            border-radius: 2px;
            height: 6px;
            overflow: hidden;
            width: 100%%;
        }

        .progress-fill {
            background: #58a6ff;
            height: 100%%;
        }

        .progress-fill.danger { background: #f85149; }
        .progress-fill.success { background: #3fb950; }
        .progress-fill.warning { background: #d29922; }

        .alert-item {
            background: rgba(248, 81, 73, 0.1);
            border-left: 3px solid #f85149;
            padding: 0.5rem 0.75rem;
            border-radius: 2px;
            margin-bottom: 0.4rem;
            font-size: 0.85rem;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>caddy-analyzer report</h1>
            <div class="meta">Period: %s — %s (%s)</div>
        </div>
    </header>
    %s

    <div class="grid-stats">
        <div class="stat-card">
            <div class="stat-label">Total Requests</div>
            <div class="stat-value">%d</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Requests / Sec</div>
            <div class="stat-value">%.2f</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Avg Duration</div>
            <div class="stat-value">%s</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Total Bandwidth</div>
            <div class="stat-value">%s</div>
        </div>
        <div class="stat-card %s">
            <div class="stat-label">Error Rate (5xx)</div>
            <div class="stat-value">%.1f%%</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Bot Traffic</div>
            <div class="stat-value">%.1f%%</div>
        </div>
    </div>

    <div class="grid-main">
        <!-- Top Paths -->
        <div class="card">
            <h2>Top Requested Paths</h2>
            <table>
                <thead><tr><th>Path</th><th>Count</th><th class="bar-cell">Distribution</th></tr></thead>
                <tbody>%s</tbody>
            </table>
        </div>

        <!-- Top IPs -->
        <div class="card">
            <h2>Top Client IP Addresses</h2>
            <table>
                <thead><tr><th>IP Address</th><th>Requests</th><th class="bar-cell">Distribution</th></tr></thead>
                <tbody>%s</tbody>
            </table>
        </div>

        <!-- Top Countries -->
        %s

        <!-- Top ASNs -->
        %s

        <!-- Status Codes -->
        <div class="card">
            <h2>Status Codes Breakdown</h2>
            <table>
                <thead><tr><th>Code Class</th><th>Requests</th><th>Ratio</th></tr></thead>
                <tbody>
                    <tr><td>2xx Success</td><td class="count">%d</td><td>%.1f%%</td></tr>
                    <tr><td>3xx Redirect</td><td class="count">%d</td><td>%.1f%%</td></tr>
                    <tr><td>4xx Client Error</td><td class="count">%d</td><td>%.1f%%</td></tr>
                    <tr><td>5xx Server Error</td><td class="count">%d</td><td>%.1f%%</td></tr>
                </tbody>
            </table>
        </div>

        <!-- Protocol & TLS -->
        <div class="card">
            <h2>Protocols & TLS Handshakes</h2>
            <table>
                <thead><tr><th>Protocol / TLS</th><th>Requests</th></tr></thead>
                <tbody>%s</tbody>
            </table>
        </div>

        <!-- Security Alerts -->
        %s
    </div>
</body>
</html>`,
		formatTime(s.StartTime), formatTime(s.EndTime), durationStr,
		renderActiveFiltersHTML(activeFilters),
		total, rps, FormatDuration(avgDur), FormatBytes(s.TotalBytes),
		cardClass(errPct), errPct, botPct,
		renderTableRows(topPaths, total),
		renderTableRows(topIPs, total),
		renderGeoCard("Top Client Countries", topCountries, total),
		renderGeoCard("Top Autonomous Systems", topASNs, total),
		s.Status2xx, Pct(s.Status2xx, total),
		s.Status3xx, Pct(s.Status3xx, total),
		s.Status4xx, Pct(s.Status4xx, total),
		s.Status5xx, Pct(s.Status5xx, total),
		renderMixedRows(topProtos, topTLS),
		renderSecurityAlertsHTML(suspicious, suspiciousDetails, detect),
	)
}

func cardClass(errPct float64) string {
	if errPct > 5 {
		return "danger"
	}
	return "success"
}

func renderTableRows(items []types.CountItem, total int64) string {
	var rows string
	for _, item := range items {
		ratio := float64(0)
		if total > 0 {
			ratio = float64(item.Count) / float64(total) * 100
		}
		rows += fmt.Sprintf(`<tr><td>%s</td><td class="count">%d</td><td class="bar-cell"><div class="progress-bar"><div class="progress-fill" style="width: %.1f%%"></div></div></td></tr>`,
			escapeHTML(item.Key), item.Count, ratio)
	}
	return rows
}

// renderGeoCard renders an optional GeoIP card (countries or ASNs). Returns
// an empty string when no data is available so the card is omitted entirely.
func renderGeoCard(title string, items []types.CountItem, total int64) string {
	if len(items) == 0 {
		return ""
	}
	return fmt.Sprintf(`<div class="card"><h2>%s</h2><table><thead><tr><th>%s</th><th>Requests</th><th class="bar-cell">Distribution</th></tr></thead><tbody>%s</tbody></table></div>`,
		escapeHTML(title), escapeHTML(title), renderTableRows(items, total))
}

func renderMixedRows(protos, tls []types.CountItem) string {
	var rows string
	for _, p := range protos {
		rows += fmt.Sprintf(`<tr><td>Proto: %s</td><td class="count">%d</td></tr>`, escapeHTML(p.Key), p.Count)
	}
	for _, t := range tls {
		rows += fmt.Sprintf(`<tr><td>TLS: %s</td><td class="count">%d</td></tr>`, escapeHTML(t.Key), t.Count)
	}
	return rows
}

func renderSecurityAlertsHTML(suspicious []types.CountItem, suspiciousDetails map[string][]string, detect bool) string {
	if !detect {
		return ""
	}
	if len(suspicious) == 0 {
		return `<div class="card"><h2>🛡️ Security Threat Inspection</h2><div style="color:#3fb950; font-weight:600; font-size:0.9rem; font-family:monospace; padding:0.5rem 0;">✔ STATUS: CLEAN — 0 security threats or scanner probes detected</div></div>`
	}
	var alerts string
	for _, item := range suspicious {
		alerts += fmt.Sprintf(`<div class="alert-item">⚠ IP: %s — %d malicious requests`, escapeHTML(item.Key), item.Count)
		if details, ok := suspiciousDetails[item.Key]; ok && len(details) > 0 {
			for _, d := range details {
				alerts += fmt.Sprintf(`<br><span style="color:#d29922; font-size:0.8rem;">&nbsp;&nbsp;↳ %s</span>`, escapeHTML(d))
			}
		}
		alerts += `</div>`
	}
	return fmt.Sprintf(`<div class="card" style="border-left: 3px solid #f85149;"><h2>🚨 Security & Threat Alerts (%d Suspicious IPs)</h2>%s<p style="color:#888888; font-size:0.8rem; margin-top:0.75rem; font-family:monospace;">💡 Action Hint: Run 'sudo caddy-analyze guard' to auto-block attack IPs via iptables.</p></div>`, len(suspicious), alerts)
}

func renderActiveFiltersHTML(filters []string) string {
	if len(filters) == 0 {
		return ""
	}
	var items string
	for _, f := range filters {
		items += fmt.Sprintf(`<span style="background:#222; color:#58a6ff; padding:2px 8px; border-radius:3px; font-size:0.8rem; font-family:monospace; margin-right:6px;">%s</span>`, escapeHTML(f))
	}
	return fmt.Sprintf(`<div style="margin-bottom:1rem;">%s</div>`, items)
}

func escapeHTML(s string) string {
	return html.EscapeString(s)
}

// generateOperationalHTML renders the Operational Events card for the HTML
// report. Returns an empty string when there are no events so the card is
// omitted entirely.
func generateOperationalHTML(op *types.OperationalStats, top int) string {
	if op == nil || op.TotalEvents == 0 {
		return ""
	}

	// Level breakdown rows
	var levelRows string
	for _, lvl := range []string{"error", "warn", "info", "debug"} {
		if c, ok := op.LevelCounts[lvl]; ok && c > 0 {
			ratio := float64(c) / float64(op.TotalEvents) * 100
			levelRows += fmt.Sprintf(`<tr><td>%s</td><td class="count">%d</td><td class="bar-cell"><div class="progress-bar"><div class="progress-fill" style="width: %.1f%%"></div></div></td></tr>`,
				escapeHTML(lvl), c, ratio)
		}
	}

	// Top loggers
	loggers := analysis.TopN(op.LoggerCounts, top)
	messages := analysis.TopN(op.MsgCounts, top)

	loggersCard := ""
	if len(loggers) > 0 {
		loggersCard = fmt.Sprintf(`<div class="card"><h2>Top Loggers</h2><table><thead><tr><th>Logger</th><th>Events</th><th class="bar-cell">Distribution</th></tr></thead><tbody>%s</tbody></table></div>`,
			renderTableRows(loggers, op.TotalEvents))
	}

	messagesCard := ""
	if len(messages) > 0 {
		messagesCard = fmt.Sprintf(`<div class="card"><h2>Top Messages</h2><table><thead><tr><th>Message</th><th>Events</th><th class="bar-cell">Distribution</th></tr></thead><tbody>%s</tbody></table></div>`,
			renderTableRows(messages, op.TotalEvents))
	}

	errLine := ""
	if op.Errors > 0 {
		errLine = fmt.Sprintf(`<p class="error">Errors: %d</p>`, op.Errors)
	}

	return fmt.Sprintf(`<div class="card"><h2>Operational Events</h2><p>Total Events: %d</p>%s<table><thead><tr><th>Level</th><th>Events</th><th class="bar-cell">Distribution</th></tr></thead><tbody>%s</tbody></table></div>%s%s`,
		op.TotalEvents, errLine, levelRows, loggersCard, messagesCard)
}
