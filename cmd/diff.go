package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
	"github.com/lenny-ts/caddy-analyzer/pkg/output"
	"github.com/lenny-ts/caddy-analyzer/pkg/parser"
	"github.com/lenny-ts/caddy-analyzer/pkg/progress"
	"github.com/lenny-ts/caddy-analyzer/pkg/reader"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

var (
	styleDiffTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99"))
	styleDiffGood  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleDiffBad   = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styleDiffWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	styleDiffDim   = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

var diffCmd = &cobra.Command{
	Use:   "diff <baseline_log> <target_log>",
	Short: "Compare two log files to detect RPS shifts, 5xx error spikes, and latency changes",
	Args:  cobra.ExactArgs(2),
	RunE:  runDiffCmd,
}

func init() {
	rootCmd.AddCommand(diffCmd)
}

func runDiffCmd(cmd *cobra.Command, args []string) error {
	baseFile := args[0]
	currFile := args[1]

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	baseEngine, err := processLogFile(ctx, baseFile)
	if err != nil {
		return fmt.Errorf("baseline file %s: %w", baseFile, err)
	}

	currEngine, err := processLogFile(ctx, currFile)
	if err != nil {
		return fmt.Errorf("target file %s: %w", currFile, err)
	}

	diff := analysis.CompareStats(baseEngine, currEngine)

	var w io.Writer = os.Stdout
	if flagOutput != "" {
		f, err := createOutputFile(flagOutput)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	switch output.ParseFormat(flagFormat) {
	case output.FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(diff)
	case output.FormatCSV:
		if _, err := fmt.Fprintln(w, "metric,baseline,target,delta"); err != nil {
			return err
		}
		rows := [][]string{
			{"total_requests", fmt.Sprintf("%d", diff.BaseRequests), fmt.Sprintf("%d", diff.CurrRequests), fmt.Sprintf("%d", diff.RequestsDelta)},
			{"requests_per_sec", fmt.Sprintf("%.2f", diff.BaseRPS), fmt.Sprintf("%.2f", diff.CurrRPS), fmt.Sprintf("%.2f", diff.RPSDelta)},
			{"5xx_errors", fmt.Sprintf("%d", diff.BaseErrors), fmt.Sprintf("%d", diff.CurrErrors), fmt.Sprintf("%d", diff.ErrorsDelta)},
			{"avg_latency_ms", fmt.Sprintf("%.2f", diff.BaseAvgDuration*1000), fmt.Sprintf("%.2f", diff.CurrAvgDuration*1000), fmt.Sprintf("%.2f", diff.AvgDurDelta*1000)},
		}
		for _, r := range rows {
			if _, err := fmt.Fprintf(w, "%s,%s,%s,%s\n", r[0], r[1], r[2], r[3]); err != nil {
				return err
			}
		}
		return nil
	}

	var werr error
	writef := func(format string, args ...any) {
		if werr != nil {
			return
		}
		_, werr = fmt.Fprintf(w, format, args...)
	}

	writef("%s\n", styleDiffTitle.Render("CADDY LOG COMPARATIVE DIFF"))
	writef("%s\n", styleDiffDim.Render("Baseline: ")+baseFile)
	writef("%s\n", styleDiffDim.Render("Target:   ")+currFile)
	writef("%s\n", styleDiffDim.Render(strings.Repeat("=", 50)))

	writef("\n%-22s  %-15s  %-15s  %-15s\n", "Metric", "Baseline", "Target", "Difference")
	writef("%s\n", styleDiffDim.Render(strings.Repeat("─", 68)))

	writef("%-22s  %-15d  %-15d  %s\n", "Total Requests", diff.BaseRequests, diff.CurrRequests, formatDeltaInt(diff.RequestsDelta))
	writef("%-22s  %-15.2f  %-15.2f  %s\n", "Requests / Sec", diff.BaseRPS, diff.CurrRPS, formatDeltaFloat(diff.RPSDelta, "req/s"))

	errStr := formatDeltaInt(diff.ErrorsDelta)
	if diff.ErrorsDelta > 0 {
		errStr = styleDiffBad.Render(fmt.Sprintf("+%d", diff.ErrorsDelta))
	} else if diff.ErrorsDelta < 0 {
		errStr = styleDiffGood.Render(fmt.Sprintf("%d", diff.ErrorsDelta))
	}
	writef("%-22s  %-15d  %-15d  %s\n", "5xx Server Errors", diff.BaseErrors, diff.CurrErrors, errStr)

	latStr := formatDurationDelta(diff.AvgDurDelta)
	writef("%-22s  %-15s  %-15s  %s\n", "Avg Latency", output.FormatDuration(diff.BaseAvgDuration), output.FormatDuration(diff.CurrAvgDuration), latStr)

	if len(diff.NewErrorPaths) > 0 {
		writef("\n%s:\n", styleDiffBad.Render("[ALERT] New Error Paths Detected in Target"))
		for i, p := range diff.NewErrorPaths {
			if flagDefang {
				p = output.Defang(p)
			}
			writef("  %d. %s\n", i+1, p)
		}
	} else {
		writef("\n%s\n", styleDiffGood.Render("[OK] No new error paths detected."))
	}

	return werr
}

func processLogFile(ctx context.Context, path string) (*analysis.Engine, error) {
	filters, err := buildFilters()
	if err != nil {
		return nil, fmt.Errorf("invalid filter flags: %w", err)
	}
	engine := analysis.New(filters)

	geoip := newGeoIPEnricher()
	if geoip != nil {
		defer func() { _ = geoip.Close() }()
	}

	src := reader.ParseSource(path)
	r := reader.FromSource(src)
	lines, err := r.Read(ctx)
	if err != nil {
		return nil, err
	}
	total := countTotalLines([]types.LogSource{src})
	bar := progress.New(os.Stderr, total, "Parsing "+filepath.Base(path))
	for line := range lines {
		entry, err := parser.Parse(line)
		if err != nil || entry == nil {
			bar.Add(1)
			continue
		}
		applyForwarded(entry, filters)
		enrichGeoIP(entry, geoip)
		engine.Process(entry)
		bar.Add(1)
	}
	bar.Done()
	engine.Finalize()
	return engine, nil
}

func formatDeltaInt(d int64) string {
	if d > 0 {
		return styleDiffWarn.Render(fmt.Sprintf("+%d", d))
	}
	if d < 0 {
		return styleDiffGood.Render(fmt.Sprintf("%d", d))
	}
	return "0"
}

func formatDeltaFloat(d float64, unit string) string {
	if d > 0 {
		return styleDiffGood.Render(fmt.Sprintf("+%.2f %s", d, unit))
	}
	if d < 0 {
		return styleDiffWarn.Render(fmt.Sprintf("%.2f %s", d, unit))
	}
	return fmt.Sprintf("0 %s", unit)
}

func formatDurationDelta(d float64) string {
	durStr := output.FormatDuration(d)
	if d > 0 {
		return styleDiffBad.Render("+" + durStr)
	}
	if d < 0 {
		return styleDiffGood.Render("-" + output.FormatDuration(-d))
	}
	return "0ms"
}
