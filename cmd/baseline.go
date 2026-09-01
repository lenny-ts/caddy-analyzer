package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
	"github.com/lenny-ts/caddy-analyzer/pkg/output"
	"github.com/lenny-ts/caddy-analyzer/pkg/reader"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

const baselineSchemaVersion = 1

var errBaselineRegression = errors.New("baseline regression exceeds threshold")

type baselineFile struct {
	SchemaVersion    int                     `json:"schema_version"`
	CreatedAt        time.Time               `json:"created_at"`
	ToolVersion      string                  `json:"tool_version"`
	Sources          []string                `json:"sources"`
	Filters          types.Filters           `json:"filters"`
	Detection        bool                    `json:"detection"`
	Stats            *types.Stats            `json:"stats"`
	OperationalStats *types.OperationalStats `json:"operational_stats"`
}

type comparisonResult struct {
	analysis.DiffResult
	BaseOperationalEvents  int64   `json:"base_operational_events"`
	CurrOperationalEvents  int64   `json:"curr_operational_events"`
	OperationalEventsDelta int64   `json:"operational_events_delta"`
	BaseOperationalErrors  int64   `json:"base_operational_errors"`
	CurrOperationalErrors  int64   `json:"curr_operational_errors"`
	OperationalErrorsDelta int64   `json:"operational_errors_delta"`
	Threshold              float64 `json:"threshold_pct"`
	Regression             bool    `json:"regression"`
}

var baselineCmd = &cobra.Command{Use: "baseline", Short: "Manage analysis baselines"}
var baselineSaveCmd = &cobra.Command{
	Use: "save <source...>", Short: "Save a versioned JSON analysis baseline", Args: cobra.MinimumNArgs(1),
	RunE: runBaselineSave,
}

func init() {
	rootCmd.AddCommand(baselineCmd)
	baselineCmd.AddCommand(baselineSaveCmd)
	// The root detector flag is local so it does not collide with tail's
	// detector flag; expose the same setting after this subcommand too.
	baselineSaveCmd.Flags().BoolVarP(&flagDetect, "detect", "d", false, "Detect suspicious activity while saving the baseline")
}

func runBaselineSave(cmd *cobra.Command, args []string) error {
	if flagOutput == "" {
		return fmt.Errorf("baseline save requires --output <baseline.json>")
	}
	if err := validateBaselinePath(flagOutput); err != nil {
		return err
	}
	filters, err := buildFilters()
	if err != nil {
		return err
	}
	sources := parseSources(args)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine, opEngine, err := analyzeSources(ctx, sources, filters)
	if err != nil {
		return err
	}
	b := baselineFile{SchemaVersion: baselineSchemaVersion, CreatedAt: time.Now().UTC(), ToolVersion: Version,
		Sources: args, Filters: filters, Detection: flagDetect, Stats: engine.Stats(), OperationalStats: opEngine.Stats()}
	f, err := createOutputFile(flagOutput)
	if err != nil {
		return fmt.Errorf("create baseline: %w", err)
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(b); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	fmt.Fprintf(os.Stderr, "baseline saved to %s\n", flagOutput)
	return nil
}

func loadBaseline(path string) (baselineFile, error) {
	var b baselineFile
	if err := validateBaselinePath(path); err != nil {
		return b, err
	}
	f, err := os.Open(path)
	if err != nil {
		return b, fmt.Errorf("open baseline: %w", err)
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return b, fmt.Errorf("decode baseline: %w", err)
	}
	var extra interface{}
	if err := dec.Decode(&extra); err == nil {
		return b, fmt.Errorf("decode baseline: multiple JSON values")
	} else if err != io.EOF {
		return b, fmt.Errorf("decode baseline: trailing data: %w", err)
	}
	if b.SchemaVersion != baselineSchemaVersion {
		return b, fmt.Errorf("unsupported baseline schema_version %d (supported: %d)", b.SchemaVersion, baselineSchemaVersion)
	}
	if b.Stats == nil || b.OperationalStats == nil {
		return b, fmt.Errorf("baseline is missing stats or operational_stats")
	}
	if b.CreatedAt.IsZero() || b.ToolVersion == "" {
		return b, fmt.Errorf("baseline is missing metadata")
	}
	return b, nil
}

func validateBaselinePath(path string) error {
	if strings.TrimSpace(path) == "" || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return fmt.Errorf("baseline path must name a file")
	}
	clean := filepath.Clean(path)
	if clean == "." || filepath.IsAbs(clean) && filepath.Base(clean) == string(filepath.Separator) {
		return fmt.Errorf("baseline path must name a file")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("baseline path must be a regular file: %s", path)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("baseline path must not be a symlink: %s", path)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat baseline path: %w", err)
	}
	return nil
}

func analyzeSources(ctx context.Context, sources []types.LogSource, filters types.Filters) (*analysis.Engine, *analysis.OperationalEngine, error) {
	engine := analysis.New(filters)
	engine.Stats().MaxCardinality = flagMaxCard
	if flagDetect {
		engine.SetDetector(newDetector())
	}
	opEngine := analysis.NewOperationalEngine(filters)
	geoip := newGeoIPEnricher()
	if geoip != nil {
		defer func() { _ = geoip.Close() }()
	}
	for _, src := range sources {
		r := readerFromSource(src)
		lines, err := r.Read(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", r.Name(), err)
		}
		processParsedLines(ctx, lines, configuredWorkers(), func(entry types.Entry, parseErr error) {
			if parseErr != nil || entry == nil {
				return
			}
			switch e := entry.(type) {
			case *types.LogEntry:
				if !filters.OpsOnly && prepareEntry(e, filters, geoip) {
					engine.Process(e)
				}
			case *types.OperationalEntry:
				if analysis.MatchOperational(e, filters) {
					opEngine.Process(e)
				}
			}
		})
	}
	engine.Finalize()
	return engine, opEngine, nil
}

func readerFromSource(src types.LogSource) reader.LogReader {
	return reader.FromSource(src)
}

func compareBaseline(b baselineFile, filters types.Filters, current *analysis.Engine, currentOperational *analysis.OperationalEngine) comparisonResult {
	d := analysis.CompareStats(analysis.NewFromStats(filters, b.Stats), current)
	result := comparisonResult{DiffResult: d, Threshold: flagThreshold,
		BaseOperationalEvents: b.OperationalStats.TotalEvents, CurrOperationalEvents: currentOperational.Stats().TotalEvents,
		OperationalEventsDelta: currentOperational.Stats().TotalEvents - b.OperationalStats.TotalEvents,
		BaseOperationalErrors:  b.OperationalStats.Errors, CurrOperationalErrors: currentOperational.Stats().Errors,
		OperationalErrorsDelta: currentOperational.Stats().Errors - b.OperationalStats.Errors}
	result.Regression = exceeds(float64(result.ErrorsDelta), float64(result.BaseErrors), flagThreshold) ||
		exceeds(result.AvgDurDelta, result.BaseAvgDuration, flagThreshold) ||
		decreases(result.RPSDelta, result.BaseRPS, flagThreshold) ||
		(result.OperationalErrorsDelta > 0 && exceeds(float64(result.OperationalErrorsDelta), float64(result.BaseOperationalErrors), flagThreshold)) ||
		(result.OperationalErrorsDelta > 0 && result.BaseOperationalErrors == 0) || len(result.NewErrorPaths) > 0
	return result
}

func runAgainst(ctx context.Context, sources []types.LogSource) error {
	b, err := loadBaseline(flagAgainst)
	if err != nil {
		return err
	}
	filters, err := buildFilters()
	if err != nil {
		return err
	}
	current, operational, err := analyzeSources(ctx, sources, filters)
	if err != nil {
		return err
	}
	result := compareBaseline(b, filters, current, operational)
	var w io.Writer = os.Stdout
	if flagOutput != "" {
		f, err := createOutputFile(flagOutput)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	if err := printComparison(w, result, output.ParseFormat(flagFormat)); err != nil {
		return err
	}
	if result.Regression {
		return fmt.Errorf("%w (threshold %.2f%%)", errBaselineRegression, flagThreshold)
	}
	return nil
}

func exceeds(delta, base, threshold float64) bool {
	return delta > 0 && (base == 0 || delta/base*100 > threshold)
}
func decreases(delta, base, threshold float64) bool {
	return delta < 0 && (base == 0 || -delta/base*100 > threshold)
}

func printComparison(w io.Writer, r comparisonResult, format output.Format) error {
	if format == output.FormatJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	rows := [][]string{{"total_requests", fmt.Sprint(r.BaseRequests), fmt.Sprint(r.CurrRequests), fmt.Sprint(r.RequestsDelta)}, {"requests_per_sec", fmt.Sprintf("%.2f", r.BaseRPS), fmt.Sprintf("%.2f", r.CurrRPS), fmt.Sprintf("%.2f", r.RPSDelta)}, {"5xx_errors", fmt.Sprint(r.BaseErrors), fmt.Sprint(r.CurrErrors), fmt.Sprint(r.ErrorsDelta)}, {"avg_latency_ms", fmt.Sprintf("%.2f", r.BaseAvgDuration*1000), fmt.Sprintf("%.2f", r.CurrAvgDuration*1000), fmt.Sprintf("%.2f", r.AvgDurDelta*1000)}, {"operational_events", fmt.Sprint(r.BaseOperationalEvents), fmt.Sprint(r.CurrOperationalEvents), fmt.Sprint(r.OperationalEventsDelta)}, {"operational_errors", fmt.Sprint(r.BaseOperationalErrors), fmt.Sprint(r.CurrOperationalErrors), fmt.Sprint(r.OperationalErrorsDelta)}}
	if format == output.FormatCSV {
		if _, err := fmt.Fprintln(w, "metric,baseline,target,delta"); err != nil {
			return err
		}
		for _, row := range rows {
			if _, err := fmt.Fprintln(w, strings.Join(row, ",")); err != nil {
				return err
			}
		}
		return nil
	}
	_, err := fmt.Fprintf(w, "CADDY BASELINE COMPARISON\n\n%-24s %-15s %-15s %-15s\n", "Metric", "Baseline", "Target", "Difference")
	for _, row := range rows {
		if err == nil {
			_, err = fmt.Fprintf(w, "%-24s %-15s %-15s %-15s\n", row[0], row[1], row[2], row[3])
		}
	}
	if err == nil {
		_, err = fmt.Fprintf(w, "\nRegression: %t (threshold: %.2f%%)\n", r.Regression, r.Threshold)
	}
	return err
}
