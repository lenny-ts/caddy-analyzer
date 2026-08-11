package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/L9Lenny/caddy-analyzer/pkg/analysis"
	"github.com/L9Lenny/caddy-analyzer/pkg/config"
	"github.com/L9Lenny/caddy-analyzer/pkg/enrich"
	"github.com/L9Lenny/caddy-analyzer/pkg/output"
	"github.com/L9Lenny/caddy-analyzer/pkg/parser"
	"github.com/L9Lenny/caddy-analyzer/pkg/progress"
	"github.com/L9Lenny/caddy-analyzer/pkg/reader"
	"github.com/L9Lenny/caddy-analyzer/pkg/tui"
	"github.com/L9Lenny/caddy-analyzer/pkg/types"
)

var (
	flagFrom       string
	flagTo         string
	flagStatus     []string
	flagMethod     string
	flagPath       string
	flagTop        int
	flagFormat     string
	flagFollow     bool
	flagK8sNS      string
	flagInterval   string
	flagWatch      bool
	flagDetect     bool
	flagOutput     string
	flag2xx        bool
	flag3xx        bool
	flag4xx        bool
	flag5xx        bool
	flagErrors     bool
	flagSlow       string
	flagIP         string
	flagExcludeIP  string
	flagNoBots     bool
	flagBotsOnly   bool
	flagGrep       string
	flagCompact    bool
	flagTrustXFF   bool
	flagMaxCard    int
	flagUARotation int
	flagHost       string
	flagMaxLatency string
	flagMinSize    string
	flagMaxSize    string
	flagDefang     bool
	flagGeoIPDB    string
)

var Version = "1.0.0"

var rootCmd = &cobra.Command{
	Use:   "caddy-analyze [flags] [source...]",
	Short: "Analyze Caddy access logs from files, stdin, Docker, Kubernetes, or journalctl",
	Args:  cobra.ArbitraryArgs,
	Long: `Analyze Caddy v2 access logs with security detection across 26 attack categories (SQLi, NoSQLi, XSS, SSTI, SSRF, RCE, path traversal, LFI wrappers, GraphQL, Log4j/JNDI, XXE, open redirect, LDAP/XPath/CRLF/SSI injection, prototype pollution, probes, scanners, UA rotation, JWT abuse, object enumeration, beaconing) using a dual-pass evasion-resistant engine.

Sources:
  /path/to/file          Local file (supports glob patterns)
  -                      Stdin (pipe)
  docker://container     Docker container
  k8s://pod              Kubernetes pod  (-n namespace)
  journalctl://unit      systemd unit

Subcommands:
  tail [source...]       Colorized real-time log viewer
  top <dimension>        Quick top-N metric inspector (path, ip, ua, status, method, host, bandwidth)
  diff <log1> <log2>     Compare two log files for RPS shifts, 5xx spikes, and latency changes

Filtering (activate colored log listing instead of report):
  --ip <ip/CIDR>         Filter by client IP or subnet
  -s, --status <codes>   Filter by HTTP status code(s)
  -m, --method <verb>    Filter by HTTP method
  -p, --path <glob>      Filter by request path (glob pattern)
  --slow <duration>      Filter requests slower than duration
  --max-latency <dur>    Filter requests faster than duration (upper bound)
  --min-size <bytes>     Filter responses at least this size (1kb, 1mb, 2gb)
  --max-size <bytes>     Filter responses at most this size (512kb, 1mb)
  --host <host>          Filter by request host (substring, case-insensitive)
  --2xx..--5xx           Filter by status class
  -e, --errors-only      Filter server errors only
  --no-bots / --bots-only Filter by traffic type
  -g, --grep <pattern>   Search across URI, User-Agent, IP

Config (auto-detected):
  ./caddy-analyzer.json        Local config
  ~/.config/caddy-analyzer/config.json  Global config

Examples:
  caddy-analyze /var/log/caddy/access.log
  caddy-analyze --detect /var/log/caddy/access.log
  caddy-analyze --ip 10.0.0.0/8 access.log
  caddy-analyze --5xx --no-bots access.log
  caddy-analyze tail --ip 192.168.1.100 docker://caddy
  caddy-analyze top ip --5xx -t 20 access.log
  caddy-analyze diff base.log current.log
`,
	RunE: runAnalysis,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	flags := rootCmd.PersistentFlags()

	flags.StringVarP(&flagFrom, "from", "", "", "From (RFC3339 or relative: 5m, 1h, 2d)")
	flags.StringVarP(&flagTo, "to", "", "", "To (RFC3339)")
	flags.StringArrayVarP(&flagStatus, "status", "s", nil, "Filter by status code (e.g. -s 200,404)")
	flags.StringVarP(&flagMethod, "method", "m", "", "Filter by HTTP method")
	flags.StringVarP(&flagPath, "path", "p", "", "Filter by path (glob: /api/*)")
	flags.IntVarP(&flagTop, "top", "t", 10, "Show top N (0 to disable)")
	flags.StringVarP(&flagFormat, "format", "f", "table", "Output format: table, json, csv, html")
	flags.StringVarP(&flagOutput, "output", "o", "", "Write report to file instead of stdout")
	flags.BoolVarP(&flag2xx, "2xx", "", false, "Filter 2xx status codes")
	flags.BoolVarP(&flag3xx, "3xx", "", false, "Filter 3xx status codes")
	flags.BoolVarP(&flag4xx, "4xx", "", false, "Filter 4xx status codes")
	flags.BoolVarP(&flag5xx, "5xx", "", false, "Filter 5xx status codes")
	flags.BoolVarP(&flagErrors, "errors-only", "e", false, "Filter 5xx server errors only")
	flags.StringVarP(&flagSlow, "slow", "", "", "Filter requests slower than duration (e.g. 500ms, 1s)")
	flags.StringVarP(&flagIP, "ip", "", "", "Filter by Remote IP")
	flags.StringVarP(&flagExcludeIP, "exclude-ip", "", "", "Exclude Remote IP")
	flags.BoolVarP(&flagNoBots, "no-bots", "", false, "Exclude automated bot and crawler traffic")
	flags.BoolVarP(&flagBotsOnly, "bots-only", "", false, "Include only automated bot traffic")
	flags.StringVar(&flagGrep, "grep", "", "Search pattern across URI, User-Agent, Remote IP")
	flags.BoolVarP(&flagCompact, "compact", "c", false, "Compact output mode")
	flags.BoolVarP(&flagTrustXFF, "trust-forwarded", "", false, "Trust X-Forwarded-For / X-Real-IP for client IP (use behind a reverse proxy/CDN)")
	flags.IntVarP(&flagMaxCard, "max-cardinality", "", 100000, "Max distinct keys tracked per counter (paths, IPs, UAs). 0 = unlimited. Bounds memory on huge-cardinality logs")
	flags.IntVarP(&flagUARotation, "ua-rotation", "", 10, "Distinct User-Agents from one IP before scanner/rotation heuristic fires (0 = default)")
	flags.StringVar(&flagHost, "host", "", "Filter by request host (substring match, case-insensitive)")
	flags.StringVar(&flagMaxLatency, "max-latency", "", "Filter requests faster than duration (e.g. 500ms, 1s). Counterpart to --slow")
	flags.StringVar(&flagMinSize, "min-size", "", "Filter responses at least this size (bytes, or k/mb/gb suffix e.g. 1mb)")
	flags.StringVar(&flagMaxSize, "max-size", "", "Filter responses at most this size (bytes, or k/mb/gb suffix e.g. 512kb)")
	flags.BoolVarP(&flagDefang, "defang", "", false, "Defang IPs in output (replace . with [.]) for safe sharing")
	flags.StringVarP(&flagGeoIPDB, "geoip-db", "", "", "Path to GeoIP mmdb file (DB-IP or MaxMind). Auto-discovers if empty")
	rootCmd.PersistentFlags().StringVarP(&flagK8sNS, "namespace", "n", "", "Kubernetes namespace")

	rootFlags := rootCmd.Flags()
	rootFlags.BoolVarP(&flagFollow, "follow", "F", false, "Follow new logs in real time")
	rootFlags.StringVarP(&flagInterval, "interval", "i", "", "Aggregation interval (e.g. 5m, 1h)")
	rootFlags.BoolVarP(&flagWatch, "watch", "w", false, "Live dashboard (RPS, top IP, status)")
	rootFlags.BoolVarP(&flagDetect, "detect", "d", false, "Detect suspicious activity (SQLi, XSS, scanners, etc.)")

	rootCmd.Flags().BoolP("version", "v", false, "Version")
	rootCmd.Version = Version
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	addHiddenCompletionCmd()
}

func addHiddenCompletionCmd() {
	c := &cobra.Command{
		Use:    "completion [bash|zsh|fish]",
		Short:  "Generate shell completion script",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			}
			return fmt.Errorf("unsupported shell: %s", args[0])
		},
	}
	rootCmd.AddCommand(c)
}

func runAnalysis(cmd *cobra.Command, args []string) error {
	if err := validateFlags(); err != nil {
		return err
	}

	sources := resolveSources(args)

	filters, err := buildFilters()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if flagWatch {
		if !output.IsTerminal(os.Stdout) {
			return fmt.Errorf("--watch requires a terminal; pipe output or use --follow instead")
		}
		return runWatch(ctx, sources)
	}

	var interval time.Duration
	if flagInterval != "" {
		d, err := time.ParseDuration(flagInterval)
		if err != nil {
			return fmt.Errorf("invalid --interval duration: %w", err)
		}
		interval = d
	}
	if interval > 0 {
		return runIntervalMode(ctx, sources, filters, interval)
	}
	if flagFollow {
		return runFollowMode(ctx, sources, filters)
	}
	return runOnceMode(ctx, sources, filters)
}

func validateFlags() error {
	if flagWatch && flagFollow {
		return fmt.Errorf("--watch and --follow are mutually exclusive")
	}
	if flagWatch && flagInterval != "" {
		return fmt.Errorf("--watch and --interval are mutually exclusive")
	}
	if flagFollow && flagInterval != "" {
		return fmt.Errorf("--follow and --interval are mutually exclusive")
	}
	if flagNoBots && flagBotsOnly {
		return fmt.Errorf("--no-bots and --bots-only are mutually exclusive")
	}
	switch strings.ToLower(flagFormat) {
	case "table", "json", "csv", "html":
	default:
		return fmt.Errorf("unsupported --format %q (supported: table, json, csv, html)", flagFormat)
	}
	return nil
}

func runOnceMode(ctx context.Context, sources []types.LogSource, filters types.Filters) error {
	engine := analysis.New(filters)
	if flagDetect {
		det := analysis.NewDetector()
		det.SetUARotationThreshold(flagUARotation)
		engine.SetDetector(det)
	}
	engine.Stats().MaxCardinality = flagMaxCard
	sections := types.DefaultTopSections()
	var parseErrors, processed int64
	var entries []*types.LogEntry
	showListing := output.HasEntryFilters(filters) && flagFormat == "table" && flagOutput == "" && !flagDetect

	geoip := newGeoIPEnricher()
	if geoip != nil {
		defer func() { _ = geoip.Close() }()
	}

	totalLines := countTotalLines(sources)
	bar := progress.New(os.Stderr, totalLines, "Analyzing")

	for _, src := range sources {
		r := reader.FromSource(src)
		lines, err := r.Read(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", r.Name(), err)
			continue
		}
		for line := range lines {
			entry, err := parser.Parse(line)
			if err != nil {
				parseErrors++
				bar.Add(1)
				continue
			}
			if entry == nil {
				bar.Add(1)
				continue
			}
			applyForwarded(entry, filters)
			if !analysis.MatchEntry(entry, filters) {
				bar.Add(1)
				continue
			}
			enrichGeoIP(entry, geoip)
			engine.Process(entry)
			processed++
			bar.Add(1)
			if showListing {
				entries = append(entries, entry)
			}
		}
	}

	bar.Done()

	if processed == 0 && parseErrors == 0 {
		fmt.Fprintln(os.Stderr, "no log entries found")
		return nil
	}

	if showListing {
		fmt.Fprintf(os.Stderr, "%d entries matched\n\n", len(entries))
		output.PrintLogEntries(entries, os.Stdout, flagDefang)
		return nil
	}

	engine.Stats().ParseErrors = parseErrors
	engine.Finalize()
	report := output.NewReportWithSections(engine, output.ParseFormat(flagFormat), flagTop, sections)
	report.SetDetect(flagDetect)
	report.SetDefang(flagDefang)
	report.SetFilters(filters)
	if flagOutput != "" {
		f, err := createOutputFile(flagOutput)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		report.SetWriter(f)
	}
	return report.Print()
}

func applyForwarded(entry *types.LogEntry, filters types.Filters) {
	if filters.TrustForwarded {
		if ip := entry.EffectiveClientIP(true); ip != "" {
			entry.RemoteIP = ip
		}
	}
}

// newGeoIPEnricher creates a GeoIP enricher from the --geoip-db flag or
// auto-discovery. Returns nil if no mmdb file is available (non-fatal:
// analysis continues without country/ASN data).
func newGeoIPEnricher() *enrich.GeoIP {
	g, err := enrich.NewGeoIP(flagGeoIPDB)
	if err != nil {
		if flagGeoIPDB != "" {
			fmt.Fprintf(os.Stderr, "warning: geoip-db: %v (continuing without GeoIP)\n", err)
		}
		return nil
	}
	return g
}

// enrichGeoIP populates entry.Geo from the GeoIP database if available.
func enrichGeoIP(entry *types.LogEntry, g *enrich.GeoIP) {
	if g == nil || entry.RemoteIP == "" {
		return
	}
	info, err := g.Lookup(entry.RemoteIP)
	if err != nil {
		return
	}
	entry.Geo = info
}

// countTotalLines counts the total number of lines across all local file
// sources. For non-file sources (stdin, docker, k8s, journalctl), returns 0
// (indeterminate progress). This is a fast pre-scan (~70K lines/sec) used
// only to set up the progress bar — the actual parsing happens in the main loop.
func countTotalLines(sources []types.LogSource) int64 {
	var total int64
	for _, src := range sources {
		if src.Type != types.SourceFile {
			return 0
		}
		f, err := os.Open(src.Path)
		if err != nil {
			return 0
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			total++
		}
		_ = scanner.Err()
		_ = f.Close()
	}
	return total
}

// fanInFollow opens every source in follow mode and multiplexes their lines
// into a single channel. Per-source read errors are logged to stderr and the
// offending source is skipped, so one bad source does not silence the rest.
// The returned channel is closed when every reader has finished (follow readers
// finish on context cancellation). This fixes the multi-source bug where the
// previous sequential `for _, src := range sources { for line := range lines {} }`
// blocked on the first source forever, since follow readers only close their
// channel on ctx.Done().
func fanInFollow(ctx context.Context, sources []types.LogSource) <-chan string {
	out := make(chan string, 10000)
	var wg sync.WaitGroup
	for _, src := range sources {
		r := reader.FromSourceFollow(src)
		lines, err := r.Read(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", r.Name(), err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for l := range lines {
				select {
				case out <- l:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func runFollowMode(ctx context.Context, sources []types.LogSource, filters types.Filters) error {
	sections := types.DefaultTopSections()
	last := time.Now()
	// Windowing: reset the engine every 5 minutes so maps and the histogram
	// do not grow unbounded over a long follow session. Each window emits a
	// fresh report.
	const window = 5 * time.Minute
	engine := analysis.New(filters)
	if flagDetect {
		det := analysis.NewDetector()
		det.SetUARotationThreshold(flagUARotation)
		engine.SetDetector(det)
	}
	engine.Stats().MaxCardinality = flagMaxCard
	windowStart := time.Now()

	geoip := newGeoIPEnricher()
	if geoip != nil {
		defer func() { _ = geoip.Close() }()
	}

	var w io.Writer = os.Stdout
	if flagOutput != "" {
		f, err := createOutputFile(flagOutput)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	resetEngine := func() {
		engine = analysis.New(filters)
		if flagDetect {
			det := analysis.NewDetector()
			det.SetUARotationThreshold(flagUARotation)
			engine.SetDetector(det)
		}
		engine.Stats().MaxCardinality = flagMaxCard
		windowStart = time.Now()
	}

	for line := range fanInFollow(ctx, sources) {
		entry, err := parser.Parse(line)
		if err != nil || entry == nil {
			continue
		}
		applyForwarded(entry, filters)
		enrichGeoIP(entry, geoip)
		engine.Process(entry)
		if time.Since(last) > 5*time.Second {
			engine.Finalize()
			report := output.NewReportWithSections(engine, output.ParseFormat(flagFormat), flagTop, sections)
			report.SetDetect(flagDetect)
			report.SetDefang(flagDefang)
			report.SetFilters(filters)
			report.SetWriter(w)
			if err := report.Print(); err != nil {
				fmt.Fprintf(os.Stderr, "write report: %v\n", err)
			}
			if time.Since(windowStart) > window {
				resetEngine()
			}
			last = time.Now()
		} else if time.Since(windowStart) > window {
			engine.Finalize()
			report := output.NewReportWithSections(engine, output.ParseFormat(flagFormat), flagTop, sections)
			report.SetDetect(flagDetect)
			report.SetDefang(flagDefang)
			report.SetFilters(filters)
			report.SetWriter(w)
			if err := report.Print(); err != nil {
				fmt.Fprintf(os.Stderr, "write report: %v\n", err)
			}
			resetEngine()
		}
	}
	return nil
}

func runIntervalMode(ctx context.Context, sources []types.LogSource, filters types.Filters, interval time.Duration) error {
	var current time.Time
	var engine *analysis.Engine
	sections := types.DefaultTopSections()
	initial := true

	geoip := newGeoIPEnricher()
	if geoip != nil {
		defer func() { _ = geoip.Close() }()
	}

	var w io.Writer = os.Stdout
	if flagOutput != "" {
		f, err := createOutputFile(flagOutput)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	reportFn := func(e *analysis.Engine, t time.Time) error {
		e.Finalize()
		fmt.Fprintf(w, "\n--- %s ---\n", t.Format(time.RFC3339))
		report := output.NewReportWithSections(e, output.ParseFormat(flagFormat), flagTop, sections)
		report.SetDetect(flagDetect)
		report.SetDefang(flagDefang)
		report.SetFilters(filters)
		report.SetWriter(w)
		return report.Print()
	}

	for _, src := range sources {
		r := reader.FromSource(src)
		lines, err := r.Read(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", r.Name(), err)
			continue
		}
		for line := range lines {
			entry, err := parser.Parse(line)
			if err != nil || entry == nil {
				continue
			}
			applyForwarded(entry, filters)
			enrichGeoIP(entry, geoip)
			bucket := entry.Timestamp.Truncate(interval)
			if initial {
				current = bucket
				engine = analysis.New(filters)
				if flagDetect {
					det := analysis.NewDetector()
					det.SetUARotationThreshold(flagUARotation)
					engine.SetDetector(det)
				}
				initial = false
			}
			if bucket != current {
				if err := reportFn(engine, current); err != nil {
					return err
				}
				engine = analysis.New(filters)
				if flagDetect {
					det := analysis.NewDetector()
					det.SetUARotationThreshold(flagUARotation)
					engine.SetDetector(det)
				}
				current = bucket
			}
			engine.Process(entry)
		}
	}
	if engine != nil && engine.Count() > 0 {
		return reportFn(engine, current)
	}
	return nil
}

func runWatch(ctx context.Context, sources []types.LogSource) error {
	linesCh := make(chan string, 10000)
	var wg sync.WaitGroup
	for _, src := range sources {
		r := reader.FromSourceFollow(src)
		lines, err := r.Read(ctx)
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for l := range lines {
				select {
				case linesCh <- l:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(linesCh)
	}()

	p := tea.NewProgram(tui.NewModel(linesCh), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// createOutputFile opens (or creates) the output file at path, creating
// parent directories with 0750 and the file with 0600 to avoid leaking
// security report data to other users.
func createOutputFile(path string) (*os.File, error) {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("create output directory: %w", err)
		}
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
}

func resolveSources(args []string) []types.LogSource {
	if len(args) > 0 {
		return parseSources(args)
	}
	cfg, cfgPath, err := config.Load()
	if err == nil && cfg != nil && cfg.Source != "" {
		fmt.Fprintf(os.Stderr, "using config: %s\n", cfgPath)
		src := reader.ParseSource(cfg.Source)
		if src.Type == types.SourceK8s && src.Namespace == "" {
			src.Namespace = flagK8sNS
			if src.Namespace == "" {
				src.Namespace = cfg.Namespace
			}
		}
		return []types.LogSource{src}
	}

	fi, err := os.Stdin.Stat()
	if err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
		return []types.LogSource{{Type: types.SourceStdin}}
	}

	candidates := []string{
		"access.log",
		"caddy.log",
		"caddy-access.log",
		"/var/log/caddy/access.log",
		"/var/log/caddy/caddy.log",
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			fmt.Fprintf(os.Stderr, "auto-detected log file: %s\n", candidate)
			return []types.LogSource{{Type: types.SourceFile, Path: candidate}}
		}
	}

	return []types.LogSource{{Type: types.SourceStdin}}
}

func parseSources(args []string) []types.LogSource {
	s := make([]types.LogSource, 0, len(args))
	for _, a := range args {
		src := reader.ParseSource(a)
		if src.Type == types.SourceK8s && flagK8sNS != "" && src.Namespace == "" {
			src.Namespace = flagK8sNS
		}
		s = append(s, src)
	}
	return s
}

func buildFilters() (types.Filters, error) {
	var f types.Filters
	if flagFrom != "" {
		t, err := parseTime(flagFrom)
		if err != nil {
			return f, fmt.Errorf("--from: %w", err)
		}
		f.From = t
		f.HasFrom = true
	}
	if flagTo != "" {
		t, err := parseTime(flagTo)
		if err != nil {
			return f, fmt.Errorf("--to: %w", err)
		}
		f.To = t
		f.HasTo = true
	}
	if f.HasFrom && f.HasTo && f.From.After(f.To) {
		return f, fmt.Errorf("--from (%s) must not be later than --to (%s)", flagFrom, flagTo)
	}
	for _, s := range flagStatus {
		for _, ss := range strings.Split(s, ",") {
			code, err := strconv.Atoi(strings.TrimSpace(ss))
			if err != nil {
				return f, fmt.Errorf("invalid status: %s", ss)
			}
			f.Status = append(f.Status, code)
		}
	}
	f.Method = flagMethod
	f.PathGlob = flagPath
	f.Only2xx = flag2xx
	f.Only3xx = flag3xx
	f.Only4xx = flag4xx
	f.Only5xx = flag5xx
	f.ErrorsOnly = flagErrors
	f.NoBots = flagNoBots
	f.BotsOnly = flagBotsOnly
	f.RemoteIP = flagIP
	f.ExcludeIP = flagExcludeIP
	f.GrepPattern = flagGrep
	f.Compact = flagCompact
	f.TrustForwarded = flagTrustXFF
	f.Host = flagHost

	if flagSlow != "" {
		dur, err := time.ParseDuration(flagSlow)
		if err != nil {
			return f, fmt.Errorf("invalid --slow duration: %w", err)
		}
		f.MinLatency = dur.Seconds()
	}
	if flagMaxLatency != "" {
		dur, err := time.ParseDuration(flagMaxLatency)
		if err != nil {
			return f, fmt.Errorf("invalid --max-latency duration: %w", err)
		}
		f.MaxLatency = dur.Seconds()
	}
	if f.MinLatency > 0 && f.MaxLatency > 0 && f.MinLatency > f.MaxLatency {
		return f, fmt.Errorf("--slow (%s) must not be greater than --max-latency (%s)", flagSlow, flagMaxLatency)
	}
	if flagMinSize != "" {
		n, err := parseSize(flagMinSize)
		if err != nil {
			return f, fmt.Errorf("invalid --min-size %q: %w", flagMinSize, err)
		}
		f.MinSize = n
	}
	if flagMaxSize != "" {
		n, err := parseSize(flagMaxSize)
		if err != nil {
			return f, fmt.Errorf("invalid --max-size %q: %w", flagMaxSize, err)
		}
		f.MaxSize = n
	}
	if f.MinSize > 0 && f.MaxSize > 0 && f.MinSize > f.MaxSize {
		return f, fmt.Errorf("--min-size (%s) must not be greater than --max-size (%s)", flagMinSize, flagMaxSize)
	}

	if flagIP != "" {
		if err := validateIPOrCIDR(flagIP); err != nil {
			return f, fmt.Errorf("invalid --ip %q: %w", flagIP, err)
		}
	}
	if flagExcludeIP != "" {
		if err := validateIPOrCIDR(flagExcludeIP); err != nil {
			return f, fmt.Errorf("invalid --exclude-ip %q: %w", flagExcludeIP, err)
		}
	}

	return f, nil
}

// validateIPOrCIDR accepts a bare IP or a CIDR. Used to fail fast on a typo'd
// --ip / --exclude-ip filter instead of silently returning "no log entries
// found" when the CIDR fails to parse inside MatchEntry.
func validateIPOrCIDR(s string) error {
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("looks like a flag")
	}
	if net.ParseIP(s) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nil
	}
	return fmt.Errorf("not a valid IP or CIDR")
}

// parseSize parses a byte size. A bare integer is bytes. A suffix of k/kb, m/mb,
// g/gb (case-insensitive) multiplies by 1024^N. Examples: 512, 1kb, 1mb, 2gb.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(strings.ToLower(s), "kb"):
		mult, s = 1<<10, s[:len(s)-2]
	case strings.HasSuffix(strings.ToLower(s), "mb"):
		mult, s = 1<<20, s[:len(s)-2]
	case strings.HasSuffix(strings.ToLower(s), "gb"):
		mult, s = 1<<30, s[:len(s)-2]
	case strings.HasSuffix(strings.ToLower(s), "k"):
		mult, s = 1<<10, s[:len(s)-1]
	case strings.HasSuffix(strings.ToLower(s), "m"):
		mult, s = 1<<20, s[:len(s)-1]
	case strings.HasSuffix(strings.ToLower(s), "g"):
		mult, s = 1<<30, s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("not a valid size: %w", err)
	}
	if n < 0 {
		return 0, fmt.Errorf("size must be non-negative")
	}
	return n * mult, nil
}

func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	unit := s[len(s)-1:]
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid time: %s", s)
	}
	if n < 0 {
		return time.Time{}, fmt.Errorf("relative time must be positive: %s", s)
	}
	now := time.Now()
	switch unit {
	case "s":
		return now.Add(-time.Duration(n) * time.Second), nil
	case "m":
		return now.Add(-time.Duration(n) * time.Minute), nil
	case "h":
		return now.Add(-time.Duration(n) * time.Hour), nil
	case "d":
		return now.Add(-time.Duration(n) * 24 * time.Hour), nil
	}
	return time.Time{}, fmt.Errorf("unknown time unit: %s", unit)
}
