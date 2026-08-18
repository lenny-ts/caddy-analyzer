package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
	"github.com/lenny-ts/caddy-analyzer/pkg/output"
	"github.com/lenny-ts/caddy-analyzer/pkg/parser"
	"github.com/lenny-ts/caddy-analyzer/pkg/progress"
	"github.com/lenny-ts/caddy-analyzer/pkg/reader"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

var flagTopBy string

var topCmd = &cobra.Command{
	Use:   "top [dimension] [source...]",
	Short: "Quickly display top-N metrics for a specific dimension (path, ip, ua, status, method, host, bandwidth, country, asn)",
	Long: `Quickly inspect the top N requests for a specific dimension without generating a full analysis report.

Dimensions:
  path        Top requested HTTP URIs / endpoints (default)
  ip          Top client IP addresses (useful for identifying scrapers & DoS)
  ua          Top User-Agent strings (useful for bot/browser classification)
  status      Top HTTP status codes (200, 404, 500, etc.)
  method      Top HTTP methods (GET, POST, PUT, DELETE, etc.)
  host        Top request domain hosts
  bandwidth   Top paths sorted by total byte bandwidth transferred
  country     Top client countries (requires GeoIP mmdb)
  asn         Top client autonomous systems (requires GeoIP mmdb)

Useful Flags:
  -t, --top <N>      Number of top entries to display (default: 10)
  -b, --by <dim>     Specify dimension via flag (path, ip, ua, status, method, host, bandwidth)
  --5xx              Filter only 5xx server error requests
  --slow <duration>  Filter requests taking longer than duration (e.g. 500ms, 1s)
  --no-bots          Exclude search engine crawlers and automated bots

Examples:
  caddy-analyze top /var/log/caddy/access.log
  caddy-analyze top ip /var/log/caddy/access.log
  caddy-analyze top ip /var/log/caddy/access.log --5xx
  caddy-analyze top bandwidth /var/log/caddy/access.log -t 20
  caddy-analyze top /var/log/caddy/access.log --by status --slow 500ms
  caddy-analyze top docker://my-caddy
`,
	Args: cobra.ArbitraryArgs,
	RunE: runTopCmd,
}

func init() {
	topCmd.Flags().StringVarP(&flagTopBy, "by", "b", "", "Dimension to group by (path, ip, ua, status, method, host, bandwidth)")
	rootCmd.AddCommand(topCmd)
}

func runTopCmd(cmd *cobra.Command, args []string) error {
	var dimension string
	var sourceArgs []string

	if flagTopBy != "" {
		dimension = flagTopBy
		sourceArgs = args
	} else if len(args) > 0 && isSupportedDimension(args[0]) {
		dimension = args[0]
		sourceArgs = args[1:]
	} else {
		dimension = "path"
		sourceArgs = args
	}

	sources, err := resolveSources(sourceArgs)
	if err != nil {
		return err
	}

	filters, err := buildFilters()
	if err != nil {
		return err
	}

	engine := analysis.New(filters)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

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
			continue
		}
		for line := range lines {
			entry, err := parser.Parse(line)
			if err != nil || entry == nil {
				bar.Add(1)
				continue
			}
			enrichGeoIP(entry, geoip)
			engine.Process(entry)
			bar.Add(1)
		}
	}

	bar.Done()

	engine.Finalize()
	s := engine.Stats()

	topN := flagTop
	if topN <= 0 {
		topN = 0
	}

	dim := strings.ToLower(dimension)
	if _, ok := topFieldForDimension(dim); !ok {
		return fmt.Errorf("unknown dimension: %s (supported: path, ip, ua, status, method, host, bandwidth)", dim)
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

	items := topItems(dim, s, topN)
	if dim == "country" || dim == "countries" {
		items = output.RenameCountryItems(items, s.CountryNames)
	}
	if flagDefang {
		for i := range items {
			items[i].Key = output.Defang(items[i].Key)
		}
	}

	switch output.ParseFormat(flagFormat) {
	case output.FormatJSON:
		return writeTopJSON(w, items)
	case output.FormatCSV:
		return writeTopCSV(w, items)
	default:
		title := topTitle(dim)
		if _, err := fmt.Fprintf(w, "Top %s:\n", title); err != nil {
			return err
		}
		for i, item := range items {
			val := item.Count
			if dim == "bandwidth" || dim == "bytes" {
				if _, err := fmt.Fprintf(w, "  %d.  %-40s  (%s)\n", i+1, item.Key, output.FormatBytes(val)); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintf(w, "  %d.  %-40s  (%d)\n", i+1, item.Key, val); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func topFieldForDimension(dim string) (types.TopField, bool) {
	switch dim {
	case "path", "paths":
		return types.TopPath, true
	case "ip", "ips":
		return types.TopRemoteIP, true
	case "ua", "useragent", "user-agent":
		return types.TopUserAgent, true
	case "status":
		return types.TopStatus, true
	case "method", "methods":
		return types.TopMethod, true
	case "host", "hosts":
		return types.TopHost, true
	case "country", "countries":
		return types.TopCountry, true
	case "asn":
		return types.TopASN, true
	case "bandwidth", "bytes":
		return types.TopPath, true
	}
	return "", false
}

func topItems(dim string, s *types.Stats, n int) []types.CountItem {
	switch dim {
	case "status":
		intItems := analysis.TopNInt(s.StatusCounts, n)
		items := make([]types.CountItem, 0, len(intItems))
		for _, it := range intItems {
			items = append(items, types.CountItem{Key: fmt.Sprintf("%d", it.Key), Count: it.Count})
		}
		return items
	case "bandwidth", "bytes":
		return analysis.TopN(s.PathBytesMap, n)
	case "path", "paths":
		return analysis.TopN(s.PathCounts, n)
	case "ip", "ips":
		return analysis.TopN(s.RemoteIPCounts, n)
	case "ua", "useragent", "user-agent":
		return analysis.TopN(s.UserAgentCounts, n)
	case "method", "methods":
		return analysis.TopN(s.MethodCounts, n)
	case "host", "hosts":
		return analysis.TopN(s.HostCounts, n)
	case "country", "countries":
		return analysis.TopN(s.CountryCounts, n)
	case "asn":
		return analysis.TopN(s.ASNCounts, n)
	}
	return nil
}

func topTitle(dim string) string {
	switch dim {
	case "status":
		return "Status Codes"
	case "bandwidth", "bytes":
		return "Bandwidth Paths"
	case "path", "paths":
		return "Paths"
	case "ip", "ips":
		return "Remote IPs"
	case "ua", "useragent", "user-agent":
		return "User Agents"
	case "method", "methods":
		return "Methods"
	case "host", "hosts":
		return "Hosts"
	case "country", "countries":
		return "Countries"
	case "asn":
		return "Autonomous Systems"
	}
	return "Results"
}

func writeTopJSON(w io.Writer, items []types.CountItem) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(items)
}

func writeTopCSV(w io.Writer, items []types.CountItem) error {
	if _, err := fmt.Fprintln(w, "rank,value,count"); err != nil {
		return err
	}
	for i, item := range items {
		if _, err := fmt.Fprintf(w, "%d,%s,%d\n", i+1, output.SafeCell(item.Key), item.Count); err != nil {
			return err
		}
	}
	return nil
}

func isSupportedDimension(s string) bool {
	switch strings.ToLower(s) {
	case "path", "paths", "ip", "ips", "ua", "useragent", "user-agent", "status", "method", "methods", "host", "hosts", "bandwidth", "bytes", "country", "countries", "asn":
		return true
	}
	return false
}
