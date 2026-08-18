package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/audit"
	"github.com/lenny-ts/caddy-analyzer/pkg/blocklist"
	"github.com/lenny-ts/caddy-analyzer/pkg/config"
	"github.com/lenny-ts/caddy-analyzer/pkg/enrich"
	"github.com/lenny-ts/caddy-analyzer/pkg/guard"
	"github.com/lenny-ts/caddy-analyzer/pkg/reader"
)

var (
	guardLimit             int
	guardWindow            string
	guardDuration          string
	guardAuthLimit         int
	guardNotFoundLimit     int
	guardDetectConfidence  int
	guardAuditLog          string
	guardStateFile         string
	guardNeverBlock        []string
	guardNeverBlockFile    string
	guardSubnetLimit       int
	guardAnomalyFactor     float64
	guardUARotation        int
	guardCredStuffingLimit int
	guardCountryBlock      []string
	guardBlocklistRefresh  string
	guardNoBlocklist       bool
	guardGeoIPDB           string
	guardNoAutoDL          bool
)

const minBlocklistRefresh = 1 * time.Hour

func init() {
	guardCmd.Flags().IntVarP(&guardLimit, "limit", "l", 100, "Max requests before blocking (0 disables)")
	guardCmd.Flags().StringVarP(&guardWindow, "window", "w", "1m", "Monitoring time window")
	guardCmd.Flags().StringVarP(&guardDuration, "duration", "d", "10m", "Block duration (e.g. 10m, 1h). 0 = permanent")
	guardCmd.Flags().IntVarP(&guardAuthLimit, "auth-limit", "", 10, "Max auth failures (401/403) before blocking (0 disables)")
	guardCmd.Flags().IntVarP(&guardNotFoundLimit, "notfound-limit", "", 50, "Max not found (404) before blocking (0 disables)")
	guardCmd.Flags().IntVarP(&guardDetectConfidence, "detect-confidence", "", 8, "Min confidence (1-10) for pattern-detection blocking; 0 disables")
	guardCmd.Flags().StringVarP(&guardAuditLog, "audit-log", "", "/var/log/caddy-analyzer-audit.jsonl", "Audit log path (empty to disable)")
	guardCmd.Flags().StringVarP(&guardStateFile, "state-file", "", "/var/lib/caddy-analyzer/blocked.json", "State file for crash recovery (empty to disable)")
	guardCmd.Flags().StringSliceVarP(&guardNeverBlock, "never-block", "", nil, "IPs/CIDRs that will never be blocked (e.g. 10.0.0.0/8,192.168.1.1)")
	guardCmd.Flags().StringVarP(&guardNeverBlockFile, "never-block-file", "", "", "File with IPs/CIDRs to never block (one per line, # comments allowed)")
	guardCmd.Flags().IntVarP(&guardSubnetLimit, "subnet-limit", "", 0, "Block a /24 when its combined requests exceed this (0 disables; distributed-scan defense)")
	guardCmd.Flags().Float64VarP(&guardAnomalyFactor, "rps-anomaly", "", 0, "Alert when current RPS exceeds this factor over the EWMA baseline (0 disables; e.g. 5 = 5x spike)")
	guardCmd.Flags().IntVarP(&guardUARotation, "ua-rotation", "", 10, "Distinct User-Agents from one IP before scanner/rotation heuristic fires")
	guardCmd.Flags().IntVarP(&guardCredStuffingLimit, "cred-stuffing-limit", "", 0, "Alert when N distinct IPs fail auth on the same path (0 disables)")
	guardCmd.Flags().StringSliceVarP(&guardCountryBlock, "country-block", "", nil, "Block IPs from these ISO country codes (e.g. CN,RU,IR)")
	guardCmd.Flags().StringVarP(&guardBlocklistRefresh, "blocklist-refresh", "", "6h", "Blocklist background refresh interval (min 1h; 0 disables)")
	guardCmd.Flags().BoolVarP(&guardNoBlocklist, "no-blocklist", "", false, "Disable blocklist feed checking")
	guardCmd.Flags().StringVarP(&guardGeoIPDB, "geoip-db", "", "", "Path to GeoIP mmdb file (auto-discovered if empty)")
	guardCmd.Flags().BoolVarP(&guardNoAutoDL, "no-auto-download", "", false, "Disable automatic download of DB-IP lite mmdb on first run")
	guardCmd.Flags().StringVarP(&blocklistCacheDir, "cache-dir", "", defaultBlocklistCacheDir(), "Directory for cached blocklist files")
	rootCmd.AddCommand(guardCmd)
}

var guardCmd = &cobra.Command{
	Use:   "guard [source]",
	Short: "Auto-block malicious IPs in real time",
	Long: `Monitor logs in real time and automatically block malicious IPs via iptables.

Detection:
  • Auth failure surge (401/403) — brute force / credential stuffing
  • 404 surge — directory scanning / enumeration
  • Request threshold — generic high-volume
  • Pattern detection — 26 categories: SQLi, NoSQLi, XSS, SSTI, SSRF, RCE, path traversal, LFI wrappers, GraphQL, Log4j/JNDI, XXE, open redirect, LDAP/XPath/CRLF/SSI injection, prototype pollution, probes, scanners, UA rotation, JWT abuse, object enumeration, beaconing (confidence >= --detect-confidence)
  • Blocklist feeds (Spamhaus DROP, FireHOL, CINS, Tor, Emerging Threats, AbuseIPDB) — immediate block
  • Country block (--country-block) — immediate block by GeoIP country code

Set any threshold to 0 to disable it. Blockade is temporary (default 10m).
For permanent block: --duration 0. Rules live in the CADDY_ANALYZER iptables
chain: unban only touches rules created by caddy-analyzer.
To unblock manually: caddy-analyze unban <ip> or --all.

Examples:
  caddy-analyze guard /var/log/caddy/access.log
  caddy-analyze guard docker://my-caddy --limit 200 --window 5m
  caddy-analyze guard docker://my-caddy --duration 1h
  caddy-analyze guard k8s://caddy-pod -n production --auth-limit 5
  caddy-analyze guard /var/log/caddy/access.log --never-block 10.0.0.0/8,192.168.1.1
  caddy-analyze guard /var/log/caddy/access.log --never-block-file /etc/caddy-analyzer/allowlist.txt
  caddy-analyze guard /var/log/caddy/access.log --country-block CN,RU,IR --geoip-db /etc/geoip/dbip-country-lite.mmdb
  caddy-analyze guard /var/log/caddy/access.log --no-blocklist
`,
	Args: cobra.ArbitraryArgs,
	RunE: runGuard,
}

func runGuard(cmd *cobra.Command, args []string) error {
	if guardLimit < 0 || guardAuthLimit < 0 || guardNotFoundLimit < 0 || guardDetectConfidence < 0 || guardSubnetLimit < 0 {
		return fmt.Errorf("limits and detect-confidence must be >= 0 (0 disables)")
	}

	window, err := time.ParseDuration(guardWindow)
	if err != nil {
		return fmt.Errorf("invalid window: %w", err)
	}
	if window <= 0 {
		return fmt.Errorf("--window must be > 0")
	}

	duration, err := time.ParseDuration(guardDuration)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", guardDuration, err)
	}
	if guardDuration == "0" {
		duration = 0
	}

	// guard drives iptables, which requires root. Without root every
	// BlockIP silently fails (logged via OnError) and the user believes
	// protection is active while it is not. Fail loud at startup instead.
	// Checked after flag validation so unit tests on invalid flags do not
	// depend on the host's euid.
	if os.Geteuid() != 0 {
		return fmt.Errorf("guard requires root: run with sudo (iptables needs CAP_NET_ADMIN)")
	}

	sources, err := resolveSources(args)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	linesCh := make(chan string, 10000)
	var wg sync.WaitGroup
	for _, src := range sources {
		r := reader.FromSourceFollow(src)
		lines, err := r.Read(ctx)
		if err != nil {
			return fmt.Errorf("reading %s: %w", r.Name(), err)
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

	var onAudit func(action, ip, reason, duration string)
	if guardAuditLog != "" {
		al, err := audit.New(guardAuditLog)
		if err != nil {
			return fmt.Errorf("audit log: %w", err)
		}
		al.SetErrorHandler(func(err error) {
			fmt.Fprintf(os.Stderr, "audit error: %v\n", err)
		})
		defer func() { _ = al.Close() }()
		onAudit = al.Log
	}

	neverBlock := guardNeverBlock
	if guardNeverBlockFile != "" {
		ips, err := loadIPList(guardNeverBlockFile)
		if err != nil {
			return fmt.Errorf("never-block-file: %w", err)
		}
		for _, ip := range ips {
			if err := validateIP(ip); err != nil {
				fmt.Fprintf(os.Stderr, "warning: skipping invalid allowlist entry %q: %v\n", ip, err)
				continue
			}
			neverBlock = append(neverBlock, ip)
		}
	}

	// Blocklist manager: load cached feeds first, then start background
	// refresh. If --no-blocklist is set, skip entirely. Source list is
	// assembled from the config file (if any) so 'blocklist init'
	// settings are honoured.
	var blMgr *blocklist.Manager
	if !guardNoBlocklist {
		var sources []blocklist.Source
		cfg, _, _ := config.Load()
		if cfg != nil && cfg.Blocklist != nil {
			var err error
			sources, err = cfg.Blocklist.ResolveSources()
			if err != nil {
				return fmt.Errorf("blocklist config: %w", err)
			}
		}
		var err error
		blMgr, err = blocklist.NewManager(sources, blocklistCacheDir)
		if err != nil {
			return fmt.Errorf("blocklist manager: %w", err)
		}
		blMgr.LoadAll()
		stats := blMgr.Stats()
		if stats.Active == 0 {
			fmt.Fprintf(os.Stderr, "No cached blocklists found. Running initial refresh...\n")
			statuses := blMgr.Refresh()
			active := 0
			for _, st := range statuses {
				if st.Error == "" && st.Entries > 0 {
					active++
				}
				if st.Error != "" {
					fmt.Fprintf(os.Stderr, "  %s: %s\n", st.Name, st.Error)
				} else {
					fmt.Fprintf(os.Stderr, "  %s: %d entries\n", st.Name, st.Entries)
				}
			}
			if active == 0 {
				fmt.Fprintf(os.Stderr, "Warning: all blocklist feeds failed. Running without blocklist protection.\n")
			}
		}
	}

	// GeoIP enricher: needed for country-block. If --geoip-db is empty,
	// auto-discovery is attempted. If country-block is set but no GeoIP
	// db is found, warn the user.
	var geoip *enrich.GeoIP
	if len(guardCountryBlock) > 0 || guardGeoIPDB != "" {
		enrich.SetAutoDownload(!guardNoAutoDL)
		var err error
		geoip, err = enrich.NewGeoIP(guardGeoIPDB)
		if err != nil {
			if len(guardCountryBlock) > 0 {
				return fmt.Errorf("--country-block requires GeoIP db: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Warning: GeoIP db not found, country/ASN enrichment disabled: %v\n", err)
			geoip = nil
		} else {
			defer func() { _ = geoip.Close() }()
		}
	}

	var blocklistRefresh time.Duration
	if guardBlocklistRefresh == "0" {
		blocklistRefresh = 0
	} else {
		blocklistRefresh, err = time.ParseDuration(guardBlocklistRefresh)
		if err != nil {
			return fmt.Errorf("invalid blocklist-refresh %q: %w", guardBlocklistRefresh, err)
		}
		if blocklistRefresh > 0 && blocklistRefresh < minBlocklistRefresh {
			return fmt.Errorf("--blocklist-refresh must be >= %s", minBlocklistRefresh)
		}
	}

	g := guard.New(guard.Config{
		Limit:               guardLimit,
		AuthLimit:           guardAuthLimit,
		NotFoundLimit:       guardNotFoundLimit,
		Window:              window,
		BlockDuration:       duration,
		DetectionConfidence: guardDetectConfidence,
		IPValidator:         validateIP,
		OnAudit:             onAudit,
		OnError: func(err error) {
			fmt.Fprintf(os.Stderr, "guard error: %v\n", err)
		},
		StatePath:           guardStateFile,
		NeverBlock:          neverBlock,
		TrustForwarded:      flagTrustXFF,
		SubnetLimit:         guardSubnetLimit,
		AnomalyFactor:       guardAnomalyFactor,
		UARotationThreshold: guardUARotation,
		CredStuffingLimit:   guardCredStuffingLimit,
		BlocklistMgr:        blMgr,
		BlocklistRefresh:    blocklistRefresh,
		CountryBlock:        guardCountryBlock,
		GeoIP:               geoip,
	})

	durMsg := duration.String()
	if duration <= 0 {
		durMsg = "permanent"
	}
	thr := func(label string, v int) string {
		if v <= 0 {
			return label + ": off"
		}
		return fmt.Sprintf("%s: >%d", label, v)
	}
	fmt.Fprintf(os.Stderr, "Guard active — %s | %s | %s / %s | block: %s\n",
		thr("auth", guardAuthLimit), thr("404", guardNotFoundLimit), thr("total", guardLimit), guardWindow, durMsg)
	if guardDetectConfidence > 0 {
		fmt.Fprintf(os.Stderr, "Pattern detection blocking: confidence >= %d\n", guardDetectConfidence)
	} else {
		fmt.Fprintf(os.Stderr, "Pattern detection blocking: off\n")
	}
	if blMgr != nil {
		stats := blMgr.Stats()
		fmt.Fprintf(os.Stderr, "Blocklist: %d entries across %d active sources\n", stats.Total, stats.Active)
		if blocklistRefresh > 0 {
			fmt.Fprintf(os.Stderr, "Blocklist refresh: every %s\n", blocklistRefresh)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Blocklist: off\n")
	}
	if len(guardCountryBlock) > 0 && geoip != nil {
		fmt.Fprintf(os.Stderr, "Country block: %s\n", strings.Join(guardCountryBlock, ", "))
	}
	fmt.Fprintf(os.Stderr, "Ctrl+C to stop\n\n")

	logf := func(format string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, format, args...)
	}

	done := make(chan struct{})
	go func() {
		g.Run(ctx, linesCh, logf)
		close(done)
	}()

	select {
	case <-ctx.Done():
		<-done
	case <-done:
	}
	fmt.Fprintln(os.Stderr, "\nGuard stopped.")
	if n := g.Count(); n > 0 {
		fmt.Fprintf(os.Stderr, "IPs blocked this session: %d\n", n)
	}
	if n := g.BlocklistHits(); n > 0 {
		fmt.Fprintf(os.Stderr, "IPs blocked via blocklist/country-block: %d\n", n)
	}
	return nil
}

func loadIPList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var ips []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ips = append(ips, line)
	}
	return ips, scanner.Err()
}
