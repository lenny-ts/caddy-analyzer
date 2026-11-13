package cmd

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/blocklist"
	"github.com/lenny-ts/caddy-analyzer/pkg/config"
	"github.com/lenny-ts/caddy-analyzer/pkg/enrich"
	"github.com/lenny-ts/caddy-analyzer/pkg/guard"
	"github.com/lenny-ts/caddy-analyzer/pkg/guard/firewall"
)

var (
	guardLimit             int
	guardWindow            string
	guardEvalInterval      string
	guardDuration          string
	guardBanEscalation     bool
	guardBanResetAfter     string
	guardMaxBanDuration    time.Duration
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
	guardFirewallBackend   string
	guardDryRun            bool
	guardProtectSelf       bool
	guardNotify            auditNotifyFlags
)

const (
	minBlocklistRefresh = 1 * time.Hour
	neverBlockRefresh   = 30 * time.Second
)

func init() {
	guardCmd.Flags().IntVarP(&guardLimit, "limit", "l", 100, "Max requests before blocking (0 disables)")
	// Only on guard (and the block/unban commands that share the firewall
	// path): the timeout is meaningless anywhere iptables is not invoked.
	guardCmd.Flags().DurationVar(&flagIPTablesTimeout, "iptables-timeout", 10*time.Second,
		"Timeout for each iptables invocation. Raise it for a huge ruleset on a busy box")
	guardCmd.Flags().StringVarP(&guardWindow, "window", "w", "1m", "Monitoring time window")
	guardCmd.Flags().StringVarP(&guardEvalInterval, "eval-interval", "", guard.DefaultEvalInterval.String(),
		"How often to evaluate blocking thresholds (capped at --window)")
	guardCmd.Flags().StringVarP(&guardDuration, "duration", "d", "10m", "Block duration (e.g. 10m, 1h). 0 = permanent")
	guardCmd.Flags().BoolVar(&guardBanEscalation, "ban-escalation", false, "Progressively increase repeat-offender bans (requires persistent state and a finite --duration)")
	guardCmd.Flags().StringVar(&guardBanResetAfter, "ban-reset-after", "30d", "Forget offender history after this period (supports days, e.g. 30d or 720h)")
	guardCmd.Flags().DurationVar(&guardMaxBanDuration, "max-ban-duration", guard.DefaultMaxBanDuration, "Maximum escalated ban duration")
	guardCmd.Flags().IntVarP(&guardAuthLimit, "auth-limit", "", 10, "Max auth failures (401/403) before blocking (0 disables)")
	guardCmd.Flags().IntVarP(&guardNotFoundLimit, "notfound-limit", "", 50, "Max not found (404) before blocking (0 disables)")
	guardCmd.Flags().IntVarP(&guardDetectConfidence, "detect-confidence", "", 8, "Min confidence (1-10) for pattern-detection blocking; 0 disables")
	guardCmd.Flags().StringVarP(&guardAuditLog, "audit-log", "", "/var/log/caddy-analyzer-audit.jsonl", "Audit log path (empty to disable)")
	guardNotify.addRest(guardCmd)
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
	guardCmd.Flags().StringVarP(&guardFirewallBackend, "firewall-backend", "", "auto",
		"Firewall backend: auto, iptables, docker, nftables, hybrid (auto-detects Docker/nftables)")
	guardCmd.Flags().BoolVar(&guardDryRun, "dry-run", false,
		"Evaluate and report blocks without changing the firewall or state file")
	guardCmd.Flags().BoolVar(&guardProtectSelf, "protect-self", true,
		"Automatically protect server interface/public IPs from bans (requires HTTPS IP discovery)")
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

Self-ban protection (enabled by default):
  • Discover server interface/public IPs at startup, every 30s and before bans
  • Protect these addresses from all automatic bans, including covering subnets
  • Discovery requires direct HTTPS; failures stop startup or suspend new bans
  • Use --protect-self=false to skip server-IP checks; explicit whitelists still apply
  • Remote administrators on another connection need their own --never-block entry

Set any threshold to 0 to disable it. Blockade is temporary (default 10m).
Thresholds are checked every --eval-interval (default 1s, capped at --window).
The counting window and per-window resets remain independent of this cadence.
For permanent block: --duration 0. Rules live in the CADDY_ANALYZER iptables
chain: unban only touches rules created by caddy-analyzer.
To unblock manually: caddy-analyze unban <ip> or --all.

Progressive bans (opt-in): --ban-escalation uses --duration for the first ban,
then at least 1h, 24h, and 168h, capped by --max-ban-duration. Successful bans
count as offenses; history expires after --ban-reset-after (default 30d).
History is stored beside --state-file in its .offenders directory.
Use "guard offenders", "guard offender show <ip>", or "guard offender reset <ip>".
Resetting history does not remove an active ban. Manual unban preserves history
unless --reset-offenses is supplied.

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
	Args:         cobra.ArbitraryArgs,
	RunE:         runGuard,
	SilenceUsage: true,
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

	evalInterval, err := time.ParseDuration(guardEvalInterval)
	if err != nil {
		return fmt.Errorf("invalid eval-interval: %w", err)
	}
	if evalInterval <= 0 {
		return fmt.Errorf("--eval-interval must be > 0")
	}

	duration, err := time.ParseDuration(guardDuration)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", guardDuration, err)
	}
	if guardDuration == "0" {
		duration = 0
	}
	resetAfter, err := parseBanResetAfter(guardBanResetAfter)
	if err != nil {
		return err
	}
	if guardMaxBanDuration <= 0 {
		return fmt.Errorf("--max-ban-duration must be > 0")
	}
	if err := guard.ValidateBanEscalation(guard.Config{
		BanEscalation: guardBanEscalation, BlockDuration: duration,
		StatePath: guardStateFile, BanResetAfter: resetAfter, MaxBanDuration: guardMaxBanDuration,
	}); err != nil {
		return err
	}

	// guard drives iptables, which requires root. Without root every
	// BlockIP silently fails (logged via OnError) and the user believes
	// protection is active while it is not. Fail loud at startup instead.
	// Checked after flag validation so unit tests on invalid flags do not
	// depend on the host's euid.
	if os.Geteuid() != 0 && !guardDryRun {
		return fmt.Errorf("guard requires root: run with sudo (iptables needs CAP_NET_ADMIN)")
	}

	sources, err := resolveSources(args)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	linesCh, err := fanInFollowWithPolicy(ctx, sources, func(name string, err error) error {
		return fmt.Errorf("reading %s: %w", name, err)
	})
	if err != nil {
		return err
	}

	guardNotify.auditLog = guardAuditLog
	dispatcher, err := guardNotify.dispatcher()
	if err != nil {
		return err
	}
	defer func() { _ = dispatcher.Close() }()

	neverBlock := guardNeverBlock
	// --never-block-file overrides the whitelist managed by the whitelist
	// command. The guard reloads whichever file is selected while running.
	neverBlockFile := guardNeverBlockFile
	if neverBlockFile == "" {
		neverBlockFile = WhitelistPath()
	}
	if guardNeverBlockFile != "" {
		// Keep the existing fail-fast behavior for an explicit override.
		if _, err := loadIPList(guardNeverBlockFile); err != nil {
			return fmt.Errorf("never-block-file: %w", err)
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

	// Detect and configure firewall backend.
	var fwBackend firewall.Backend
	switch guardFirewallBackend {
	case "iptables":
		fwBackend = firewall.NewIptablesBackend("iptables", "INPUT")
	case "docker":
		fwBackend = firewall.NewDockerBackend("iptables")
	case "nftables":
		fwBackend = firewall.NewNftablesBackend("ip")
	case "hybrid":
		fwBackend = firewall.Detect(firewall.BackendHybrid)
	case "auto":
		fwBackend = firewall.Detect(firewall.BackendAuto)
	default:
		return fmt.Errorf("unknown firewall backend %q: use auto, iptables, docker, nftables, or hybrid", guardFirewallBackend)
	}

	var selfIPs []string
	var selfLookup func(context.Context) ([]string, error)
	if guardProtectSelf {
		selfLookup = guard.DetectSelfIPs
		selfIPs, err = selfLookup(ctx)
		if err != nil {
			return fmt.Errorf("server IP protection: %w; restart with --protect-self=false to disable server IP checks", err)
		}
	}
	g := guard.New(guard.Config{
		Limit:               guardLimit,
		AuthLimit:           guardAuthLimit,
		NotFoundLimit:       guardNotFoundLimit,
		Window:              window,
		EvalInterval:        evalInterval,
		BlockDuration:       duration,
		BanEscalation:       guardBanEscalation,
		BanResetAfter:       resetAfter,
		MaxBanDuration:      guardMaxBanDuration,
		DetectionConfidence: guardDetectConfidence,
		IPValidator:         validateIP,
		OnAudit:             dispatcher.Log,
		OnError: func(err error) {
			fmt.Fprintf(os.Stderr, "guard error: %v\n", err)
		},
		StatePath:           guardStateFile,
		NeverBlock:          neverBlock,
		NeverBlockFile:      neverBlockFile,
		NeverBlockRefresh:   neverBlockRefresh,
		SelfIPs:             selfIPs,
		SelfIPLookup:        selfLookup,
		TrustForwarded:      flagTrustXFF,
		SubnetLimit:         guardSubnetLimit,
		AnomalyFactor:       guardAnomalyFactor,
		UARotationThreshold: guardUARotation,
		CustomPatterns:      customPatterns,
		AuthAbuse:           authAbuse.NewSession(),
		CredStuffingLimit:   guardCredStuffingLimit,
		BlocklistMgr:        blMgr,
		BlocklistRefresh:    blocklistRefresh,
		CountryBlock:        guardCountryBlock,
		GeoIP:               geoip,
		FirewallBackend:     fwBackend,
		DryRun:              guardDryRun,
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
	mode := "active"
	if guardDryRun {
		mode = "dry-run"
	}
	fmt.Fprintf(os.Stderr, "Guard %s — %s | %s | %s / %s | block: %s\n", mode,
		thr("auth", guardAuthLimit), thr("404", guardNotFoundLimit), thr("total", guardLimit), guardWindow, durMsg)
	fmt.Fprintf(os.Stderr, "Firewall backend: %s\n", fwBackend.Name())
	if guardBanEscalation {
		fmt.Fprintf(os.Stderr, "Ban escalation: on | reset: %s | maximum: %s\n", resetAfter, guardMaxBanDuration)
	}
	if guardProtectSelf {
		fmt.Fprintf(os.Stderr, "Server IP protection: %s (refresh every 30s and before bans)\n", strings.Join(selfIPs, ", "))
	}
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
	if n := g.AllowlistCount(); n > 0 {
		fmt.Fprintf(os.Stderr, "Whitelist: %d entries (%s)\n", n, neverBlockFile)
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
		fmt.Fprintln(os.Stderr, "\nShutting down gracefully...")
		<-done
	case <-done:
	}

	// Final state flush — ensure all blocks are persisted to disk.
	g.FlushState()

	fmt.Fprintln(os.Stderr, "Guard stopped.")
	if n := g.SessionBlocks(); n > 0 {
		label := "IPs blocked this session"
		if guardDryRun {
			label = "IPs that would be blocked this session"
		}
		fmt.Fprintf(os.Stderr, "%s: %d\n", label, n)
	}
	if n := g.BlocklistHits(); n > 0 {
		label := "IPs blocked via blocklist/country-block"
		if guardDryRun {
			label = "IPs that would be blocked via blocklist/country-block"
		}
		fmt.Fprintf(os.Stderr, "%s: %d\n", label, n)
	}
	return nil
}

func parseBanResetAfter(value string) (time.Duration, error) {
	multiplier := time.Duration(1)
	if strings.HasSuffix(value, "d") {
		value = strings.TrimSuffix(value, "d") + "h"
		multiplier = 24
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 || duration > time.Duration(math.MaxInt64)/multiplier {
		return 0, fmt.Errorf("--ban-reset-after must be a positive duration (e.g. 30d or 720h)")
	}
	return duration * multiplier, nil
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
