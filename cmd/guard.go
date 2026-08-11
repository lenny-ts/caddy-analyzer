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

	"github.com/L9Lenny/caddy-analyzer/pkg/audit"
	"github.com/L9Lenny/caddy-analyzer/pkg/guard"
	"github.com/L9Lenny/caddy-analyzer/pkg/reader"
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
)

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

	sources := resolveSources(args)

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
