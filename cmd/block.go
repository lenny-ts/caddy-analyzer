package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/audit"
	"github.com/lenny-ts/caddy-analyzer/pkg/guard"
)

var blockAuditLog string
var blockStateFile string

var blockCmd = &cobra.Command{
	Use:   "block <ip> [ip...]",
	Short: "Block IP via iptables",
	Long: `Block one or more IPs via iptables.

Manual blocks are also written to the guard state file (if --state-file is
set) so they survive guard restarts.

Examples:
  caddy-analyze block 10.0.0.1
  caddy-analyze block 192.168.1.1 10.0.0.2
`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("requires root: run with sudo")
		}
		var al *audit.Logger
		if blockAuditLog != "" {
			var err error
			al, err = audit.New(blockAuditLog)
			if err != nil {
				return fmt.Errorf("audit log: %w", err)
			}
			defer func() { _ = al.Close() }()
		}
		hadErr := false
		for _, ip := range args {
			if err := validateIP(ip); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", ip, err)
				hadErr = true
				continue
			}
			if err := guard.BlockIP(ip); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", ip, err)
				hadErr = true
				continue
			}
			fmt.Printf("  ✓ %s blocked\n", ip)
			if al != nil {
				al.Log("block", ip, "manual block", "permanent")
			}
			if blockStateFile != "" {
				if err := guard.AddPermanentBlockToState(blockStateFile, ip); err != nil {
					fmt.Fprintf(os.Stderr, "  ⚠ %s: state sync: %v\n", ip, err)
				}
			}
		}
		if hadErr {
			return fmt.Errorf("one or more IPs failed to block")
		}
		return nil
	},
}

func init() {
	blockCmd.Flags().StringVarP(&blockAuditLog, "audit-log", "", "/var/log/caddy-analyzer-audit.jsonl", "Audit log path (empty to disable)")
	blockCmd.Flags().StringVarP(&blockStateFile, "state-file", "", "/var/lib/caddy-analyzer/blocked.json", "Guard state file to sync manual blocks (empty to disable)")
	rootCmd.AddCommand(blockCmd)
}
