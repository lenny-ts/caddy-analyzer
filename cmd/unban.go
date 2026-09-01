package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/lenny-ts/caddy-analyzer/pkg/guard"
)

var unbanCmd = &cobra.Command{
	Use:   "unban <ip> [ip...]",
	Short: "Remove IP from firewall",
	Long: `Remove one or more IPs from the firewall (iptables).

Manual unbans are also reflected in the guard state file (if --state-file is
set) so the guard does not re-block the IP on restart.

Examples:
  caddy-analyze unban 192.168.1.1
  caddy-analyze unban 10.0.0.1 10.0.0.2
  caddy-analyze unban --all
  caddy-analyze unban --list
`,
	RunE: runUnban,
}

var (
	unbanAll       bool
	unbanList      bool
	unbanAuditLog  string
	unbanStateFile string
	unbanNotify    auditNotifyFlags
)

func init() {
	unbanCmd.Flags().BoolVarP(&unbanAll, "all", "A", false, "Unblock all currently blocked IPs")
	unbanCmd.Flags().BoolVarP(&unbanList, "list", "l", false, "Show currently blocked IPs")
	unbanCmd.Flags().StringVarP(&unbanAuditLog, "audit-log", "", "/var/log/caddy-analyzer-audit.jsonl", "Audit log path (empty to disable)")
	unbanNotify.addRest(unbanCmd)
	unbanCmd.Flags().StringVarP(&unbanStateFile, "state-file", "", "/var/lib/caddy-analyzer/blocked.json", "Guard state file to sync manual unbans (empty to disable)")
	rootCmd.AddCommand(unbanCmd)
}

func runUnban(cmd *cobra.Command, args []string) error {
	if unbanAll && unbanList {
		return fmt.Errorf("--all and --list are mutually exclusive")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("requires root: run with sudo")
	}
	unbanNotify.auditLog = unbanAuditLog
	dispatcher, err := unbanNotify.dispatcher()
	if err != nil {
		return err
	}
	defer func() { _ = dispatcher.Close() }()
	if unbanList {
		return listBlocked()
	}
	if unbanAll {
		return unblockAll(dispatcher)
	}
	if len(args) == 0 {
		return fmt.Errorf("specify at least one IP to unblock, or use --all")
	}
	return unblockIPs(args, dispatcher)
}

func unblockIPs(ips []string, al interface {
	Log(string, string, string, string)
}) error {
	hadErr := false
	for _, ip := range ips {
		if err := validateIP(ip); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", ip, err)
			hadErr = true
			continue
		}
		if err := guard.UnblockIP(ip); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", ip, err)
			hadErr = true
			continue
		}
		fmt.Printf("  ✓ %s unblocked\n", ip)
		if al != nil {
			al.Log("unblock", ip, "manual unban", "")
		}
		if unbanStateFile != "" {
			if err := guard.RemoveBlockFromState(unbanStateFile, ip); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠ %s: state sync: %v\n", ip, err)
			}
		}
	}
	if hadErr {
		return fmt.Errorf("one or more IPs failed to unblock")
	}
	return nil
}

func unblockAll(al interface {
	Log(string, string, string, string)
}) error {
	ips, err := guard.ListBlockedIPs()
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		fmt.Println("No blocked IPs.")
		return nil
	}
	return unblockIPs(ips, al)
}

func listBlocked() error {
	ips, err := guard.ListBlockedIPs()
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		fmt.Println("No blocked IPs.")
		return nil
	}
	fmt.Println("Blocked IPs:")
	for _, ip := range ips {
		fmt.Printf("  %s\n", ip)
	}
	return nil
}
