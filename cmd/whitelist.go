package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	whitelistFile string
	whitelistAdd  []string
	whitelistRem  []string
	whitelistList bool
	whitelistInit bool
)

const defaultWhitelistPath = "/etc/caddy-analyzer/whitelist.txt"

var whitelistCmd = &cobra.Command{
	Use:   "whitelist",
	Short: "Manage the IP whitelist (never-block list)",
	Long: `Manage the IP whitelist — IPs/CIDRs in this list will never be blocked
by the guard daemon.

The whitelist is stored in a file (default: /etc/caddy-analyzer/whitelist.txt)
and loaded automatically by the guard via --never-block-file.

Examples:
  caddy-analyze whitelist --list
  caddy-analyze whitelist --add 10.0.0.0/8,192.168.1.1
  caddy-analyze whitelist --add 172.16.0.0/12
  caddy-analyze whitelist --remove 192.168.1.1
  caddy-analyze whitelist --init
`,
	Args: cobra.NoArgs,
	RunE: runWhitelist,
}

func init() {
	whitelistCmd.Flags().StringVar(&whitelistFile, "file", defaultWhitelistPath, "Whitelist file path")
	whitelistCmd.Flags().StringSliceVar(&whitelistAdd, "add", nil, "IPs/CIDRs to add to the whitelist")
	whitelistCmd.Flags().StringSliceVar(&whitelistRem, "remove", nil, "IPs/CIDRs to remove from the whitelist")
	whitelistCmd.Flags().BoolVarP(&whitelistList, "list", "l", false, "Show current whitelist")
	whitelistCmd.Flags().BoolVar(&whitelistInit, "init", false, "Create the whitelist file with header")
	rootCmd.AddCommand(whitelistCmd)
}

func runWhitelist(cmd *cobra.Command, args []string) error {
	// --init: create the whitelist file with a header.
	if whitelistInit {
		return initWhitelist()
	}

	// --list: show current entries.
	if whitelistList {
		return listWhitelist()
	}

	// --add: append entries.
	if len(whitelistAdd) > 0 {
		if err := addWhitelist(whitelistAdd); err != nil {
			return err
		}
	}

	// --remove: delete entries.
	if len(whitelistRem) > 0 {
		if err := removeWhitelist(whitelistRem); err != nil {
			return err
		}
	}

	// No flags provided — show help.
	if !whitelistInit && !whitelistList && len(whitelistAdd) == 0 && len(whitelistRem) == 0 {
		_ = cmd.Help()
	}

	return nil
}

func initWhitelist() error {
	if _, err := os.Stat(whitelistFile); err == nil {
		fmt.Fprintf(os.Stderr, "Whitelist file already exists: %s\n", whitelistFile)
		fmt.Fprintf(os.Stderr, "Use --list to view, --add to append, --remove to delete.\n")
		return nil
	}

	dir := strings.TrimSuffix(whitelistFile, "/whitelist.txt")
	if dir == whitelistFile {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create whitelist dir: %w", err)
	}

	header := `# caddy-analyzer whitelist
# IPs and CIDRs listed here will NEVER be blocked by the guard daemon.
# One entry per line. Lines starting with # are comments.
# Example:
#   10.0.0.0/8
#   192.168.1.1
#   203.0.113.50/32
`
	if err := os.WriteFile(whitelistFile, []byte(header), 0600); err != nil {
		return fmt.Errorf("create whitelist: %w", err)
	}
	fmt.Printf("  ✓ Whitelist created: %s\n", whitelistFile)
	return nil
}

func listWhitelist() error {
	entries, err := loadWhitelist()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("Whitelist is empty.")
		return nil
	}
	fmt.Printf("Whitelist (%s):\n", whitelistFile)
	for _, e := range entries {
		fmt.Printf("  %s\n", e)
	}
	return nil
}

func addWhitelist(ips []string) error {
	existing, err := loadWhitelist()
	if err != nil {
		return err
	}
	existSet := make(map[string]bool, len(existing))
	for _, e := range existing {
		existSet[e] = true
	}

	f, err := os.OpenFile(whitelistFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("open whitelist: %w", err)
	}
	defer func() { _ = f.Close() }()

	added := 0
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if err := validateIP(ip); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", ip, err)
			continue
		}
		if existSet[ip] {
			fmt.Fprintf(os.Stderr, "  - %s (already in whitelist)\n", ip)
			continue
		}
		if _, err := fmt.Fprintf(f, "%s\n", ip); err != nil {
			return fmt.Errorf("write whitelist: %w", err)
		}
		fmt.Printf("  ✓ %s added\n", ip)
		existSet[ip] = true
		added++
	}

	if added > 0 {
		fmt.Printf("Whitelist updated: %s (%d entries)\n", whitelistFile, len(existing)+added)
	}
	return nil
}

func removeWhitelist(ips []string) error {
	entries, err := loadWhitelist()
	if err != nil {
		return err
	}

	removeSet := make(map[string]bool, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			removeSet[ip] = true
		}
	}

	var kept []string
	removed := 0
	for _, e := range entries {
		if removeSet[e] {
			fmt.Printf("  ✓ %s removed\n", e)
			removed++
			delete(removeSet, e)
		} else {
			kept = append(kept, e)
		}
	}

	for ip := range removeSet {
		fmt.Fprintf(os.Stderr, "  - %s (not found in whitelist)\n", ip)
	}

	// Rewrite the file.
	var content strings.Builder
	content.WriteString("# caddy-analyzer whitelist\n")
	content.WriteString("# IPs and CIDRs listed here will NEVER be blocked by the guard daemon.\n")
	content.WriteString("# One entry per line. Lines starting with # are comments.\n")
	for _, e := range kept {
		content.WriteString(e)
		content.WriteString("\n")
	}

	if err := os.WriteFile(whitelistFile, []byte(content.String()), 0600); err != nil {
		return fmt.Errorf("write whitelist: %w", err)
	}

	if removed > 0 {
		fmt.Printf("Whitelist updated: %s (%d entries)\n", whitelistFile, len(kept))
	}
	return nil
}

func loadWhitelist() ([]string, error) {
	f, err := os.Open(whitelistFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open whitelist: %w", err)
	}
	defer func() { _ = f.Close() }()

	var entries []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	return entries, scanner.Err()
}

// WhitelistPath returns the path to the whitelist file for use by the guard.
func WhitelistPath() string {
	return whitelistFile
}
