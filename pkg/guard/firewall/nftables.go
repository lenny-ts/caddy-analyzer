package firewall

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// NftablesBackend implements Backend using nftables with named sets.
// nftables sets provide O(1) lookup vs iptables linear scan, making them
// significantly faster for large blocklists.
type NftablesBackend struct {
	// Table is the nftables table name (default: "filter").
	Table string
	// Set is the nftables set name for blocked IPs.
	Set string
	// Family is the address family ("ip" or "ip6").
	Family string
}

// NewNftablesBackend creates an nftables backend.
func NewNftablesBackend(family string) *NftablesBackend {
	set := "caddy_analyzer"
	if family == "ip6" {
		set = "caddy_analyzer_v6"
	}
	return &NftablesBackend{
		Table:  "filter",
		Set:    set,
		Family: family,
	}
}

func (b *NftablesBackend) Name() string {
	return "nftables:" + b.Family
}

func (b *NftablesBackend) EnsureChain() error {
	ctx := context.Background()

	// Create table if missing.
	if err := RunCmd(ctx, "nft", "add", "table", b.Family, b.Table); err != nil {
		if !isAlreadyExists(err) {
			return fmt.Errorf("create table: %w", err)
		}
	}

	// Create set if missing.
	if err := RunCmd(ctx, "nft", "add", "set", b.Family, b.Table, b.Set, "{ type ipv4_addr ; }"); err != nil {
		if !isAlreadyExists(err) {
			return fmt.Errorf("create set: %w", err)
		}
	}

	// Create chain if missing.
	if err := RunCmd(ctx, "nft", "add", "chain", b.Family, b.Table, "caddy_analyzer"); err != nil {
		if !isAlreadyExists(err) {
			return fmt.Errorf("create chain: %w", err)
		}
	}

	// Create rule that drops IPs in the set (if not already present).
	rule := fmt.Sprintf("ip saddr @%s drop", b.Set)
	if err := RunCmd(ctx, "nft", "list", "chain", b.Family, b.Table, "caddy_analyzer"); err == nil {
		out, _ := exec.CommandContext(ctx, "nft", "list", "chain", b.Family, b.Table, "caddy_analyzer").Output()
		if strings.Contains(string(out), rule) {
			return nil // Rule already exists.
		}
	}
	if err := RunCmd(ctx, "nft", "add", "rule", b.Family, b.Table, "caddy_analyzer", rule); err != nil {
		return fmt.Errorf("add drop rule: %w", err)
	}

	// Insert jump from input chain to our chain.
	if err := RunCmd(ctx, "nft", "insert", "rule", b.Family, b.Table, "input", "jump caddy_analyzer"); err != nil {
		return fmt.Errorf("insert jump: %w", err)
	}

	return nil
}

func (b *NftablesBackend) Block(ip string) error {
	if err := b.EnsureChain(); err != nil {
		return fmt.Errorf("ensure chain: %w", err)
	}
	ctx := context.Background()

	// Add IP to set (idempotent — nft silently ignores duplicates).
	if err := RunCmd(ctx, "nft", "add", "element", b.Family, b.Table, b.Set, "{", ip, "}"); err != nil {
		return fmt.Errorf("add element: %w", err)
	}

	// Verify the element was added.
	if err := RunCmd(ctx, "nft", "get", "element", b.Family, b.Table, b.Set, "{", ip, "}"); err != nil {
		return fmt.Errorf("verification failed for %s: %w", ip, err)
	}

	return nil
}

func (b *NftablesBackend) Unblock(ip string) error {
	ctx := context.Background()
	return RunCmd(ctx, "nft", "delete", "element", b.Family, b.Table, b.Set, "{", ip, "}")
}

func (b *NftablesBackend) ListBlocked() ([]string, error) {
	ctx := context.Background()
	out, err := exec.CommandContext(ctx, "nft", "list", "set", b.Family, b.Table, b.Set).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, nil
		}
		return nil, fmt.Errorf("list set: %w", err)
	}
	return parseNftSetOutput(string(out)), nil
}

func (b *NftablesBackend) Validate() error {
	ctx := context.Background()

	// 1. Check table exists.
	if err := RunCmd(ctx, "nft", "list", "table", b.Family, b.Table); err != nil {
		return fmt.Errorf("table %s does not exist: %w", b.Table, err)
	}

	// 2. Check set exists.
	if err := RunCmd(ctx, "nft", "list", "set", b.Family, b.Table, b.Set); err != nil {
		return fmt.Errorf("set %s does not exist: %w", b.Set, err)
	}

	// 3. Check chain exists.
	if err := RunCmd(ctx, "nft", "list", "chain", b.Family, b.Table, "caddy_analyzer"); err != nil {
		return fmt.Errorf("chain caddy_analyzer does not exist: %w", err)
	}

	// 4. Check jump rule exists.
	out, err := exec.CommandContext(ctx, "nft", "list", "chain", b.Family, b.Table, "input").Output()
	if err == nil && !strings.Contains(string(out), "jump caddy_analyzer") {
		return fmt.Errorf("jump from input to caddy_analyzer missing")
	}

	return nil
}

// isAlreadyExists checks if an nftables error is "already exists".
func isAlreadyExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already exists")
}

// parseNftSetOutput extracts IPs from "nft list set" output.
func parseNftSetOutput(output string) []string {
	var ips []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// Elements appear as: "ip saddr 1.2.3.4" or just "1.2.3.4"
		// Also handle: "elements = { ip saddr 1.1.1.1, ip saddr 10.0.0.0 }"
		if strings.HasPrefix(line, "ip saddr ") {
			ip := strings.TrimPrefix(line, "ip saddr ")
			ip = strings.TrimSpace(ip)
			// Remove trailing comma if present.
			ip = strings.TrimSuffix(ip, ",")
			if ip != "" {
				ips = append(ips, ip)
			}
		} else if strings.HasPrefix(line, "ip6 saddr ") {
			ip := strings.TrimPrefix(line, "ip6 saddr ")
			ip = strings.TrimSpace(ip)
			ip = strings.TrimSuffix(ip, ",")
			if ip != "" {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}
