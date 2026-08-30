package firewall

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// IptablesBackend implements Backend using iptables/ip6tables with a dedicated
// chain jumped from a configurable parent chain (default: INPUT).
type IptablesBackend struct {
	// Bin is the iptables binary ("iptables" or "ip6tables").
	Bin string
	// JumpChain is the parent chain to jump from (default: "INPUT").
	JumpChain string
}

// NewIptablesBackend creates an iptables backend that jumps from the given chain.
func NewIptablesBackend(bin, jumpChain string) *IptablesBackend {
	if jumpChain == "" {
		jumpChain = "INPUT"
	}
	return &IptablesBackend{Bin: bin, JumpChain: jumpChain}
}

func (b *IptablesBackend) Name() string {
	return b.Bin
}

func (b *IptablesBackend) EnsureChain() error {
	ctx := context.Background()
	// Create chain if missing.
	if err := RunCmd(ctx, b.Bin, "-N", ChainName); err != nil && !IsChainError(err) {
		return fmt.Errorf("create chain: %w", err)
	}
	// Insert jump at TOP of parent chain (-I, not -A) so our rules are
	// evaluated before any broad ACCEPT.
	if err := RunCmd(ctx, b.Bin, "-C", b.JumpChain, "-j", ChainName); err != nil {
		if err := RunCmd(ctx, b.Bin, "-I", b.JumpChain, "1", "-j", ChainName); err != nil {
			return fmt.Errorf("insert jump: %w", err)
		}
	}
	return nil
}

func (b *IptablesBackend) Block(ip string) error {
	if err := b.EnsureChain(); err != nil {
		return fmt.Errorf("ensure chain: %w", err)
	}
	ctx := context.Background()
	args := []string{ChainName, "-s", ip, "-m", "comment", "--comment", CommentMarker, "-j", "DROP"}
	// Idempotent: skip if rule already exists.
	if err := RunCmd(ctx, b.Bin, append([]string{"-C"}, args...)...); err == nil {
		return nil
	}
	// Insert at top of chain (-I) so DROP is evaluated first.
	if err := RunCmd(ctx, b.Bin, append([]string{"-I"}, args...)...); err != nil {
		return fmt.Errorf("insert rule: %w", err)
	}
	// Verify the rule was actually added.
	if err := RunCmd(ctx, b.Bin, append([]string{"-C"}, args...)...); err != nil {
		return fmt.Errorf("rule verification failed for %s: %w", ip, err)
	}
	return nil
}

func (b *IptablesBackend) Unblock(ip string) error {
	ctx := context.Background()
	err := RunCmd(ctx, b.Bin, "-D", ChainName, "-s", ip,
		"-m", "comment", "--comment", CommentMarker, "-j", "DROP")
	if err != nil && IsBadRuleError(err) {
		return nil
	}
	return err
}

func (b *IptablesBackend) ListBlocked() ([]string, error) {
	ctx := context.Background()
	out, err := exec.CommandContext(ctx, b.Bin, "-S", ChainName).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// Chain doesn't exist yet — benign.
			return nil, nil
		}
		return nil, fmt.Errorf("list rules: %w", err)
	}
	return parseBlockedIPs(string(out)), nil
}

func (b *IptablesBackend) Validate() error {
	ctx := context.Background()

	// 1. Check chain exists.
	if err := RunCmd(ctx, b.Bin, "-L", ChainName, "-n"); err != nil {
		return fmt.Errorf("chain %s does not exist: %w", ChainName, err)
	}

	// 2. Check jump rule exists in parent chain.
	if err := RunCmd(ctx, b.Bin, "-C", b.JumpChain, "-j", ChainName); err != nil {
		return fmt.Errorf("jump from %s to %s missing: %w", b.JumpChain, ChainName, err)
	}

	// 3. Check jump position (should be rule 1 or early).
	if err := b.validateJumpPosition(); err != nil {
		return err
	}

	return nil
}

func (b *IptablesBackend) validateJumpPosition() error {
	ctx := context.Background()
	out, err := exec.CommandContext(ctx, b.Bin, "-S", b.JumpChain).Output()
	if err != nil {
		return nil // Best effort.
	}
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if strings.Contains(line, "-j "+ChainName) {
			if i > 2 {
				return fmt.Errorf("jump to %s is at position %d in %s — may be after an ACCEPT rule", ChainName, i+1, b.JumpChain)
			}
			return nil
		}
	}
	return nil
}

// ParseBlockedIPs extracts IPs from iptables -S output belonging to this tool.
func parseBlockedIPs(output string) []string {
	var ips []string
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "-j DROP") || !strings.Contains(line, CommentMarker) {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "-s" && i+1 < len(fields) {
				ip := strings.Split(fields[i+1], "/")[0]
				ip = strings.Trim(ip, "[]")
				if ip == "" || ip == "0.0.0.0" || ip == "::" {
					continue
				}
				ips = append(ips, ip)
				break
			}
		}
	}
	return ips
}
