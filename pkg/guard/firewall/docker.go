package firewall

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// DockerBackend implements Backend using iptables with the DOCKER-USER chain.
// Docker forwards external traffic through PREROUTING → DOCKER → DNAT → FORWARD,
// completely bypassing the INPUT chain. The DOCKER-USER chain is the only
// iptables hook that processes external traffic destined to Docker containers.
type DockerBackend struct {
	// Bin is the iptables binary ("iptables" or "ip6tables").
	Bin string
}

// NewDockerBackend creates a backend that targets the DOCKER-USER chain.
func NewDockerBackend(bin string) *DockerBackend {
	return &DockerBackend{Bin: bin}
}

func (b *DockerBackend) Name() string {
	return "docker:" + b.Bin
}

func (b *DockerBackend) EnsureChain() error {
	ctx := context.Background()

	// Create the CADDY_ANALYZER chain.
	if err := RunCmd(ctx, b.Bin, "-N", ChainName); err != nil && !IsChainError(err) {
		return fmt.Errorf("create chain: %w", err)
	}

	// Ensure DOCKER-USER chain exists (Docker creates it, but verify).
	if err := RunCmd(ctx, b.Bin, "-L", "DOCKER-USER", "-n"); err != nil {
		return fmt.Errorf("DOCKER-USER chain not found — is Docker running? %w", err)
	}

	// Insert jump from DOCKER-USER to CADDY_ANALYZER at position 1.
	// This ensures our rules are evaluated BEFORE Docker's default ACCEPT.
	if err := RunCmd(ctx, b.Bin, "-C", "DOCKER-USER", "-j", ChainName); err != nil {
		if err := RunCmd(ctx, b.Bin, "-I", "DOCKER-USER", "1", "-j", ChainName); err != nil {
			return fmt.Errorf("insert jump into DOCKER-USER: %w", err)
		}
	}
	return nil
}

func (b *DockerBackend) Block(ip string) error {
	if err := b.EnsureChain(); err != nil {
		return fmt.Errorf("ensure chain: %w", err)
	}
	ctx := context.Background()
	args := []string{ChainName, "-s", ip, "-m", "comment", "--comment", CommentMarker, "-j", "DROP"}

	// Idempotent: skip if rule already exists.
	if err := RunCmd(ctx, b.Bin, append([]string{"-C"}, args...)...); err == nil {
		return nil
	}

	// Insert at top of chain.
	if err := RunCmd(ctx, b.Bin, append([]string{"-I"}, args...)...); err != nil {
		return fmt.Errorf("insert rule: %w", err)
	}

	// Verify the rule was actually added.
	if err := RunCmd(ctx, b.Bin, append([]string{"-C"}, args...)...); err != nil {
		return fmt.Errorf("rule verification failed for %s: %w", ip, err)
	}
	return nil
}

func (b *DockerBackend) Unblock(ip string) error {
	ctx := context.Background()
	return RunCmd(ctx, b.Bin, "-D", ChainName, "-s", ip,
		"-m", "comment", "--comment", CommentMarker, "-j", "DROP")
}

func (b *DockerBackend) ListBlocked() ([]string, error) {
	ctx := context.Background()
	out, err := exec.CommandContext(ctx, b.Bin, "-S", ChainName).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, nil
		}
		return nil, fmt.Errorf("list rules: %w", err)
	}
	return parseBlockedIPs(string(out)), nil
}

func (b *DockerBackend) Validate() error {
	ctx := context.Background()

	// 1. Check CADDY_ANALYZER chain exists.
	if err := RunCmd(ctx, b.Bin, "-L", ChainName, "-n"); err != nil {
		return fmt.Errorf("chain %s does not exist: %w", ChainName, err)
	}

	// 2. Check DOCKER-USER chain exists.
	if err := RunCmd(ctx, b.Bin, "-L", "DOCKER-USER", "-n"); err != nil {
		return fmt.Errorf("DOCKER-USER chain not found: %w", err)
	}

	// 3. Check jump from DOCKER-USER to CADDY_ANALYZER.
	if err := RunCmd(ctx, b.Bin, "-C", "DOCKER-USER", "-j", ChainName); err != nil {
		return fmt.Errorf("jump from DOCKER-USER to %s missing: %w", ChainName, err)
	}

	// 4. Verify jump is at position 1 (before Docker's default rules).
	if err := b.validateJumpPosition(); err != nil {
		return err
	}

	return nil
}

func (b *DockerBackend) validateJumpPosition() error {
	ctx := context.Background()
	out, err := exec.CommandContext(ctx, b.Bin, "-S", "DOCKER-USER").Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if strings.Contains(line, "-j "+ChainName) {
			if i > 0 {
				return fmt.Errorf("jump to %s is at position %d in DOCKER-USER — should be position 1", ChainName, i+1)
			}
			return nil
		}
	}
	return nil
}
