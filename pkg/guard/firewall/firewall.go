// Package firewall provides the Backend interface (port) for IP blocking
// and multiple adapter implementations for different firewall environments
// (iptables, nftables, Docker).
//
// The guard domain uses only the Backend interface. Adapters are selected
// at startup based on environment detection (auto) or CLI flags (manual).
package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

const (
	// ChainName is the dedicated chain for caddy-analyzer rules.
	ChainName = "CADDY_ANALYZER"

	// CommentMarker identifies rules owned by this tool.
	CommentMarker = "caddy-analyzer"
)

// Timeout bounds every firewall invocation so a stuck command cannot freeze the guard.
var Timeout = 10 * time.Second

// Backend is the port that the guard domain uses to block/unblock IPs.
// Implementations are adapters that translate to the actual firewall mechanism.
type Backend interface {
	// Block adds a DROP rule for ip. Idempotent: returns nil if already blocked.
	Block(ip string) error

	// Unblock removes the DROP rule for ip.
	Unblock(ip string) error

	// ListBlocked returns all IPs currently blocked by this tool.
	ListBlocked() ([]string, error)

	// EnsureChain creates the dedicated chain and jump rule if missing.
	EnsureChain() error

	// Validate checks that the chain and jump rule are correctly positioned
	// and that the firewall is actually effective.
	Validate() error

	// Name returns the backend type for logging.
	Name() string
}

// RunCmd runs bin with args, capturing stderr so failures carry the firewall's
// own diagnostic. The *exec.ExitError is preserved via %w so callers can
// inspect the exit code.
func RunCmd(ctx context.Context, bin string, args ...string) error {
	c, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(c, bin, args...)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("%s %s: %w", bin, strings.Join(args, " "), err)
	}
	return nil
}

// BinForIP returns the firewall binary matching the address family of ip.
func BinForIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed != nil {
		if parsed.To4() == nil {
			return "ip6tables"
		}
		return "iptables"
	}
	if _, ipnet, err := net.ParseCIDR(ip); err == nil {
		if ipnet.IP.To4() == nil {
			return "ip6tables"
		}
	}
	return "iptables"
}

// SetTimeout overrides the per-invocation firewall command timeout.
// Must be called before any Backend is used.
func SetTimeout(d time.Duration) {
	if d <= 0 {
		return
	}
	Timeout = d
}

// IsChainError checks if an error is a benign "chain already exists" from iptables -N.
func IsChainError(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "already exists")
}
