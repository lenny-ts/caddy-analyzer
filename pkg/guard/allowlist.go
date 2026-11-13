package guard

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// loadAllowlistFile reads one IP/CIDR per line, ignoring blank lines and
// comments. The format matches the file managed by `caddy-analyze whitelist`.
func loadAllowlistFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
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
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func parseAllowlistEntries(entries []string) ([]*net.IPNet, error) {
	for _, entry := range entries {
		if net.ParseIP(entry) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(entry); err != nil {
			return nil, fmt.Errorf("invalid IP or CIDR %q", entry)
		}
	}
	return parseCIDRList(entries), nil
}

// reloadAllowlist reads the configured whitelist file and replaces only the
// file-derived allowlist. Explicit NeverBlock entries stay in place. On any
// read or validation error the current allowlist is left untouched.
func (g *Guard) reloadAllowlist() error {
	if g.cfg.NeverBlockFile == "" {
		return nil
	}
	entries, err := loadAllowlistFile(g.cfg.NeverBlockFile)
	if err != nil {
		return err
	}
	fileNets, err := parseAllowlistEntries(entries)
	if err != nil {
		return err
	}
	g.allowlistMu.Lock()
	combined := make([]*net.IPNet, 0, len(g.baseAllowlist)+len(fileNets))
	combined = append(combined, g.baseAllowlist...)
	combined = append(combined, fileNets...)
	g.allowlist = combined
	g.allowlistMu.Unlock()
	g.clearProtectedBlocks()
	return nil
}

// AllowlistCount returns the number of active allowlist entries.
func (g *Guard) AllowlistCount() int {
	g.allowlistMu.RLock()
	defer g.allowlistMu.RUnlock()
	return len(g.allowlist)
}
