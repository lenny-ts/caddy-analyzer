package cmd

import (
	"fmt"
	"net"
	"strings"
)

// validateIP accepts a bare IP address or a CIDR block, and rejects empty
// input and anything that looks like a flag. Used both to fail fast on a
// typo'd --ip / --exclude-ip filter -- which would otherwise surface as "no
// log entries found" when the CIDR fails to parse inside MatchEntry -- and to
// keep a mistyped block/unban argument away from iptables.
func validateIP(ip string) error {
	if ip == "" {
		return fmt.Errorf("empty IP")
	}
	if strings.HasPrefix(ip, "-") {
		return fmt.Errorf("invalid IP or CIDR %q: looks like a flag", ip)
	}
	if net.ParseIP(ip) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(ip); err == nil {
		return nil
	}
	return fmt.Errorf("invalid IP or CIDR %q", ip)
}
