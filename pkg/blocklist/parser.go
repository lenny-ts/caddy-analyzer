package blocklist

import (
	"net"
	"strings"
)

// parseEntries extracts valid CIDR/IP entries from the raw blocklist body.
// It handles all common blocklist formats:
//   - CIDR notation (e.g. "1.2.3.0/24")
//   - Bare IPv4/IPv6 addresses (auto-promoted to /32 or /128)
//   - Inline comments after ";", "#", or whitespace
//   - Blank lines
//
// Lines that do not parse as a CIDR or IP after comment stripping are
// silently skipped — blocklist feeds occasionally contain descriptive
// text or headers that are not addresses.
func parseEntries(body []byte) []net.IPNet {
	var entries []net.IPNet
	for _, line := range strings.Split(string(body), "\n") {
		cidr := extractEntry(line)
		if cidr == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		entries = append(entries, *ipnet)
	}
	return entries
}

// extractEntry returns the CIDR or bare-IP portion of a line, or "" if
// the line contains no usable entry. Comment characters ";" and "#"
// and trailing whitespace are stripped. A bare IP is promoted to a /32
// (IPv4) or /128 (IPv6) CIDR so cidranger can store it uniformly.
func extractEntry(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	for _, sep := range []string{";", "#"} {
		if i := strings.Index(line, sep); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
	}
	if line == "" {
		return ""
	}
	if strings.Contains(line, "/") {
		return line
	}
	ip := net.ParseIP(line)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return line + "/32"
	}
	return line + "/128"
}
