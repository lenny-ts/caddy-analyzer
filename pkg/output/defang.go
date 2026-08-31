package output

import (
	"regexp"
	"strings"
)

var (
	bareIPv4Pattern    = regexp.MustCompile(`\b(\d{1,3}\.){3}\d{1,3}\b`)
	urlHostnamePattern = regexp.MustCompile(`://([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}`)
)

// Defang replaces dots in IPv4 addresses and URL hostnames with [.] and
// URL schemes with hxxp[s]:// to prevent accidental clicks in shared reports.
// Example: http://185.220.101.42 → hxxp://185[.]220[.]101[.]42
func Defang(s string) string {
	s = defangSchemes(s)
	s = defangIPv4(s)
	return defangURLHostnames(s)
}

func defangSchemes(s string) string {
	s = strings.ReplaceAll(s, "https://", "hxxps://")
	return strings.ReplaceAll(s, "http://", "hxxp://")
}

func defangIPv4(s string) string {
	return bareIPv4Pattern.ReplaceAllStringFunc(s, func(ip string) string {
		return strings.ReplaceAll(ip, ".", "[.]")
	})
}

func defangURLHostnames(s string) string {
	return urlHostnamePattern.ReplaceAllStringFunc(s, func(urlHost string) string {
		return strings.ReplaceAll(urlHost, ".", "[.]")
	})
}

// DefangIP is a convenience wrapper for defanging a bare IP address.
func DefangIP(ip string) string {
	return Defang(ip)
}
