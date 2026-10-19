package guard

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DetectSelfIPs discovers interface addresses and public egress addresses.
// Direct, family-specific HTTPS requests avoid mistaking an HTTP proxy's IP
// for the server's. No request headers or access-log contents are trusted.
func DetectSelfIPs(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	ips := make(map[string]bool)
	families := make(map[string]bool)
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		ips[ip.String()] = true
		if !ip.IsLoopback() && ip.IsGlobalUnicast() {
			family := "tcp6"
			if ip.To4() != nil {
				family = "tcp4"
			}
			families[family] = true
		}
	}
	for _, family := range []string{"tcp4", "tcp6"} {
		if !families[family] {
			continue
		}
		transport := &http.Transport{
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, family, address)
			},
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   4 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		urls := []string{"https://api.ipify.org", "https://ipv4.icanhazip.com"}
		if family == "tcp6" {
			urls = []string{"https://api6.ipify.org", "https://ipv6.icanhazip.com"}
		}
		var ip string
		for _, url := range urls {
			ip, err = fetchPublicIP(ctx, client, url, family)
			if err == nil {
				break
			}
		}
		transport.CloseIdleConnections()
		if err != nil {
			return nil, fmt.Errorf("discover %s public IP: %w", family, err)
		}
		ips[ip] = true
	}
	if len(families) == 0 {
		return nil, fmt.Errorf("no usable network interfaces")
	}
	result := make([]string, 0, len(ips))
	for ip := range ips {
		result = append(result, ip)
	}
	sort.Strings(result)
	return result, nil
}

func fetchPublicIP(ctx context.Context, client *http.Client, url, family string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65))
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if len(body) > 64 || ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() ||
		(family == "tcp4") != (ip.To4() != nil) {
		return "", fmt.Errorf("%s: invalid public %s address", url, family)
	}
	return ip.String(), nil
}

func (g *Guard) isSelfIP(ip string) bool {
	g.selfMu.RLock()
	defer g.selfMu.RUnlock()
	parsed := net.ParseIP(ip)
	_, subnet, _ := net.ParseCIDR(ip)
	for _, own := range g.selfIPs {
		if own.Equal(parsed) || subnet != nil && subnet.Contains(own) {
			return true
		}
	}
	return false
}

func (g *Guard) refreshSelfIPs(ctx context.Context) bool {
	if g.cfg.SelfIPLookup == nil {
		return true
	}
	ips, err := g.cfg.SelfIPLookup(ctx)
	if err == nil {
		var parsed []net.IP
		for _, s := range ips {
			ip := net.ParseIP(s)
			if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
				err = fmt.Errorf("invalid server IP %q", s)
				break
			}
			parsed = append(parsed, ip)
		}
		if err == nil && len(parsed) == 0 {
			err = fmt.Errorf("no server IPs discovered")
		}
		if err == nil {
			g.selfMu.Lock()
			g.selfIPs = parsed
			g.selfMu.Unlock()
			g.clearProtectedBlocks()
			return true
		}
	}
	if g.cfg.OnError != nil {
		g.cfg.OnError(fmt.Errorf("server IP protection: new bans suspended: %w; restart with --protect-self=false to disable server IP checks", err))
	}
	return false
}

// clearProtectedBlocks also removes subnet bans containing a server address.
// Failed firewall removals remain in state so the next refresh retries them.
func (g *Guard) clearProtectedBlocks() {
	g.mu.Lock()
	var protected []string
	for ip := range g.blocked {
		if g.isAllowlisted(ip) {
			protected = append(protected, ip)
		}
	}
	g.mu.Unlock()
	for _, ip := range protected {
		if !g.cfg.DryRun {
			if err := g.blocker.Unblock(ip); err != nil {
				if g.cfg.OnError != nil {
					g.cfg.OnError(fmt.Errorf("unblock protected IP %s: %w", ip, err))
				}
				continue
			}
		}
		g.removeBlocked(ip)
		g.mu.Lock()
		delete(g.expiries, ip)
		g.mu.Unlock()
		if g.cfg.OnAudit != nil {
			action := "unblock"
			if g.cfg.DryRun {
				action = "would_unblock"
			}
			g.cfg.OnAudit(action, ip, "never-block/server IP protection", "")
		}
		g.saveStateDebounced()
	}
}
