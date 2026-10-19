package guard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestSelfIPProtectionAcrossBanPaths(t *testing.T) {
	for _, mode := range []string{"requests", "auth", "404", "detection", "blocklist", "country", "subnet", "ipv6-subnet"} {
		t.Run(mode, func(t *testing.T) {
			own, other := "8.8.8.8", "9.9.9.9"
			if mode == "ipv6-subnet" {
				own, other = "2001:4860::1", "2001:4861::1"
			}
			fb := newFakeBlocker()
			cfg := Config{Window: time.Minute, Blocker: fb, SelfIPs: []string{own},
				SelfIPLookup: func(context.Context) ([]string, error) { return []string{own}, nil }}
			path, status := "/heartbeat", 200
			switch mode {
			case "requests":
				cfg.Limit = 1
			case "auth":
				cfg.AuthLimit, status = 1, 401
			case "404":
				cfg.NotFoundLimit, status = 1, 404
			case "detection":
				cfg.DetectionConfidence, path = 1, "/.env"
			case "blocklist":
				cfg.BlocklistMgr = newTestBlocklistMgr(t, own+"\n"+other+"\n")
			case "country":
				cfg.CountryBlock = []string{"CN"}
				cfg.GeoIP = &mockGeoIP{info: map[string]types.GeoInfo{
					own: {CountryCode: "CN"}, other: {CountryCode: "CN"},
				}}
			case "subnet", "ipv6-subnet":
				cfg.SubnetLimit = 1
			}
			g := New(cfg)
			g.Evaluate(caddyLine(own, path, "GET", status))
			g.Evaluate(caddyLine(other, path, "GET", status))
			g.Tick(context.Background())
			if g.IsBlocked(own) || fb.blocked[own] || fb.blocked[subnetKey(own)] {
				t.Fatal("server address was blocked")
			}
			if !g.IsBlocked(other) {
				t.Fatal("protection must not disable bans for other sources")
			}
		})
	}
}

func TestSelfIPChangeCheckedBeforeBan(t *testing.T) {
	current := "8.8.8.8"
	for _, immediate := range []bool{false, true} {
		t.Run(fmt.Sprint(immediate), func(t *testing.T) {
			current = "8.8.8.8"
			cfg := Config{Limit: 1, Window: time.Minute, Blocker: newFakeBlocker(),
				SelfIPs:      []string{current},
				SelfIPLookup: func(context.Context) ([]string, error) { return []string{current}, nil }}
			if immediate {
				cfg.BlocklistMgr = newTestBlocklistMgr(t, "9.9.9.9\n8.8.8.8\n")
			}
			g := New(cfg)
			current = "9.9.9.9" // Router reconnects before the periodic refresh.
			g.Evaluate(caddyLine(current, "/heartbeat", "GET", 200))
			g.Tick(context.Background())
			if g.IsBlocked(current) || g.SessionBlocks() != 0 || g.BlocklistHits() != 0 {
				t.Fatal("new public IP was banned before refresh")
			}
			g.Evaluate(caddyLine("8.8.8.8", "/heartbeat", "GET", 200))
			g.Tick(context.Background())
			if !g.IsBlocked("8.8.8.8") {
				t.Fatal("old public IP must no longer be exempt")
			}
		})
	}
}

func TestSelfIPLookupFailureSuspendsBans(t *testing.T) {
	for _, ips := range [][]string{nil, {"not-an-ip"}, {"0.0.0.0"}} {
		g := New(Config{Limit: 1, Window: time.Minute, Blocker: newFakeBlocker(), SelfIPs: []string{"8.8.8.8"},
			SelfIPLookup: func(context.Context) ([]string, error) { return ips, nil }})
		g.Evaluate(caddyLine("9.9.9.9", "/heartbeat", "GET", 200))
		g.Tick(context.Background())
		if g.Count() != 0 || !g.isSelfIP("8.8.8.8") {
			t.Fatal("invalid discovery must suspend bans and preserve known server IPs")
		}
	}
	failed := true
	lookupErr := errors.New("network unavailable")
	var reported error
	g := New(Config{Limit: 1, Window: time.Minute, Blocker: newFakeBlocker(),
		OnError: func(err error) { reported = err },
		SelfIPLookup: func(context.Context) ([]string, error) {
			if failed {
				return nil, lookupErr
			}
			return []string{"8.8.8.8"}, nil
		}})
	g.Evaluate(caddyLine("9.9.9.9", "/heartbeat", "GET", 200))
	g.Tick(context.Background())
	if g.Count() != 0 {
		t.Fatal("lookup failure must suspend bans")
	}
	if !errors.Is(reported, lookupErr) || !strings.Contains(reported.Error(), "restart with --protect-self=false to disable server IP checks") {
		t.Fatalf("error must preserve the cause and explain how to disable checks: %v", reported)
	}
	failed = false
	g.Tick(context.Background())
	if !g.IsBlocked("9.9.9.9") {
		t.Fatal("bans must resume after discovery recovers")
	}
}

func TestSelfIPRemovesSavedAndDynamicSubnetBans(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		t.Run(fmt.Sprint(dryRun), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "blocked.json")
			sf := newStateFile(path)
			if err := sf.saveEntries([]stateEntry{
				{IP: "8.8.8.8"}, {IP: "9.9.9.0/24", When: time.Now().Add(time.Hour)},
			}); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			fb := newFakeBlocker()
			fb.blocked["8.8.8.8"], fb.blocked["9.9.9.0/24"] = true, true
			current := "8.8.8.8"
			g := New(Config{Window: time.Minute, BlockDuration: time.Hour, Blocker: fb,
				StatePath: path, DryRun: dryRun, SelfIPs: []string{current},
				SelfIPLookup: func(context.Context) ([]string, error) { return []string{current}, nil }})
			if g.IsBlocked(current) {
				t.Fatal("own saved ban must not be restored")
			}
			current = "9.9.9.9"
			if !g.refreshSelfIPs(context.Background()) || g.IsBlocked(current) || g.Count() != 0 {
				t.Fatal("refresh must remove an existing subnet ban covering the new IP")
			}
			g.FlushState()
			after, _ := os.ReadFile(path)
			if dryRun {
				if string(before) != string(after) || len(fb.blocked) != 2 {
					t.Fatal("dry-run changed firewall or persistent state")
				}
			} else {
				entries, err := sf.load()
				if err != nil || len(entries) != 0 || len(fb.blocked) != 0 {
					t.Fatal("protected bans remain in firewall or state")
				}
			}
		})
	}
}

func TestFetchPublicIPValidation(t *testing.T) {
	for _, tc := range []struct {
		body, family string
		status       int
		valid        bool
	}{
		{"8.8.8.8\n", "tcp4", 200, true},
		{"2001:4860::1", "tcp6", 200, true},
		{"2001:4860::1", "tcp4", 200, false},
		{"8.8.8.8", "tcp6", 200, false},
		{"192.168.1.100", "tcp4", 200, false},
		{"127.0.0.1", "tcp4", 200, false},
		{"<html>error</html>", "tcp4", 200, false},
		{"8.8.8.8", "tcp4", 503, false},
		{"8.8.8.8", "tcp4", 302, false},
		{"8.8.8.8" + strings.Repeat(" ", 65), "tcp4", 200, false},
	} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer s.Close()
			_, err := fetchPublicIP(context.Background(), s.Client(), s.URL, tc.family)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, err=%v", tc.valid, err)
			}
		})
	}
}

type failingUnblocker struct {
	*fakeBlocker
	fail bool
}

func (f *failingUnblocker) Unblock(ip string) error {
	if f.fail {
		return errors.New("firewall unavailable")
	}
	return f.fakeBlocker.Unblock(ip)
}

func TestSelfIPCleanupRetriesFailedRemoval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	sf := newStateFile(path)
	if err := sf.saveEntries([]stateEntry{{IP: "8.8.8.8"}}); err != nil {
		t.Fatal(err)
	}
	fb := &failingUnblocker{fakeBlocker: newFakeBlocker(), fail: true}
	fb.blocked["8.8.8.8"] = true
	g := New(Config{Window: time.Minute, Blocker: fb, StatePath: path, SelfIPs: []string{"8.8.8.8"},
		SelfIPLookup: func(context.Context) ([]string, error) { return []string{"8.8.8.8"}, nil }})
	g.FlushState()
	entries, err := sf.load()
	if err != nil || len(entries) != 1 || !fb.blocked["8.8.8.8"] {
		t.Fatal("failed removal must remain tracked for retry")
	}
	fb.fail = false
	g.refreshSelfIPs(context.Background())
	g.FlushState()
	entries, err = sf.load()
	if err != nil || len(entries) != 0 || fb.blocked["8.8.8.8"] {
		t.Fatal("successful retry must clear firewall and persistent state")
	}
}

func TestNeverBlockCleansSavedBan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.json")
	if err := newStateFile(path).saveEntries([]stateEntry{{IP: "8.8.8.8"}}); err != nil {
		t.Fatal(err)
	}
	fb := newFakeBlocker()
	fb.blocked["8.8.8.8"] = true
	g := New(Config{StatePath: path, Blocker: fb, NeverBlock: []string{"8.8.8.8"}})
	if g.IsBlocked("8.8.8.8") || fb.blocked["8.8.8.8"] {
		t.Fatal("explicit allowlist must also override saved bans")
	}
}

func TestSelfIPCleanupLeavesStaleExpiriesHarmless(t *testing.T) {
	fb := newFakeBlocker()
	var audits int
	g := New(Config{Window: time.Minute, Blocker: fb,
		OnAudit: func(string, string, string, string) { audits++ }})
	old := time.Now().Add(-time.Second)
	g.initial = []expiryEntry{{ip: "8.8.8.8", when: old}, {ip: "9.9.9.9", when: old}}
	// The first ban was removed by protection; the second was replaced later.
	g.blocked["9.9.9.9"] = true
	g.expiries["9.9.9.9"] = time.Now().Add(time.Hour)
	fb.blocked["9.9.9.9"] = true
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	g.runExpiryLoop(ctx)
	if audits != 0 || !fb.blocked["9.9.9.9"] || !g.IsBlocked("9.9.9.9") {
		t.Fatal("stale expiries must not remove newer bans or emit duplicate unbans")
	}
}
