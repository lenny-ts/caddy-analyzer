package guard

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/analysis"
)

func TestGuardAuthAbuse(t *testing.T) {
	for _, block := range []bool{false, true} {
		auth, err := analysis.NewAuthAbuseDetector(analysis.AuthAbuseConfig{Enabled: true, Block: block,
			BruteForce:    analysis.AuthThreshold{Failures: 3, Window: "1m"},
			PasswordSpray: analysis.AuthThreshold{Failures: 3, Window: "1m", UniqueIPs: 3}})
		if err != nil {
			t.Fatal(err)
		}
		var audits []string
		g := New(Config{Window: time.Second, AuthAbuse: auth, Blocker: newFakeBlocker(), NeverBlock: []string{"203.0.113.2"},
			OnAudit: func(action, ip, reason, duration string) { audits = append(audits, action+" "+ip+" "+reason) }})
		// Each reset must leave authentication evidence intact.
		for i := 0; i < 3; i++ {
			g.Evaluate(caddyLine("203.0.113.1", "/login", "POST", 401))
			g.resetWindow(time.Now(), time.Second)
		}
		got := g.Tick(context.Background())
		if g.IsBlocked("203.0.113.1") != block {
			t.Fatalf("block=%v: candidates=%v", block, got)
		}
		if !strings.Contains(strings.Join(audits, "\n"), "brute_force") {
			t.Fatal("missing auth audit")
		}
		if block {
			g.removeBlocked("203.0.113.1")
			if got := g.Tick(context.Background()); len(got) != 0 {
				t.Fatal("stale auth evidence caused re-ban")
			}
		}
		for i := 0; i < 3; i++ {
			g.Evaluate(caddyLine("203.0.113.2", "/login", "POST", 401))
		}
		g.Tick(context.Background())
		if g.IsBlocked("203.0.113.2") {
			t.Fatal("allowlist bypassed")
		}
	}
}

func TestGuardPasswordSprayIsAlertOnly(t *testing.T) {
	auth, err := analysis.NewAuthAbuseDetector(analysis.AuthAbuseConfig{Enabled: true, Block: true,
		PasswordSpray: analysis.AuthThreshold{Failures: 3, Window: "1m", UniqueIPs: 3}})
	if err != nil {
		t.Fatal(err)
	}
	var spray bool
	g := New(Config{Window: time.Minute, AuthAbuse: auth, Blocker: newFakeBlocker(),
		OnAudit: func(action, ip, reason, duration string) {
			if action == "password_spray" {
				spray = true
				if ip != "" {
					t.Fatal("aggregate has source IP")
				}
			}
		}})
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		g.Evaluate(caddyLine(ip, "/login", "POST", 401))
	}
	if got := g.Tick(context.Background()); len(got) != 0 || !spray {
		t.Fatalf("want alert without blocks, got %v, alert=%v", got, spray)
	}
}

func TestGuardSubnetBanConsumesAuthEvidence(t *testing.T) {
	auth, err := analysis.NewAuthAbuseDetector(analysis.AuthAbuseConfig{Enabled: true, Block: true,
		BruteForce: analysis.AuthThreshold{Failures: 3, Window: "1m"}})
	if err != nil {
		t.Fatal(err)
	}
	g := New(Config{Window: time.Minute, AuthAbuse: auth, Blocker: newFakeBlocker()})
	for i := 0; i < 3; i++ {
		g.Evaluate(caddyLine("203.0.113.1", "/login", "POST", 401))
	}
	if !g.block(context.Background(), Candidate{IP: "203.0.113.0/24", Why: "distributed scan"}, time.Now()) {
		t.Fatal("subnet ban failed")
	}
	g.removeBlocked("203.0.113.0/24")
	if got := g.Tick(context.Background()); len(got) != 0 {
		t.Fatalf("subnet unban triggered stale per-IP ban: %v", got)
	}
}

func TestGuardAuthAbuseCanonicalIP(t *testing.T) {
	auth, err := analysis.NewAuthAbuseDetector(analysis.AuthAbuseConfig{Enabled: true, Block: true,
		BruteForce: analysis.AuthThreshold{Failures: 3, Window: "1m"}})
	if err != nil {
		t.Fatal(err)
	}
	g := New(Config{Window: time.Minute, AuthAbuse: auth, Blocker: newFakeBlocker()})
	for _, ip := range []string{"2001:db8::1", "2001:db8:0:0:0:0:0:1", "2001:db8::1"} {
		g.Evaluate(caddyLine(ip, "/login", "POST", 401))
	}
	if got := g.Tick(context.Background()); len(got) != 1 {
		t.Fatalf("IP spellings split evidence: %v", got)
	}
	if !g.IsBlocked("2001:db8:0:0:0:0:0:1") {
		t.Fatal("expanded IP bypasses ban lookup")
	}
	before := g.Engine().Count()
	g.Evaluate(caddyLine("2001:db8:0:0:0:0:0:1", "/login", "POST", 401))
	if g.Engine().Count() != before {
		t.Fatal("blocked IP added fresh evidence")
	}
}
