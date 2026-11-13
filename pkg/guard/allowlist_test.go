package guard

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeAllowlistFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}
}

func TestAllowlistReloadPicksUpFileChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.txt")
	writeAllowlistFile(t, path, "# managed by caddy-analyze whitelist\n10.0.0.0/8\n")

	g := New(Config{
		Window:            time.Minute,
		BlockDuration:     0,
		Blocker:           newFakeBlocker(),
		NeverBlock:        []string{"192.168.1.1"},
		NeverBlockFile:    path,
		NeverBlockRefresh: time.Millisecond,
	})

	if !g.isAllowlisted("10.1.2.3") {
		t.Fatal("initial whitelist file entry was not loaded")
	}
	if g.isAllowlisted("203.0.113.7") {
		t.Fatal("203.0.113.7 should not be allowlisted before it is added")
	}

	writeAllowlistFile(t, path, "10.0.0.0/8\n203.0.113.7\n")
	if err := g.reloadAllowlist(); err != nil {
		t.Fatalf("reload after add: %v", err)
	}
	if !g.isAllowlisted("203.0.113.7") {
		t.Error("newly added whitelist entry was not applied")
	}

	writeAllowlistFile(t, path, "203.0.113.7\n")
	if err := g.reloadAllowlist(); err != nil {
		t.Fatalf("reload after remove: %v", err)
	}
	if g.isAllowlisted("10.1.2.3") {
		t.Error("removed whitelist entry still applies")
	}
	if !g.isAllowlisted("203.0.113.7") {
		t.Error("remaining whitelist entry was lost")
	}

	if !g.isAllowlisted("192.168.1.1") {
		t.Error("explicit never-block entry was dropped by a file reload")
	}
}

func TestAllowlistReloadFailureKeepsLastGoodList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.txt")
	writeAllowlistFile(t, path, "10.0.0.0/8\n")

	g := New(Config{
		Window:         time.Minute,
		BlockDuration:  0,
		Blocker:        newFakeBlocker(),
		NeverBlock:     []string{"192.168.1.1"},
		NeverBlockFile: path,
	})

	for _, tc := range []struct {
		name    string
		content string
		remove  bool
	}{
		{name: "malformed entry", content: "not-an-ip\n"},
		{name: "invalid CIDR", content: "10.0.0.0/33\n"},
		{name: "missing file", remove: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.remove {
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove whitelist: %v", err)
				}
			} else {
				writeAllowlistFile(t, path, tc.content)
			}

			if err := g.reloadAllowlist(); err == nil {
				t.Fatal("expected a reload error")
			}
			if !g.isAllowlisted("10.1.2.3") {
				t.Error("previous whitelist was dropped after a failed reload")
			}
			if !g.isAllowlisted("192.168.1.1") {
				t.Error("explicit never-block entry was dropped after a failed reload")
			}
		})
	}
}

func TestAllowlistReloadInRunLogsFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.txt")
	writeAllowlistFile(t, path, "10.0.0.0/8\n")

	var (
		mu   sync.Mutex
		errs []error
	)
	g := New(Config{
		Window:            time.Minute,
		BlockDuration:     0,
		Blocker:           newFakeBlocker(),
		NeverBlockFile:    path,
		NeverBlockRefresh: 5 * time.Millisecond,
		OnError: func(err error) {
			mu.Lock()
			errs = append(errs, err)
			mu.Unlock()
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		g.Run(ctx, make(chan string), func(string, ...interface{}) {})
		close(done)
	}()

	writeAllowlistFile(t, path, "not-an-ip\n")

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		found := false
		for _, err := range errs {
			if strings.Contains(err.Error(), "whitelist reload") {
				found = true
				break
			}
		}
		mu.Unlock()
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reload failure was not reported")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if !g.isAllowlisted("10.1.2.3") {
		t.Error("previous whitelist was dropped after a failed reload")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after context cancel")
	}
}

func TestAllowlistReloadUnblocksNewlyProtectedIP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.txt")
	writeAllowlistFile(t, path, "10.0.0.0/8\n")

	fb := newFakeBlocker()
	g := New(Config{
		Limit:          1,
		Window:         time.Minute,
		BlockDuration:  0,
		Blocker:        fb,
		NeverBlockFile: path,
	})

	g.Evaluate(caddyLine("203.0.113.7", "/", "GET", 200))
	g.Tick(context.Background())
	if !g.IsBlocked("203.0.113.7") {
		t.Fatal("expected 203.0.113.7 to be blocked before the reload")
	}

	writeAllowlistFile(t, path, "10.0.0.0/8\n203.0.113.7\n")
	if err := g.reloadAllowlist(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if g.IsBlocked("203.0.113.7") {
		t.Error("newly allowlisted IP is still blocked")
	}
	if fb.blocked["203.0.113.7"] {
		t.Error("firewall rule for newly allowlisted IP was not removed")
	}
}
