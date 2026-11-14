package doctor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func checkByID(t *testing.T, checks []Check, id string) Check {
	t.Helper()
	for _, c := range checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("check %q not found in %+v", id, checks)
	return Check{}
}

func TestRuntimeChecks(t *testing.T) {
	checks := runtimeChecks(Env{
		Version:   "1.2.3",
		GOOS:      "linux",
		GOARCH:    "amd64",
		Euid:      0,
		StateFile: filepath.Join(t.TempDir(), "blocked.json"),
	})

	version := checkByID(t, checks, "runtime.version")
	if version.Status != StatusOK || !strings.Contains(version.Message, "1.2.3") {
		t.Errorf("version check = %+v", version)
	}
	priv := checkByID(t, checks, "runtime.privileges")
	if priv.Status != StatusOK {
		t.Errorf("root privilege check = %+v", priv)
	}
	state := checkByID(t, checks, "runtime.state_dir")
	if state.Status != StatusOK || state.Critical {
		t.Errorf("state dir check = %+v", state)
	}
}

func TestRuntimeNonRootPrivilegesWarn(t *testing.T) {
	checks := runtimeChecks(Env{Version: "dev", GOOS: "linux", Euid: 1000, StateFile: ""})
	priv := checkByID(t, checks, "runtime.privileges")
	if priv.Status != StatusWarn || priv.Critical {
		t.Errorf("non-root privilege check = %+v", priv)
	}
	state := checkByID(t, checks, "runtime.state_dir")
	if state.Status != StatusWarn || state.Critical {
		t.Errorf("disabled state check = %+v", state)
	}
}

func TestStateDirProblemIsWarnOffLinux(t *testing.T) {
	notDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	check := stateDirCheck(Env{
		GOOS:      "windows",
		StateFile: filepath.Join(notDir, "blocked.json"),
	})
	if check.Status != StatusWarn || check.Critical {
		t.Fatalf("non-linux state problem = %+v", check)
	}
}

func TestCaddyChecksValidLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "access.log")
	line := `{"level":"info","ts":1.5,"msg":"handled request","request":{"method":"GET","uri":"/","remote_ip":"1.2.3.4"},"status":200,"duration":0.01}`
	if err := os.WriteFile(logPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	checks := caddyChecks(Env{
		AccessLogCandidates: []string{logPath},
		LookPath:            func(string) (string, error) { return "", errors.New("not found") },
	})

	executable := checkByID(t, checks, "caddy.executable")
	if executable.Status != StatusWarn {
		t.Errorf("executable check = %+v", executable)
	}
	logCheck := checkByID(t, checks, "caddy.access_log")
	if logCheck.Status != StatusOK || !strings.Contains(logCheck.Message, logPath) {
		t.Errorf("log check = %+v", logCheck)
	}
	fields := checkByID(t, checks, "caddy.log_fields")
	if fields.Status != StatusOK {
		t.Errorf("fields check = %+v", fields)
	}
}

func TestCaddyChecksMissingFields(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "access.log")
	line := `{"ts":1.5,"msg":"handled request","request":{"method":"GET","uri":"/","remote_ip":"1.2.3.4"}}`
	if err := os.WriteFile(logPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	checks := caddyChecks(Env{
		AccessLogCandidates: []string{logPath},
		LookPath:            func(string) (string, error) { return "/usr/bin/caddy", nil },
	})

	fields := checkByID(t, checks, "caddy.log_fields")
	if fields.Status != StatusWarn {
		t.Fatalf("fields check = %+v", fields)
	}
	for _, want := range []string{"status", "duration"} {
		if !strings.Contains(fields.Message, want) {
			t.Errorf("fields message missing %q: %s", want, fields.Message)
		}
	}
}

func TestCaddyChecksNoLog(t *testing.T) {
	checks := caddyChecks(Env{
		LookPath: func(string) (string, error) { return "", errors.New("not found") },
	})
	logCheck := checkByID(t, checks, "caddy.access_log")
	if logCheck.Status != StatusWarn || logCheck.Critical {
		t.Errorf("missing log check = %+v", logCheck)
	}
	for _, c := range checks {
		if c.ID == "caddy.log_fields" {
			t.Errorf("did not expect fields check without a log: %+v", c)
		}
	}
}

func TestGuardChecksReadOnlyProbes(t *testing.T) {
	var calls [][]string
	checks := guardChecks(Env{
		GOOS:     "linux",
		LookPath: func(name string) (string, error) { return "/usr/sbin/" + name, nil },
		RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, append([]string{name}, args...))
			return nil, nil
		},
	})

	for _, id := range []string{"guard.iptables", "guard.nftables", "guard.docker", "guard.backend"} {
		c := checkByID(t, checks, id)
		if c.Status != StatusOK {
			t.Errorf("%s = %+v", id, c)
		}
	}

	if len(calls) != 3 {
		t.Fatalf("probe calls = %d, want 3", len(calls))
	}
	for _, call := range calls {
		joined := strings.Join(call, " ")
		for _, mutating := range []string{" -A ", " -I ", " -D ", " -N ", " add ", " insert ", " delete ", " flush "} {
			if strings.Contains(" "+joined+" ", mutating) {
				t.Errorf("probe used mutating firewall command: %s", joined)
			}
		}
	}
}

func TestGuardChecksNoBackendIsCritical(t *testing.T) {
	checks := guardChecks(Env{
		GOOS:       "linux",
		LookPath:   func(string) (string, error) { return "", errors.New("not found") },
		RunCommand: func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
	})

	aggregate := checkByID(t, checks, "guard.backend")
	if aggregate.Status != StatusFail || !aggregate.Critical {
		t.Errorf("aggregate check = %+v", aggregate)
	}
}

func TestGuardChecksProbeFailureIsWarnButNoBackendIsCritical(t *testing.T) {
	checks := guardChecks(Env{
		GOOS:     "linux",
		LookPath: func(name string) (string, error) { return "/usr/sbin/" + name, nil },
		RunCommand: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("permission denied"), errors.New("exit status 4")
		},
	})

	iptables := checkByID(t, checks, "guard.iptables")
	if iptables.Status != StatusWarn || iptables.Critical {
		t.Errorf("iptables check = %+v", iptables)
	}
	if !strings.Contains(iptables.Message, "permission denied") {
		t.Errorf("iptables message = %s", iptables.Message)
	}
	aggregate := checkByID(t, checks, "guard.backend")
	if aggregate.Status != StatusFail || !aggregate.Critical {
		t.Errorf("aggregate check = %+v", aggregate)
	}
}

func TestGuardChecksNonLinux(t *testing.T) {
	checks := guardChecks(Env{GOOS: "windows"})
	if len(checks) != 1 || checks[0].Status != StatusWarn || checks[0].Critical {
		t.Fatalf("non-linux guard checks = %+v", checks)
	}
}

func TestBlocklistCacheFresh(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	writeBlocklistCache(t, dir, "feed.json", now.Add(-2*time.Hour))

	check := blocklistCacheCheck(Env{BlocklistCacheDir: dir, Now: now})
	if check.Status != StatusOK {
		t.Fatalf("fresh cache check = %+v", check)
	}
}

func TestBlocklistCacheStale(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	writeBlocklistCache(t, dir, "feed.json", now.Add(-8*24*time.Hour))

	check := blocklistCacheCheck(Env{BlocklistCacheDir: dir, Now: now})
	if check.Status != StatusWarn || check.Critical {
		t.Fatalf("stale cache check = %+v", check)
	}
	if !strings.Contains(check.Message, "stale") {
		t.Errorf("stale cache message = %s", check.Message)
	}
}

func TestBlocklistCacheMissing(t *testing.T) {
	check := blocklistCacheCheck(Env{BlocklistCacheDir: filepath.Join(t.TempDir(), "missing")})
	if check.Status != StatusWarn || check.Critical {
		t.Fatalf("missing cache check = %+v", check)
	}
}

func TestGeoIPCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "GeoIP.mmdb")
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	present := geoIPCheck(Env{GeoIPDB: path})
	if present.Status != StatusOK {
		t.Errorf("present GeoIP check = %+v", present)
	}
	missing := geoIPCheck(Env{GeoIPDB: filepath.Join(t.TempDir(), "missing.mmdb")})
	if missing.Status != StatusWarn || missing.Critical {
		t.Errorf("missing GeoIP check = %+v", missing)
	}
}

func writeBlocklistCache(t *testing.T, dir, name string, fetchedAt time.Time) {
	t.Helper()
	data := `{"entries":["192.0.2.0/24"],"fetched_at":"` + fetchedAt.Format(time.RFC3339) + `"}`
	if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
