package doctor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/enrich"
)

const (
	commandTimeout    = 5 * time.Second
	logSampleLines    = 2000
	blocklistCacheTTL = 7 * 24 * time.Hour
)

// Env carries the host-specific inputs for a doctor run. Command and lookup
// hooks can be replaced in tests so no live firewall is required.
type Env struct {
	Version             string
	GOOS                string
	GOARCH              string
	Euid                int
	StateFile           string
	AccessLog           string
	AccessLogCandidates []string
	GeoIPDB             string
	BlocklistCacheDir   string
	Now                 time.Time
	LookPath            func(string) (string, error)
	RunCommand          func(context.Context, string, ...string) ([]byte, error)
}

func (e Env) goos() string {
	if e.GOOS != "" {
		return e.GOOS
	}
	return runtime.GOOS
}

func (e Env) goarch() string {
	if e.GOARCH != "" {
		return e.GOARCH
	}
	return runtime.GOARCH
}

func (e Env) lookPath(name string) (string, error) {
	if e.LookPath != nil {
		return e.LookPath(name)
	}
	return exec.LookPath(name)
}

func (e Env) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if e.RunCommand != nil {
		return e.RunCommand(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Collect runs every read-only check and returns the report groups in display
// order.
func Collect(env Env) []Group {
	if env.Now.IsZero() {
		env.Now = time.Now()
	}
	return []Group{
		{Name: "Runtime", Checks: runtimeChecks(env)},
		{Name: "Caddy", Checks: caddyChecks(env)},
		{Name: "Guard", Checks: guardChecks(env)},
		{Name: "Optional Dependencies", Checks: optionalChecks(env)},
	}
}

func runtimeChecks(env Env) []Check {
	return []Check{
		Pass("runtime.version", fmt.Sprintf("version: %s (%s/%s)", env.Version, env.goos(), env.goarch())),
		Pass("runtime.os", fmt.Sprintf("OS: %s/%s", env.goos(), env.goarch())),
		privilegeCheck(env),
		stateDirCheck(env),
	}
}

func privilegeCheck(env Env) Check {
	if env.goos() == "windows" {
		return Warning("runtime.privileges", "privilege check not applicable on windows; guard firewall backends are Linux-only")
	}
	if env.Euid == 0 {
		return Pass("runtime.privileges", "running as root; firewall changes permitted")
	}
	return Warning("runtime.privileges", fmt.Sprintf("running as uid %d; firewall changes require root or CAP_NET_ADMIN", env.Euid))
}

func stateDirCheck(env Env) Check {
	if strings.TrimSpace(env.StateFile) == "" {
		return Warning("runtime.state_dir", "state file disabled; guard crash recovery is off")
	}
	dir := filepath.Dir(env.StateFile)
	existing, err := nearestExistingDir(dir)
	if err != nil {
		return stateDirProblem(env, fmt.Sprintf("state directory %s is unusable: %v", dir, err))
	}
	if !canWriteDir(existing) {
		return stateDirProblem(env, fmt.Sprintf("state directory %s is not writable", dir))
	}
	if filepath.Clean(existing) != filepath.Clean(dir) {
		return Pass("runtime.state_dir", fmt.Sprintf("state directory %s writable (will be created under %s)", dir, existing))
	}
	return Pass("runtime.state_dir", fmt.Sprintf("state directory %s writable", dir))
}

// stateDirProblem is critical only where guard can actually run. On other
// platforms the default state path is POSIX-specific and guard is unsupported.
func stateDirProblem(env Env, message string) Check {
	if env.goos() == "linux" {
		return CriticalFailure("runtime.state_dir", message)
	}
	return Warning("runtime.state_dir", message)
}

func nearestExistingDir(dir string) (string, error) {
	for {
		info, err := os.Stat(dir)
		if err == nil {
			if info.IsDir() {
				return dir, nil
			}
			return "", fmt.Errorf("%s is not a directory", dir)
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", err
		}
		dir = parent
	}
}

func caddyChecks(env Env) []Check {
	checks := make([]Check, 0, 3)
	if path, err := env.lookPath("caddy"); err == nil {
		checks = append(checks, Pass("caddy.executable", fmt.Sprintf("executable detected: %s", path)))
	} else {
		checks = append(checks, Warning("caddy.executable", "executable not found in PATH (Docker/remote deployments may still work)"))
	}

	var logCheck Check
	var fieldsCheck *Check
	if explicit := strings.TrimSpace(env.AccessLog); explicit != "" {
		logCheck, fieldsCheck = inspectExplicitAccessLog(explicit)
	} else {
		logCheck, fieldsCheck = inspectAccessLogs(env.AccessLogCandidates)
	}
	checks = append(checks, logCheck)
	if fieldsCheck != nil {
		checks = append(checks, *fieldsCheck)
	}
	return checks
}

// inspectAccessLogs checks auto-discovered candidates in order and returns the
// log and sample field checks. It only opens regular files for reading; nothing
// is created or modified.
func inspectAccessLogs(candidates []string) (Check, *Check) {
	return inspectAccessLogCandidates(candidates, false)
}

// inspectExplicitAccessLog diagnoses a user-supplied --log path directly:
// failures are critical and there is no fallback to auto-discovery.
func inspectExplicitAccessLog(path string) (Check, *Check) {
	return inspectAccessLogCandidates([]string{path}, true)
}

func inspectAccessLogCandidates(candidates []string, explicit bool) (Check, *Check) {
	var (
		foundPath        string
		openErr          error
		readableNoSample string
	)

	seen := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true

		info, err := os.Stat(candidate)
		if err != nil {
			if openErr == nil && (explicit || !os.IsNotExist(err)) {
				openErr = fmt.Errorf("%s: %w", candidate, err)
			}
			continue
		}
		if info.IsDir() {
			if explicit && openErr == nil {
				openErr = fmt.Errorf("%s: is a directory", candidate)
			}
			continue
		}
		if !info.Mode().IsRegular() {
			if openErr == nil {
				openErr = fmt.Errorf("%s: not a regular file (%s); refusing to open", candidate, info.Mode().Type())
			}
			continue
		}
		if foundPath == "" {
			foundPath = candidate
		}

		f, err := os.Open(candidate)
		if err != nil {
			if openErr == nil {
				openErr = fmt.Errorf("%s: %w", candidate, err)
			}
			continue
		}
		missing, found, scanErr := inspectLogSample(f)
		_ = f.Close()
		if scanErr != nil {
			if openErr == nil {
				openErr = fmt.Errorf("%s: %w", candidate, scanErr)
			}
			continue
		}
		if found {
			logCheck := Pass("caddy.access_log", fmt.Sprintf("JSON access log readable: %s", candidate))
			var fieldsCheck Check
			if len(missing) == 0 {
				fieldsCheck = Pass("caddy.log_fields", "sample entry contains ts, request, status, duration")
			} else {
				fieldsCheck = Warning("caddy.log_fields", fmt.Sprintf("sample entry missing expected fields: %s", strings.Join(missing, ", ")))
			}
			return logCheck, &fieldsCheck
		}
		if readableNoSample == "" {
			readableNoSample = candidate
		}
	}

	if readableNoSample != "" {
		logCheck := Warning("caddy.access_log", fmt.Sprintf("access log %s readable but no Caddy JSON access entry found", readableNoSample))
		fieldsCheck := Warning("caddy.log_fields", "no access-log sample available to verify fields")
		return logCheck, &fieldsCheck
	}
	if foundPath != "" && openErr != nil {
		return CriticalFailure("caddy.access_log", fmt.Sprintf("access log %s is not readable: %v", foundPath, openErr)), nil
	}
	if openErr != nil {
		if explicit {
			return CriticalFailure("caddy.access_log", fmt.Sprintf("explicit access log is not usable: %v", openErr)), nil
		}
		return Warning("caddy.access_log", fmt.Sprintf("no JSON access log found (%v)", openErr)), nil
	}
	if explicit {
		return CriticalFailure("caddy.access_log", "explicit access log path is empty"), nil
	}
	return Warning("caddy.access_log", "no JSON access log found; pass a source, --log, or configure caddy-analyzer.json"), nil
}

func inspectLogSample(r *os.File) (missing []string, found bool, err error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanned := 0; scanned < logSampleLines && scanner.Scan(); scanned++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal([]byte(line), &obj) != nil {
			continue
		}
		var msg string
		if raw, ok := obj["msg"]; ok {
			_ = json.Unmarshal(raw, &msg)
		}
		if msg != "handled request" {
			continue
		}
		return missingLogFields(obj), true, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, false, err
	}
	return nil, false, nil
}

func missingLogFields(obj map[string]json.RawMessage) []string {
	var missing []string
	if _, ok := obj["ts"]; !ok {
		missing = append(missing, "ts")
	}
	if raw, ok := obj["request"]; !ok {
		missing = append(missing, "request")
	} else {
		var req map[string]json.RawMessage
		if json.Unmarshal(raw, &req) != nil {
			missing = append(missing, "request")
		} else {
			for _, key := range []string{"method", "uri"} {
				if _, ok := req[key]; !ok {
					missing = append(missing, "request."+key)
				}
			}
			if _, ok := req["remote_ip"]; !ok {
				if _, ok := req["remote_addr"]; !ok {
					missing = append(missing, "request.remote_ip")
				}
			}
		}
	}
	if _, ok := obj["status"]; !ok {
		missing = append(missing, "status")
	}
	if _, ok := obj["duration"]; !ok {
		if _, ok := obj["latency"]; !ok {
			if _, ok := obj["latency_seconds"]; !ok {
				missing = append(missing, "duration")
			}
		}
	}
	return missing
}

type firewallProbe struct {
	id    string
	label string
	bin   string
	args  []string
}

func guardChecks(env Env) []Check {
	if env.goos() != "linux" {
		return []Check{Warning("guard.platform", fmt.Sprintf("firewall backends are not supported on %s; guard is Linux-only", env.goos()))}
	}

	probes := []firewallProbe{
		{id: "guard.iptables", label: "iptables", bin: "iptables", args: []string{"-S"}},
		{id: "guard.nftables", label: "nftables", bin: "nft", args: []string{"list", "tables"}},
	}

	checks := make([]Check, 0, len(probes)+2)
	usable := make([]string, 0, len(probes)+1)
	for _, probe := range probes {
		path, err := env.lookPath(probe.bin)
		if err != nil {
			checks = append(checks, Warning(probe.id, fmt.Sprintf("%s not installed", probe.label)))
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		out, err := env.run(ctx, probe.bin, probe.args...)
		cancel()
		if err != nil {
			checks = append(checks, Warning(probe.id, fmt.Sprintf("%s found at %s but not usable: %s", probe.label, path, commandError(err, out))))
			continue
		}
		usable = append(usable, probe.label)
		checks = append(checks, Pass(probe.id, fmt.Sprintf("%s available and usable (%s)", probe.label, path)))
	}

	dockerCheck, dockerUsable := dockerBackendCheck(env)
	checks = append(checks, dockerCheck)
	if dockerUsable {
		usable = append(usable, "docker")
	}

	if len(usable) == 0 {
		checks = append(checks, CriticalFailure("guard.backend", "no usable firewall backend; guard cannot block IPs"))
	} else {
		checks = append(checks, Pass("guard.backend", fmt.Sprintf("usable firewall backend(s): %s", strings.Join(usable, ", "))))
	}
	return checks
}

// dockerBackendCheck verifies that the Docker firewall backend can actually
// apply rules, not merely that the daemon is reachable. DockerBackend uses the
// host iptables binary and the DOCKER-USER chain, so both are required.
func dockerBackendCheck(env Env) (Check, bool) {
	path, err := env.lookPath("docker")
	if err != nil {
		return Warning("guard.docker", "docker not installed"), false
	}

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	out, err := env.run(ctx, "docker", "info", "--format", "{{.ServerVersion}}")
	cancel()
	if err != nil {
		return Warning("guard.docker", fmt.Sprintf("docker found at %s but not usable: %s", path, commandError(err, out))), false
	}

	iptablesPath, err := env.lookPath("iptables")
	if err != nil {
		return Warning("guard.docker", "docker daemon is accessible but local iptables is not installed; Docker firewall backend unusable"), false
	}
	ctx, cancel = context.WithTimeout(context.Background(), commandTimeout)
	out, err = env.run(ctx, "iptables", "-S", "DOCKER-USER")
	cancel()
	if err != nil {
		return Warning("guard.docker", fmt.Sprintf("docker daemon is accessible but DOCKER-USER chain is not usable via %s: %s", iptablesPath, commandError(err, out))), false
	}
	return Pass("guard.docker", fmt.Sprintf("docker daemon accessible and DOCKER-USER chain usable (%s)", iptablesPath)), true
}

func commandError(err error, out []byte) string {
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		return err.Error()
	}
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	if len(msg) > 200 {
		msg = msg[:197] + "..."
	}
	return msg
}

func optionalChecks(env Env) []Check {
	return []Check{geoIPCheck(env), blocklistCacheCheck(env)}
}

func geoIPCheck(env Env) Check {
	path := strings.TrimSpace(env.GeoIPDB)
	if path == "" {
		path = enrich.FindDB("")
	}
	if path == "" {
		return Warning("optional.geoip", "no GeoIP database found; country/ASN features unavailable (auto-download may fetch one)")
	}

	info, err := os.Stat(path)
	if err != nil {
		return Warning("optional.geoip", fmt.Sprintf("GeoIP database not found: %s", path))
	}
	if info.IsDir() {
		return Warning("optional.geoip", fmt.Sprintf("GeoIP database path is a directory: %s", path))
	}
	f, err := os.Open(path)
	if err != nil {
		return Warning("optional.geoip", fmt.Sprintf("GeoIP database not readable: %s", path))
	}
	_ = f.Close()
	return Pass("optional.geoip", fmt.Sprintf("GeoIP database present: %s", path))
}

type blocklistCacheEntry struct {
	FetchedAt time.Time `json:"fetched_at"`
}

func blocklistCacheCheck(env Env) Check {
	dir := strings.TrimSpace(env.BlocklistCacheDir)
	if dir == "" {
		return Warning("optional.blocklist_cache", "blocklist cache disabled (empty --cache-dir)")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return Warning("optional.blocklist_cache", fmt.Sprintf("no blocklist cache at %s; run 'caddy-analyze blocklist refresh'", dir))
		}
		return Warning("optional.blocklist_cache", fmt.Sprintf("blocklist cache unreadable: %v", err))
	}

	now := env.Now
	if now.IsZero() {
		now = time.Now()
	}
	var oldest time.Time
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var cf blocklistCacheEntry
		if json.Unmarshal(data, &cf) != nil || cf.FetchedAt.IsZero() {
			continue
		}
		count++
		if oldest.IsZero() || cf.FetchedAt.Before(oldest) {
			oldest = cf.FetchedAt
		}
	}

	if count == 0 {
		return Warning("optional.blocklist_cache", fmt.Sprintf("no cached blocklist sources in %s; run 'caddy-analyze blocklist refresh'", dir))
	}

	age := now.Sub(oldest)
	if age < 0 {
		age = 0
	}
	if age >= blocklistCacheTTL {
		return Warning("optional.blocklist_cache", fmt.Sprintf("blocklist cache stale: oldest source is %s old; run 'caddy-analyze blocklist refresh'", formatAge(age)))
	}
	return Pass("optional.blocklist_cache", fmt.Sprintf("blocklist cache age: oldest source %s (%d cached)", formatAge(age), count))
}

func formatAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < time.Hour:
		return d.Round(time.Minute).String()
	case d < 48*time.Hour:
		return d.Round(time.Hour).String()
	default:
		days := int(d / (24 * time.Hour))
		hours := int((d % (24 * time.Hour)) / time.Hour)
		return fmt.Sprintf("%dd %dh", days, hours)
	}
}
