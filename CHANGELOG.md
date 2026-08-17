# Changelog

All notable changes to `caddy-analyzer` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-08-17

### Added
- **Blocklist feed system**: `blocklist` subcommand with four actions — `refresh` (download + cache all feeds), `list` (per-feed status), `config` (print resolved sources), `init` (persist flag settings to `caddy-analyzer.json`). Feeds are cached as a CIDR trie in `~/.cache/caddy-analyzer/blocklists/` (7-day TTL). Flags: `--cache-dir`, `--no-default-blocklists`, `--blocklist-config`, `--blocklist-remove`.
- **8 default blocklist feeds**: Spamhaus DROP v4/v6, FireHOL level 1/2, CINS Army, Tor exit nodes, Emerging Threats, AbuseIPDB s100-7d mirror. JSON Lines (Spamhaus) and plain-text formats supported.
- **Guard blocklist integration**: incoming IPs are checked against the CIDR trie for immediate block. `--no-blocklist` disables; `--blocklist-refresh` (default `6h`) controls background re-fetch.
- **Guard country-block**: `--country-block CN,RU,IR` immediately blocks IPs by GeoIP country code. Fails fast if no mmdb is available.
- **GeoIP enrichment**: offline mmdb lookup (no API key, no network at query time). `--geoip-db` with auto-discovery in cwd, `~/.config/caddy-analyzer/`, `/var/lib/caddy-analyzer/`, `/usr/share/GeoIP/`. Auto-downloads `GeoLite2-Country.mmdb` + `GeoLite2-ASN.mmdb` from the P3TERX mirror on first run; disable with `--no-auto-download`.
- **`top country` / `top asn` dimensions** with human-readable country names ("Italy" instead of `IT`). Country and ASN sections now in the default report (auto-hidden when no GeoIP data).
- **Documentation site**: glassmorphism-design docs (index, subcommands, security, sources, installation) with TOC sidebar, back-to-top, Lighthouse-optimized performance.

### Fixed
- **GeoIP download URLs**: dead `download.dbip.com` (DNS does not resolve) replaced with the P3TERX/GeoLite.mmdb GitHub release mirror. Auto-download now fetches both country and ASN databases.
- **CINS Army URL** corrected to `http://cinsscore.com/list/ci-badguys.txt`.
- **Country codes shown instead of names** in `top country` and the default report.

### Changed
- **AbuseIPDB enricher removed**: the `pkg/enrich/abuseipdb.go` file (shipped in 0.3.0 but never wired to any command) is deleted. GeoIP mmdb is the sole enrichment backend.
- **Guard startup summary** now prints blocklist stats and country-block list alongside existing thresholds.
- **Go 1.25.13** (was 1.24.6).

## [0.3.0] - 2026-08-06

### Added
- **3 new detection categories** (26 total): JWT abuse (`jwt_abuse`), object enumeration/BOLA (`object_enumeration`), beaconing/C2 (`beaconing`). All tagged with MITRE ATT&CK technique IDs.
- **`export-sigma` subcommand**: exports 23 detection categories as Sigma YAML for SIEM import. Includes MITRE ATT&CK tags and deterministic UUIDs.
- **`--defang` flag**: defangs IPs (`.` → `[.]`) and URL schemes (`http://` → `hxxp://`) across all commands for safe IOC sharing.
- **`tail --detect`**: inline threat highlighting on streamed entries. IP colored by severity, attack types appended after a `→` arrow. Clean entries unchanged.
- **Progress bar**: determinate bar on TTY for file analysis (`caddy-analyze`, `top`, `diff`); indeterminate spinner for non-file sources. Auto-disabled on pipe.
- **Threat-intel enrichment**: GeoIP enrichment via DB-IP/MaxMind mmdb (offline, zero API key). `--geoip-db` flag with auto-discovery. Country/ASN top-N dimensions (`--top country`, `--top asn`).
- **Guard features**: sliding-window rate limiting, distributed-scan defense (`--subnet-limit`), RPS anomaly alerting (`--rps-anomaly`), credential stuffing detection (`--cred-stuffing-limit`), `--trust-forwarded` for reverse proxy/CDN.
- **`--state-file` on `block`/`unban`**: manual blocks/unbans sync with guard state file — survive restarts.
- **Detection engine 2x throughput**: case-fold elimination, per-source marker triage, literal fast path. ~7K lines/sec with `--detect` (was ~3.5K).
- **Streaming latency histogram**: O(1) log10-spaced buckets replace O(n) slice. Saves ~80MB on million-line logs.
- **MITRE ATT&CK tags** on all detections. **Structured detections in JSON** output.
- **New filter flags**: `--host`, `--max-latency`, `--min-size`/`--max-size`, `--max-cardinality`, `--ua-rotation`.
- **Subcommand flag inheritance**: shared flags (`-t`, `-f`, `-o`, filters) now persistent across `top`, `diff`, `tail`, `config`.
- **Dedicated iptables chain** (`CADDY_ANALYZER`) with comment marker — `unban` only touches rules created by this tool.
- **Cosign signature verification** in `install.sh`. **Dockerfile non-root user**. **CI coverage gate** (≥50%).

### Fixed
- **Guard**: shutdown race losing state on Ctrl+C (now waits for `saveState`); dirty-flag race losing concurrent blocks; `ListBlockedIPs` misleading error on fresh systems; manual `block`/`unban` not synced to state; duplicate iptables rules on double-block; `block`/`unban` always exit 0; `loadState` hitting real iptables in tests.
- **Detection engine**: zero timestamp corrupting `StartTime`; unbounded `PathTimestamps` per IP (now capped at 1K); FIFO eviction mislabeled as LRU (now true LRU); `extractPureLiterals` dropping 1-char alternatives; `lowercaseFold` missing `OpCharClass`; UA-rotation firing only once; `MinDuration` corrupted by zero/negative durations.
- **Audit logger**: double-`Close()` panic; goroutine leak after rotation failure; no reopen after write error.
- **Reader**: follow mode + multiple files only reading first file (now concurrent fan-in).
- **TUI**: `truncate(s, 0)` panic; negative table height on tiny terminals; `StreamEndMsg` freeze.
- **Output**: ANSI codes leaking to `-o` files; `-o` creating files with 0666 (now 0600 with dir creation).
- **Parser**: silent error on Status/Size parse; `classifyUserAgent` rebuilding map every call + non-deterministic BotName.
- **cmd**: SIGPIPE in `tail | head`; signal goroutine leaks in `root`/`tail`/`guard`; `--top 0` ignored in `top` command.
- **30+ earlier fixes**: JWT base64 decode, beaconing per-path, defang in follow/interval modes, authFailPaths map leak, ring buffer off-by-one, sigma YAML escaping, enrichment cap, parseInt overflow, math.Sqrt on zero, duration histogram P99, guard busy-loop, partial lines at EOF, journalctl output format, and more (see git log for full detail).

### Changed
- **Go 1.24.6** (23 stdlib vulnerabilities fixed).
- **golangci-lint v2** config format. gosec excludes G401/G501 (MD5 for deterministic UUIDs). gitleaks `.gitleaksignore` for test fixtures.
- **IP eviction**: true LRU (was FIFO). Enrich cache bounded to 10K entries. File output 0600 with parent dir 0750.
- **Scanner detection**: `curl`, `wget`, `python-requests` no longer flagged as scanners standalone (too many false positives).
- **Narrowed false-positive patterns**: SSRF metadata, `.env` path delimiters, SSTI regex escaping, XSS token cleanup.

## [0.2.0] - 2026-08-01

### Added
- **Multi-category detection**: `DetectAll()` returns all matching attack categories per request instead of stopping at the first match. Polyglot payloads (e.g. SQLi+XSS) are now classified as both.
- **Confidence scoring**: Every detection pattern carries a 1-10 score based on specificity. Included in JSON output for filtering and prioritization.
- **Guard audit logging**: Structured JSON-lines audit log (timestamp, action, IP, reason, duration, user) via `--audit-log` on `guard`, `block`, and `unban`. File created with `0600` permissions.
- **Guard state persistence**: `--state-file` (default `/var/lib/caddy-analyzer/blocked.json`) survives restarts; expired entries cleaned on load.
- **Guard IP allowlist**: `--never-block` (comma-separated IPs/CIDRs) and `--never-block-file` (file, one per line, `#` comments) prevent banning trusted IPs. Flags are merged.
- **IP validation**: `validateIP()` accepts IPv4/IPv6/CIDR and rejects flag injection. Applied to all three iptables call sites.
- **Version injection via ldflags**: `Version` variable populated by GoReleaser, CI, and Dockerfile.
- **CI quality gates**: `go vet`, `golangci-lint`, `govulncheck`, coverage reporting. Actions SHA-pinned, `permissions: contents: read`. Secret scanning (gitleaks) and SAST (gosec, with G104/G204/G304 excluded as inherent to CLI design).
- **SBOM and release signing**: SPDX JSON SBOMs via Syft, cosign keyless signature uploaded as release asset.
- **CODEOWNERS**: Requires review on CI workflows, installers, and build config.

### Fixed
- **Regex false positives**: Removed 11 duplicate patterns, bounded 8 unbounded `.*` quantifiers, removed overly broad `/docs/` admin probe.
- **Race condition on `blocked` map**: `sync.Mutex` protection, fixed bypass where blocked IPs weren't removed after `iptables -D`, and false-positive marking on `iptables -A` failure.
- **`parseBlockedIPs` field index bug**: Read wrong column, returning garbage IPs.
- **Swallowed `ParseDuration` errors**: `--duration abc` and `--interval abc` now fail instead of silently using 0 (permanent block).
- **Goroutine leak and DoS**: `unblockAfter` now uses `select` with `ctx.Done()` (cancelled on Ctrl+C). Replaced per-IP `time.Sleep` goroutines with a single min-heap-based expiry loop.
- **File rotation data loss**: `readFileAndFollow` detects rotation via `os.SameFile()` and reopens.
- **`cmd.Wait()` errors ignored**: Now logged; zombie processes reaped after `Process.Kill()`.
- **`install.sh`**: Added `set -euo pipefail` and checksum verification.
- **Custom HTML escaper**: Replaced with `html.EscapeString` (also escapes `'`).
- **Scanner UA list duplicates**: Removed 5 duplicate entries.
- **Windows CI test failures**: File-permission tests now skip on Windows (Unix perms not honored). `cmd.Wait()` error explicitly discarded after `Process.Kill()`.

### Changed
- **Detection gap coverage**: 4 new pattern families (SSTI FreeMarker/ERB/Thymeleaf, Java/Node deserialization, CRLF Java ghost bits, open redirect backslash bypass).
- **Go 1.24 aligned** across `go.mod`, Dockerfile, CI matrix, and release workflow.
- **Dockerfile production image pinned** to `alpine:3.20` with SHA256 digest.
- **`listBlockedIPs` switched to `iptables -S`**: Stable one-rule-per-line format instead of locale-dependent `iptables -L`.
- **Config file permissions tightened**: Directory `0755`→`0750`, file `0644`→`0600` (gosec G301/G306).

## [0.1.3] - 2026-07-30

### Added
- **Expanded to 22 attack categories** (was 15): added XXE/XInclude, Open Redirect, LDAP Injection, XPath Injection, CRLF Injection, Prototype Pollution, SSI Injection, SSRF (cloud metadata / protocol smuggling), SSTI (Freemarker, Jinja2, MRO), NoSQL Injection (`$ne`, `$gt`, `$regex`, `$where`), GraphQL Introspection (`__schema`, `__type`), LFI Wrapper Abuse (`phar://`, `data://`, `compress.*`), WordPress probes, and CGI probes.
- **Raw URI matching**: Percent-encoded path traversal sequences (`%c0%ae%c0%ae%c0%af`, `%252e%252e%252f`) and internal host probes are checked against the raw URI before URL unescaping — closing evasion gaps.
- **Expanded existing signatures**: RCE now matches time-based exfiltration (`sleep`, `ping`, `/dev/tcp/`); Log4j catches obfuscated variants (`${lower:jndi`, `${${::-j}}`); path traversal catches null-byte tricks (`%00..`); sensitive file probes cover `.gitignore`, `composer.json`, `package.json`; admin probes cover `/h2-console`, `/heapdump`, `/jolokia`; scanner UA list includes `httpx`, `nuclei`, `ffuf`, `katana`, `dalfox`, `xsstrike`, `commix`, `tplmap`, `nosqlmap`.
- **Comprehensive test suite**: 55+ test cases covering all 22 categories, dual-pass matching, and false positives.
- **Security-first README**: Hero callout, Demo GIF at top, 22-row detection table with examples, restructured for immediate security impact.
- **docs/security.html**: Updated with all 22 categories and compact pattern table.

### Changed
- **Detection engine**: Introduced `rawPatterns` pre-compiled init block for rules that must match against the raw (non-unescaped) URI, executed before the main `patterns` block.
- **README reordered**: Hero security callout → Demo GIF → Security Detection → Quick Start → Why caddy-analyzer? → Features → Installation → Docs.
- **Help text**: `cmd/root.go` and `cmd/guard.go` now reference 22 categories and dual-pass engine.

## [0.1.2] - 2026-07-29

### Added
- **Per-IP & CIDR Filtering**: `--ip` now accepts both single IPs (`1.2.3.4`) and CIDR subnets (`10.0.0.0/8`). `--exclude-ip` also supports CIDR.
- **Smart Filter Listing**: When entry-level filters are active (`--ip`, `--5xx`, `--no-bots`, etc.), `caddy-analyze` now shows a color-coded log listing (like `tail`) instead of the aggregate report — making filtered output immediately actionable.
- **Filter Support for `tail`**: The `tail` subcommand now accepts all root-level filters (`--ip`, `--5xx`, `--no-bots`, etc.) for real-time filtered streaming.
- **Active Filter Display**: All active filters are shown in the report header for table, JSON, CSV, and HTML formats.
- **TUI Dashboard Colors**: The real-time stream tab (tab 2) in `--watch` mode now uses the same color scheme as `caddy-analyze tail` (2xx green, 3xx cyan, 4xx yellow, 5xx red, IP purple, etc.).
- **Suspicious Request Details in `--detect`**: The security report now shows the actual suspicious requests (detection type, description, method, path) per offending IP in all output formats.
- **Public `MatchEntry` API**: Exported `analysis.MatchEntry()` to allow external use of filter logic.

### Fixed
- **`--ip` filter not working**: The `--ip` flag was declared and parsed but the filtering logic was missing in `Engine.match()`. Now correctly filters by IP/CIDR.

### Changed
- **Help text**: Updated root command help with filter examples and expanded flag descriptions.

## [0.1.1] - 2026-07-28

### Added & Improved
- **Focused Security Inspection Mode (`--detect`)**: Running `--detect` now outputs a standalone, zero-noise Security Threat Inspection Report focused purely on attack alerts, offending IPs, and threat categories.
- **Enhanced `top` Command Usability**: Automatically defaults to `path` dimension when log source is passed directly (`caddy-analyze top access.log`). Added `-b, --by` flag.
- **Enhanced `config` Command Usability**: Added `show` and `reset` actions with clear user feedback for managing persistent default log sources.
- **Clean Unix Terminal Formatting**: Removed emojis from terminal outputs, adopting a crisp, high-contrast Unix developer aesthetic.
- **Documentation Suite**: Added complete multi-page documentation website (`docs/`) with comprehensive reference tables for all 19 CLI flags and options.
- **Permission Diagnostics**: Added friendly diagnostic hints when opening log files fails due to permission errors (`permission denied`), suggesting `sudo` or user group membership.

### Fixed
- **Windows PowerShell Installer**: Fixed asset filename pattern and encoding compatibility for PowerShell 5.1 in `install.ps1`.
- **POSIX Shell Installer**: Fixed release asset URL template and ASCII formatting in `install.sh`.

## [0.1.0] - 2026-07-28

### Initial Release

#### Core Features
- **Native Caddy v2 JSON Parsing**: Zero-config parsing of Caddy's structured log schema including nested TLS versions, request headers, float durations, and status codes.
- **Traffic Classification**: Automatic detection of human users vs search engine crawlers (Googlebot, Bingbot, Yandex, DuckDuckBot) and scrapers.
- **Percentile Latency Analysis**: Computes P50, P95, P99 latencies alongside average, min, and max durations.
- **Bandwidth Metrics**: Track bytes transferred per path and remote IP address.

#### Security & Anomaly Detection Engine
- **Threat Detection (`--detect`)**: Scans URIs and headers for SQL Injection, XSS, Path Traversal / LFI, Log4j / JNDI, RCE, sensitive file probes (`.env`, `.git/config`, `wp-config.php`, `id_rsa`), admin probes, and automated scanner User-Agents.
- **Real-time Firewall Guard (`guard`)**: Automatically monitors log streams and blocks offending malicious IPs in real time via `iptables` rules.
- **Manual Ban Tools**: Added `block <ip>` and `unban <ip>` commands.

#### CLI & Output Formats
- **Visual Terminal Bar Charts**: Displays Unicode proportion bars (`████████░░`) and status code badges directly in terminal output.
- **Real-time Streaming (`tail`)**: Colorized real-time log viewer for streaming logs from files, Docker, K8s, or stdin.
- **Metric Inspector (`top`)**: Quick top-N metric inspector by dimension (`path`, `ip`, `ua`, `status`, `bandwidth`).
- **Comparative Log Diff (`diff`)**: Compare two log files side-by-side (baseline vs target) to detect 5xx error spikes, RPS shifts, and latency regressions.
- **Standalone Offline HTML Report (`-f html`)**: Single-file dark-mode HTML report generator.
- **6-Tab Interactive TUI (`--watch`)**: Live Bubbletea terminal user interface featuring Summary, Realtime Stream, Security Alerts, Top IPs, Top Paths, and User Agents.

#### Multi-Source Reader
- Supports reading from local files, stdin pipe (`-`), Docker containers (`docker://container`), Kubernetes pods (`k8s://pod`), and systemd journalctl (`journalctl://unit`).

#### Cross-Platform Installers & Automation
- 1-Line installer scripts for Linux/macOS (`install.sh`) and Windows PowerShell (`install.ps1`).
- GitHub Actions CI matrix testing on Ubuntu, macOS, and Windows.
- GoReleaser automated static binary build matrix for `linux/amd64`, `linux/arm64`, `linux/armv7`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`.
- GitHub Pages documentation site with live interactive HTML report demo.
