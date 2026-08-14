<p align="center">
  <img src="assets/mascot.svg" width="90" alt="caddy-analyzer mascot"><br>
  <img src="assets/title.svg" alt="caddy-analyzer" height="80">
  <br>
  <sub>Gopher created with <a href="https://gopherize.me">gopherize.me</a> &middot; Artwork by <a href="https://twitter.com/ashleymcnamara">Ashley McNamara</a>, inspired by <a href="http://reneefrench.blogspot.com/">Renee French</a></sub>
</p>

<p align="center">
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.25-38bdf8?style=flat-square&logo=go" alt="Go Version"></a>
  <a href="https://pkg.go.dev/github.com/lenny-ts/caddy-analyzer"><img src="https://pkg.go.dev/badge/github.com/lenny-ts/caddy-analyzer.svg" alt="Go Reference"></a>
  <a href="https://lenny-ts.github.io/caddy-analyzer/"><img src="https://img.shields.io/badge/Documentation-238636?style=flat-square&logo=github" alt="Documentation"></a>
  <a href="https://github.com/lenny-ts/caddy-analyzer/actions"><img src="https://github.com/lenny-ts/caddy-analyzer/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-purple.svg?style=flat-square" alt="License"></a>
  <a href="https://github.com/lenny-ts/caddy-analyzer/releases"><img src="https://img.shields.io/github/v/release/lenny-ts/caddy-analyzer?style=flat-square&color=fbbf24" alt="Release"></a>
  <a href="https://github.com/lenny-ts/caddy-analyzer"><img src="https://img.shields.io/github/stars/lenny-ts/caddy-analyzer?style=flat-square" alt="Stars"></a>
</p>

<p align="center"><strong>🛡️ 26 attack categories · Dual-pass evasion-resistant engine · Real-time iptables firewall guard · Sigma export · MITRE ATT&CK tagged</strong></p>

---

## Demo

![](assets/demo.gif)

---

## Security Detection Engine

Scans every Caddy v2 request against **26 attack categories** using a dual-pass pattern engine — first on the URL-unescaped URI, second on the raw URI to catch multibyte and double-encoded bypass attempts. Every detection is tagged with MITRE ATT&CK technique IDs. Suspicious requests are grouped by offending IP and surfaced in all output formats. Detections can be exported as Sigma rules for SIEM import.

| Category | Covers | Example Patterns |
|---|---|---|
| **SQL Injection** | SQLi probes, blind injection, DB fingerprinting | `UNION SELECT`, `OR 1=1`, `pg_sleep`, `INTO OUTFILE`, `@@version`, etc. |
| **NoSQL Injection** | MongoDB operators, JS eval injection | `$ne`, `$gt`, `$regex`, `$where`, `$nin`, `%24ne`, etc. |
| **XSS** | Reflected/stored/DOM XSS, event handlers, protocol JS | `<script`, `onerror=`, `onfocus=`, `alert(`, `document.cookie`, `data:text/html`, etc. |
| **SSTI** | Server-side template injection (Jinja2, Freemarker, ERB, Thymeleaf, Twig, etc.) | `__class__`, `__mro__`, `freemarker`, `nunjucks`, `{{7*7}}`, `os.popen`, `<#assign`, `<%=`, `__${...}__`, etc. |
| **SSRF** | Cloud metadata, loopback/private IPs, protocol smuggling | `169.254.169.254`, `0x7f000001`, `gopher://`, `dict://`, `redis://`, etc. |
| **RCE** | Shell injection, reverse shells, downloaders, LOLBins, deserialization | `/bin/sh`, `whoami`, `/dev/tcp/`, `powershell`, `certutil`, `eval()`, `rO0AB`, `_$$ND_FUNC$$_`, etc. |
| **Path Traversal / LFI** | Directory traversal, null byte, `/proc/` filesystem, Windows system files | `../`, `..%00`, `/etc/passwd`, `/proc/self/*`, `php://input`, etc. |
| **GraphQL Introspection** | Schema discovery queries | `__schema`, `__type`, `IntrospectionQuery`, etc. |
| **Log4j / JNDI** | Log4Shell, JNDI lookups, env/sys access, obfuscated variants | `${jndi:ldap://`, `${env:`, `${lower:jndi`, `${::-j}`, etc. |
| **XXE / XInclude** | XML entity expansion, external DTD, XInclude | `<!ENTITY`, `SYSTEM`, `PUBLIC`, `xi:include`, `xpointer`, etc. |
| **Open Redirect** | URL parameter injection, protocol-relative URLs, backslash bypass | `?url=http://`, `?redirect=//`, `//evil.com`, `?url=/\`, etc. |
| **LDAP Injection** | LDAP filter manipulation | `(&(`, `(|(`, `)(|(`, URL-encoded operators, etc. |
| **XPath Injection** | XPath query manipulation | `]\|//*`, `.//*`, etc. |
| **CRLF / Log Injection** | HTTP response header injection, log poisoning, Java ghost bits | `%0d%0aSet-Cookie:`, `%0d%0aLocation:`, literal CRLF, `%E5%98%8A%E5%98%8D`, etc. |
| **Prototype Pollution** | JS prototype chain tampering | `__proto__`, `constructor.prototype`, JSON payloads, etc. |
| **SSI Injection** | Server-side include directive injection | `<!--#exec cmd=`, `#include virtual=`, `#echo var=`, etc. |
| **User-Agent Rotation** | Behavioral heuristic — IPs rotating ≥10 distinct UAs | credential stuffing, evasive scanners, etc. |
| **JWT Abuse** | JWT alg:none bypass, token in URI, kid path traversal, Bearer token leak | `eyJ...` in URI, `"alg":"none"`, `kid":"../../../`, `Authorization: Bearer`, etc. |
| **Object Enumeration** | BOLA/IDOR — sequential ID enumeration per path template | `/api/users/1`, `/api/users/2`, `/api/users/3` (≥10 distinct IDs), etc. |
| **Beaconing / C2** | Periodic callback detection (C2 beaconing) | inter-arrival CV < 0.25, 10-50 samples per path, etc. |
| **LFI Wrapper Abuse** | PHP stream wrappers for file read/execution | `phar://`, `data://`, `expect://`, `compress.zlib`, etc. |
| **Sensitive File Probes** | Credentials, backups, configs, source code, git exposure | `.env`, `.git/config`, `id_rsa`, `dump.sql`, `phpinfo.php`, etc. |
| **Admin Probes** | DB admin panels, Spring Actuator, heapdumps, API docs, VCS metadata | `/phpmyadmin`, `/actuator/*`, `/h2-console`, `/swagger-ui`, etc. |
| **WordPress Probes** | Plugin scanning, XML-RPC, rest API, backup directories | `/wp-content/plugins/`, `/xmlrpc.php`, `/wp-json/wp/v2/`, etc. |
| **CGI Probes** | Legacy CGI script discovery | `/cgi-bin/`, `.cgi`, `.fcgi`, etc. |
| **Scanner Tools** | 30+ scanner/user-agent signatures, automated tooling | `sqlmap`, `nuclei`, `gobuster`, `ffuf`, `wpscan`, `masscan`, `hydra`, `metasploit`, `shodan`, etc. |

Output example:

```
  - 192.168.1.100     15 malicious requests
       [sql_injection] SQL injection attempt GET /search?id=1' OR '1'='1
       [scanner] Scanner / automated tool detected GET /admin
```

> **Guard mode** (`caddy-analyze guard`) extends detection with automatic `iptables` banning — blocks offending IPs at the firewall on configurable thresholds. Uses a **sliding window** (per-IP, per-second buckets) so attackers cannot evade limits by straddling a tick boundary. Supports audit logging (`--audit-log`), state persistence across restarts (`--state-file`), an IP allowlist (`--never-block` / `--never-block-file`), distributed-scan defense (`--subnet-limit`), RPS anomaly alerting (`--rps-anomaly`), and `--trust-forwarded` for deployments behind a reverse proxy/CDN. Pattern-detection blocks are filtered by confidence via `--detect-confidence` (default 8, `0` disables).

---

## Quick Start

```bash
# Set default log source once (persistent config)
caddy-analyze config /var/log/caddy/access.log

# Analyze with full security detection
caddy-analyze --detect

# Top-N metric inspector
caddy-analyze top ip

# Real-time streaming with filters
caddy-analyze tail --ip 10.0.0.0/8 --no-bots docker://my-caddy

# Real-time streaming with inline threat detection
caddy-analyze tail --detect docker://my-caddy

# Generate standalone HTML report
caddy-analyze -f html -o report.html --detect

# Compare two log files for regressions
caddy-analyze diff before.log after.log

# Launch interactive TUI dashboard
caddy-analyze --watch
```

---

## Why caddy-analyzer?

Caddy v2 uses a **structured JSON log format** that differs from the Common/Combined Log Format used by Apache, Nginx, and most log analysis tools. Generic tools like `goaccess`, `lnav`, or `grep`/`awk` pipelines cannot parse Caddy's nested schema out of the box.

| Capability | caddy-analyzer | goaccess | lnav | grep/awk |
|---|---|---|---|---|
| Caddy v2 JSON native | ✅ | ❌ | ❌ | ❌ |
| Security threat detection (26 categories) | ✅ | ❌ | ❌ | ❌ |
| Dual-pass evasion-resistant detection | ✅ | ❌ | ❌ | ❌ |
| Real-time firewall guard (iptables) | ✅ | ❌ | ❌ | ❌ |
| Per-IP suspicious request details | ✅ | ❌ | ❌ | ❌ |
| Comparative diff engine (RPS, 5xx, latency) | ✅ | ❌ | ❌ | ❌ |
| TUI dashboard with live streaming | ✅ | ✅ | ✅ | ❌ |
| Standalone HTML reports | ✅ | ✅ | ❌ | ❌ |
| Multi-source (Docker, K8s, journalctl) | ✅ | ❌ | ✅ | ❌ |
| CIDR filtering | ✅ | ❌ | ❌ | ❌ |
| Traffic classifier (crawler vs human) | ✅ | ❌ | ❌ | ❌ |

---

## Features

| Area | Capability |
|---|---|
| **Parsing** | Native Caddy v2 structured JSON — no regex, no config required |
| **Security** | 26 attack categories: SQLi, NoSQLi, XSS, SSTI, SSRF, RCE, path traversal/LFI, LFI wrapper abuse, GraphQL introspection, Log4j/JNDI, XXE/XInclude, open redirect, LDAP injection, XPath injection, CRLF injection, prototype pollution, SSI injection, UA rotation, JWT abuse, object enumeration (BOLA/IDOR), beaconing (C2), sensitive file probes, WordPress probes, CGI probes, admin probes, scanner tools |
| **Detection Accuracy** | Dual-pass engine: URL-unescaped + raw URI matching catches multibyte-encoded and double-encoded bypass attempts. Confidence scoring (1-10) per detection. LRU IP eviction (100K cap) bounds memory on huge logs |
| **Firewall** | `guard` daemon auto-blocks malicious IPs via `iptables` with configurable thresholds, ban duration, audit logging, state persistence (survives restarts), IP allowlist, and `block`/`unban` state sync |
| **Traffic Analysis** | Classifies human users vs crawlers (Googlebot, Bingbot, Yandex, DuckDuckBot) and automated scrapers |
| **Diff Engine** | Side-by-side comparison of two log files detecting 5xx spikes, RPS shifts, and latency regressions |
| **TUI Dashboard** | 6-tab Bubbletea/Lipgloss interface with live streaming, security alerts, and top metrics |
| **HTML Reports** | Standalone dark-mode single-file HTML reports for sharing with your team |
| **Data Sources** | Local files, stdin, Docker (`docker://`), Kubernetes (`k8s://`), systemd journalctl (`journalctl://`) |
| **Filtering** | Entry-level filters auto-switch to color-coded log listings. Supports CIDR, status classes, methods, path globs |

---

## Real-Time Threat Detection (`tail --detect`)

The `tail` subcommand accepts `--detect` (`-d`) to run the full detection engine on every streamed entry, inline:

```bash
caddy-analyze tail --detect docker://my-caddy
caddy-analyze tail -d --ip 10.0.0.0/8 /var/log/caddy/access.log
caddy-analyze tail --detect --defang journalctl://
```

Suspicious entries are highlighted with **zero visual noise**:

- The client **IP** is colored by the highest-severity detection on that entry:
  - **Critical / High** — bright red (bold)
  - **Medium** — amber
  - **Low** — olive
- After the User-Agent info, a dim `→` arrow is followed by the **attack types** in severity color:

```
21:06:07  404 WARN  GET /cms/gather/getArticle  (1.71 KB, 2.27ms) - 2.58.137.2 [macOS/Safari] → XSS · RCE
21:06:07  404 WARN  GET /wp-content/plugins/restropress/readme.txt  (9 B, 73µs) - 2.58.137.2 [Linux/Firefox] → WP
21:06:06  200 OK  GET /  (3.04 KB, 5.95ms) - 2.58.137.2 [macOS/Firefox]
```

Clean entries look identical to `tail` without `--detect` — no markers, no badges, no extra lines. Works with `--defang` for safe IOC sharing.

> **Note:** `--detect` is a local flag on `tail` (not the root-level `--detect`). Run `caddy-analyze tail --help` for details.

---

## Progress Bar

When analyzing files on a TTY, a determinate progress bar is shown:

```
[████████████░░░░░░░░] 5000/10000 (50%) caddy_access.log
```

Active on `caddy-analyze` (offline mode), `top`, and `diff` (per-file with filename label). Auto-disabled when stderr is redirected to a pipe or file. For non-file sources (stdin, `docker://`, `k8s://`, `journalctl://`) an indeterminate spinner is shown instead. Pre-scan overhead is <3%.

---

## Installation

```bash
# Linux / macOS
curl -sSfL https://raw.githubusercontent.com/lenny-ts/caddy-analyzer/main/install.sh | bash

# Windows (PowerShell)
iwr -useb https://raw.githubusercontent.com/lenny-ts/caddy-analyzer/main/install.ps1 | iex

# Go toolchain
go install github.com/lenny-ts/caddy-analyzer/cmd/caddy-analyze@latest

# Docker
docker run --rm -v /var/log/caddy:/logs ghcr.io/lenny-ts/caddy-analyzer /logs/access.log
```

---

## Documentation

Full documentation is available at **[lenny-ts.github.io/caddy-analyzer](https://lenny-ts.github.io/caddy-analyzer/)**.

<details>
<summary><strong>Command Reference</strong></summary>

```
caddy-analyze [flags] [source...]

Subcommands:
  tail                         Stream and colorize logs in real time
  top <dimension>              Top-N metric inspector (path, ip, ua, status, method, host, bandwidth)
  diff <baseline> <target>     Compare two log files
  guard                        Auto-block malicious IPs via iptables
  export-sigma                 Export detection rules as Sigma YAML (23 rules, MITRE ATT&CK tagged)
  config                       Manage default log source configuration
  block <ip...>                Manually block IP via iptables (--audit-log)
  unban <ip...>               Remove IP block from iptables (--all, --list, --audit-log)
```
</details>

<details>
<summary><strong>Flags Reference</strong></summary>

| Flag | Short | Default | Description |
|---|---|---|---|
| `--detect` | `-d` | `false` | Enable security threat detection |
| `--format` | `-f` | `table` | Output format: `table`, `json`, `csv`, `html` |
| `--output` | `-o` | `""` | Write report to file |
| `--watch` | `-w` | `false` | Launch 6-tab interactive TUI dashboard |
| `--top` | `-t` | `10` | Max top entries in tables (0 disables) |
| `--from` | | `""` | Time filter start (RFC3339 or relative: `5m`, `1h`, `2d`) |
| `--to` | | `""` | Time filter end (RFC3339) |
| `--interval` | `-i` | `""` | Periodic aggregation |
| `--follow` | `-F` | `false` | Stream and report every 5 seconds |
| `--slow` | | `""` | Filter requests slower than duration |
| `--ip` | | `""` | Filter by client IP or CIDR subnet |
| `--exclude-ip` | | `""` | Exclude IP or CIDR subnet |
| `--status` | `-s` | `""` | Filter by status code(s) |
| `--method` | `-m` | `""` | Filter by HTTP method |
| `--path` | `-p` | `""` | Filter by path glob |
| `--2xx` | | `false` | Filter 2xx responses |
| `--3xx` | | `false` | Filter 3xx responses |
| `--4xx` | | `false` | Filter 4xx responses |
| `--5xx` | | `false` | Filter 5xx responses |
| `--errors-only` | `-e` | `false` | Filter errors only |
| `--no-bots` | | `false` | Exclude bot/crawler traffic |
| `--bots-only` | | `false` | Include only bot traffic |
| `--grep` | | `""` | Regex search across URI, User-Agent, IP, Host (invalid pattern falls back to substring) |
| `--compact` | `-c` | `false` | Compact output mode |
| `--defang` | | `false` | Defang IPs and URLs in output (`.` → `[.]`, `http://` → `hxxp://`) for safe sharing |
| `--trust-forwarded` | | `false` | Trust `X-Forwarded-For` / `X-Real-IP` for client IP (use behind a reverse proxy/CDN) |
| `--max-cardinality` | | `100000` | Max distinct keys tracked per counter (paths, IPs, UAs). `0` = unlimited |
| `--ua-rotation` | | `10` | Distinct User-Agents from one IP before scanner/rotation heuristic fires |
| `--host` | | `""` | Filter by request host (substring match, case-insensitive) |
| `--max-latency` | | `""` | Filter requests faster than duration (counterpart to `--slow`) |
| `--min-size` | | `""` | Filter responses at least this size (bytes, or `k`/`mb`/`gb` suffix) |
| `--max-size` | | `""` | Filter responses at most this size (bytes, or `k`/`mb`/`gb` suffix) |
| `--namespace` | `-n` | `""` | Kubernetes pod namespace |
| `--audit-log` | | `/var/log/caddy-analyzer-audit.jsonl` | JSON-lines audit log of block/unblock/anomaly actions (guard/block/unban). Empty to disable |
| `--state-file` | | `/var/lib/caddy-analyzer/blocked.json` | Persist blocked-IP state across restarts (guard/block/unban). Empty to disable |
| `--never-block` | | `""` | Comma-separated IPs/CIDRs that should never be blocked (guard) |
| `--never-block-file` | | `""` | File with IPs/CIDRs (one per line, `#` comments) to never block (guard) |
| `--detect-confidence` | | `8` | Min confidence (1-10) for pattern-detection blocking (guard). `0` disables |
| `--subnet-limit` | | `0` | Block a /24 when its combined requests exceed this (guard). `0` disables; distributed-scan defense |
| `--rps-anomaly` | | `0` | Alert when current RPS exceeds this factor over the EWMA baseline (guard). `0` disables; e.g. `5` = 5× spike |
| `--cred-stuffing-limit` | | `0` | Alert when N distinct IPs fail auth on the same path (guard). `0` disables |
| `--enrich` | | `false` | Enable threat-intel enrichment via AbuseIPDB (guard). Set `ABUSEIPDB_KEY` env var |
| `--enrich-threshold` | | `70` | Min AbuseIPDB score to pre-block IP with auth failures (guard). `0` disables enrichment blocking |
| `--version` | `-v` | `false` | Print version and exit |
</details>

---

## Performance

Benchmarks run on a single core with synthetic Caddy v2 JSON logs (10% attack traffic, 8 source IPs, mixed paths):

| Log size | `--detect` | Parse only | RAM |
|----------|-----------|------------|-----|
| 1.5K lines (real) | 0.6s | <0.1s | 21 MB |
| 10K lines | 1.5s | 0.2s | 25 MB |
| 100K lines | 14.3s | 1.4s | 53 MB |
| 1M lines | 2m29s | ~14s | 138 MB |

Throughput: ~7,000 lines/sec with `--detect`, ~70,000 lines/sec parse-only. Memory scales linearly (~1.3 KB/line with detection, ~0.16 KB/line parse-only).

The detection engine uses three optimizations to achieve this throughput:

1. **Case-fold elimination** — Regex patterns are compiled with lowercased literals (including `OpCharClass` ranges) and matched against lowercased source, eliminating `unicode.SimpleFold` overhead (~8% CPU).
2. **Per-source marker triage** — Before running regexes, a fast `strings.Contains` check verifies whether any attack marker (literal extracted from the regex) is present in the source. Markers are split by source type (URI, User-Agent, Authorization) to avoid cross-source false positives. For benign traffic (~90%), this skips nearly all regex evaluations.
3. **Literal fast path** — Patterns that are pure literal alternations (e.g. WordPress probes, scanner UAs) use `strings.Contains` directly instead of the regex engine (~100x faster per pattern).

Memory is bounded by LRU IP eviction (100K cap, configurable via `Detector.SetIPCap`) and per-IP path caps (1K paths). The enrich cache is bounded to 10K entries with TTL eviction.

## Development

```bash
git clone https://github.com/lenny-ts/caddy-analyzer.git
cd caddy-analyzer
go build ./cmd/caddy-analyze
go test ./...
```

PRs and issues are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).


## License

MIT License — see [LICENSE](LICENSE) for details.
