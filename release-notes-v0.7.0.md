# caddy-analyzer v0.7.0

Analyze Caddy v2 logs with security detection, operational metrics, and firewall protection.

## Install

```bash
curl -sSfL https://raw.githubusercontent.com/lenny-ts/caddy-analyzer/main/install.sh | bash
go install github.com/lenny-ts/caddy-analyzer/cmd/caddy-analyze@latest
docker run --rm -v /var/log/caddy:/logs ghcr.io/lenny-ts/caddy-analyzer /logs/access.log
```

## Upgrade

For an existing installation, `caddy-analyze update` downloads the latest release, verifies its Cosign signature and SHA256 checksum, and replaces the binary atomically.

Use `--check` to preview the available version, or `--version v0.7.0` to install this exact release.

```bash
caddy-analyze update --check
caddy-analyze update
caddy-analyze update --version v0.7.0
```

## What Changed

### Added

- **Custom detection patterns (#76)**: load validated, repeatable JSON rule files with URI, header, User-Agent, and combined matching sources.
- **Remote audit delivery (#70, #77)**: forward guard, block, and unban events to syslog or generic, Slack, Discord, and PagerDuty webhooks with bounded retries and per-IP rate limiting.
- **Elasticsearch/OpenSearch and Loki exporters (#74)**: publish aggregated reports over authenticated HTTP with batching, retry, and bulk error handling.
- **Cosign bundle verification (#93)**: new releases use Sigstore bundles and trusted roots while older releases remain verifiable through legacy signature sidecars.
- **Guard dry-run (#78)**: exercise thresholds, detection, blocklists, and country rules without changing firewall rules or persistent state; emits `would_block` events and a summary.
- **Persistent baselines (#73)**: save versioned JSON snapshots and compare future runs with `--against`, configurable regression thresholds, structured output, and CI-friendly exit codes.
- **Bounded analysis caches (#69)**: replace unbounded grep/glob caches with concurrent LRU caches.
- **O(1) detector LRU updates (#68)**: replace linear IP recency updates with a map-backed linked list.
- **Single-pass progress analysis (#66)**: remove the full-file pre-scan that doubled I/O for large logs.
- **Container deployment examples (#72)**: add a hardened Docker Compose demo and an opt-in, non-root Helm chart.
- **Shared source fan-in (#65)**: centralize watch and guard stream coordination with consistent cancellation and error policies.
- **Contributors section (#82)**: add an automatically updated contributor list to the README.

### Security

- Remote notification failures never block firewall decisions, and webhook credentials are excluded from diagnostics.
