# caddy-analyzer v0.7.3

Patch release adding live request-domain visibility and refreshing the GitHub Actions toolchain.

## Install

```bash
curl -sSfL https://raw.githubusercontent.com/lenny-ts/caddy-analyzer/main/install.sh | bash
go install github.com/lenny-ts/caddy-analyzer/cmd/caddy-analyze@v0.7.3
docker run --rm -v /var/log/caddy:/logs ghcr.io/lenny-ts/caddy-analyzer:v0.7.3 /logs/access.log
```

## Upgrade

```bash
caddy-analyze update --check
caddy-analyze update --version v0.7.3
```

## Added

- **Top domains in `--watch` (#104)**: a dedicated ninth tab ranks the top 20 request hosts. Press `6` to open it; User Agents, Geo, and Operational now use keys `7`, `8`, and `9`.

## Changed

- **GitHub Actions dependencies (#103)**: refreshed checkout, lint, Pages, SBOM, GoReleaser, Cosign, and release publishing actions while retaining full-SHA pins.

## Fixed

- **Govulncheck CI toolchain (#104)**: the vulnerability scan can automatically use the Go version required by the latest `govulncheck` without changing the project's Go 1.25 baseline.
