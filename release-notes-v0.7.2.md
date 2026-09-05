# caddy-analyzer v0.7.2

Patch release focused on log readability across terminal themes and a reliable self-update verification.

## Install

```bash
curl -sSfL https://raw.githubusercontent.com/lenny-ts/caddy-analyzer/main/install.sh | bash
go install github.com/lenny-ts/caddy-analyzer/cmd/caddy-analyze@v0.7.2
docker run --rm -v /var/log/caddy:/logs ghcr.io/lenny-ts/caddy-analyzer:v0.7.2 /logs/access.log
```

## Upgrade

```bash
caddy-analyze update --check
caddy-analyze update --version v0.7.2
```

## Fixed

- **Log path readability on light terminals (#100)**: request paths in `tail` and the `--watch` live log stream no longer force bright white, which was unreadable on white backgrounds. Paths now use the terminal default foreground in bold.
- **Self-update cosign verification**: `caddy-analyze update` failed with `--trusted-root only supported with --new-bundle-format` because releases published old-format bundles. Releases now publish new-format Sigstore bundles, and the updater falls back to the legacy certificate/signature sidecars whenever a bundle is not in the new format.
