# caddy-analyzer v0.7.1

Patch release focused on a reliable progress display and complete command documentation.

## Install

```bash
curl -sSfL https://raw.githubusercontent.com/lenny-ts/caddy-analyzer/main/install.sh | bash
go install github.com/lenny-ts/caddy-analyzer/cmd/caddy-analyze@v0.7.1
docker run --rm -v /var/log/caddy:/logs ghcr.io/lenny-ts/caddy-analyzer:v0.7.1 /logs/access.log
```

## Upgrade

```bash
caddy-analyze update --check
caddy-analyze update --version v0.7.1
```

## Fixed

- **Progress bar for large analyses**: finite local files now show deterministic progress, including `--detect`; streaming sources keep the animated spinner.
- **Animated detection progress**: the spinner advances independently while expensive detection work is running instead of waiting for the next parsed entry.

## Documentation

- Added a complete command guide in English and Italian covering every command, subcommand, global flag, command-specific flag, safety requirement, output mode, and common workflow.
