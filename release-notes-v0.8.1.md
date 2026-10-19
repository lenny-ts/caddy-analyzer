# caddy-analyzer v0.8.1

Fix the missing Docker image reported in #120 by publishing release images to GitHub Container Registry.

## Install

```bash
curl -sSfL https://raw.githubusercontent.com/lenny-ts/caddy-analyzer/main/install.sh | bash
go install github.com/lenny-ts/caddy-analyzer/cmd/caddy-analyze@v0.8.1
docker run --rm -v /var/log/caddy:/logs:ro ghcr.io/lenny-ts/caddy-analyzer:v0.8.1 /logs/access.log
```

## Upgrade

```bash
caddy-analyze update --check
caddy-analyze update --version v0.8.1
docker pull ghcr.io/lenny-ts/caddy-analyzer:v0.8.1
```

## Fixed

- Publish Docker images for Linux amd64 and arm64 after successful releases, using the existing non-root Alpine image.
- Publish both `v0.8.1` and `0.8.1` tags, keeping the Helm chart's default image tag compatible. Only stable releases update `latest`.
- Verify the published image reports the release version with `--version`.

## Changed

- Cross-compile Go on the build platform instead of compiling under ARM64 emulation; cache image layers between releases.
- Update English and Italian installation instructions, release references and the Helm chart (0.1.1, app version 0.8.1).

## First publication checklist (maintainer)

1. Push tag `v0.8.1` after merging the release changes and wait for the Release workflow, including **Publish Docker image**, to succeed.
2. Open the `caddy-analyzer` container package settings on GitHub and ensure visibility is **Public**. New packages default to private; repository linking does not make them public automatically.
3. From a Docker client without GHCR credentials, verify both tags before closing #120:

   ```bash
   docker run --rm ghcr.io/lenny-ts/caddy-analyzer:v0.8.1 --version
   docker run --rm ghcr.io/lenny-ts/caddy-analyzer:latest --version
   # expected for both: caddy-analyze version 0.8.1
   ```
