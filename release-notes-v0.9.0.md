# caddy-analyzer v0.9.0

Release range: [`v0.8.1...v0.9.0`](https://github.com/lenny-ts/caddy-analyzer/compare/v0.8.1...v0.9.0).
Prepared from `develop`, including merged PRs #123, #126, #129, #130, #132 and #133,
plus the integrated progressive-ban and CI fixes.

## Highlights

- Read-only `doctor` diagnostics, with JSON output and critical-failure exit codes.
- Opt-in progressive bans and persistent repeat-offender history.
- Opt-in behavioral brute-force, suspected credential-stuffing and aggregate password-spray detection.
- Whitelist reload every 30 seconds, atomic replacement and cross-process writer locking.
- One-second guard evaluations, independent window deadlines and evidence consumption after successful bans.
- Nine default feeds, including [NetAPI honeypot attackers](https://netapi.com/compromised-ips/) under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

See [CHANGELOG.md](CHANGELOG.md) for the complete change list.

## Contributors

Thanks to everyone who contributed to this release:

- @noahkhomer18 — implemented live whitelist reload and atomic replacement, protection against overlapping subnet bans (#130), the read-only `doctor` command and diagnostic follow-up fixes (#132), and prompt guard threshold evaluation with independent window deadlines and evidence consumption (#126).
- @slavaolesik — added the NetAPI honeypot attackers feed to the default blocklists (#133).
- @lenny-ts — implemented progressive bans and persistent offender history, preserved effective ban durations in audits, added behavioral authentication-abuse detection (#129), and contributed integration fixes, review-driven hardening, CI fixes and release documentation (#134).
- @dependabot[bot] — updated pinned GitHub Actions used for release builds, signing and Docker publishing (#123).

## Install or upgrade after publication

```bash
caddy-analyze update --check
caddy-analyze update --version v0.9.0
go install github.com/lenny-ts/caddy-analyzer/cmd/caddy-analyze@v0.9.0
docker pull ghcr.io/lenny-ts/caddy-analyzer:v0.9.0
docker run --rm ghcr.io/lenny-ts/caddy-analyzer:v0.9.0 --version
# expected: caddy-analyze version 0.9.0
```

Archives cover Linux, macOS and Windows on the supported GoReleaser architectures;
Docker images cover Linux amd64 and arm64. Stable image tags are `v0.9.0`,
`0.9.0` and `latest`. Helm chart 0.1.2 defaults to app version 0.9.0.

## Upgrade notes

- Back up the guard state file and, when escalation is enabled, its adjacent
  `<state-file>.offenders/` directory. Existing active-ban state remains readable.
  Progressive bans and authentication-abuse detection are disabled unless opted in.
- Guard evaluates thresholds every second by default (`--eval-interval 1s`).
  Evaluation is capped at `--window`; counting-window resets are independent.
  Self-IP discovery and firewall calls can still add latency.
- Validate the whitelist before restarting guard: malformed/unreadable files now
  stop CLI startup. The absent default managed whitelist remains optional.
  Runtime reload failures retain the last good list. New exemptions also remove
  overlapping subnet bans, so an entire covering subnet rule may be lifted.
- Whitelist CLI writes use a persistent adjacent `.lock` file. Do not remove that
  file while writers are running. The OS releases its lock when the process exits.
- The NetAPI feed is enabled by default. To exclude it from guard, add
  `netapi-honeypot` to the active config's `blocklist.remove_sources`, preserving
  your other settings, or use `blocklist init --blocklist-remove netapi-honeypot`.
- `doctor` does not change firewall rules, refresh feeds or download GeoIP.
  It is not proof that a service is healthy: review warnings and run it as the
  same user and with the same paths used by the service.
- Restart a running guard after upgrading its binary. Whitelist edits then
  propagate within the 30-second refresh cycle without another restart.

## Maintainer publication checklist

Preparation checks (no publication):

```bash
DOCS_VERSION=v0.9.0 node tools/build-docs.js
bash tools/minify.sh
node tools/check-docs.js
go vet ./...
go test -race ./...
go build ./...
goreleaser check
goreleaser build --snapshot --skip=before --parallelism 2
```

Snapshot versions are derived from the last existing tag; the final `v0.9.0`
tag supplies the release version through GoReleaser ldflags.

1. Merge this preparation branch into `develop`, then merge the tested release
   into `main`; check CI before tagging. Adjust the changelog date if publishing later.
2. Create and push the annotated `v0.9.0` tag on the release commit in `main`.
   The tag triggers GoReleaser, SBOM generation, Cosign signing and GHCR publishing.
3. Confirm release archives, checksums, Sigstore bundle, signature/certificate
   sidecars, trusted root and SPDX SBOMs are attached.
4. Wait for **Publish Docker image** and verify both the versioned image and
   `latest` report `caddy-analyze version 0.9.0`. Ensure the GHCR package is public.
5. Verify the documentation site displays v0.9.0 and the new command references.

This preparation does not create a tag, publish artifacts or modify `main`.
