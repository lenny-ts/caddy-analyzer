# caddy-analyzer — agent notes

## Commit style

- Single line, imperative mood, ~35-62 chars
- No body, no trailers, no `type:` prefix, no version prefix
- Examples: `Add GeoIP tab to --watch dashboard`, `Fix GeoIP download URLs and show country names instead of codes`

## Release workflow

- `.github/workflows/release.yml` triggers on `v*` tag push → GoReleaser + SBOM (syft) + cosign
- User handles merge to `main` + tag + push themselves
- `.goreleaser.yaml`: CGO_ENABLED=0, linux/darwin/windows × amd64/arm64/arm, ldflags inject `cmd.Version={{.Version}}`

## Build / test / lint

```
go vet ./...
go test ./...
go build ./...
```

## Docs

- `tools/minify.sh` rebuilds `docs/styles.min.css`, `docs/docs.min.js`, `docs/search-index.json` and stamps `doc:modified` meta tags from git
- Run after editing any `docs/*.html`, `docs/styles.css`, or `docs/docs.js`
