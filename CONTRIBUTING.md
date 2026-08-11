# Contributing to caddy-analyzer

Thank you for your interest in contributing to `caddy-analyzer`! We welcome contributions from everyone.

## Development Setup

1. Prerequisites: [Go](https://go.dev) (v1.25+).
2. Clone the repository:
   ```bash
   git clone https://github.com/L9Lenny/caddy-analyzer.git
   cd caddy-analyzer
   ```
3. Run tests:
   ```bash
   go test -race ./...
   ```
4. Build binary:
   ```bash
   go build -o caddy-analyze ./cmd/caddy-analyze
   ```

## Code Quality

Before submitting a PR, ensure all checks pass:

```bash
# Format
gofmt -w .

# Vet
go vet ./...

# Lint (golangci-lint must be installed)
golangci-lint run

# Tests with race detector
go test -race -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | tail -1

# Vulnerability scan
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

CI enforces a **60%** total coverage threshold.

## Pull Request Guidelines

- Ensure all existing tests pass (`go test -race ./...`).
- Add unit test cases for any new features or security signatures.
- Keep commits clean and descriptive.
- New detection patterns must include a confidence score (1-10) and pass `TestPatternUniqueness` (no duplicates).
- New blocklist sources must be added to `DefaultSources` in `pkg/blocklist/blocklist.go` with a test entry in `pkg/blocklist/blocklist_test.go`.
- New GeoIP or enrichment sources must implement the `Enricher` interface in `pkg/enrich/enrich.go`.
- Guard rule changes must include a test in `pkg/guard/guard_test.go` or `pkg/guard/blocklist_test.go`.

## Blocklist Source Format

Blocklist config files support two JSON shapes:

**Source array** (simple):
```json
[{"name": "my-feed", "url": "https://example.com/list.txt"}]
```

**Full object** (with defaults control):
```json
{
  "no_defaults": false,
  "custom_sources": [{"name": "my-feed", "url": "https://example.com/list.txt"}],
  "remove_sources": ["tor-exit-nodes"]
}
```

Use `caddy-analyze blocklist init` to write current CLI settings to the config file.
