# Contributing to caddy-analyzer

Thank you for your interest in contributing to `caddy-analyzer`! We welcome contributions from everyone.

## Development Setup

1. Prerequisites: [Go](https://go.dev) (v1.25+).
2. Clone the repository:
   ```bash
   git clone https://github.com/lenny-ts/caddy-analyzer.git
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

## Pull Request Guidelines

- Ensure all existing tests pass (`go test -race ./...`).
- Add unit tests for any new features or security signatures.
- Keep commits clean and descriptive.
- New detection patterns must include a confidence score (1-10) and pass `TestPatternUniqueness` (no duplicates).
