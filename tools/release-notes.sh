#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

tag=${1:-}
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "Usage: bash tools/release-notes.sh vMAJOR.MINOR.PATCH" >&2
    exit 1
fi

if ! section=$(awk -v heading="[${tag#v}]" '
    /^## / {
        if (found) exit
        found = ($2 == heading)
        if (found) print
        next
    }
    found { print; if (NF) body = 1 }
    END { if (!body) exit 1 }
' CHANGELOG.md); then
    echo "Missing or empty $tag section in CHANGELOG.md" >&2
    exit 1
fi

cat <<EOF
# caddy-analyzer $tag

Analyze Caddy v2 logs with security detection, operational metrics, and firewall protection.

## Install

\`\`\`bash
curl -sSfL https://raw.githubusercontent.com/lenny-ts/caddy-analyzer/main/install.sh | bash
go install github.com/lenny-ts/caddy-analyzer/cmd/caddy-analyze@$tag
docker run --rm -v /var/log/caddy:/logs ghcr.io/lenny-ts/caddy-analyzer:$tag /logs/access.log
\`\`\`

## Upgrade

\`caddy-analyze update\` verifies the Cosign signature and SHA256 checksum before replacing the binary atomically.

\`\`\`bash
caddy-analyze update --check
caddy-analyze update --version $tag
\`\`\`

$section
EOF

# Optional acknowledgments, as used in v0.9.0.
if [[ -f "release-notes-$tag.md" ]]; then
    awk '
        /^## Contributors$/ { active = 1; printf "\n"; print; next }
        active && /^## / { exit }
        active { print }
    ' "release-notes-$tag.md"
fi
