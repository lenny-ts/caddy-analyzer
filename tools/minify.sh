#!/usr/bin/env bash
# Minify docs CSS/JS using esbuild — run after editing source files
# Output: docs/styles.min.css, docs/docs.min.js
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v npx &>/dev/null; then
    echo "Error: npx not found. Install Node.js first." >&2
    exit 1
fi

echo "Minifying CSS..."
npx --yes esbuild docs/styles.css --minify --outfile=docs/styles.min.css

echo "Minifying JS..."
npx --yes esbuild docs/docs.js --minify --outfile=docs/docs.min.js

echo "Building search index..."
node tools/build-search-index.js

echo "Stamping real last-updated dates from git..."
for f in docs/*.html; do
    date=$(git log -1 --format=%cI -- "$f" 2>/dev/null || true)
    if [ -n "$date" ]; then
        sed -i -E "s|(<meta name=\"doc:modified\" content=\")[^\"]*(\")|\1$date\2|" "$f"
    fi
done

echo "Done."
echo "  styles.css  $(wc -c < docs/styles.css) -> $(wc -c < docs/styles.min.css) bytes"
echo "  docs.js     $(wc -c < docs/docs.js) -> $(wc -c < docs/docs.min.js) bytes"
