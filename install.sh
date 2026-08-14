#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
    echo "Error: this script requires bash. Run with: curl -sSfL <url> | bash" >&2
    exit 1
fi
set -euo pipefail

# caddy-analyze static binary installer
# Supports: Linux (amd64, arm64, armv7, 386), macOS (amd64, arm64)

REPO="lenny-ts/caddy-analyzer"
BINARY_NAME="caddy-analyze"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64|amd64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    armv7*)
        ARCH="arm"
        ;;
    i386|i686)
        ARCH="386"
        ;;
    *)
        echo "Error: Unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

case "$OS" in
    linux)
        OS="linux"
        ;;
    darwin)
        OS="darwin"
        ;;
    *)
        echo "Error: Unsupported operating system: $OS" >&2
        exit 1
        ;;
esac

TAG=$(curl -sSfL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

ARCHIVE_NAME="caddy-analyzer_${TAG#v}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/$TAG/$ARCHIVE_NAME"
if ! curl -sSf -I "$URL" >/dev/null 2>&1; then
    ARCHIVE_NAME="caddy-analyze_${TAG#v}_${OS}_${ARCH}.tar.gz"
    URL="https://github.com/$REPO/releases/download/$TAG/$ARCHIVE_NAME"
fi

echo "[*] Installing $BINARY_NAME $TAG for $OS/$ARCH..."

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

echo "[*] Downloading $ARCHIVE_NAME..."
curl -sSfL "$URL" -o "$TMP_DIR/$ARCHIVE_NAME"

echo "[*] Downloading checksums..."
CHECKSUMS_URL="https://github.com/$REPO/releases/download/$TAG/checksums.txt"
curl -sSfL "$CHECKSUMS_URL" -o "$TMP_DIR/checksums.txt"

echo "[*] Verifying checksum..."
(
    cd "$TMP_DIR"
    grep "$ARCHIVE_NAME$" checksums.txt | sha256sum -c
) || {
    echo "ERROR: checksum verification failed for $ARCHIVE_NAME" >&2
    exit 1
}

# Verify the cosign signature on checksums.txt if cosign is available, so a
# compromise of GitHub releases cannot replace both archive and checksums
# without also compromising the signer identity.
if command -v cosign >/dev/null 2>&1; then
    SIG_URL="https://github.com/$REPO/releases/download/$TAG/checksums.txt.sig"
    CERT_URL="https://github.com/$REPO/releases/download/$TAG/checksums.txt.pem"
    if curl -sSfL "$SIG_URL" -o "$TMP_DIR/checksums.txt.sig" 2>/dev/null && \
       curl -sSfL "$CERT_URL" -o "$TMP_DIR/checksums.txt.pem" 2>/dev/null; then
        echo "[*] Verifying cosign signature on checksums.txt..."
        if cosign verify-blob \
            --certificate "$TMP_DIR/checksums.txt.pem" \
            --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            --signature "$TMP_DIR/checksums.txt.sig" \
            "$TMP_DIR/checksums.txt" 2>/dev/null; then
            echo "[+] Cosign signature verified."
        else
            echo "[!] WARNING: cosign signature verification failed (SHA256 still verified)." >&2
        fi
    fi
else
    echo "[*] cosign not found; skipping signature verification (SHA256 still verified)." >&2
fi

tar -xzf "$TMP_DIR/$ARCHIVE_NAME" -C "$TMP_DIR"
BIN_PATH="$TMP_DIR/$BINARY_NAME"

chmod +x "$BIN_PATH"

DEST_DIR="/usr/local/bin"
if [ ! -w "$DEST_DIR" ]; then
    echo "[*] Installing to $DEST_DIR (requires sudo)..."
    sudo mv "$BIN_PATH" "$DEST_DIR/$BINARY_NAME"
else
    mv "$BIN_PATH" "$DEST_DIR/$BINARY_NAME"
fi

echo "[+] Success! $BINARY_NAME $TAG installed to $DEST_DIR/$BINARY_NAME"
echo "Run '$BINARY_NAME --help' to get started."
