#!/bin/sh
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/accuknox/gh-audit/main/install.sh | sh
#
# Environment variables:
#   INSTALL_DIR  — directory to install into (default: /usr/local/bin, or ~/.local/bin if not writable)
#   VERSION      — specific version to install (default: latest)

set -e

REPO="accuknox/gh-audit"
BINARY_NAME="pipeaudit"

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$OS" in
        linux)  OS="linux" ;;
        darwin) OS="darwin" ;;
        mingw*|msys*|cygwin*) OS="windows" ;;
        *) echo "ERROR: Unsupported OS: $OS" >&2; exit 1 ;;
    esac

    case "$ARCH" in
        x86_64|amd64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) echo "ERROR: Unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac

    # No linux-arm64 or windows-arm64 builds yet
    if [ "$OS" = "linux" ] && [ "$ARCH" = "arm64" ]; then
        echo "ERROR: No pre-built binary for linux-arm64. Install from source: pip install pipeaudit" >&2
        exit 1
    fi
    if [ "$OS" = "windows" ] && [ "$ARCH" = "arm64" ]; then
        echo "ERROR: No pre-built binary for windows-arm64. Install from source: pip install pipeaudit" >&2
        exit 1
    fi

    PLATFORM="${OS}-${ARCH}"
}

# Resolve the version tag (latest or user-specified)
resolve_version() {
    if [ -n "$VERSION" ]; then
        TAG="$VERSION"
        # Prepend 'v' if missing
        case "$TAG" in v*) ;; *) TAG="v$TAG" ;; esac
    else
        TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | cut -d '"' -f 4)
        if [ -z "$TAG" ]; then
            echo "ERROR: Could not determine latest release." >&2
            exit 1
        fi
    fi
}

# Pick install directory
resolve_install_dir() {
    if [ -n "$INSTALL_DIR" ]; then
        DIR="$INSTALL_DIR"
    elif [ -w /usr/local/bin ]; then
        DIR="/usr/local/bin"
    else
        DIR="$HOME/.local/bin"
        mkdir -p "$DIR"
    fi
}

main() {
    detect_platform
    resolve_version
    resolve_install_dir

    SUFFIX=""
    if [ "$OS" = "windows" ]; then
        SUFFIX=".exe"
    fi

    ASSET_NAME="${BINARY_NAME}-${PLATFORM}${SUFFIX}"
    URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET_NAME}"

    echo "Downloading ${BINARY_NAME} ${TAG} for ${PLATFORM}..."
    TMPFILE="$(mktemp)"
    trap 'rm -f "$TMPFILE"' EXIT

    HTTP_CODE=$(curl -fsSL -w "%{http_code}" -o "$TMPFILE" "$URL" 2>/dev/null) || true
    if [ "$HTTP_CODE" != "200" ] || [ ! -s "$TMPFILE" ]; then
        echo "ERROR: Failed to download ${URL}" >&2
        echo "  HTTP status: ${HTTP_CODE}" >&2
        echo "  Check that release ${TAG} exists and has a binary for ${PLATFORM}." >&2
        exit 1
    fi

    DEST="${DIR}/${BINARY_NAME}${SUFFIX}"
    mv "$TMPFILE" "$DEST"
    chmod +x "$DEST"

    echo "Installed ${BINARY_NAME} ${TAG} to ${DEST}"

    # Warn if not on PATH
    case ":$PATH:" in
        *":${DIR}:"*) ;;
        *)
            echo ""
            echo "WARNING: ${DIR} is not in your PATH."
            echo "  Add it with:  export PATH=\"${DIR}:\$PATH\""
            ;;
    esac
}

main
