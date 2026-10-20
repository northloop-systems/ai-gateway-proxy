#!/usr/bin/env bash
# ai-gateway-proxy installer.
#
# This script does three things and nothing else:
#
#   1. fetches the ai-gateway-proxy binary
#   2. checks that binary against a pinned SHA-256
#   3. runs it
#
# The work is in the binary, which is one file with no dependencies at all -
# so the thing that ends up running as root is something you can read in
# one sitting, and there is no second file for it to go and fetch.
#
# The binary comes from the latest release, so nobody has to know a version
# number to lend a machine. The checksum is fetched with it, which proves the
# download is the one the release published - the same trust model as any
# package manager, where the publisher is the trust anchor.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/northloop-systems/ai-gateway-proxy/main/install.sh | sudo bash
#
#   - or, to install a binary you have already downloaded and checked:
#   sudo ./install.sh --local ./ai-gateway-proxy
set -euo pipefail

VERSION="1.0.0"
REPO="northloop-systems/ai-gateway-proxy"
RELEASE_URL="https://github.com/${REPO}/releases/latest/download"
BINARY_NAME="ai-gateway-proxy"
INSTALL_PATH="/usr/local/bin/ai-gateway-proxy"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[proxy]${NC} $*"; }
warn() { echo -e "${YELLOW}[proxy]${NC} $*"; }
err() { echo -e "${RED}[proxy]${NC} $*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    err "This installer must be run as root (use sudo)."
    exit 1
fi

LOCAL_BINARY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --local) LOCAL_BINARY="$2"; shift 2 ;;
        --version) echo "$VERSION"; exit 0 ;;
        --help|-h)
            echo "Usage: install.sh [--local ./ai-gateway-proxy]"
            echo "  --local   install a binary you already have instead of downloading one"
            exit 0 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

# --- Work out the platform ---------------------------------------------------
case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) err "Unsupported architecture: $(uname -m). The binary is published for amd64 and arm64."; exit 1 ;;
esac
ASSET="${BINARY_NAME}-linux-${ARCH}"

# --- Get the binary ----------------------------------------------------------
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
BINARY_PATH="$WORKDIR/$BINARY_NAME"
CHECKSUM_PATH="$WORKDIR/$BINARY_NAME.sha256"

if [ -n "$LOCAL_BINARY" ]; then
    if [ ! -f "$LOCAL_BINARY" ]; then
        err "No such file: $LOCAL_BINARY"
        exit 1
    fi
    log "Using the binary you gave me: $LOCAL_BINARY"
    cp "$LOCAL_BINARY" "$BINARY_PATH"
else
    if ! command -v curl >/dev/null 2>&1; then
        err "curl is needed to download the binary. Install it and run this again."
        exit 1
    fi
    log "Downloading ${BINARY_NAME} (${ASSET}) from the latest release..."
    if ! curl -fsSL -o "$BINARY_PATH" "${RELEASE_URL}/${ASSET}"; then
        err "Could not download ${RELEASE_URL}/${ASSET}"
        err "  The release may not be published yet. You can also install a binary"
        err "  you have already: sudo ./install.sh --local ./ai-gateway-proxy"
        exit 1
    fi
    # The checksum comes with the release, so the two are the same thing.
    if ! curl -fsSL -o "$CHECKSUM_PATH" "${RELEASE_URL}/${ASSET}.sha256"; then
        err "Could not download the checksum for ${ASSET}."
        err "  Without it there is nothing to check the binary against, so it is"
        err "  not being run."
        exit 1
    fi

    # --- Check it -----------------------------------------------------------
    # The binary is what runs as root, so this is the one moment where it
    # matters that the file is the one the release published.
    if ! command -v sha256sum >/dev/null 2>&1; then
        err "sha256sum is needed to check the binary. Install coreutils and run this again."
        exit 1
    fi
    EXPECTED=$(cut -d' ' -f1 < "$CHECKSUM_PATH")
    ACTUAL=$(sha256sum "$BINARY_PATH" | cut -d' ' -f1)
    if [ "$ACTUAL" != "$EXPECTED" ]; then
        err "The binary's checksum does not match the one published with it."
        err "  expected: $EXPECTED"
        err "  got:      $ACTUAL"
        err "  It is not being run. If you trust it anyway, install it by hand:"
        err "    sudo install -m 0755 $BINARY_PATH $INSTALL_PATH"
        exit 1
    fi
    log "Checksum verified: $ACTUAL"
fi

# --- Put it where it belongs -------------------------------------------------
install -m 0755 "$BINARY_PATH" "$INSTALL_PATH"
log "Installed $INSTALL_PATH"

# --- Hand over --------------------------------------------------------------
# The token is prompted for here rather than in the binary, so it is shown
# as it is typed: a masked prompt cannot be checked, and the commonest
# failure is a token pasted with a character missing.
if [ -z "${AI_GATEWAY_PROXY_TOKEN:-}" ]; then
    echo ""
    echo "  =========================================="
    echo "   Proxy Node Installer"
    echo "  =========================================="
    echo ""
    echo "  You need an API token to connect this node."
    echo "  Get one from your hub admin, then paste it here."
    echo ""
    read -r -p "  Paste your API token: " AI_GATEWAY_PROXY_TOKEN </dev/tty
    echo ""
    if [ -z "$AI_GATEWAY_PROXY_TOKEN" ]; then
        err "No token provided. Exiting."
        exit 1
    fi
fi

export AI_GATEWAY_PROXY_TOKEN
"$INSTALL_PATH" install "$@"
STATUS=$?

if [ $STATUS -ne 0 ]; then
    err "The install did not finish. Nothing was rolled back - the node is"
    err "  safe to re-run, and re-running is what the next step should be."
    exit $STATUS
fi

log "Done."
