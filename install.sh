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
# The checksum is PINNED in this script, not fetched alongside the binary.
# A checksum published next to the file it checks proves only that the two
# arrived together; a checksum that lives here proves the binary is the
# one this script was written for. Someone who can change the release can
# change this script too - so if that matters to you, read the script
# before you run it, which is the whole reason it is a script.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/northloop-systems/ai-gateway-proxy/main/install.sh | sudo bash
#
#   - or, to install a binary you have already downloaded and checked:
#   sudo ./install.sh --local ./ai-gateway-proxy
set -euo pipefail

VERSION="1.0.0"
REPO="northloop-systems/ai-gateway-proxy"
BINARY_NAME="ai-gateway-proxy"
INSTALL_PATH="/usr/local/bin/ai-gateway-proxy"

# Where the binary is fetched from, in the order it is tried. The first
# one is the hub's own domain, so a friend is not pulled through GitHub to
# lend a machine; the release is the mirror, for when the domain is having
# a bad day.
MIRRORS=(
    "https://ai.shuffled-family.com/proxy-node"
    "https://github.com/${REPO}/releases/download/v${VERSION}"
)

# The SHA-256 of the binary this version of the script installs. A mismatch
# stops the install: a binary that is not the one this script was written
# for is a binary nobody has read.
SHA256="35ea014d001a9fef6fa9cf610220b112ef09c47007d2f64e1447206da766c610"

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
    DOWNLOADED=""
    for mirror in "${MIRRORS[@]}"; do
        log "Downloading ${BINARY_NAME} ${VERSION} (${ASSET}) from ${mirror}..."
        if curl -fsSL -o "$BINARY_PATH" "${mirror}/${ASSET}"; then
            DOWNLOADED="$mirror"
            break
        fi
        rm -f "$BINARY_PATH"
    done
    if [ -z "$DOWNLOADED" ]; then
        err "Could not download ${ASSET} from any of them:"
        for mirror in "${MIRRORS[@]}"; do err "  ${mirror}"; done
        err "  You can also install a binary you have already: "
        err "    sudo ./install.sh --local ./ai-gateway-proxy"
        exit 1
    fi
    log "Downloaded from ${DOWNLOADED}"
fi

# --- Check it ---------------------------------------------------------------
# The binary is what runs as root, so this is the one moment where it
# matters that the file is the one we expect.
if [ "$SHA256" = "__SHA256__" ]; then
    err "This script has no pinned checksum for the binary."
    err "  That is a bug in the installer, not something to work around."
    exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    err "sha256sum is needed to check the binary. Install coreutils and run this again."
    exit 1
fi
ACTUAL=$(sha256sum "$BINARY_PATH" | cut -d' ' -f1)
if [ "$ACTUAL" != "$SHA256" ]; then
    err "The binary's checksum does not match."
    err "  expected: $SHA256"
    err "  got:      $ACTUAL"
    err "  This binary is not the one this script was written for, so it is not"
    err "  being run. If you trust it anyway, install it by hand:"
    err "    sudo install -m 0755 $BINARY_PATH $INSTALL_PATH"
    exit 1
fi
log "Checksum verified: $ACTUAL"

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
