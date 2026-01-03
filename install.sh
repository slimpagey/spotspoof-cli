#!/bin/bash
set -e

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    ARCH="arm64"
fi

BINARY="spotspoof-${OS}-${ARCH}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

echo "Downloading $BINARY..."
curl -LO "https://github.com/username/repo/releases/latest/download/${BINARY}"

chmod +x "$BINARY"
mkdir -p "$INSTALL_DIR"
mv "$BINARY" "$INSTALL_DIR/spotspoof"

echo "Installed to $INSTALL_DIR/spotspoof"
echo "Make sure $INSTALL_DIR is in your PATH"