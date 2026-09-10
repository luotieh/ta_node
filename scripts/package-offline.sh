#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="${VERSION:-$(date +%Y%m%d%H%M%S)}"
PKG_DIR="release/ta_node-offline-${VERSION}"

rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"
cp -r dist "$PKG_DIR/"
cp -r configs "$PKG_DIR/"
cp -r patterns "$PKG_DIR/"
cp -r deploy "$PKG_DIR/"
cp -r scripts "$PKG_DIR/"
cp README.md "$PKG_DIR/" || true
mkdir -p "$PKG_DIR/data/evidence"

tar -czf "release/ta_node-offline-${VERSION}.tar.gz" -C release "ta_node-offline-${VERSION}"
echo "created release/ta_node-offline-${VERSION}.tar.gz"
