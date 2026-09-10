#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/5] gofmt"
gofmt -w .
echo "[2/5] go test"
CGO_ENABLED=0 go test ./...
echo "[3/5] build arm64"
./scripts/build-arm64-offline.sh
echo "[4/5] build armv7"
./scripts/build-armv7-offline.sh
echo "[5/5] check binaries"
ls -lh dist/
file dist/ta_node-linux-arm64 || true
file dist/ta_node-linux-armv7 || true
echo "offline verification passed"
