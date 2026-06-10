#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p dist
CGO_ENABLED=0 \
GOOS=linux \
GOARCH=arm \
GOARM=7 \
go build -mod=vendor -trimpath -ldflags="-s -w" \
  -o dist/ta_node-linux-armv7 \
  ./cmd/ta_node

file dist/ta_node-linux-armv7 || true
