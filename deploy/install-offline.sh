#!/usr/bin/env bash
set -euo pipefail

ARCH="${1:-arm64}"
case "$ARCH" in
  arm64)
    BIN="dist/ta_node-linux-arm64"
    ;;
  armv7|arm)
    BIN="dist/ta_node-linux-armv7"
    ;;
  *)
    echo "unsupported arch: $ARCH"
    echo "usage: $0 [arm64|armv7]"
    exit 1
    ;;
esac

if [ ! -f "$BIN" ]; then
  echo "binary not found: $BIN"
  exit 1
fi

sudo mkdir -p /opt/ta_node
sudo mkdir -p /opt/ta_node/data/evidence

# Stop a previously installed service first, otherwise its running binary is
# held "Text file busy" (ETXTBSY) and cannot be replaced on upgrade/re-install.
# Harmless on a first install (the unit does not exist yet).
sudo systemctl stop ta_node 2>/dev/null || true

# Replace the binary atomically: copy to a temp path, then rename over the
# target. rename() only swaps the directory entry and never writes into the
# inode the old process may still hold, so this never triggers ETXTBSY.
sudo cp "$BIN" /opt/ta_node/ta_node.new
sudo chmod +x /opt/ta_node/ta_node.new
sudo mv -f /opt/ta_node/ta_node.new /opt/ta_node/ta_node

sudo cp -r configs /opt/ta_node/
sudo cp -r patterns /opt/ta_node/
sudo cp deploy/systemd/ta_node.service /etc/systemd/system/ta_node.service
sudo systemctl daemon-reload
sudo systemctl enable ta_node
sudo systemctl restart ta_node
sudo systemctl status ta_node --no-pager
