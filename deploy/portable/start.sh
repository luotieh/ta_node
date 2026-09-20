#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec ./bin/ta_node --config ./configs/ta_node.yaml "$@"
