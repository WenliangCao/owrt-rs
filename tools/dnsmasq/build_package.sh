#!/bin/sh
# Build the dnsmasq replacement candidate; never assemble or deploy an image.
# Usage: build_package.sh SDK_DIR NEW_PRIVATE_OUTPUT_DIR --budget BUDGET_JSON
set -eu
repo=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
exec python3 "$repo/tools/dnsmasq/build_package.py" "$@"
