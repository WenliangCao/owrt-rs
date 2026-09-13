#!/bin/sh
# netifd_suite adapter; the exact candidate path need not be named netifd-rs.
set -eu
rootfs=$1; candidate=$2; output=$3
here=$(cd "$(dirname "$0")" && pwd)
bundle=$(mktemp -d /tmp/r90-netifd-bins-XXXXXX)
trap 'rm -rf "$bundle"' EXIT
ln -s "$(realpath "$candidate")" "$bundle/netifd-rs"
# The suite creates each case directory up front; the probe requires a fresh
# child directory so no previous run can satisfy its completeness checks.
python3 "$here/r90_lifecycle_probe.py" "$rootfs" "$bundle" "$output/probe" --component netifd
