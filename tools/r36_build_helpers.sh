#!/bin/sh
# Build the two test-only helpers r36 copies into the sandbox rootfs, using the
# OpenWrt SDK's target toolchain. Output: $OUT/asuser and $OUT/busprobe.
set -eu
OUT=${1:-/tmp/r36-helpers}
mkdir -p "$OUT"
here=$(cd "$(dirname "$0")" && pwd)
SDK=$(ls -d /tmp/rustcp-sdk/extracted/openwrt-sdk-*/staging_dir ~/sdk/openwrt-sdk-*/staging_dir 2>/dev/null | head -1)
[ -n "$SDK" ] || { echo "no OpenWrt SDK staging_dir found" >&2; exit 1; }
CC=$(ls "$SDK"/toolchain-*/bin/aarch64-openwrt-linux-musl-gcc | head -1)
for t in asuser busprobe; do
	env -u LD_PRELOAD STAGING_DIR="$SDK" "$CC" -static -O2 -o "$OUT/$t" "$here/testsrc/$t.c"
	echo "built $OUT/$t"
done
