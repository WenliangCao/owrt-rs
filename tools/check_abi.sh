#!/bin/sh
# Compile tools/testsrc/abi_assert.c for the device's target with the SDK's
# cross compiler. Every assertion is a _Static_assert about a struct layout or
# constant that a hand-written #[repr(C)] declaration in this repo assumes.
# It either compiles or it does not; nothing is executed.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
SDK=${SDK:-$(ls -d /tmp/rustcp-sdk/extracted/openwrt-sdk-*/staging_dir \
	~/sdk/openwrt-sdk-*/staging_dir \
	~/release/*/openwrt-sdk-*/staging_dir 2>/dev/null | head -1)}
[ -n "${SDK:-}" ] || { echo "check-abi: no OpenWrt SDK staging_dir found; NOT RUN" >&2; exit 2; }
CC=$(ls "$SDK"/toolchain-*/bin/aarch64-openwrt-linux-musl-gcc 2>/dev/null | head -1)
[ -n "$CC" ] || { echo "check-abi: no target gcc under $SDK; NOT RUN" >&2; exit 2; }
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
if env -u LD_PRELOAD STAGING_DIR="$SDK" "$CC" -c "$here/testsrc/abi_assert.c" -o "$out/abi.o" 2>"$out/err"; then
	echo "check-abi: all FFI struct layouts match the target ABI"
else
	grep -v 'runas.so\|STAGING_DIR' "$out/err" >&2 || true
	echo "check-abi: FAILED -- a #[repr(C)] declaration does not match the target" >&2
	exit 1
fi
