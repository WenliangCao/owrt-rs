#!/bin/sh
# SDK COMPONENT_SOURCES NEW_OUTPUT_DIR
# Build the exact-image-compatible libubus client and matching link-only
# libraries. Link-only artifacts stay on the build host and are never copied
# to a router.
set -eu
[ "$#" -eq 3 ] || exit 2
sdk=$(cd "$1" && pwd)
src=$(cd "$2" && pwd)
out_arg=$3
[ ! -e "$out_arg" ] || { echo 'output directory already exists' >&2; exit 2; }
mkdir -p "$out_arg"
out=$(cd "$out_arg" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
"$(cd "$(dirname "$0")" && pwd)/build-register-libubus.sh" "$sdk" "$src" "$tmp/register"
mkdir -p "$out/link-only"
cp "$tmp/register/link-only/libubox.so.20260213" "$out/link-only/"
cp "$tmp/register/link-only/libubus.so.20251202" "$out/link-only/"
export STAGING_DIR="$sdk/staging_dir/target-aarch64_cortex-a53_musl"
cc="$sdk/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc"
client=$(cd "$(dirname "$0")" && pwd)/user_event_libubus.c
"$cc" -O2 -Wall -Wextra -Werror -fuse-ld=bfd -I"$src" -I"$src/ubus" \
    "$client" "$out/link-only/libubus.so.20251202" \
    "$out/link-only/libubox.so.20260213" -o "$out/user-event-libubus"
sha256sum "$client" "$out/user-event-libubus" "$out/link-only"/*.so.*
