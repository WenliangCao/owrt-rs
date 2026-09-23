#!/bin/sh
# SDK COMPONENT_SOURCES NEW_OUTPUT_DIR
# Reuse the existing exact-image link-symbol recipe; only the new caller ELF
# is an execution artifact. Never upload link-only/ to the router.
set -eu
[ "$#" -eq 3 ] || exit 2
sdk=$(cd "$1" && pwd)
src=$(cd "$2" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
sh "$here/build-register-libubus.sh" "$sdk" "$src" "$3"
out=$(cd "$3" && pwd)
export STAGING_DIR="$sdk/staging_dir/target-aarch64_cortex-a53_musl"
cc="$sdk/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc"
"$cc" -O2 -Wall -Wextra -Werror -fuse-ld=bfd -I"$src" -I"$src/ubus" \
    "$here/register_libubus_latency.c" "$out/link-only/libubus.so.20251202" \
    "$out/link-only/libubox.so.20260213" -o "$out/register-libubus-latency"
sha256sum "$here/register_libubus_latency.c" "$out/register-libubus-latency"
