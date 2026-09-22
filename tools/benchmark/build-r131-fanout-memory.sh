#!/bin/sh
# SDK EXACT_COMPONENT_SOURCES LINK_ONLY_LIBRARIES NEW_OUTPUT_DIRECTORY
set -eu
[ "$#" -eq 4 ] || exit 2
sdk=$(cd "$1" && pwd)
src=$(cd "$2" && pwd)
link=$(cd "$3" && pwd)
[ ! -e "$4" ] || exit 2
mkdir -p "$4"
out=$(cd "$4" && pwd)
client=$(cd "$(dirname "$0")" && pwd)/event_memory_libubus.c
export STAGING_DIR="$sdk/staging_dir/target-aarch64_cortex-a53_musl"
cc="$sdk/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc"
"$cc" -DEVENT_MEMORY_HANDLERS=8 -O2 -Wall -Wextra -Werror -fuse-ld=bfd -MMD -MF "$out/helper.d" -I"$src" -I"$src/ubus" "$client" "$link/libubus.so.20251202" "$link/libubox.so.20260213" -o "$out/fanout-memory"
"$cc" --version > "$out/compiler-version.txt"
sha256sum "$cc" "$client" "$out/fanout-memory" "$link/libubus.so.20251202" "$link/libubox.so.20260213" > "$out/build-identities.sha256"
