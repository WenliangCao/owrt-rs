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
client=$(cd "$(dirname "$0")" && pwd)/r131_event_memory_repeat_libubus.c
export STAGING_DIR="$sdk/staging_dir/target-aarch64_cortex-a53_musl"
cc="$sdk/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc"
"$cc" -O2 -Wall -Wextra -Werror -fuse-ld=bfd -MMD -MF "$out/helper.d" \
    -I"$src" -I"$src/ubus" "$client" "$link/libubus.so.20251202" \
    "$link/libubox.so.20260213" -o "$out/event-memory-repeat"
sha256sum "$client" "$(dirname "$client")/event_memory_libubus.c" "$out/event-memory-repeat" \
    "$link/libubus.so.20251202" "$link/libubox.so.20260213" > "$out/build-identities.sha256"
