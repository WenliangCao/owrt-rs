#!/bin/sh
# SDK COMPONENT_SOURCES NEW_OUTPUT_DIR; link-only libraries never go to router.
set -eu
[ "$#" -eq 3 ] || exit 2
sdk=$(cd "$1" && pwd)
src=$(cd "$2" && pwd)
[ ! -e "$3" ] || { echo 'output exists' >&2; exit 2; }
mkdir -p "$3"
out=$(cd "$3" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
"$here/build-register-libubus.sh" "$sdk" "$src" "$out/imports"
export STAGING_DIR="$sdk/staging_dir/target-aarch64_cortex-a53_musl"
cc="$sdk/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc"
"$cc" -O2 -Wall -Wextra -Werror -fuse-ld=bfd -I"$src" -I"$src/ubus" \
    "$here/r131_event_stress_libubus.c" "$out/imports/link-only/libubus.so.20251202" \
    "$out/imports/link-only/libubox.so.20260213" -o "$out/r131-event-stress-libubus"
sha256sum "$here/r131_event_stress_libubus.c" "$out/r131-event-stress-libubus"
