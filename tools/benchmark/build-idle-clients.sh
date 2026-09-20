#!/bin/sh
# SDK NEW_OUTPUT_DIR
set -eu
[ "$#" -eq 2 ] || exit 2
sdk=$(cd "$1" && pwd)
out_arg=$2
[ ! -e "$out_arg" ] || { echo 'output directory already exists' >&2; exit 2; }
mkdir -p "$out_arg"
out=$(cd "$out_arg" && pwd)
cc="$sdk/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc"
source=$(cd "$(dirname "$0")" && pwd)/idle_clients.c
"$cc" -O2 -Wall -Wextra -Werror -fuse-ld=bfd "$source" -o "$out/idle-clients"
sha256sum "$source" "$out/idle-clients"
