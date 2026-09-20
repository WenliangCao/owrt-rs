#!/bin/sh
# SDK COMPONENT_SOURCES NEW_OUTPUT_DIR
# Section-stripped image libraries cannot serve as linker inputs. Rebuild
# matching sources only to resolve imports; never copy link-only/ to a device.
set -eu
[ "$#" -eq 3 ] || exit 2
sdk=$(cd "$1" && pwd)
src=$(cd "$2" && pwd)
client=$(cd "$(dirname "$0")" && pwd)/register_libubus.c
[ ! -e "$3" ] || { echo 'output directory already exists' >&2; exit 2; }
mkdir -p "$3/link-only"
out=$(cd "$3" && pwd)
export STAGING_DIR="$sdk/staging_dir/target-aarch64_cortex-a53_musl"
cc="$sdk/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc"
cd "$src/libubox"
"$cc" -O2 -fPIC -shared -fuse-ld=bfd -I"$src" -Wl,-soname,libubox.so.20260213 \
    avl.c avl-cmp.c blob.c blobmsg.c uloop.c usock.c ustream.c ustream-fd.c \
    vlist.c utils.c safe_list.c runqueue.c md5.c kvlist.c ulog.c base64.c \
    udebug.c udebug-remote.c -o "$out/link-only/libubox.so.20260213"
cd "$src/ubus"
"$cc" -O2 -fPIC -shared -fuse-ld=bfd -I"$src" \
    '-DUBUS_UNIX_SOCKET="/var/run/ubus/ubus.sock"' -DUBUS_MAX_MSGLEN=1048576 \
    -Wl,-soname,libubus.so.20251202 \
    libubus.c libubus-io.c libubus-obj.c libubus-sub.c libubus-req.c libubus-acl.c \
    "$out/link-only/libubox.so.20260213" -o "$out/link-only/libubus.so.20251202"
"$cc" -O2 -Wall -Wextra -Werror -fuse-ld=bfd -I"$src" -I"$src/ubus" \
    "$client" "$out/link-only/libubus.so.20251202" \
    "$out/link-only/libubox.so.20260213" -o "$out/register-libubus"
sha256sum "$client" "$out/register-libubus"
