#!/bin/sh
# Native Linux reference. Explicit dependencies must match the source manifest.
# Usage: build_reference.sh PATCHED_SOURCE LIBUBOX_SOURCE UBUS_SOURCE OUTPUT
# No service is started. Output must be a new, task-owned directory.
set -eu
src=$(realpath "$1")
ubox=$(realpath "$2")
ubus=$(realpath "$3")
out=$(realpath -m "$4")
[ "$(uname -s)" = Linux ] || { echo 'Linux build host required' >&2; exit 1; }
[ ! -e "$out" ] || { echo 'choose a new output directory' >&2; exit 1; }
mkdir -p "$out/deps" "$out/dnsmasq"
cmake -S "$ubox" -B "$out/build-ubox" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$out/deps" -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF > "$out/libubox.log" 2>&1
cmake --build "$out/build-ubox" -j2 >> "$out/libubox.log" 2>&1
cmake --install "$out/build-ubox" >> "$out/libubox.log" 2>&1
cmake -S "$ubus" -B "$out/build-ubus" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$out/deps" -DCMAKE_PREFIX_PATH="$out/deps" \
    -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF > "$out/ubus.log" 2>&1
cmake --build "$out/build-ubus" -j2 >> "$out/ubus.log" 2>&1
cmake --install "$out/build-ubus" >> "$out/ubus.log" 2>&1
make -C "$src" -j2 BUILDDIR="$out/dnsmasq" \
    COPTS='-DHAVE_UBUS -DHAVE_POLL_H -DNO_DHCP6 -DNO_AUTH -DNO_IPSET -DNO_ID' \
    CFLAGS="-O2 -g -Wall -W -I$out/deps/include" \
    LDFLAGS="-L$out/deps/lib -Wl,-rpath,$out/deps/lib" > "$out/dnsmasq.log" 2>&1
"$out/dnsmasq/dnsmasq" --version > "$out/version.txt"
sha256sum "$out/dnsmasq/dnsmasq" > "$out/binary.sha256"
cc --version > "$out/compiler.txt"
cat "$out/version.txt" "$out/binary.sha256"
