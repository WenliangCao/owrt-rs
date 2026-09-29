#!/bin/sh
# Final canonical image stage, after ci_build_image.sh and ci_build_core.sh.
# Only the build host is changed. No router connection or flash command.
set -eu
ver=${OPENWRT_VERSION:?set OPENWRT_VERSION}
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(cd "${1:?usage: ci_integrate_image.sh WORKDIR}" && pwd)
spec=$repo/packaging/image/native-$ver.json
test -f "$spec"
set -- "$work"/openwrt-imagebuilder-"$ver"-*/
[ "$#" = 1 ] && [ -d "$1" ] || exit 1
ib=${1%/}
apk=$ib/staging_dir/host/bin/apk
python3 "$repo/tools/native_image.py" prepare "$work" "$spec" "$apk"

# The SDK APKs are build intermediates. The final image installs only the
# unified native APK, alongside the unchanged official package set.
rm -f "$ib"/packages/owrt-*.apk "$ib/packages/packages.adb"
cp "$work"/native/*.apk "$ib/packages/"
pkgs=$(tr '\n' ' ' < "$work/native/packages.txt")
cd "$ib"
make image PROFILE=xiaomi_mi-router-ax3000t PACKAGES="$pkgs" \
    ADD_LOCAL_KEY=1 DISABLED_SERVICES= FILES= BIN_DIR="$work/native/bin" \
    > "$work/native/image.log" 2>&1 || { tail -60 "$work/native/image.log"; exit 1; }
mkdir "$work/native/unpacked"
tar -xf "$work"/native/bin/*-sysupgrade.bin -C "$work/native/unpacked"
set -- "$work"/native/unpacked/sysupgrade-*/root
[ "$#" = 1 ] && [ -f "$1" ] || exit 1
sudo -n unsquashfs -n -d "$work/native/rootfs" "$1" > "$work/native/unpack.log" 2>&1
# Verify the kernel payload itself, not just its package version.
cmp "$work"/verify/sysupgrade-*/kernel "$work"/native/unpacked/sysupgrade-*/kernel
sudo -n python3 "$repo/tools/native_image.py" verify "$work" "$spec" "$apk"
echo 'Native nine-component image assembled and audited; no device was flashed.'
