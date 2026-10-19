#!/bin/sh
# Final canonical image stage, after ci_build_image.sh and ci_build_core.sh.
# Only the build host is changed. No router connection or flash command.
set -eu
ver=${OPENWRT_VERSION:?set OPENWRT_VERSION}
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(cd "${1:?usage: ci_integrate_image.sh WORKDIR}" && pwd)
spec=${OWRT_NATIVE_SPEC:-$repo/packaging/image/native-$ver.json}
test -f "$spec"
set -- "$work"/openwrt-imagebuilder-"$ver"-*/
[ "$#" = 1 ] && [ -d "$1" ] || exit 1
ib=${1%/}
apk=$ib/staging_dir/host/bin/apk
kernel=$ib/build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic/xiaomi_mi-router-ax3000t-kernel.bin
test -f "$kernel"
python3 "$repo/tools/native_image.py" fetch "$work" "$spec" "$apk"
stock=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["stock_image"]["file"])' "$spec")
mkdir "$work/native/base-image"
tar -xf "$work/dl/$stock" -C "$work/native/base-image"
sudo -n unsquashfs -n -d "$work/native/base-rootfs" \
    "$work"/native/base-image/sysupgrade-*/root > "$work/native/base-unpack.log" 2>&1
# Exact stock configuration includes root-owned 0600 files. Preserve those
# modes and compare as root, just as the final extracted-filesystem audit does.
sudo -n python3 "$repo/tools/native_image.py" prepare "$work" "$spec" "$apk"

# Reuse the verified original filesystem. ImageBuilder's ordinary package
# install resolves rolling feeds, even for a fixed OpenWrt release number.
sudo -n cp -a "$work/native/base-rootfs" "$work/native/assembled-rootfs"
sudo -n "$apk" --root "$work/native/assembled-rootfs" --no-network --no-scripts \
    --allow-untrusted add "$work"/native/*.apk > "$work/native/install.log" 2>&1 \
    || { tail -50 "$work/native/install.log"; exit 1; }
epoch=$(git -C "$repo" show -s --format=%ct HEAD)
# These are the exact ImageBuilder squashfs settings for this target. Device
# nodes and ownership already come from the original rootfs, including console.
sudo -n env SOURCE_DATE_EPOCH="$epoch" "$ib/staging_dir/host/bin/mksquashfs4" \
    "$work/native/assembled-rootfs" "$work/native/root.squashfs" \
    -nopad -noappend -root-owned -comp xz -Xpreset 9 -Xe -Xlc 0 -Xlp 2 -Xpb 2 \
    -b 256k -no-xattrs -block-readers 4 -small-readers 4 \
    > "$work/native/squashfs.log" 2>&1
mkdir "$work/native/bin"
export TOPDIR="$ib" SOURCE_DATE_EPOCH="$epoch"
sh "$ib/scripts/sysupgrade-tar.sh" --board xiaomi_mi-router-ax3000t \
    --kernel "$kernel" \
    --rootfs "$work/native/root.squashfs" "$work/native/bin/$stock" > "$work/native/image.log" 2>&1
"$ib/staging_dir/host/bin/fwtool" -i "$work/native/metadata.json" "$work/dl/$stock"
"$ib/staging_dir/host/bin/fwtool" -I "$work/native/metadata.json" "$work/native/bin/$stock"
mkdir "$work/native/unpacked"
tar -xf "$work"/native/bin/*-sysupgrade.bin -C "$work/native/unpacked"
set -- "$work"/native/unpacked/sysupgrade-*/root
[ "$#" = 1 ] && [ -f "$1" ] || exit 1
sudo -n unsquashfs -n -d "$work/native/rootfs" "$1" > "$work/native/unpack.log" 2>&1
# The final kernel volume must contain the AN8855-only FIT from the first
# stage. native_image.py also checks its DTB and unchanged Linux payload.
cmp "$kernel" "$work"/native/unpacked/sysupgrade-*/kernel
cmp "$work"/native/base-image/sysupgrade-*/CONTROL "$work"/native/unpacked/sysupgrade-*/CONTROL
"$ib/staging_dir/host/bin/fwtool" -i "$work/native/final-metadata.json" "$work/native/bin/$stock"
cmp "$work/native/metadata.json" "$work/native/final-metadata.json"
sudo -n python3 "$repo/tools/native_image.py" verify "$work" "$spec" "$apk"
echo 'Selected native image assembled and audited; no device was flashed.'
