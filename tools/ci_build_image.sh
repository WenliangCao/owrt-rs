#!/bin/sh
# Build the seven owrt-* apks and the xiaomi_mi-router-ax3000t sysupgrade image
# for one OpenWrt release, on any x86_64 Linux host (GitHub Actions or a laptop).
# Same recipe as tools/release.sh, but self-contained: no build host, no router.
#
#   OPENWRT_VERSION=25.12.5 sh tools/ci_build_image.sh [workdir]
#
# Needs: curl, tar+zstd, make, gcc, python3, rsync, file, rustup with the
# toolchain in RUST_TOOLCHAIN (default 1.94.0) and target aarch64-unknown-linux-musl.
# Output: <workdir>/out/{owrt-*.apk, *-sysupgrade.bin, SHA256SUMS, manifest.json, *.log}
set -eu
ver=${OPENWRT_VERSION:?set OPENWRT_VERSION, e.g. 25.12.5}
REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(cd "$(mkdir -p "${1:-$REPO/work}" && echo "${1:-$REPO/work}")" && pwd)
OUT=$WORK/out
TARGET=mediatek/filogic; ARCH=aarch64_cortex-a53; PROFILE=xiaomi_mi-router-ax3000t
BASE="https://downloads.openwrt.org/releases/$ver/targets/$TARGET"
PKGS="owrt-uci owrt-reload-config owrt-logd owrt-httpd owrt-fw4 owrt-rpcd owrt-switch"
PKGLIST=$REPO/packaging/image/packages-$ver.txt
RUST_TOOLCHAIN=${RUST_TOOLCHAIN:-1.94.0}
CARGO=${CARGO:-"env RUSTUP_TOOLCHAIN=$RUST_TOOLCHAIN cargo"}
NPROC=$(nproc 2>/dev/null || echo 2)

log() { printf '\n== %s\n' "$*"; }
[ -f "$PKGLIST" ] || { echo "no package list for $ver: $PKGLIST (capture it with: ssh router 'apk info' | sort)" >&2; exit 1; }
mkdir -p "$WORK/dl" "$OUT"

log "fetch SDK + ImageBuilder $ver"
cd "$WORK/dl"
curl -sSfLO "$BASE/sha256sums"
for f in $(grep -oE "openwrt-(sdk|imagebuilder)-$ver-[^ ]*\.tar\.(zst|xz)" sha256sums | sort -u); do
	[ -f "$f" ] || curl -sSfL -o "$f" "$BASE/$f"
done
grep -E 'openwrt-(sdk|imagebuilder)-' sha256sums | sha256sum -c
cd "$WORK"
for f in dl/openwrt-sdk-$ver-*.tar.* dl/openwrt-imagebuilder-$ver-*.tar.*; do
	d=$(basename "${f%.tar.*}")
	[ -d "$d" ] || tar -xf "$f"
done
SDK=$(ls -d "$WORK"/openwrt-sdk-$ver-*/ | head -1); SDK=${SDK%/}
IB=$(ls -d "$WORK"/openwrt-imagebuilder-$ver-*/ | head -1); IB=${IB%/}

log "toolchain"
rustup toolchain list | grep -q "^$RUST_TOOLCHAIN" || rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
rustup target add --toolchain "$RUST_TOOLCHAIN" aarch64-unknown-linux-musl
$CARGO --version

log "build apks in $SDK"
for p in $PKGS; do rsync -a --delete "$REPO/packaging/openwrt/$p/" "$SDK/package/$p/"; done
cd "$SDK"
[ -f .config ] || make defconfig >/dev/null 2>&1 || true
for p in $PKGS; do
	echo "-- $p"
	make "package/$p/compile" V=s -j1 \
		V1_CARGO="$CARGO" V1_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" V1_RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
		OWRT_COMPONENTS_SOURCE="$REPO/components" RELOAD_CONFIG_RS_SOURCE="$REPO/components/reload-config" \
		${V1_PACKAGE_RELEASE:+V1_PACKAGE_RELEASE=$V1_PACKAGE_RELEASE} > "$OUT/build-$p.log" 2>&1 \
		|| { tail -40 "$OUT/build-$p.log"; exit 1; }
done
cp "$SDK/bin/packages/$ARCH/base"/owrt-*.apk "$OUT/"
ls -la "$OUT"/owrt-*.apk

log "image in $IB"
rm -rf "$WORK/files"; mkdir -p "$WORK/files/etc"
for c in uci reload-config logd httpd fw4 rpcd; do : > "$WORK/files/etc/owrt-$c.boot-enable"; done
mkdir -p "$IB/packages"; rm -f "$IB/packages"/owrt-*.apk "$IB/packages/packages.adb"
cp "$OUT"/owrt-*.apk "$IB/packages/"
pkgs=$(tr '\n' ' ' < "$PKGLIST")
cd "$IB"
make image PROFILE="$PROFILE" PACKAGES="$pkgs" FILES="$WORK/files" \
	DISABLED_SERVICES='rpcd uhttpd log' ADD_LOCAL_KEY=1 BIN_DIR="$WORK/bin" -j"$NPROC" > "$OUT/image.log" 2>&1 \
	|| { tail -60 "$OUT/image.log"; exit 1; }
img=$(ls "$WORK/bin"/*"$PROFILE"*-squashfs-sysupgrade.bin)
cp "$img" "$OUT/"
[ -f "$WORK/bin/profiles.json" ] && cp "$WORK/bin/profiles.json" "$OUT/" || true

log "offline validation"
cd "$WORK"; rm -rf verify; mkdir verify; cd verify
tar -xf "$img"
ls -la
UNSQ=$(command -v unsquashfs || ls "$IB"/staging_dir/host/bin/unsquashfs4 2>/dev/null | head -1 || true)
if [ -n "$UNSQ" ]; then
	"$UNSQ" -d root -n root 2>&1 | tail -1 || "$UNSQ" -d root root >/dev/null
	fail=0
	for p in $PKGS; do ls root/lib/apk/packages/ 2>/dev/null | grep -q "^$p\.list$" || { echo "MISSING package $p"; fail=1; }; done
	for c in uci reload-config logd httpd fw4 rpcd; do [ -f "root/etc/owrt-$c.boot-enable" ] || { echo "MISSING marker $c"; fail=1; }; done
	for s in rpcd uhttpd log; do ls root/etc/rc.d/ | grep -q "^S..$s$" && { echo "service $s NOT disabled"; fail=1; }; done
	for b in uci-rs fw4-rs reload_config_rs logd-rs httpd-rs rpcd-rs; do [ -x "root/usr/sbin/$b" ] || { echo "MISSING binary $b"; fail=1; }; done
	ls root/etc/apk/keys/ | grep -q . || { echo "MISSING local apk key"; fail=1; }
	[ $fail = 0 ] && echo "image content OK: 7 packages, 6 markers, 3 services disabled, local key present"
	[ $fail = 0 ] || exit 1
else
	echo "unsquashfs not available; content check skipped"
fi

log "manifest"
cd "$OUT"
sha256sum owrt-*.apk *-sysupgrade.bin > SHA256SUMS
python3 - "$ver" "$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)" <<'EOF'
import json, os, sys, hashlib, re
ver, commit = sys.argv[1], sys.argv[2]
sums = dict(line.split()[::-1] for line in open("SHA256SUMS") if line.strip())
pkgs = {}
for f in sorted(sums):
    m = re.match(r"(owrt-[a-z-]+)-(\d+\.\d+\.\d+-r\d+)\.apk$", f)
    if m:
        pkgs[m.group(1)] = m.group(2)
img = [f for f in sums if f.endswith("-sysupgrade.bin")][0]
json.dump({"openwrt": ver, "profile": "xiaomi_mi-router-ax3000t", "source_commit": commit,
           "packages": pkgs, "image": {"file": img, "size": os.path.getsize(img), "sha256": sums[img]},
           "apk_sha256": {f: s for f, s in sums.items() if f.endswith(".apk")},
           "imagebuilder_args": {"DISABLED_SERVICES": "rpcd uhttpd log", "ADD_LOCAL_KEY": 1,
                                 "FILES": "etc/owrt-{uci,reload-config,logd,httpd,fw4,rpcd}.boot-enable"},
           "flashed": False}, open("manifest.json", "w"), indent=1)
print(open("manifest.json").read())
EOF
cat SHA256SUMS
