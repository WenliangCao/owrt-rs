#!/bin/sh
# Release pipeline for a given OpenWrt release (see docs/RELEASE.md).
#   release.sh apk   <version>   build the seven owrt-* packages with that release's SDK
#   release.sh image <version>   build a xiaomi_mi-router-ax3000t sysupgrade image that
#                                contains them (ImageBuilder), packages list = the device's
#   release.sh fetch <version>   download + verify SDK and ImageBuilder on the build host
# Everything heavy runs on the build host ($BUILD_HOST, ssh alias). Nothing here
# touches the router except `image`, which reads `apk info` for the package list
# when PKGLIST is not given.
set -eu
cmd=${1:?apk|image|fetch}; ver=${2:?openwrt version, e.g. 25.12.5}
BUILD_HOST=${BUILD_HOST:-oracle}
ROUTER=${ROUTER:-openwrt}
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARGET=mediatek/filogic; ARCH=aarch64_cortex-a53; PROFILE=xiaomi_mi-router-ax3000t
BASE="https://downloads.openwrt.org/releases/$ver/targets/$TARGET"
REMOTE_ROOT=/home/ubuntu/release/$ver
COMPONENTS_DIR=$REMOTE_ROOT/components
PKGS="owrt-uci owrt-reload-config owrt-logd owrt-httpd owrt-fw4 owrt-rpcd owrt-switch"
R() { ssh -o ConnectTimeout=15 "$BUILD_HOST" "$@"; }

sdk_dir() { R "ls -d $REMOTE_ROOT/openwrt-sdk-$ver-*/ 2>/dev/null | head -1 | sed 's#/\$##'"; }
ib_dir()  { R "ls -d $REMOTE_ROOT/openwrt-imagebuilder-$ver-*/ 2>/dev/null | head -1 | sed 's#/\$##'"; }

fetch() {
	R "mkdir -p $REMOTE_ROOT && cd $REMOTE_ROOT && curl -sSLO $BASE/sha256sums && \
	   for f in \$(grep -oE 'openwrt-(sdk|imagebuilder)-$ver-[^ ]*\.tar\.(zst|xz)' sha256sums); do \
	     [ -f \$f ] || curl -sSL -o \$f $BASE/\$f; done && \
	   grep -E 'openwrt-(sdk|imagebuilder)-' sha256sums | sha256sum -c && \
	   for f in openwrt-sdk-$ver-*.tar.* openwrt-imagebuilder-$ver-*.tar.*; do \
	     d=\${f%.tar.*}; [ -d \$d ] || tar --zstd -xf \$f 2>/dev/null || tar -xf \$f; done && ls -d */"
}

sync_sources() {
	R "mkdir -p $COMPONENTS_DIR"
	rsync -a --delete --exclude target --exclude '*/target' "$REPO_ROOT/components/" "$BUILD_HOST:$COMPONENTS_DIR/"
	sdk=$(sdk_dir); [ -n "$sdk" ] || { echo "SDK for $ver not present, run: release.sh fetch $ver" >&2; exit 1; }
	for p in $PKGS; do rsync -a --delete "$REPO_ROOT/packaging/openwrt/$p/" "$BUILD_HOST:$sdk/package/$p/"; done
	echo "$sdk"
}

apk() {
	sdk=$(sync_sources)
	for p in $PKGS; do
		echo "== $p"
		R "cd $sdk && make package/$p/compile V=s -j1 \
		   V1_CARGO='env RUSTUP_TOOLCHAIN=${RUST_TOOLCHAIN:-1.94.0-aarch64-unknown-linux-gnu} /home/ubuntu/.cargo/bin/cargo' \
		   V1_CARGO_HOME=/home/ubuntu/.cargo V1_RUSTUP_HOME=/home/ubuntu/.rustup \
		   OWRT_COMPONENTS_SOURCE=$COMPONENTS_DIR > /tmp/release-$p.log 2>&1 || { tail -30 /tmp/release-$p.log; exit 1; }"
	done
	R "cd $sdk/bin/packages/$ARCH/base && sha256sum owrt-*.apk"
}

image() {
	sdk=$(sdk_dir); ib=$(ib_dir)
	[ -n "$sdk" ] && [ -n "$ib" ] || { echo "SDK/ImageBuilder for $ver missing, run: release.sh fetch $ver, release.sh apk $ver" >&2; exit 1; }
	# package list: the router's installed set (names only), or a file given as PKGLIST
	if [ -n "${PKGLIST:-}" ]; then pkgs=$(tr '\n' ' ' < "$PKGLIST")
	else pkgs=$(ssh "$ROUTER" 'apk info 2>/dev/null' | tr '\n' ' '); fi
	[ -n "$pkgs" ] || { echo "empty package list" >&2; exit 1; }
	# files baked into the image: the six boot-enable markers (the layer takes over at first boot)
	R "rm -rf $REMOTE_ROOT/files && mkdir -p $REMOTE_ROOT/files/etc && \
	   for c in uci reload-config logd httpd fw4 rpcd; do : > $REMOTE_ROOT/files/etc/owrt-\$c.boot-enable; done && \
	   cp $sdk/bin/packages/$ARCH/base/owrt-*.apk $ib/packages/ && rm -f $ib/packages/packages.adb && \
	   cd $ib && make image PROFILE=$PROFILE PACKAGES='$pkgs' FILES=$REMOTE_ROOT/files \
	     DISABLED_SERVICES='rpcd uhttpd log' ADD_LOCAL_KEY=1 BIN_DIR=$REMOTE_ROOT/bin > $REMOTE_ROOT/image.log 2>&1 \
	     || { tail -40 $REMOTE_ROOT/image.log; exit 1; } && \
	   cd $REMOTE_ROOT/bin && ls -la *sysupgrade* && sha256sum *sysupgrade*"
}

case $cmd in
	fetch) fetch ;;
	apk) apk ;;
	image) image ;;
	*) echo "usage: release.sh apk|image|fetch <version>" >&2; exit 64 ;;
esac
