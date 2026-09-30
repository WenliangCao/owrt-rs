#!/bin/sh
# Build the inert dnsmasq-rs staging package with the matching OpenWrt SDK.
# Usage: build_package.sh SDK_DIR OUTPUT_DIR
set -eu

sdk=${1:?usage: build_package.sh SDK_DIR OUTPUT_DIR}
out=${2:?usage: build_package.sh SDK_DIR OUTPUT_DIR}
repo=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
target=aarch64-unknown-linux-musl
channel=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$repo/rust-toolchain.toml")
cargo_bin=${CARGO:-$(command -v cargo 2>/dev/null || true)}
[ -n "$cargo_bin" ] || cargo_bin="$HOME/.cargo/bin/cargo"
[ -x "$cargo_bin" ] || { echo "cargo not found: $cargo_bin" >&2; exit 2; }

[ -d "$sdk" ] || { echo "SDK not found: $sdk" >&2; exit 2; }
[ -f "$sdk/staging_dir/target-aarch64_cortex-a53_musl/usr/include/stdio.h" ] || {
	echo "SDK target headers are missing: $sdk" >&2
	exit 2
}
mkdir -p "$out"
rm -rf "$sdk/package/owrt-dnsmasq"
mkdir -p "$sdk/package/owrt-dnsmasq"
cp -a "$repo/packaging/openwrt/owrt-dnsmasq/." "$sdk/package/owrt-dnsmasq/"
cd "$sdk"
RUSTUP_TOOLCHAIN="$channel" make package/owrt-dnsmasq/compile V=s -j1 \
	V1_CARGO="$cargo_bin" \
	V1_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
	V1_RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
	OWRT_COMPONENTS_SOURCE="$repo/components" \
	> "$out/build-owrt-dnsmasq.log" 2>&1 || {
	tail -80 "$out/build-owrt-dnsmasq.log" >&2
	exit 1
}
find "$sdk/bin/packages" -type f -name 'owrt-dnsmasq-*.apk' -exec cp -f {} "$out/" \;
set -- "$out"/owrt-dnsmasq-*.apk
[ -f "$1" ] || { echo "SDK did not produce owrt-dnsmasq APK" >&2; exit 1; }
sha256sum "$@" | tee "$out/SHA256SUMS"
