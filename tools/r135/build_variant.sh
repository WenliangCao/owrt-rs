#!/bin/bash
# Build isolated experimental snapshots concurrently, with canonical SDK flags.
# Usage: build_variant.sh COMPONENTS OUT WORK_ROOT
set -euo pipefail
src=$(realpath "$1"); out=$(realpath -m "$2"); fixed=$(realpath -m "$3")
[[ "$fixed" == /tmp/owrt-build/r135/* && ! -e "$fixed" && ! -e "$out" ]] || exit 2
sdk=/home/ubuntu/release/25.12.5/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64
staging_root=$sdk/staging_dir
staging=$staging_root/target-aarch64_cortex-a53_musl
tc=$staging_root/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin
export PATH="$staging/host/bin:$staging_root/hostpkg/bin:$tc:/home/ubuntu/.cargo/bin:$PATH"
export RUSTUP_HOME=/home/ubuntu/.rustup CARGO_HOME=/home/ubuntu/.cargo
export RUSTUP_TOOLCHAIN=1.98.1-aarch64-unknown-linux-gnu
export STAGING_DIR="$staging" STAGING_DIR_HOST="$staging_root/host" STAGING_DIR_HOSTPKG="$staging_root/hostpkg"
export GCC_HONOUR_COPTS=0 CARGO_BUILD_TARGET=aarch64-unknown-linux-musl CARGO_BUILD_JOBS=1
export CARGO_PROFILE_RELEASE_PANIC=abort
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-openwrt-linux-musl-gcc
export CC_aarch64_unknown_linux_musl=aarch64-openwrt-linux-musl-gcc
export AR_aarch64_unknown_linux_musl=aarch64-openwrt-linux-musl-gcc-ar
export RUSTFLAGS="--remap-path-prefix=$fixed=/build --remap-path-prefix=/home/ubuntu/.cargo=/cargo -Clink-arg=-fuse-ld=bfd -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs"
mkdir -p "$fixed" "$out"
cp -a "$src/." "$fixed/"
cargo build --release --locked --manifest-path "$fixed/ubusd/Cargo.toml" --target-dir "$out/target"
cp "$out/target/aarch64-unknown-linux-musl/release/ubusd-rs" "$out/ubusd-rs"
"$staging_root/host/bin/sstrip" -z "$out/ubusd-rs"
sha256sum "$out/ubusd-rs" > "$out/binary.sha256"
