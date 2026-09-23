#!/bin/bash
set -euo pipefail
src=/home/ubuntu/r135/repo
out=/home/ubuntu/r135/benchmark-01
[[ ! -e "$out" ]] || exit 2
sdk=/home/ubuntu/release/25.12.5/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64
export PATH=/home/ubuntu/.cargo/bin:$PATH
export RUSTUP_TOOLCHAIN=1.98.1-aarch64-unknown-linux-gnu
export STAGING_DIR=$sdk/staging_dir/target-aarch64_cortex-a53_musl
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=$sdk/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc
export RUSTFLAGS="--remap-path-prefix=$src=/build -Clink-arg=-fuse-ld=bfd -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs"
cargo build --locked --release --manifest-path "$src/tools/benchmark/Cargo.toml" --target aarch64-unknown-linux-musl --target-dir "$out/target"
cp "$out/target/aarch64-unknown-linux-musl/release/owrt-benchmark" "$out/owrt-benchmark"
sha256sum "$out/owrt-benchmark" > "$out/binary.sha256"
