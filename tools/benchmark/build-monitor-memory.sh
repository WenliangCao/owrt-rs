#!/bin/bash
# REPO SDK NEW_OUTPUT_DIR. Build only the separate memory helper.
set -euo pipefail
[[ "$#" == 3 ]] || exit 2
src=$(cd "$1" && pwd)
sdk=$(cd "$2" && pwd)
[[ ! -e "$3" ]] || exit 2
mkdir -p "$3"
out=$(cd "$3" && pwd)
export PATH=/home/ubuntu/.cargo/bin:$PATH
export RUSTUP_TOOLCHAIN=1.98.1-aarch64-unknown-linux-gnu
export CARGO_PROFILE_RELEASE_PANIC=abort
export STAGING_DIR="$sdk/staging_dir/target-aarch64_cortex-a53_musl"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$sdk/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc"
export RUSTFLAGS="--remap-path-prefix=$src=/build -Clink-arg=-fuse-ld=bfd -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs"
printf '%s\n' "$RUSTFLAGS" > "$out/rustflags.txt"
rustc -vV > "$out/rustc.txt"
cargo build --locked --release --manifest-path "$src/tools/benchmark/Cargo.toml" \
    --example monitor_memory --target aarch64-unknown-linux-musl --target-dir "$out/target"
cp "$out/target/aarch64-unknown-linux-musl/release/examples/monitor_memory" "$out/monitor-memory"
sha256sum "$out/monitor-memory" > "$out/binary.sha256"
