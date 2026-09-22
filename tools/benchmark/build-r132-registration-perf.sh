#!/bin/sh
# SDK NEW_OUTPUT_DIRECTORY
# Build a separate static diagnostic ELF. Never replace the frozen benchmark.
set -eu
[ "$#" -eq 2 ] || exit 2
sdk=$(cd "$1" && pwd)
[ ! -e "$2" ] || exit 2
mkdir -p "$2"
out=$(cd "$2" && pwd)
source=$(cd "$(dirname "$0")" && pwd)
export STAGING_DIR="$sdk/staging_dir/target-aarch64_cortex-a53_musl"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$sdk/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc"
export RUSTFLAGS="--remap-path-prefix=$source=/build/benchmark -Clink-arg=-fuse-ld=bfd -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs"
cargo build --locked --release --features registration-perf --manifest-path "$source/Cargo.toml" \
    --target aarch64-unknown-linux-musl --target-dir "$out/target"
cp "$out/target/aarch64-unknown-linux-musl/release/owrt-benchmark" "$out/owrt-register-perf"
sha256sum "$source/Cargo.toml" "$source/Cargo.lock" "$source/src/main.rs" \
    "$source/src/registration_perf.rs" "$out/owrt-register-perf" > "$out/build-identities.sha256"
