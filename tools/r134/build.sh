#!/bin/bash
# Build router candidates on the Oracle host with the canonical SDK flags.
# usage: [EXAMPLES=1] build.sh SRC_COMPONENTS_DIR OUT_DIR COMPONENT...
# Builds in a fixed path so equal sources give equal bytes; strips like the
# SDK package (sstrip -z). Cargo's release profile already strips symbols;
# the target-directory copy is before sstrip, not a symbolized profiling ELF.
set -euo pipefail
SRC=$(realpath "$1"); OUT=$2; shift 2
SDK=/home/ubuntu/release/25.12.5/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64
STAGING_ROOT=$SDK/staging_dir
STAGING=$(ls -d $STAGING_ROOT/target-aarch64_* | head -1)
TC=$(ls -d $STAGING_ROOT/toolchain-aarch64_*/bin | head -1)
FIXED=/tmp/owrt-build/r134
export PATH="$STAGING/host/bin:$STAGING_ROOT/hostpkg/bin:$TC:/home/ubuntu/.cargo/bin:$PATH"
export RUSTUP_HOME=/home/ubuntu/.rustup CARGO_HOME=/home/ubuntu/.cargo
export RUSTUP_TOOLCHAIN=1.98.1-aarch64-unknown-linux-gnu
export STAGING_DIR="$STAGING" STAGING_DIR_HOST="$STAGING_ROOT/host" STAGING_DIR_HOSTPKG="$STAGING_ROOT/hostpkg"
export GCC_HONOUR_COPTS=0
export CARGO_BUILD_TARGET=aarch64-unknown-linux-musl
export CARGO_PROFILE_RELEASE_PANIC=abort
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-openwrt-linux-musl-gcc
export CC_aarch64_unknown_linux_musl=aarch64-openwrt-linux-musl-gcc
export AR_aarch64_unknown_linux_musl=aarch64-openwrt-linux-musl-gcc-ar
export RUSTFLAGS="--remap-path-prefix=$FIXED=/build --remap-path-prefix=/home/ubuntu/.cargo=/cargo -Clink-arg=-fuse-ld=bfd -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs"
rm -rf "$FIXED"; mkdir -p "$FIXED" "$OUT"
rsync -a --delete --exclude target/ "$SRC"/ "$FIXED"/
for comp in "$@"; do
  bin=$(sed -n '/^\[\[bin\]\]/,/^name/{s/^name *= *"\(.*\)"/\1/p}' "$FIXED/$comp/Cargo.toml" | head -1)
  cargo build --release --locked --manifest-path "$FIXED/$comp/Cargo.toml" --target-dir "$OUT/target" 2>&1 | tail -2
  cp "$OUT/target/aarch64-unknown-linux-musl/release/$bin" "$OUT/$bin"
  "$STAGING_ROOT/host/bin/sstrip" -z "$OUT/$bin"
  echo "BUILT $comp $bin $(sha256sum "$OUT/$bin" | cut -d' ' -f1) $(stat -c%s "$OUT/$bin")"
  if [ -n "${EXAMPLES:-}" ]; then
    cargo build --release --locked --examples --manifest-path "$FIXED/$comp/Cargo.toml" --target-dir "$OUT/target" 2>&1 | tail -2
    mkdir -p "$OUT/examples"
    find "$OUT/target/aarch64-unknown-linux-musl/release/examples" -maxdepth 1 -type f -perm -u+x ! -name '*-*' -exec cp {} "$OUT/examples/" \;
  fi
done
