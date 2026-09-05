#!/bin/sh
# Reproducibility diagnostics for owrt-httpd: run the packaging recipe's exact
# cargo step with the target dir preserved, then collect every intermediate that
# could be the first to differ between two hosts.
#
#   repro_diag.sh fetch <workdir>   download + unpack the SDK
#   repro_diag.sh build <workdir>   build and collect into <workdir>/diag
#
# Collects (never secrets, never a full environment dump): the unstripped ELF,
# ring's OUT_DIR (.a/.o/generated headers/build-script output), every .rlib, the
# cargo -vv log, and the identities of the tools that actually ran.
set -eu
cmd=${1:?fetch|build}
WORK=$(cd "${2:?workdir}" 2>/dev/null && pwd || { mkdir -p "$2" && cd "$2" && pwd; })
REPO=$(cd "$(dirname "$0")/.." && pwd)
ver=${OPENWRT_VERSION:-25.12.5}
TARGET=mediatek/filogic
BASE="https://downloads.openwrt.org/releases/$ver/targets/$TARGET"
RUST_TARGET=aarch64-unknown-linux-musl
PIN=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$REPO/rust-toolchain.toml")

sdk_dir() { ls -d "$WORK"/openwrt-sdk-"$ver"-*/ 2>/dev/null | head -1; }

case "$cmd" in
fetch)
	mkdir -p "$WORK/dl"
	cd "$WORK/dl"
	curl -sSfLO "$BASE/sha256sums"
	f=$(grep -oE "openwrt-sdk-$ver-[^ ]*\.tar\.(zst|xz)" sha256sums | sort -u | head -1)
	[ -f "$f" ] || curl -sSfLO "$BASE/$f"
	grep " $f\$" sha256sums | sha256sum -c
	cd "$WORK"
	d=$(basename "${f%.tar.*}")
	[ -d "$d" ] || tar -xf "dl/$f"
	echo "sdk: $d"
	;;
build)
	SDK=$(sdk_dir); SDK=${SDK%/}
	[ -n "$SDK" ] || { echo "no SDK in $WORK; run fetch first" >&2; exit 1; }
	OUT=$WORK/diag
	rm -rf "$OUT" /tmp/owrt-build/owrt-httpd
	mkdir -p "$OUT" /tmp/owrt-build

	# Same host-independent source path the packaging recipe uses.
	src=/tmp/owrt-build/owrt-httpd
	mkdir -p "$src/httpd/src" "$src/ubus/src"
	cp "$REPO/components/httpd/Cargo.toml" "$REPO/components/httpd/Cargo.lock" "$src/httpd/"
	cp "$REPO"/components/httpd/src/*.rs "$src/httpd/src/"
	cp "$REPO/components/ubus/Cargo.toml" "$src/ubus/"
	cp "$REPO"/components/ubus/src/*.rs "$src/ubus/src/"

	tc=$(ls -d "$SDK"/staging_dir/toolchain-*/bin | head -1)
	# The recipe passes bare tool names and lets the SDK's PATH resolve them.
	PATH=$tc:$PATH
	export PATH
	CC=$(basename "$(ls "$tc"/*-openwrt-linux-musl-gcc | head -1)")
	AR=$(basename "$(ls "$tc"/*-openwrt-linux-musl-ar | head -1)")
	# -fuse-ld takes a linker *name*, not a path. Taken from the real build log
	# of this SDK rather than re-derived: `grep -o "fuse-ld=[^ ]*"` shows bfd.
	LD=${TARGET_LINKER:-bfd}
	CARGO=${CARGO:-"env RUSTUP_TOOLCHAIN=$PIN cargo"}
	CARGO_HOME_DIR=${CARGO_HOME:-$HOME/.cargo}

	set +e
	env \
		CARGO_HOME="$CARGO_HOME_DIR" \
		CARGO_BUILD_TARGET="$RUST_TARGET" \
		CARGO_PROFILE_RELEASE_PANIC=abort \
		CC_aarch64_unknown_linux_musl="$CC" \
		AR_aarch64_unknown_linux_musl="$AR" \
		CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CC" \
		RUSTFLAGS="--remap-path-prefix=$src=/build --remap-path-prefix=$CARGO_HOME_DIR=/cargo -Clink-arg=-fuse-ld=$LD -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs" \
		$CARGO build --release --locked -vv \
		--manifest-path "$src/httpd/Cargo.toml" --target-dir "$OUT/target" > "$OUT/cargo-vv.log" 2>&1
	rc=$?
	set -e
	[ "$rc" = 0 ] || { tail -30 "$OUT/cargo-vv.log"; exit 1; }

	rel=$OUT/target/$RUST_TARGET/release
	mkdir -p "$OUT/collect"
	cp "$rel/httpd-rs" "$OUT/collect/httpd-rs.unstripped"
	# ring's OUT_DIR: the .a, its objects, generated headers, build-script output
	ringout=$(ls -d "$rel"/build/ring-*/out 2>/dev/null | head -1 || true)
	if [ -n "$ringout" ]; then
		mkdir -p "$OUT/collect/ring-out"
		cp -a "$ringout"/. "$OUT/collect/ring-out/" 2>/dev/null || true
		bs=$(dirname "$ringout")/../output
		[ -f "$bs" ] && cp "$bs" "$OUT/collect/ring-build-script-output" || true
	fi
	for f in "$rel"/deps/*.rlib; do [ -f "$f" ] && cp "$f" "$OUT/collect/"; done

	# identities of the tools that actually ran
	{
		echo "pin=$PIN"
		echo "cargo=$(sh -c "$CARGO -V")"
		echo "rustc=$(sh -c "$CARGO rustc -V" 2>/dev/null || env RUSTUP_TOOLCHAIN=$PIN rustc -vV | tr '\n' ';')"
		echo "cc=$CC"; "$CC" --version | head -1
		echo "ar=$AR"; "$AR" --version | head -1
		echo "fuse_ld=${LD:-<default>}"
		echo "sdk=$(basename "$SDK")"
		echo "host_uname=$(uname -m)"
		echo "src=$src"
		echo "cargo_home=$CARGO_HOME_DIR"
		echo "umask=$(umask)"; echo "TZ=${TZ:-unset}"; echo "LC_ALL=${LC_ALL:-unset}"
		echo "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-unset}"
	} > "$OUT/collect/tools.txt"

	( cd "$OUT/collect" && find . -type f | sort | xargs sha256sum ) > "$OUT/collect-sha256.txt"
	echo "collected into $OUT"
	cat "$OUT/collect-sha256.txt"
	;;
*)
	echo "usage: repro_diag.sh fetch|build <workdir>" >&2; exit 1 ;;
esac
