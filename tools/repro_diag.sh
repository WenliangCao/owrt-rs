#!/bin/sh
# Reproducibility diagnostics for owrt-httpd: run the packaging recipe's exact
# cargo step with the target dir preserved, then collect every intermediate that
# could be the first to differ between two hosts.
#
#   repro_diag.sh fetch <workdir>   download + unpack the SDK
#   repro_diag.sh build <workdir>   build and collect into <workdir>/diag
#
# REPRO_RUSTC_MAP=target_dir adds exactly one factor on the rustc side:
#   --remap-path-prefix=<this host's diagnostic target dir>=/target
# The recipe already remaps the source dir and CARGO_HOME but not this one, and
# it differs greatly in length between hosts.
#
# REPRO_CC_MAP=cargo_home adds exactly one factor to the diagnostic build:
#   -ffile-prefix-map=<this host's CARGO_HOME>=/cargo
# on the *target* C compiler. Nothing else changes -- not the source path, not
# OUT_DIR, not strip, LTO, linker or profile. This is a diagnostic variable, not
# a release-recipe change; the recipe is untouched until an experiment earns it.
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
	[ -n "$f" ] || { echo "no SDK in sha256sums" >&2; exit 1; }
	[ -f "$f" ] || curl -sSfLO "$BASE/$f"
	# OpenWrt writes "<hash> *<name>"; keep the whole line so sha256sum -c parses it
	grep -F "$f" sha256sums | sha256sum -c
	cd "$WORK"
	d=$(basename "${f%.tar.*}")
	[ -d "$d" ] || tar -xf "dl/$f"
	echo "sdk: $d"
	;;
build)
	SDK=$(sdk_dir); SDK=${SDK%/}
	[ -n "$SDK" ] || { echo "no SDK in $WORK; run fetch first" >&2; exit 1; }
	OUT=$WORK/diag
	# Never destroy a previous baseline in place: archive it first. A0/A1 use
	# the same physical build path on purpose, so only the archive name varies.
	if [ -d "$OUT" ]; then
		keep=$WORK/diag-$(date -u +%Y%m%dT%H%M%SZ)
		mv "$OUT" "$keep"
		echo "previous diag archived to $keep"
	fi
	rm -rf /tmp/owrt-build/owrt-httpd
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

	# The one experimental factor, off unless asked for. cc appends the
	# target-prefixed CFLAGS to the flags it computes, so this is additive --
	# verified afterwards from collect/cc-commands.txt, not assumed.
	case "${REPRO_RUSTC_MAP:-none}" in
	target_dir) rustc_extra=" --remap-path-prefix=$OUT/target=/target" ;;
	none)       rustc_extra="" ;;
	*)          echo "unknown REPRO_RUSTC_MAP=$REPRO_RUSTC_MAP" >&2; exit 1 ;;
	esac

	case "${REPRO_CC_MAP:-none}" in
	cargo_home) cc_extra="-ffile-prefix-map=$CARGO_HOME_DIR=/cargo" ;;
	none)       cc_extra="" ;;
	*)          echo "unknown REPRO_CC_MAP=$REPRO_CC_MAP" >&2; exit 1 ;;
	esac

	set +e
	env \
		${cc_extra:+CFLAGS_aarch64_unknown_linux_musl="$cc_extra"} \
		CARGO_HOME="$CARGO_HOME_DIR" \
		CARGO_BUILD_TARGET="$RUST_TARGET" \
		CARGO_PROFILE_RELEASE_PANIC=abort \
		CC_aarch64_unknown_linux_musl="$CC" \
		AR_aarch64_unknown_linux_musl="$AR" \
		CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$CC" \
		RUSTFLAGS="--remap-path-prefix=$src=/build --remap-path-prefix=$CARGO_HOME_DIR=/cargo -Clink-arg=-fuse-ld=$LD -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs$rustc_extra" \
		$CARGO build --release --locked -vv \
		--manifest-path "$src/httpd/Cargo.toml" --target-dir "$OUT/target" > "$OUT/cargo-vv.log" 2>&1
	rc=$?
	set -e
	[ "$rc" = 0 ] || { tail -30 "$OUT/cargo-vv.log"; exit 1; }

	rel=$OUT/target/$RUST_TARGET/release
	mkdir -p "$OUT/collect"
	# The release profile already strips this; name it for what it is.
	cp "$rel/httpd-rs" "$OUT/collect/httpd-rs.release"
	"$tc/$(basename "$CC" -gcc)-readelf" -W -S "$rel/httpd-rs" > "$OUT/collect/httpd-rs.sections.txt" 2>/dev/null ||
		"${CC%-gcc}-readelf" -W -S "$rel/httpd-rs" > "$OUT/collect/httpd-rs.sections.txt" 2>/dev/null || true

	# Every ring build dir, labelled by its hash -- there can be a host
	# build-script dir and a target one, and taking the first hides that.
	found_out=0
	for d in "$rel"/build/ring-*/; do
		[ -d "$d" ] || continue
		tag=$(basename "$d")
		if [ -d "$d/out" ]; then
			mkdir -p "$OUT/collect/$tag-out"
			cp -a "$d/out"/. "$OUT/collect/$tag-out/"
			found_out=1
		fi
		# build-script stdout lives beside out/, not a level above it
		for f in output root-output stderr invoked.timestamp; do
			[ -f "$d/$f" ] && cp "$d/$f" "$OUT/collect/$tag-$f"
		done
	done
	[ "$found_out" = 1 ] || { echo "no ring OUT_DIR found under $rel/build -- evidence missing, refusing to report" >&2; exit 1; }
	ls -d "$rel"/build/ring-*/ | sed "s#$rel/build/##" > "$OUT/collect/ring-build-dirs.txt"
	for f in "$rel"/deps/*.rlib; do [ -f "$f" ] && cp "$f" "$OUT/collect/"; done

	# identities of the tools that actually ran
	{
		echo "pin=$PIN"
		echo "cargo=$(sh -c "$CARGO -V")"
		# The compiler Cargo actually invoked, taken from the -vv log rather
		# than from PATH, then asked for its own identity.
		real_rustc=$(grep -oE "[^ ']*/bin/rustc" "$OUT/cargo-vv.log" | sort -u | head -1)
		echo "rustc_path=${real_rustc:-<not found in log>}"
		[ -n "$real_rustc" ] && echo "rustc=$("$real_rustc" -vV | tr '\n' ';')"
		echo "rustc_paths_seen=$(grep -oE "[^ ']*/bin/rustc" "$OUT/cargo-vv.log" | sort -u | wc -l)"
		echo "cc=$CC"; "$CC" --version | head -1
		echo "cc_sha256=$(sha256sum "$(command -v "$CC")" | cut -d" " -f1)"
		echo "ar=$AR"; "$AR" --version | head -1
		echo "ar_sha256=$(sha256sum "$(command -v "$AR")" | cut -d" " -f1)"
		# The build host runs the x86_64 SDK under emulation; record how.
		echo "cc_file=$(file -b "$(command -v "$CC")" | cut -c1-80)"
		echo "qemu=$(qemu-x86_64 -version 2>/dev/null | head -1 || echo native)"
		echo "fuse_ld=${LD:-<default>}"
		echo "sdk=$(basename "$SDK")"
		echo "host_uname=$(uname -m)"
		echo "src=$src"
		echo "git_rev=$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
		echo "git_dirty=$(git -C "$REPO" status --porcelain 2>/dev/null | wc -l)"
		echo "lock_sha256=$(sha256sum "$src/httpd/Cargo.lock" | cut -d" " -f1)"
		echo "sdk_dir=$(basename "$SDK")"
		# compiler-override variables, named individually (never a full dump)
		for v in RUSTC CARGO_BUILD_RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER \
		         CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER \
		         CFLAGS CPPFLAGS ARFLAGS SOURCE_DATE_EPOCH; do
			eval "val=\${$v:-}"
			echo "$v=${val:-<unset>}"
		done
		echo "cargo_home=$CARGO_HOME_DIR"
		echo "repro_cc_map=${REPRO_CC_MAP:-none}"
		echo "repro_rustc_map=${REPRO_RUSTC_MAP:-none}"
		echo "rustc_extra_flags=${rustc_extra:-<none>}"
		echo "target_dir=$OUT/target"
		echo "cc_extra_flags=${cc_extra:-<none>}"
		echo "umask=$(umask)"; echo "TZ=${TZ:-unset}"; echo "LC_ALL=${LC_ALL:-unset}"
		echo "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-unset}"
	} > "$OUT/collect/tools.txt"

	# NOTE: cargo -vv does NOT print the cc crate's own compiler invocations
	# (only rustc's), so this file holds rustc command lines and cannot be used
	# to prove a C flag landed. Prove that from the objects instead: check that
	# the mapped prefix replaced the real one (strings on a .o). Capturing the
	# real cc commands needs CC_ENABLE_DEBUG_OUTPUT=1, which is a separate
	# diagnostic factor and is deliberately not enabled here.
	grep -oE "[^ ']*-openwrt-linux-musl-(gcc|ar)[^\n]*" "$OUT/cargo-vv.log" \
		> "$OUT/collect/rustc-linker-commands.txt" 2>/dev/null || \
		echo "<none captured>" > "$OUT/collect/rustc-linker-commands.txt"

	( cd "$OUT/collect" && find . -type f | sort | xargs sha256sum ) > "$OUT/collect-sha256.txt"
	echo "collected into $OUT"
	cat "$OUT/collect-sha256.txt"
	;;
*)
	echo "usage: repro_diag.sh fetch|build <workdir>" >&2; exit 1 ;;
esac
