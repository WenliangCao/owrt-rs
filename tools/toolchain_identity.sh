#!/bin/sh
# The one place "which compiler is this really" is answered. Both the Makefile
# check and the release manifest source it, so the identity that is verified is
# the identity that gets recorded.
#
# Emits KEY=VALUE lines on stdout:
#   channel        pinned version from rust-toolchain.toml
#   cargo_bin      the cargo entry point ($CARGO, else cargo)
#   rustc_bin      the compiler cargo will use ($RUSTC, else rustc)
#   cargo_version  cargo -V from that entry point
#   rustc_version  rustc -V from that compiler
#   rustc_verbose  rustc -vV, newlines replaced by '; '
#   official       yes when nothing overrides the pin, no otherwise
#   override       empty, or why `official` is no
#
# Exits non-zero when the pin is missing, the compiler cannot be run, or the
# effective version differs from the pin. An override makes `official=no`; set
# OWRT_ALLOW_TOOLCHAIN_OVERRIDE=1 to allow it to continue anyway (for A/B
# experiments), never for a release.
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
pin=$repo/rust-toolchain.toml
[ -f "$pin" ] || { echo "no rust-toolchain.toml at $pin" >&2; exit 1; }
channel=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$pin")
[ -n "$channel" ] || { echo "rust-toolchain.toml has no channel" >&2; exit 1; }

override=
note() { override=${override:+$override, }$1; }

# Cargo picks the entry point from $CARGO and the compiler from $RUSTC,
# $CARGO_BUILD_RUSTC (the env form of build.rustc), a wrapper, or a config file.
# Checking `rustc` on PATH would miss every one of them.
#
# $CARGO, $RUSTC and $CARGO_BUILD_RUSTC are legitimate pinning mechanisms (the
# release pipeline uses `env RUSTUP_TOOLCHAIN=<pin> cargo`), so they are
# resolved and version-checked rather than rejected outright. A wrapper cannot
# be version-checked -- it can substitute flags or the compiler itself -- so it
# marks the build unofficial.
cargo_bin=${CARGO:-cargo}
# Precedence follows Cargo: RUSTC beats build.rustc / CARGO_BUILD_RUSTC.
if [ -n "${RUSTC:-}" ]; then
	rustc_bin=$RUSTC
elif [ -n "${CARGO_BUILD_RUSTC:-}" ]; then
	rustc_bin=$CARGO_BUILD_RUSTC
else
	# Ask through the same entry point, so `env RUSTUP_TOOLCHAIN=x cargo`
	# is answered by that toolchain's rustc and not by whatever PATH has.
	rustc_bin=$(printf '%s' "$cargo_bin" | sed 's/cargo$/rustc/')
	[ "$rustc_bin" = "$cargo_bin" ] && rustc_bin=rustc
fi
for v in RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER; do
	eval "val=\${$v:-}"
	[ -n "$val" ] && note "$v=$val"
done
# `cargo --config build.rustc=...` bypasses every variable above.
case "$cargo_bin" in
*--config*) note "--config in CARGO" ;;
esac
# Cargo reads .cargo/config.toml from the working directory upward, then
# $CARGO_HOME; a build.rustc there overrides the compiler silently.
dir=$repo
while :; do
	for cfg in "$dir/.cargo/config.toml" "$dir/.cargo/config"; do
		[ -f "$cfg" ] || continue
		grep -qE '^[[:space:]]*(rustc|rustc-wrapper|rustc-workspace-wrapper)[[:space:]]*=' "$cfg" && note "compiler override in $cfg"
	done
	[ "$dir" = "/" ] && break
	dir=$(dirname "$dir")
done
for cfg in "${CARGO_HOME:-$HOME/.cargo}/config.toml" "${CARGO_HOME:-$HOME/.cargo}/config"; do
	[ -f "$cfg" ] || continue
	grep -qE '^[[:space:]]*(rustc|rustc-wrapper|rustc-workspace-wrapper)[[:space:]]*=' "$cfg" && note "compiler override in $cfg"
done

# $CARGO may carry a leading `env VAR=...`; run it through sh so both forms work.
cargo_version=$(sh -c "$cargo_bin -V" 2>/dev/null) || { echo "cannot run cargo ($cargo_bin)" >&2; exit 1; }
rustc_version=$(sh -c "$rustc_bin -V" 2>/dev/null) || { echo "cannot run rustc ($rustc_bin)" >&2; exit 1; }
rustc_verbose=$(sh -c "$rustc_bin -vV" 2>/dev/null | tr '\n' ';' | sed 's/;/; /g')

official=yes
[ -n "$override" ] && official=no

printf 'channel=%s\n' "$channel"
printf 'cargo_bin=%s\n' "$cargo_bin"
printf 'rustc_bin=%s\n' "$rustc_bin"
printf 'cargo_version=%s\n' "$cargo_version"
printf 'rustc_version=%s\n' "$rustc_version"
printf 'rustc_verbose=%s\n' "$rustc_verbose"
printf 'official=%s\n' "$official"
printf 'override=%s\n' "$override"

fail=0
case "$rustc_version" in
*" $channel "*) ;;
*) echo "effective rustc is not the pinned $channel: $rustc_version ($rustc_bin)" >&2; fail=1 ;;
esac
case "$cargo_version" in
*" $channel "*) ;;
*) echo "effective cargo is not the pinned $channel: $cargo_version ($cargo_bin)" >&2; fail=1 ;;
esac
[ "$fail" = 0 ] || exit 1
if [ "$official" = no ] && [ "${OWRT_ALLOW_TOOLCHAIN_OVERRIDE:-0}" != 1 ]; then
	echo "compiler overridden ($override); set OWRT_ALLOW_TOOLCHAIN_OVERRIDE=1 for an unofficial build" >&2
	exit 1
fi
