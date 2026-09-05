#!/bin/sh
# Negative checks for the toolchain pin. No SDK download, no network, no device:
# it only runs `rustc -V` / `cargo -V` under different environments and asserts
# that check-toolchain refuses the ones a release must never use.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
fail=0

expect() { # expect <want-exit> <name> <cmd...>
	want=$1; name=$2; shift 2
	if "$@" >/dev/null 2>&1; then got=0; else got=1; fi
	if [ "$got" = "$want" ]; then
		echo "ok       $name"
	else
		echo "NOT OK   $name (wanted exit-nonzero=$want, got $got)" >&2
		fail=1
	fi
}

pin=$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)

# Absolute paths to a second, known-different compiler. Do NOT switch versions
# with RUSTUP_TOOLCHAIN here: that only works when the entry point is a rustup
# proxy, and PATH may point straight at one toolchain's own cargo.
old=$(rustup toolchain list 2>/dev/null | sed 's/ .*//' | grep -E '^[0-9]' | grep -v "^$pin" | head -1 || true)
old_rustc=; old_cargo=
if [ -n "$old" ]; then
	old_rustc=$(rustup which --toolchain "$old" rustc 2>/dev/null || true)
	old_cargo=$(rustup which --toolchain "$old" cargo 2>/dev/null || true)
	[ -x "$old_rustc" ] || old_rustc=
	[ -x "$old_cargo" ] || old_cargo=
fi

expect 0 "pinned toolchain accepted" sh tools/toolchain_identity.sh
expect 0 "CARGO pinned to the same version accepted" \
	env CARGO="env RUSTUP_TOOLCHAIN=$pin cargo" sh tools/toolchain_identity.sh
expect 1 "RUSTC pointing at a missing binary refused" \
	env RUSTC=/nonexistent/rustc sh tools/toolchain_identity.sh
for v in RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER; do
	expect 1 "$v refused" env "$v=/usr/bin/true" sh tools/toolchain_identity.sh
done
expect 0 "wrapper allowed when explicitly unofficial" \
	env OWRT_ALLOW_TOOLCHAIN_OVERRIDE=1 RUSTC_WRAPPER=/usr/bin/true sh tools/toolchain_identity.sh
expect 1 "cargo --config override refused" \
	env CARGO="cargo --config build.rustc=\"/usr/bin/true\"" sh tools/toolchain_identity.sh

if [ -n "$old_rustc" ]; then
	expect 1 "RUSTC on $old refused" env RUSTC="$old_rustc" sh tools/toolchain_identity.sh
	expect 1 "CARGO_BUILD_RUSTC on $old refused" env CARGO_BUILD_RUSTC="$old_rustc" sh tools/toolchain_identity.sh
else
	echo "skip     no second toolchain rustc; version-mismatch cases not exercised"
fi
if [ -n "$old_cargo" ]; then
	expect 1 "CARGO on $old refused" env CARGO="$old_cargo" sh tools/toolchain_identity.sh
else
	echo "skip     no second toolchain cargo; CARGO mismatch case not exercised"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sed 's/^channel = .*/channel = "0.0.0-nonexistent"/' rust-toolchain.toml > "$tmp/bad.toml"
cp rust-toolchain.toml "$tmp/good.toml"
cp "$tmp/bad.toml" rust-toolchain.toml
expect 1 "bogus pin refused" sh tools/toolchain_identity.sh
mv rust-toolchain.toml "$tmp/parked.toml"
expect 1 "missing pin refused" sh tools/toolchain_identity.sh
cp "$tmp/good.toml" rust-toolchain.toml

[ "$fail" = 0 ] || exit 1
echo "toolchain negative checks: all as expected"
