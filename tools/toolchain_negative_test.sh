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
old=$(rustup toolchain list 2>/dev/null | sed 's/ .*//' | grep -v "^$pin" | grep -E '^[0-9]' | head -1 || true)

expect 0 "pinned toolchain accepted" sh tools/toolchain_identity.sh
expect 0 "CARGO pinned to the same version accepted" \
	env CARGO="env RUSTUP_TOOLCHAIN=$pin cargo" sh tools/toolchain_identity.sh
expect 1 "RUSTC_WRAPPER refused" env RUSTC_WRAPPER=/usr/bin/true sh tools/toolchain_identity.sh
expect 0 "RUSTC_WRAPPER allowed when explicitly unofficial" \
	env OWRT_ALLOW_TOOLCHAIN_OVERRIDE=1 RUSTC_WRAPPER=/usr/bin/true sh tools/toolchain_identity.sh
expect 1 "RUSTC pointing at a missing binary refused" \
	env RUSTC=/nonexistent/rustc sh tools/toolchain_identity.sh

if [ -n "$old" ]; then
	expect 1 "CARGO on $old refused" env CARGO="env RUSTUP_TOOLCHAIN=$old cargo" sh tools/toolchain_identity.sh
	rustc_old=$(rustup which --toolchain "$old" rustc 2>/dev/null || true)
	[ -n "$rustc_old" ] && expect 1 "RUSTC on $old refused" env RUSTC="$rustc_old" sh tools/toolchain_identity.sh
else
	echo "skip     no second toolchain installed; version-mismatch cases not exercised"
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
