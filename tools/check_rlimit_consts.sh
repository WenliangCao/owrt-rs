#!/bin/sh
# Check the RLIMIT_* numbers procd-rs hard-codes against the real headers.
#
# The table in components/procd/src/sys.rs maps procd's limit names to resource
# numbers. Those numbers are architecture-dependent -- RLIMIT_NOFILE is 7 on
# Linux and 8 on Darwin -- and a wrong one is not a compile error: it silently
# sets a different limit than the service asked for. This extracts the pairs
# from the Rust table and compiles C static assertions against the headers.
# The target executable need not run on the build host.
#
# Usage: check_rlimit_consts.sh [rust src file] [cc]
#
# `cc` may carry flags so the headers are the target's rather than the host's.
# Run it with the target toolchain: on a Darwin build host the host cc will
# disagree, and that disagreement is the point.
set -eu
src=${1:-components/procd/src/sys.rs}
cc=${2:-cc}
tmp=$(mktemp -d /tmp/rlconst-XXXXXX)
trap 'rm -rf "$tmp"' EXIT

# Other tables (notably syslog facilities) have the same tuple shape.
sed -n '/^pub const RLIMIT_NAMES:/,/^];/p' "$src" |
    sed -n 's/^[[:space:]]*("\([a-z]*\)", \([0-9]*\)),$/\1 \2/p' |
    sort -u > "$tmp/rust.txt"
[ -s "$tmp/rust.txt" ] || { echo "no limits found in $src"; exit 1; }

{
	echo '#include <sys/resource.h>'
	while read -r name value; do
		up=$(echo "$name" | tr 'a-z' 'A-Z')
		printf '_Static_assert(RLIMIT_%s == %s, "RLIMIT_%s mismatch");\n' "$up" "$value" "$up"
	done < "$tmp/rust.txt"
} > "$tmp/probe.c"

if $cc -c -o "$tmp/probe.o" "$tmp/probe.c"; then
	echo "rlimit constants: $(wc -l < "$tmp/rust.txt" | tr -d ' ') ok"
else
	echo "rlimit constants DISAGREE with the headers" >&2
	exit 1
fi
