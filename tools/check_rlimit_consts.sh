#!/bin/sh
# Check the RLIMIT_* numbers procd-rs hard-codes against the real headers.
#
# The table in components/procd/src/sys.rs maps procd's limit names to resource
# numbers. Those numbers are architecture-dependent -- RLIMIT_NOFILE is 7 on
# Linux and 8 on Darwin -- and a wrong one is not a compile error: it silently
# sets a different limit than the service asked for. This extracts the pairs
# from the Rust source, generates a C program that prints the same names from
# the headers, and diffs the two.
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

sed -n 's/^[[:space:]]*("\([a-z]*\)", \([0-9]*\)),$/\1 \2/p' "$src" | sort -u > "$tmp/rust.txt"
[ -s "$tmp/rust.txt" ] || { echo "no limits found in $src"; exit 1; }

{
	echo '#include <stdio.h>'
	echo '#include <sys/resource.h>'
	echo 'int main(void) {'
	while read -r name _; do
		up=$(echo "$name" | tr 'a-z' 'A-Z')
		printf '  printf("%s %%d\\n", RLIMIT_%s);\n' "$name" "$up"
	done < "$tmp/rust.txt"
	echo '  return 0;'
	echo '}'
} > "$tmp/probe.c"

$cc -o "$tmp/probe" "$tmp/probe.c"
"$tmp/probe" | sort -u > "$tmp/c.txt"

if diff -u "$tmp/rust.txt" "$tmp/c.txt"; then
	echo "rlimit constants: $(wc -l < "$tmp/rust.txt" | tr -d ' ') ok"
else
	echo "rlimit constants DISAGREE with the headers" >&2
	exit 1
fi
