#!/bin/sh
# Check every kernel constant netifd-rs hard-codes against the real headers.
#
# The constants in components/netifd/src/{netlink,sys,ethtool}.rs are transcribed from
# <linux/*.h>. A transcription slip is not a compile error and often not even a
# runtime error — it silently sets the wrong bridge option. This extracts the
# names and values from the Rust source, generates a C program that prints the
# same names from the headers, and diffs the two.
#
# Usage: check_netlink_consts.sh [rust src dir] [cc]
#
# `cc` may carry flags, e.g. "gcc -I<sdk>/include" so the UAPI headers are the
# target kernel's rather than the build host's.
set -eu
src=${1:-components/netifd/src}
cc=${2:-cc}
tmp=$(mktemp -d /tmp/nlconst-XXXXXX)
trap 'rm -rf "$tmp"' EXIT

# Only names that exist in the UAPI headers; anything else in the file (our own
# helpers, netlink group numbers used as `1 << (n-1)`) is skipped by the filter.
grep -hoE '^(pub )?const (RTM_[A-Z0-9_]+|IFLA_[A-Z0-9_]+|IFA_[A-Z0-9_]+|RTA_[A-Z0-9_]+|RTAX_[A-Z0-9_]+|RT_TABLE_[A-Z]+|RT_SCOPE_[A-Z]+|RTN_[A-Z]+|RTPROT_[A-Z]+|RTNH_F_[A-Z]+|IFF_[A-Z_]+|NLM_F_[A-Z]+|NLMSG_[A-Z]+|NLA_F_[A-Z]+|AF_[A-Z0-9]+|RTNLGRP_[A-Z0-9_]+|NDA_[A-Z0-9_]+|NUD_[A-Z0-9_]+|SIOC[A-Z0-9_]+|ETHTOOL_[A-Z0-9_]+): [a-z0-9]+ = [^;]+;' \
	"$src"/netlink.rs "$src"/sys.rs "$src"/ethtool.rs \
	| sed -E 's/^(pub )?const ([A-Z0-9_]+): [a-z0-9]+ = (.*);$/\2 \3/' \
	| sort -u > "$tmp/rust.txt"

[ -s "$tmp/rust.txt" ] || { echo "no constants found in $src"; exit 1; }

{
	echo '#include <stdio.h>'
	echo '#include <linux/netlink.h>'
	echo '#include <linux/rtnetlink.h>'
	echo '#include <linux/if_link.h>'
	echo '#include <linux/if_addr.h>'
	echo '#include <linux/if.h>'
	echo '#include <linux/neighbour.h>'
	echo '#include <linux/sockios.h>'
	echo '#include <linux/ethtool.h>'
	echo '#include <sys/socket.h>'
	echo 'int main(void) {'
	while read -r name _; do
		printf '  printf("%%s %%ld\\n", "%s", (long)%s);\n' "$name" "$name"
	done < "$tmp/rust.txt"
	echo '  return 0; }'
} > "$tmp/c.c"

if ! $cc -o "$tmp/c" "$tmp/c.c" 2> "$tmp/cc.log"; then
	echo "the generated program does not compile — a name here is not a kernel name:"
	grep -E 'error|undeclared' "$tmp/cc.log" | head -20
	exit 1
fi

"$tmp/c" | sort -u > "$tmp/kernel.txt"

# Compare numerically: the Rust side may write 0x100 or `A | B` where the
# header says a plain decimal.
norm() {
	python3 -c '
import sys
for line in open(sys.argv[1]):
    name, _, val = line.strip().partition(" ")
    v = 0
    for part in val.split("|"):
        v |= int(part.strip(), 0)
    print(name, v)
' "$1" | sort -u
}
norm "$tmp/rust.txt" > "$tmp/rust.n"
norm "$tmp/kernel.txt" > "$tmp/kernel.n"

if diff -u "$tmp/kernel.n" "$tmp/rust.n" > "$tmp/diff.txt"; then
	echo "RESULT: all $(wc -l < "$tmp/rust.n") constants match the kernel headers"
else
	echo "RESULT: MISMATCH (- kernel, + rust)"
	cat "$tmp/diff.txt"
	exit 1
fi
