#!/bin/bash
# The netifd differential suite: every harness, one line of verdict each.
#
# Usage: netifd_suite.sh <rootfs-files> <netifd-rs musl binary> [outdir] [example-dir]
#
# <example-dir> holds the musl-built `devstatus` and `ifstatus` example probes
# that r47 and r48 drive; it defaults to the directory netifd-rs sits in.
set -u
rootfs=$1; cand=$2; out=${3:-/tmp/netifd-suite}
exdir=${4:-$(dirname "$cand")}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
fail=0
for h in "$here"/r4[7-9]_*.sh "$here"/r5*_*.sh; do
	n=$(basename "$h" .sh)
	case $n in netifd_suite) continue ;; esac
	# r46/r47/r48 drive the example probes, not the daemon; the rest take
	# netifd-rs. Handing the daemon to a probe harness produces an argument
	# error that reads like a difference.
	case $n in
		r47_*) bin=$exdir/devstatus ;;
		r48_*) bin=$exdir/ifstatus ;;
		*)     bin=$cand ;;
	esac
	if [ ! -x "$bin" ]; then
		printf '%-26s %-7s (no binary at %s)\n' "$n" SKIP "$bin"
		continue
	fi
	start=$(date +%s)
	# bash, not sh: several harnesses use process substitution, and dash
	# fails them with a syntax error that looks nothing like a difference
	if bash "$h" "$rootfs" "$bin" "$out/$n" > "$out/$n.log" 2>&1; then
		v=ok
	else
		v=FAILED; fail=1
	fi
	printf '%-26s %-7s %4ss\n' "$n" "$v" "$(( $(date +%s) - start ))"
	[ "$v" = FAILED ] && tail -20 "$out/$n.log" | sed 's/^/    /'
done
[ $fail -eq 0 ] && echo "SUITE: all identical" || echo "SUITE: FAILURES"
exit $fail
