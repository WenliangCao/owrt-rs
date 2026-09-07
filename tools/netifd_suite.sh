#!/bin/bash
# The netifd differential suite: an explicit list of cases, one verdict each.
#
# Usage: netifd_suite.sh <rootfs-files> <netifd-rs musl binary> [outdir] [example-dir]
#        SUBSET="r52 r60"  netifd_suite.sh ...     run only these
#
# <example-dir> holds the musl-built `devstatus` and `ifstatus` probes that r47
# and r48 drive; it defaults to the directory netifd-rs sits in.
#
# The list is explicit rather than a glob because a glob silently drops a new
# case: `r5*_*.sh` never matched r60, so the harness written for the wireless
# handler was never once run by "the suite". A missing probe binary is a hard
# failure, not a skip -- with every path wrong this script used to print
# thirteen SKIPs and then `SUITE: all identical` with exit 0.
set -u
rootfs=${1:-}; cand=${2:-}; out=${3:-/tmp/netifd-suite}; exdir=${4:-}
here=$(cd "$(dirname "$0")" && pwd)
[ -n "$exdir" ] || exdir=$(dirname "$cand")
mkdir -p "$out"

# name | script | which binary | extra env
CASES='
r47|r47_devstatus_diff.sh|devstatus|
r48|r48_ifstatus_diff.sh|ifstatus|
r49|r49_daemon_diff.sh|netifd|
r50|r50_cycle_loop.sh|netifd|
r51|r51_event_diff.sh|netifd|
r52|r52_dhcp_diff.sh|netifd|
r53|r53_fault_diff.sh|netifd|
r54|r54_reload_diff.sh|netifd|
r55|r55_writemethods_diff.sh|netifd|
r56|r56_dhcpv6_diff.sh|netifd|
r57|r57_busreconnect_diff.sh|netifd|
r58|r58_devobjects_diff.sh|netifd|
r59|r59_wireless_diff.sh|netifd|
r60_up_cmds|r60_wireless_handler_diff.sh|netifd|MODE=up CMDS=yes
r60_up|r60_wireless_handler_diff.sh|netifd|MODE=up CMDS=no
r60_fail_cmds|r60_wireless_handler_diff.sh|netifd|MODE=fail CMDS=yes
r60_fail|r60_wireless_handler_diff.sh|netifd|MODE=fail CMDS=no
r60_flood|r60_wireless_handler_diff.sh|netifd|MODE=flood CMDS=no
'

# Everything the run needs must exist up front. Discovering a missing rootfs
# thirteen cases in is how a suite reports success having compared nothing.
missing=0
for f in "$rootfs" "$cand" "$exdir/devstatus" "$exdir/ifstatus"; do
	[ -e "$f" ] || { echo "MISSING: $f"; missing=1; }
done
while IFS= read -r line; do
	[ -n "$line" ] || continue
	script=$(echo "$line" | cut -d'|' -f2)
	[ -f "$here/$script" ] || { echo "MISSING: $here/$script"; missing=1; }
done <<< "$CASES"
if [ $missing -ne 0 ]; then
	echo "SUITE: NOT RUN -- required inputs are missing"
	exit 2
fi

pass=0; failn=0; skipped=0; total=0
while IFS= read -r line; do
	[ -n "$line" ] || continue
	name=$(echo "$line" | cut -d'|' -f1)
	script=$(echo "$line" | cut -d'|' -f2)
	which=$(echo "$line" | cut -d'|' -f3)
	envs=$(echo "$line" | cut -d'|' -f4)
	total=$((total+1))
	if [ -n "${SUBSET:-}" ] && ! echo " $SUBSET " | grep -q " $name "; then
		skipped=$((skipped+1)); continue
	fi
	case $which in
		devstatus) bin=$exdir/devstatus ;;
		ifstatus)  bin=$exdir/ifstatus ;;
		*)         bin=$cand ;;
	esac
	# a fresh directory per case: these harnesses append to files, and reusing
	# one lets a previous run's records be read as this run's
	rm -rf "$out/$name"; mkdir -p "$out/$name"
	start=$(date +%s)
	# bash, not sh: several harnesses use process substitution, and dash's
	# syntax error on those reads nothing like a difference
	if env $envs bash "$here/$script" "$rootfs" "$bin" "$out/$name" > "$out/$name.log" 2>&1; then
		v=ok; pass=$((pass+1))
	else
		v=FAILED; failn=$((failn+1))
	fi
	printf '%-16s %-7s %4ss  %s\n' "$name" "$v" "$(( $(date +%s) - start ))" "$envs"
	[ "$v" = FAILED ] && tail -20 "$out/$name.log" | sed 's/^/    /'
done <<< "$CASES"

ran=$((pass+failn))
echo "SUITE: $ran of $total run -- $pass passed, $failn failed, $skipped not selected"
[ $ran -eq 0 ] && { echo "SUITE: NOTHING RAN"; exit 2; }
[ $failn -eq 0 ] || exit 1
[ $skipped -eq 0 ] || { echo "SUITE: partial run, not a full pass"; exit 0; }
echo "SUITE: full pass"
exit 0
