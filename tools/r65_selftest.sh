#!/bin/sh
# Prove r65 can fail.
#
# Astra's review replaced both supervisors with /bin/false and the harness
# still reported `r65: ok` with a zero-byte diff. A gate that cannot go red
# is not a gate, so this runs that exact injection and REQUIRES a non-zero
# exit. It is cheap and belongs in front of any run whose result will be
# quoted as evidence.
#
# Usage: r65_selftest.sh <rootfs> <candidate> <outdir> [examples dir]
set -eu
root=$1
cand=$2
out=$3
ex=${4:-}
mkdir -p "$out"

here=$(dirname "$0")
sed \
	-e 's#^DBGLVL=0 /sbin/procd -S -I /tmp/initd -R /tmp/rcd.*#/bin/false \&#' \
	-e 's#^/sbin/procd-rs -I /tmp/initd.*#/bin/false \&#' \
	"$here/r65_procd_diff.sh" > "$out/r65-no-supervisors.sh"

# Confirm the substitution actually happened; a silently-unmodified copy
# would "pass" this self-test for the worst possible reason.
if ! grep -q '/bin/false &' "$out/r65-no-supervisors.sh"; then
	echo "r65-selftest: could not inject the fault -- the starter lines moved" >&2
	exit 2
fi
if [ "$(grep -c '/bin/false &' "$out/r65-no-supervisors.sh")" != 2 ]; then
	echo "r65-selftest: expected to disable exactly two supervisors" >&2
	exit 2
fi

rc=0
sh "$out/r65-no-supervisors.sh" "$root" "$cand" "$out/negative" $ex \
	> "$out/negative.log" 2>&1 || rc=$?

if [ "$rc" = 0 ]; then
	echo "r65-selftest: FAILED -- the harness passed with no supervisor running" >&2
	echo "  see $out/negative.log" >&2
	exit 1
fi
echo "r65-selftest: ok (harness correctly failed with no supervisor, rc=$rc)"
