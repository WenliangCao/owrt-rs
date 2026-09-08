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

# A non-zero exit is not by itself proof that the INJECTION did it. If the
# candidate is missing, or the rootfs is wrong, the negative run fails for
# that reason and this script would report "correctly failed" -- passing for
# precisely the wrong reason, which is the bug this script exists to catch.
# So check the inputs first, then check WHY the run went red.
[ -x "$cand" ] || { echo "r65-selftest: candidate is missing or not executable: $cand" >&2; exit 2; }
[ -d "$root" ] || { echo "r65-selftest: rootfs is not a directory: $root" >&2; exit 2; }
[ -z "$ex" ] || [ -x "$ex/notifier" ] || { echo "r65-selftest: examples dir has no notifier: $ex" >&2; exit 2; }

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

# It went red -- but for the right reason? The injection removes the
# supervisor, so the readiness gate is the check that MUST have fired. A run
# that died early (bad rootfs, harness syntax error, no candidate) also exits
# non-zero and would otherwise be read as a successful self-test.
for want in \
	'supervisor was not ready' \
	'never reported a pid at all' \
	'did not do what the case expected'
do
	if ! grep -q "$want" "$out/negative.log"; then
		echo "r65-selftest: FAILED -- it went red, but not because of the injection." >&2
		echo "  expected a line containing: $want" >&2
		echo "  see $out/negative.log" >&2
		exit 1
	fi
done

# And it must have got far enough to compare something, otherwise "red" only
# means the script fell over.
if [ ! -s "$out/negative/c-calls.txt" ] || [ ! -s "$out/negative/rs-calls.txt" ]; then
	echo "r65-selftest: FAILED -- the negative run produced no calls to judge" >&2
	exit 1
fi

echo "r65-selftest: ok (harness correctly failed with no supervisor, rc=$rc)"
echo "r65-selftest:    and it failed via the readiness gate, not by falling over"

# Second injection: a drive script that stops part-way. This is the failure
# the no-supervisor injection CANNOT catch, because the supervisor is fine --
# both sides simply run fewer cases, identically, so the diff is clean and
# the readiness gate is satisfied. Truncating after drive.done is written
# defeats the completion marker too. Only the case-marker floor sees it.
sed -e 's#^printf -- .--- F13: pidfile must be written.*#echo "TRUNCATED-HERE" > /tmp/out/drive.done; exit 0#' \
	"$here/r65_procd_diff.sh" > "$out/r65-truncated.sh"
if ! grep -q 'TRUNCATED-HERE' "$out/r65-truncated.sh"; then
	echo "r65-selftest: could not inject the truncation -- the anchor moved" >&2
	exit 2
fi

trc=0
sh "$out/r65-truncated.sh" "$root" "$cand" "$out/truncated" $ex \
	> "$out/truncated.log" 2>&1 || trc=$?

if [ "$trc" = 0 ]; then
	echo "r65-selftest: FAILED -- a drive that stopped part-way still passed" >&2
	echo "  see $out/truncated.log" >&2
	exit 1
fi
if ! grep -q 'the drive stopped early' "$out/truncated.log"; then
	echo "r65-selftest: FAILED -- the truncated run went red for another reason" >&2
	echo "  expected the case-marker floor to fire; see $out/truncated.log" >&2
	exit 1
fi
echo "r65-selftest: ok (a truncated drive is caught by the case-marker floor, rc=$trc)"
