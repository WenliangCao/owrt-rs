#!/bin/bash
# Prove a real namespace run with BOTH netifd implementations disabled fails
# through the survival gate, not a missing file or a shell error.
# Usage: netifd_suite_selftest.sh <rootfs> <candidate> <outdir>
set -eu
root=$1; cand=$2; out=$3
here=$(cd "$(dirname "$0")" && pwd)
[ -d "$root" ] && [ -x "$cand" ] || { echo "netifd-selftest: missing inputs" >&2; exit 2; }
mkdir -p "$out"
work=$(mktemp -d /tmp/netifd-selftest-XXXXXX)
trap 'rm -rf "$work"' EXIT
sed \
    -e 's#^/sbin/netifd >.*#/bin/false \&#' \
    -e 's#^/sbin/netifd-rs >.*#/bin/false \&#' \
    "$here/r49_daemon_diff.sh" > "$work/r49-no-daemons.sh"
[ "$(grep -c '^/bin/false &' "$work/r49-no-daemons.sh")" = 2 ] || {
    echo "netifd-selftest: could not disable exactly two daemons" >&2; exit 2;
}
cp "$here/audit_checks.py" "$work/audit_checks.py"
rc=0
bash "$work/r49-no-daemons.sh" "$root" "$cand" "$out/negative" > "$out/negative.log" 2>&1 || rc=$?
[ "$rc" -ne 0 ] || { echo "netifd-selftest: both-dead run incorrectly passed" >&2; exit 1; }
for side in c rs; do
    [ "$(cat "$out/negative/$side-alive.txt")" = no ] || {
        echo "netifd-selftest: $side injection did not stop the daemon" >&2; exit 1;
    }
    [ -s "$out/negative/$side-ubus.txt" ] || {
        echo "netifd-selftest: $side produced no transcript" >&2; exit 1;
    }
done
grep -q 'evidence gate FAILED: c: netifd did not survive' "$out/negative.log" || {
    echo "netifd-selftest: failed for a reason other than the injected fault" >&2; exit 1;
}
echo "netifd-selftest: PASS (both dead; survival gate rejected the run, rc=$rc)"
