#!/bin/sh
# Diagnostic unit binaries, not a daemon performance comparison.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] && [ "$3" = rs ] || exit 125
out=/tmp/out
export TMPDIR=/tmp/epoch-tests
mkdir -p "$TMPDIR"
sha256sum /tmp/bin/ubusd-rs > "$out/binary-sha256.txt"
sha256sum /tmp/bin/before-rs > "$out/before-sha256.txt"
rc=0
/tmp/bin/before-rs event_round_wrap --test-threads=1 --nocapture > "$out/before.log" 2>&1 || rc=$?
[ "$rc" -eq 101 ]
grep -F 'test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 29 filtered out' "$out/before.log"
grep -F 'last_seen=0: wrap must deliver once, not omit or duplicate' "$out/before.log"
grep -F '  left: 0' "$out/before.log"
grep -F ' right: 1' "$out/before.log"
/tmp/bin/ubusd-rs --test-threads=1 --nocapture > "$out/fixed.log" 2>&1
grep -F 'test result: ok. 32 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out' "$out/fixed.log"
printf '{"expected_before_exit":101,"fixed_exit":0,"diagnostic_only":true}\n' > "$out/reproduction.json"
touch "$out/COMPLETE"
