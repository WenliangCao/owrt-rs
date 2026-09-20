#!/bin/sh
# Correctness differential only; always entered through the guarded namespace.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] && [ "$3" = rs ] || exit 125
out=/tmp/out
sha256sum /tmp/bin/ubusd-rs > "$out/binary-sha256.txt"
sha256sum /tmp/bin/owrt-benchmark /tmp/bin/before-rs /sbin/ubusd > "$out/probe-identities.txt"
mkdir -p /var/run/ubus
cat > /usr/share/acl.d/r97-method.json <<'JSON'
{"user":"nobody","access":{"r97.wire":{"methods":["ping"]},"r97.denied":{"methods":["ping"]},"r97.config":{"methods":["ping\u0000suffix"]},"r97.wildcard":{"methods":["*\u0000suffix"]},"r97.empty":{"methods":[""]},"r97.padding":{"methods":["ab"]},"r97.normal":{"methods":["ping"]}}}
JSON
chmod 644 /usr/share/acl.d/r97-method.json
for side in c before candidate; do
    case "$side" in c) bin=/sbin/ubusd ;; before) bin=/tmp/bin/before-rs ;; candidate) bin=/tmp/bin/ubusd-rs ;; esac
    socket=/var/run/ubus/r97.sock
    rm -f "$socket"
    "$bin" -s "$socket" > "$out/$side-daemon.log" 2>&1 & pid=$!
    tries=0
    until ubus -s "$socket" -t 1 list >/dev/null 2>&1; do
        kill -0 "$pid"; [ "$tries" -lt 10 ]; sleep 1; tries=$((tries + 1))
    done
    /tmp/bin/owrt-benchmark "$socket" method_acl > "$out/$side.txt" 2> "$out/$side-probe.log"
    kill "$pid"; wait "$pid" 2>/dev/null || true
    [ "$(wc -l < "$out/$side.txt")" -eq 14 ]
done
cmp "$out/c.txt" "$out/candidate.txt"
! cmp -s "$out/c.txt" "$out/before.txt"
! grep -q 'canonical=false' "$out/c.txt"
[ "$(grep -c 'visible=true expected=true' "$out/c.txt")" -eq 6 ]
grep -q 'r97.denied visible=false expected=false' "$out/c.txt"
grep -q 'r97.wire visible=false expected=true' "$out/before.txt"
grep -q 'r97.config visible=false expected=true' "$out/before.txt"
grep -q 'r97.padding canonical=false' "$out/before.txt"
touch "$out/COMPLETE"
