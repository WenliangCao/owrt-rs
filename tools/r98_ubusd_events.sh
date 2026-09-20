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
    socket=/var/run/ubus/r98.sock
    rm -f "$socket"
    "$bin" -s "$socket" > "$out/$side-daemon.log" 2>&1 & pid=$!
    tries=0
    until ubus -s "$socket" -t 1 list >/dev/null 2>&1; do
        kill -0 "$pid"; [ "$tries" -lt 10 ]; sleep 1; tries=$((tries + 1))
    done
    for scenario in object_events events monitor release utf8 monitor_lookup method_acl; do
        /tmp/bin/owrt-benchmark "$socket" "$scenario" > "$out/$side-$scenario.txt" 2> "$out/$side-$scenario.log"
    done
    kill "$pid"; wait "$pid" 2>/dev/null || true
done
for scenario in object_events events monitor release utf8 monitor_lookup method_acl; do
    cmp "$out/c-$scenario.txt" "$out/before-$scenario.txt"
    cmp "$out/c-$scenario.txt" "$out/candidate-$scenario.txt"
done
[ "$(wc -l < "$out/c-object_events.txt")" -eq 6 ]
[ "$(wc -l < "$out/c-method_acl.txt")" -eq 14 ]
! grep -q 'canonical=false' "$out/c-method_acl.txt"
touch "$out/COMPLETE"
