#!/bin/sh
# Correctness/measurement smoke only; no comparative performance verdict.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] && [ "$3" = rs ] || exit 125
unset LD_PRELOAD LD_LIBRARY_PATH
out=/tmp/out
bench=/tmp/bin/owrt-benchmark
sha256sum /tmp/bin/ubusd-rs > "$out/binary-sha256.txt"
sha256sum /tmp/bin/before-rs /sbin/ubusd "$bench" > "$out/probe-identities.txt"
sha256sum /lib/libubus.so.20251202 /lib/libubox.so.20260213 /lib/libc.so /lib/libgcc_s.so.1 > "$out/libraries.sha256"
mkdir -p /var/run/ubus
for side in c before candidate; do
    case "$side" in c) bin=/sbin/ubusd ;; before) bin=/tmp/bin/before-rs ;; candidate) bin=/tmp/bin/ubusd-rs ;; esac
    socket=/var/run/ubus/r101.sock
    rm -f "$socket"
    "$bench" exec-cpu 1 "$bin" -s "$socket" > "$out/$side-daemon.log" 2>&1 & pid=$!
    tries=0
    until ubus -s "$socket" -t 1 list >/dev/null 2>&1; do
        kill -0 "$pid"; [ "$tries" -lt 10 ]; sleep 1; tries=$((tries + 1))
    done
    cat /proc/$pid/stat > "$out/$side-stat-before.txt"
    cat /proc/$pid/status > "$out/$side-status-before.txt"
    "$bench" "$socket" "$4" 100 "$pid" > "$out/$side.json" 2> "$out/$side-client.log"
    cat /proc/$pid/stat > "$out/$side-stat-after.txt"
    cat /proc/$pid/status > "$out/$side-status-after.txt"
    kill "$pid"; wait "$pid" 2>/dev/null || true
done
sha256sum -c "$out/libraries.sha256"
touch "$out/COMPLETE"
