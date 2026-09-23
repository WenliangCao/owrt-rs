#!/bin/sh
# R134 FD placement differential (guarded namespace only). C and R131 (C-exact
# receive) must agree on all six cases; the R134 candidate must match C on the
# three sender-framed cases and pass witness/single-delivery/no-leak on all.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] && [ "$3" = rs ] || exit 125
unset LD_PRELOAD LD_LIBRARY_PATH
out=/tmp/out
sha256sum /tmp/bin/ubusd-rs /tmp/bin/before-rs /tmp/bin/owrt-benchmark /sbin/ubusd > "$out/identities.txt"
mkdir -p /var/run/ubus
for side in c before candidate; do
    case "$side" in c) bin=/sbin/ubusd ;; before) bin=/tmp/bin/before-rs ;; candidate) bin=/tmp/bin/ubusd-rs ;; esac
    socket=/var/run/ubus/r134.sock
    rm -f "$socket"
    "$bin" -s "$socket" > "$out/$side-daemon.log" 2>&1 & pid=$!
    tries=0
    until ubus -s "$socket" -t 1 list >/dev/null 2>&1; do
        kill -0 "$pid"; [ "$tries" -lt 10 ]; sleep 1; tries=$((tries + 1))
    done
    sleep 1
    baseline_fds=$(ls /proc/$pid/fd | wc -l)
    code=0
    /tmp/bin/owrt-benchmark "$socket" fd_boundary > "$out/$side-fd_boundary.txt" 2> "$out/$side-fd_boundary.log" || code=$?
    [ "$code" -eq 0 ]
    [ ! -s "$out/$side-fd_boundary.log" ]
    tries=0
    while [ "$(ls /proc/$pid/fd | wc -l)" -ne "$baseline_fds" ]; do
        kill -0 "$pid"; [ "$tries" -lt 10 ]; sleep 1; tries=$((tries + 1))
    done
    ubus -s "$socket" -t 1 list > "$out/$side-objects-after.txt"
    [ ! -s "$out/$side-objects-after.txt" ]
    kill "$pid"
    code=0; wait "$pid" 2>/dev/null || code=$?
    [ "$code" -eq 0 ] || [ "$code" -eq 143 ]
    [ "$(wc -l < "$out/$side-fd_boundary.txt")" -eq 7 ]
    grep -qx 'fd_boundary compatible=true cases=6' "$out/$side-fd_boundary.txt"
    [ "$(grep -c ' handcrafted c_placement=' "$out/$side-fd_boundary.txt")" -eq 3 ]
done
cmp "$out/c-fd_boundary.txt" "$out/before-fd_boundary.txt"
[ "$(grep -c 'c_placement=true' "$out/c-fd_boundary.txt")" -eq 3 ]
grep -v ' handcrafted ' "$out/c-fd_boundary.txt" > "$out/c-framed.txt"
grep -v ' handcrafted ' "$out/candidate-fd_boundary.txt" > "$out/candidate-framed.txt"
cmp "$out/c-framed.txt" "$out/candidate-framed.txt"
touch "$out/COMPLETE"
