#!/bin/sh
# Independent FD-framing differential; only inside the guarded namespace.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] && [ "$3" = rs ] || exit 125
unset LD_PRELOAD LD_LIBRARY_PATH
out=/tmp/out
sha256sum /tmp/bin/ubusd-rs > "$out/binary-sha256.txt"
sha256sum /tmp/bin/owrt-benchmark /tmp/bin/ns-exec > "$out/benchmark-sha256.txt"
sha256sum /tmp/bin/owrt-benchmark /tmp/bin/before-rs /sbin/ubusd > "$out/probe-identities.txt"
mkdir -p /var/run/ubus
for side in c before candidate; do
    case "$side" in c) bin=/sbin/ubusd ;; before) bin=/tmp/bin/before-rs ;; candidate) bin=/tmp/bin/ubusd-rs ;; esac
    socket=/var/run/ubus/r113.sock
    rm -f "$socket"
    "$bin" -s "$socket" > "$out/$side-daemon.log" 2>&1 & pid=$!
    tries=0
    until ubus -s "$socket" -t 1 list >/dev/null 2>&1; do
        kill -0 "$pid"; [ "$tries" -lt 10 ]; sleep 1; tries=$((tries + 1))
    done
    sleep 1
    baseline_fds=$(ls /proc/$pid/fd | wc -l)
    [ "$baseline_fds" -gt 0 ]
    code=0
    /tmp/bin/owrt-benchmark "$socket" fd_boundary > "$out/$side-fd_boundary.txt" 2> "$out/$side-fd_boundary.log" || code=$?
    printf '%s\n' "$code" > "$out/$side-probe-exit.txt"
    # Exit 1 is reserved for a fully collected compatibility mismatch. A
    # panic, timeout, failed witness or leak check is never a valid control.
    case "$side" in before) [ "$code" -eq 1 ] ;; *) [ "$code" -eq 0 ] ;; esac
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
done
cmp "$out/c-fd_boundary.txt" "$out/candidate-fd_boundary.txt"
[ "$(wc -l < "$out/c-fd_boundary.txt")" -eq 7 ]
[ "$(wc -l < "$out/before-fd_boundary.txt")" -eq 7 ]
grep -qx 'fd_boundary compatible=true cases=6' "$out/c-fd_boundary.txt"
! grep -q 'compatible=false' "$out/c-fd_boundary.txt"
grep -qx 'fd_boundary compatible=false cases=6' "$out/before-fd_boundary.txt"
for known in \
    'case=bundled invoke_order=first,second seq=101,102 fds=0,1 witness=true no_leak=true compatible=false' \
    'case=fd_in_first_body invoke_order=first,second seq=101,102 fds=1,0 witness=true no_leak=true compatible=false' \
    'case=fd_on_first_body_plus_second_frame invoke_order=first,second seq=101,102 fds=0,1 witness=true no_leak=true compatible=false'; do
    grep -qx "$known" "$out/before-fd_boundary.txt"
done
touch "$out/COMPLETE"
