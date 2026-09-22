#!/bin/sh
# Exact libubus multi-owner/monitor/backpressure gates in disposable namespace.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "$#" -eq 4 ] && [ "$1" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] || exit 125
case "$3" in c) bin=/sbin/ubusd ;; rs) bin=/tmp/bin/ubusd-rs ;; *) exit 125 ;; esac
bench=/tmp/bin/owrt-benchmark
helper=/tmp/bin/event-benchmark
out=/tmp/out
socket=/var/run/ubus/ubus.sock
mkdir -p /var/run/ubus
unset LD_PRELOAD LD_LIBRARY_PATH
sha256sum "$bin" > "$out/binary-sha256.txt"
sha256sum "$bench" /tmp/bin/ns-exec > "$out/benchmark-sha256.txt"
sha256sum "$helper" > "$out/event-benchmark-sha256.txt"
sha256sum /tmp/workload.sh > "$out/workload-sha256.txt"
sha256sum /lib/libubus.so.20251202 /lib/libubox.so.20260213 /lib/libc.so /lib/libgcc_s.so.1 > "$out/libraries.sha256"
printf '{"implementation":"%s","iterations":%s,"slow_iterations":192,"subject_cpu":1,"client_cpu":0,"daemon_argv0":"/sbin/ubusd","cases":["grouped","interleaved","monitor","slow"]}\n' "$3" "$4" > "$out/meta.json"
daemon=
cleanup() {
    [ -z "$daemon" ] || { kill "$daemon" 2>/dev/null || true; wait "$daemon" 2>/dev/null || true; }
}
trap cleanup EXIT HUP INT TERM
for mode in grouped interleaved monitor slow; do
    case_dir=$out/$mode
    mkdir "$case_dir"
    rm -f "$socket"
    "$bench" exec-cpu-as 1 "$bin" /sbin/ubusd -s "$socket" > "$case_dir/daemon.log" 2>&1 & daemon=$!
    tries=0
    until ubus -s "$socket" -t 1 list > "$case_dir/ready.txt" 2> "$case_dir/ready.log"; do
        kill -0 "$daemon"; [ "$tries" -lt 10 ]; sleep 1; tries=$((tries + 1))
    done
    [ ! -s "$case_dir/ready.txt" ]
    [ "$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/$daemon/status)" = 1 ]
    printf '/sbin/ubusd\0-s\0%s\0' "$socket" > "$case_dir/expected.cmdline"
    cat /proc/$daemon/cmdline > "$case_dir/before.cmdline"
    cat /proc/$daemon/status > "$case_dir/before.status"
    awk '{sub(/^.*\) /, ""); print $20}' /proc/$daemon/stat > "$case_dir/before.starttime"
    sha256sum /proc/$daemon/exe > "$case_dir/before.exe-sha256"
    cmp "$case_dir/expected.cmdline" "$case_dir/before.cmdline"
    count=$4
    [ "$mode" != slow ] || count=192
    "$helper" event-stress "$socket" "$mode" "$count" "$daemon" > "$case_dir/helper.jsonl" 2> "$case_dir/helper.log"
    [ ! -s "$case_dir/helper.log" ]
    [ "$(grep -c '"phase":"RESULT"' "$case_dir/helper.jsonl")" -eq 1 ]
    kill -0 "$daemon"
    ubus -s "$socket" -t 1 list > "$case_dir/objects-after.txt"
    [ ! -s "$case_dir/objects-after.txt" ]
    cat /proc/$daemon/cmdline > "$case_dir/after.cmdline"
    cat /proc/$daemon/status > "$case_dir/after.status"
    awk '{sub(/^.*\) /, ""); print $20}' /proc/$daemon/stat > "$case_dir/after.starttime"
    sha256sum /proc/$daemon/exe > "$case_dir/after.exe-sha256"
    cmp "$case_dir/before.cmdline" "$case_dir/after.cmdline"
    cmp "$case_dir/before.starttime" "$case_dir/after.starttime"
    cmp "$case_dir/before.exe-sha256" "$case_dir/after.exe-sha256"
    kill "$daemon"
    wait "$daemon" 2>/dev/null || code=$?
    [ "${code:-0}" -eq 0 ] || [ "$code" -eq 143 ]
    daemon=
    code=0
    touch "$case_dir/COMPLETE"
done
sha256sum -c "$out/libraries.sha256" > "$out/libraries-verified.txt"
sha256sum "$helper" > "$out/event-benchmark-after-sha256.txt"
cmp "$out/event-benchmark-sha256.txt" "$out/event-benchmark-after-sha256.txt"
touch "$out/COMPLETE"
