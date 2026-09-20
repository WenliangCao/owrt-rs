#!/bin/sh
# Paired real-protocol CPU diagnostic: alternate ABBA and BAAB quartets.
# Only isolated test processes are pinned; no simultaneous request streams.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] || exit 125
[ "$3" = rs ] || exit 125
bin=/tmp/bin/ubusd-rs
n=$4
bench=/tmp/bin/owrt-benchmark
out=/tmp/out
socket=/var/run/ubus/ubus.sock
mkdir -p /var/run/ubus
sha256sum "$bin" > "$out/binary-sha256.txt"
sha256sum "$bench" /tmp/bin/ns-exec > "$out/benchmark-sha256.txt"
uname -r > "$out/kernel.txt"
cat /sys/devices/system/cpu/online > "$out/cpus-online.txt"
frequencies() {
    for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        [ ! -r "$f" ] || { printf '%s ' "$f"; cat "$f"; }
    done
}
frequencies > "$out/frequency-before.txt"
# Slot a is the explicit control upload; slot b is the candidate upload.
test -x /tmp/bin/before-rs
sha256sum /tmp/bin/before-rs > "$out/control-sha256.txt"
"$bench" exec-cpu 1 /tmp/bin/before-rs -s "${socket}.a" > "$out/a-bus.log" 2>&1 & a_pid=$!
"$bench" exec-cpu 1 "$bin" -s "${socket}.b" > "$out/b-bus.log" 2>&1 & b_pid=$!
for side in a b; do
    case "$side" in a) pid=$a_pid ;; b) pid=$b_pid ;; esac
    tries=0
    until ubus -s "${socket}.$side" -t 1 list >/dev/null 2>&1; do
        kill -0 "$pid"; [ "$tries" -lt 20 ]; sleep 1; tries=$((tries + 1))
    done
    [ "$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/$pid/status)" = 1 ]
    ubus -s "${socket}.$side" list > "$out/$side-objects-before.txt"
    [ ! -s "$out/$side-objects-before.txt" ]
done
"$bench" snapshot "$a_pid,$b_pid" > "$out/before.json"
segment=0
quartet=0
while [ "$quartet" -lt 10 ]; do
    case $((quartet % 2)) in 0) order="a b b a" ;; 1) order="b a a b" ;; esac
    for side in $order; do
        segment=$((segment + 1))
        case "$side" in a) pid=$a_pid ;; b) pid=$b_pid ;; esac
        "$bench" exec-cpu 0 "$bench" register-cpu "${socket}.$side" 1 8 "$n" 2000 "$pid" > "$out/segment-$segment-$side.json"
    done
    quartet=$((quartet + 1))
done
"$bench" snapshot "$a_pid,$b_pid" > "$out/after.json"
frequencies > "$out/frequency-after.txt"
for side in a b; do
    ubus -s "${socket}.$side" list > "$out/$side-objects-after.txt"
    [ ! -s "$out/$side-objects-after.txt" ]
done
printf '{"a_pid":%s,"b_pid":%s,"iterations":%s,"warmup":2000,"segments":40,"subject_cpu":1,"client_cpu":0,"serial_cpu_loop":true}\n' "$a_pid" "$b_pid" "$n" > "$out/meta.json"
touch "$out/COMPLETE"
