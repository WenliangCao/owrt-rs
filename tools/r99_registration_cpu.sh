#!/bin/sh
# Serial real-protocol CPU diagnostic. Pin only the isolated test processes.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] || exit 125
case "$3" in c) bin=/sbin/ubusd ;; rs) bin=/tmp/bin/ubusd-rs ;; *) exit 125 ;; esac
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
"$bench" exec-cpu 1 "$bin" -s "$socket" > "$out/bus.log" 2>&1 & bus=$!
tries=0
until ubus -t 1 list >/dev/null 2>&1; do
    kill -0 "$bus"; [ "$tries" -lt 20 ]; sleep 1; tries=$((tries + 1))
done
[ "$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/$bus/status)" = 1 ]
cat /proc/$bus/status > "$out/subject-status-before.txt"
ubus list > "$out/objects-before.txt"
[ ! -s "$out/objects-before.txt" ]
"$bench" snapshot "$bus" > "$out/before.json"
"$bench" exec-cpu 0 "$bench" register-cpu "$socket" 1 8 "$n" 2000 "$bus" > "$out/register_cpu_1_8.json"
"$bench" snapshot "$bus" > "$out/after.json"
cat /proc/$bus/status > "$out/subject-status-after.txt"
frequencies > "$out/frequency-after.txt"
ubus list > "$out/objects-after.txt"
[ ! -s "$out/objects-after.txt" ]
printf '{"subject_pid":%s,"iterations":%s,"warmup":2000,"subject_cpu":1,"client_cpu":0,"serial_cpu_loop":true}\n' "$bus" "$n" > "$out/meta.json"
touch "$out/COMPLETE"
