#!/bin/sh
# Direct ubus_send_event workload. The benchmark override is the exact-image
# C libubus caller and also provides exec-cpu; the daemon remains disposable.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] || exit 125
case "$3" in
    c) bin=/sbin/ubusd ;;
    rs) bin=/tmp/bin/ubusd-rs ;;
    *) exit 125 ;;
esac
bench=/tmp/bin/owrt-benchmark
event_bench=/tmp/bin/event-benchmark
out=/tmp/out
socket=/var/run/ubus/ubus.sock
mkdir -p /var/run/ubus
sha256sum "$bin" > "$out/binary-sha256.txt"
sha256sum "$bench" /tmp/bin/ns-exec > "$out/benchmark-sha256.txt"
sha256sum "$event_bench" > "$out/event-benchmark-sha256.txt"
uname -r > "$out/kernel.txt"
cat /sys/devices/system/cpu/online > "$out/cpus-online.txt"
cat /proc/cpuinfo > "$out/cpuinfo.txt"
frequencies() {
    for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        [ ! -r "$f" ] || { printf '%s ' "$f"; cat "$f"; }
    done
}
frequencies > "$out/frequency-before.txt"
"$bench" exec-cpu-as 1 "$bin" /sbin/ubusd -s "$socket" > "$out/daemon.log" 2>&1 & pid=$!
cleanup() {
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM
tries=0
until ubus -s "$socket" -t 1 list >/dev/null 2>&1; do
    kill -0 "$pid"
    [ "$tries" -lt 20 ]
    sleep 1
    tries=$((tries + 1))
done
[ "$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/$pid/status)" = 1 ]
printf '/sbin/ubusd\0-s\0%s\0' "$socket" > "$out/daemon-expected.cmdline"
cat /proc/$pid/status > "$out/daemon-before.status"
cat /proc/$pid/cmdline > "$out/daemon-before.cmdline"
readlink /proc/$pid/exe > "$out/daemon-before.exe"
sha256sum /proc/$pid/exe > "$out/daemon-before.exe-sha256"
awk '{sub(/^.*\) /, ""); print $20}' /proc/$pid/stat > "$out/daemon-before.starttime"
cmp "$out/daemon-before.cmdline" "$out/daemon-expected.cmdline"
ubus -s "$socket" list > "$out/objects-before.txt"
[ ! -s "$out/objects-before.txt" ]
printf '{"subject_pid":%s,"subject_cpu":1,"client_cpu":0,"implementation":"%s","iterations":%s,"warmup":20,"scenarios":["user_1_1","user_8_1","user_1_0"],"exact_image_caller":true,"daemon_argv0":"/sbin/ubusd"}\n' "$pid" "$3" "$4" > "$out/meta.json"
"$event_bench" user-event "$socket" 1 1 "$4" 20 "$pid" > "$out/user_1_1.json"
"$event_bench" user-event "$socket" 8 1 "$4" 20 "$pid" > "$out/user_8_1.json"
"$event_bench" user-event "$socket" 1 0 "$4" 20 "$pid" > "$out/user_1_0.json"
frequencies > "$out/frequency-after.txt"
cat /proc/$pid/status > "$out/daemon-after.status"
cat /proc/$pid/cmdline > "$out/daemon-after.cmdline"
readlink /proc/$pid/exe > "$out/daemon-after.exe"
sha256sum /proc/$pid/exe > "$out/daemon-after.exe-sha256"
sha256sum "$bin" > "$out/binary-after-sha256.txt"
sha256sum "$bench" /tmp/bin/ns-exec > "$out/benchmark-after-sha256.txt"
sha256sum "$event_bench" > "$out/event-benchmark-after-sha256.txt"
awk '{sub(/^.*\) /, ""); print $20}' /proc/$pid/stat > "$out/daemon-after.starttime"
cmp "$out/daemon-before.cmdline" "$out/daemon-after.cmdline"
cmp "$out/daemon-before.exe-sha256" "$out/daemon-after.exe-sha256"
cmp "$out/daemon-before.starttime" "$out/daemon-after.starttime"
ubus -s "$socket" list > "$out/objects-after.txt"
[ ! -s "$out/objects-after.txt" ]
printf '{"daemon_pid":%s,"iterations":%s,"warmup":20,"scenarios":3,"serial_client":true,"event_payload_validated":true}\n' "$pid" "$4" > "$out/summary.json"
touch "$out/COMPLETE"
