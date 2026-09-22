#!/bin/sh
# Measure per-connection receive-buffer residency in disposable namespaces.
set -eu
export OWRT_UBUSD_NORMALIZED=1
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] || exit 125
case "$3" in c) bin=/sbin/ubusd ;; rs) bin=/tmp/bin/ubusd-rs ;; *) exit 125 ;; esac
bench=/tmp/bin/owrt-benchmark; out=/tmp/out
socket=/var/run/ubus/ubus.sock; mkdir -p /var/run/ubus
sha256sum "$bin" > "$out/binary-sha256.txt"
sha256sum "$bench" /tmp/bin/ns-exec > "$out/benchmark-sha256.txt"
uname -r > "$out/kernel.txt"; cat /sys/devices/system/cpu/online > "$out/cpus-online.txt"
printf 'clients,vmrss_before_kb,vmrss_after_kb,rssanon_before_kb,rssanon_after_kb,vmdata_before_kb,vmdata_after_kb,pss_before_kb,pss_after_kb\n' > "$out/memory.csv"
sample() {
    pid=$1; status=/proc/$pid/status
    awk '/^VmRSS:/ {rss=$2} /^RssAnon:/ {anon=$2} /^VmData:/ {data=$2} END {printf "%s,%s,%s", rss+0, anon+0, data+0}' "$status"
    if [ -r /proc/$pid/smaps_rollup ]; then
        printf ','; awk '/^Pss:/ {print $2; found=1} END {if (!found) print "NA"}' /proc/$pid/smaps_rollup
    else printf ',NA'; fi
}
start_daemon() {
    "$bench" exec-cpu-as 1 "$bin" /sbin/ubusd -s "$socket" > "$out/daemon-$clients.log" 2>&1 & daemon=$!
    tries=0
    until ubus -s "$socket" -t 1 list >/dev/null 2>&1; do
        kill -0 "$daemon"; [ "$tries" -lt 20 ]; sleep 1; tries=$((tries + 1))
    done
    [ "$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/$daemon/status)" = 1 ]
}
stop_daemon() { kill "$daemon" 2>/dev/null || true; wait "$daemon" 2>/dev/null || true; }
for clients in 0 1 8 32 64; do
    start_daemon
    sleep 1
    cat /proc/$daemon/status > "$out/status-$clients-before.txt"
    baseline_fds=$(ls /proc/$daemon/fd | wc -l)
    before=$(sample "$daemon")
    if [ "$clients" -gt 0 ]; then
        "$bench" rx-idle "$socket" "$clients" 30 > "$out/clients-$clients.json" 2> "$out/clients-$clients.err" & holder=$!
        tries=0
        until grep -q '"replies_validated":true,"holding":true' "$out/clients-$clients.json"; do
            kill -0 "$holder"; [ "$tries" -lt 20 ]; sleep 1; tries=$((tries + 1))
        done
        sleep 1
        kill -0 "$daemon"
        kill -0 "$holder"
        [ "$(ls /proc/$daemon/fd | wc -l)" -eq "$((baseline_fds + clients))" ]
        cat /proc/$daemon/status > "$out/status-$clients.txt"
        after=$(sample "$daemon")
        kill "$holder"; wait "$holder"
        tries=0
        while [ "$(ls /proc/$daemon/fd | wc -l)" -ne "$baseline_fds" ]; do
            kill -0 "$daemon"; [ "$tries" -lt 10 ]; sleep 1; tries=$((tries + 1))
        done
    else sleep 1; cat /proc/$daemon/status > "$out/status-$clients.txt"; after=$(sample "$daemon"); fi
    before_rss=$(printf '%s' "$before" | cut -d, -f1)
    before_anon=$(printf '%s' "$before" | cut -d, -f2)
    before_data=$(printf '%s' "$before" | cut -d, -f3)
    before_pss=$(printf '%s' "$before" | cut -d, -f4)
    after_rss=$(printf '%s' "$after" | cut -d, -f1)
    after_anon=$(printf '%s' "$after" | cut -d, -f2)
    after_data=$(printf '%s' "$after" | cut -d, -f3)
    after_pss=$(printf '%s' "$after" | cut -d, -f4)
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$clients" "$before_rss" "$after_rss" "$before_anon" "$after_anon" "$before_data" "$after_data" "$before_pss" "$after_pss" >> "$out/memory.csv"
    stop_daemon
done
cat "$out/memory.csv"; touch "$out/COMPLETE"
