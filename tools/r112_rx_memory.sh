#!/bin/sh
# Measure per-connection receive-buffer residency in disposable namespaces.
# Fix argv[0] to the common production entry name for every ELF.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] || exit 125
bin=/tmp/bin/ubusd-rs; bench=/tmp/bin/owrt-benchmark; out=/tmp/out
socket=/var/run/ubus/ubus.sock; mkdir -p /var/run/ubus
sha256sum "$bin" > "$out/binary-sha256.txt"
sha256sum "$bench" /tmp/bin/ns-exec > "$out/benchmark-sha256.txt"
uname -r > "$out/kernel.txt"; cat /sys/devices/system/cpu/online > "$out/cpus-online.txt"
printf 'clients,vmrss_before_kb,vmrss_after_kb,rssanon_before_kb,rssanon_after_kb,vmdata_before_kb,vmdata_after_kb,pss_before_kb,pss_after_kb\n' > "$out/memory.csv"
status_values() {
    awk -v expected="$1" '
        /^VmRSS:|^RssAnon:|^VmData:/ {
            seen[$1]++; value[$1]=$2
            if (NF != 3 || $2 !~ /^[0-9]+$/ || $3 != "kB") bad=1
        }
        /^Pid:|^Tgid:/ { seen[$1]++; if ($2 != expected) bad=1 }
        /^Threads:/ { seen[$1]++; if ($2 != 1) bad=1 }
        /^Cpus_allowed_list:/ { seen[$1]++; if ($2 != "1") bad=1 }
        /^State:/ { seen[$1]++; if ($2 !~ /^[RSDTtIW]$/) bad=1 }
        END {
            if (bad || seen["VmRSS:"] != 1 || seen["RssAnon:"] != 1 ||
                seen["VmData:"] != 1 || seen["Pid:"] != 1 || seen["Tgid:"] != 1 ||
                seen["Threads:"] != 1 || seen["Cpus_allowed_list:"] != 1 || seen["State:"] != 1) exit 1
            printf "%s,%s,%s", value["VmRSS:"], value["RssAnon:"], value["VmData:"]
        }' "$2"
}
process_identity() {
    awk -v expected="$daemon" '{
        pid=$1; sub(/^.*\) /, "")
        if (NR != 1 || pid != expected || NF < 20 || $1 !~ /^[RSDTtIW]$/ || $20 !~ /^[0-9]+$/) exit 1
        print pid, $20
    } END { if (NR != 1) exit 1 }' "$1"
}
sample() {
    pid=$1; phase=$2
    case "$phase" in held) status="$out/status-$clients.txt" ;; *) status="$out/status-$clients-$phase.txt" ;; esac
    cat /proc/$pid/stat > "$out/stat-$clients-$phase-before.txt"
    cat /proc/$pid/status > "$status"
    # CSV and retained evidence use the very same status snapshot.
    status_values "$pid" "$status" || return $?
    if [ -r /proc/$pid/smaps_rollup ]; then
        printf ','; awk '/^Pss:/ {print $2; found=1} END {if (!found) print "NA"}' /proc/$pid/smaps_rollup
    else printf ',NA'; fi
    cat /proc/$pid/stat > "$out/stat-$clients-$phase-after.txt"
    [ "$(process_identity "$out/stat-$clients-$phase-before.txt")" = "$daemon_identity" ]
    [ "$(process_identity "$out/stat-$clients-$phase-after.txt")" = "$daemon_identity" ]
}
start_daemon() {
    "$bench" exec-cpu-as 1 "$bin" /sbin/ubusd -s "$socket" > "$out/daemon-$clients.log" 2>&1 & daemon=$!
    tries=0
    until ubus -s "$socket" -t 1 list >/dev/null 2>&1; do
        kill -0 "$daemon"; [ "$tries" -lt 20 ]; sleep 1; tries=$((tries + 1))
    done
    [ "$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/$daemon/status)" = 1 ]
    tr '\000' '\n' < /proc/$daemon/cmdline > "$out/cmdline-$clients.txt"
    [ "$(head -n 1 "$out/cmdline-$clients.txt")" = /sbin/ubusd ]
    cat /proc/$daemon/stat > "$out/stat-$clients-start.txt"
    daemon_identity=$(process_identity "$out/stat-$clients-start.txt")
}
stop_daemon() {
    [ "$(process_identity /proc/$daemon/stat)" = "$daemon_identity" ]
    kill "$daemon"
    rc=0; wait "$daemon" || rc=$?
    printf '%s\n' "$rc" > "$out/exit-$clients.txt"
    [ "$rc" -eq 0 ] || [ "$rc" -eq 143 ]
}
for clients in 0 1 8 32 64; do
    start_daemon
    sleep 1
    baseline_fds=$(ls /proc/$daemon/fd | wc -l)
    before=$(sample "$daemon" before)
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
        after=$(sample "$daemon" held)
        kill "$holder"; wait "$holder"
        tries=0
        while [ "$(ls /proc/$daemon/fd | wc -l)" -ne "$baseline_fds" ]; do
            kill -0 "$daemon"; [ "$tries" -lt 10 ]; sleep 1; tries=$((tries + 1))
        done
    else sleep 1; after=$(sample "$daemon" held); fi
    sample "$daemon" after-disconnect > "$out/after-disconnect-$clients.csv"
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
