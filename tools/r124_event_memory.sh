#!/bin/sh
# Dedicated event-retention workload. Outer r95_device_smoke/namespace guard
# owns failure cleanup; this script never touches a production daemon.
# --implementation c|rs selects the subject; --iterations 1|2 selects size order.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "$#" -eq 4 ] && [ "$1" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] || exit 125
implementation=$3
case "$implementation" in c) bin=/sbin/ubusd ;; rs) bin=/tmp/bin/ubusd-rs ;; *) exit 125 ;; esac
case "$4" in
    1) sizes="32768 262144 786432"; json_sizes="32768,262144,786432" ;;
    2) sizes="786432 262144 32768"; json_sizes="786432,262144,32768" ;;
    *) exit 125 ;;
esac
order=$4
unset LD_PRELOAD LD_LIBRARY_PATH
bench=/tmp/bin/owrt-benchmark
out=/tmp/out
socket=/var/run/ubus/r124-memory.sock
mkdir -p /var/run/ubus
[ ! -e "$out/memory.csv" ]
[ ! -e "$out/COMPLETE" ]
trap 'code=$?; if [ "$code" -ne 0 ]; then printf "{\"exit\":%s,\"payload_bytes\":%s,\"phase\":\"%s\"}\n" "$code" "${bytes:-0}" "${current_phase:-startup}" > "$out/FAILED.json"; fi' 0
sha256sum "$bin" > "$out/binary-sha256.txt"
binary_sha=$(awk 'NR == 1 {print $1}' "$out/binary-sha256.txt")
sha256sum "$bench" /tmp/bin/ns-exec /tmp/bin/guard > "$out/benchmark-sha256.txt"
sha256sum /tmp/workload.sh > "$out/workload-sha256.txt"
sha256sum /lib/libubus.so.20251202 /lib/libubox.so.20260213 /lib/libc.so /lib/libgcc_s.so.1 \
    /lib/libblobmsg_json.so.20260213 /usr/lib/libjson-c.so.5.4.0 > "$out/libraries.sha256"
uname -r > "$out/kernel.txt"
cat /sys/devices/system/cpu/online > "$out/cpus-online.txt"
cat /proc/sys/kernel/random/boot_id > "$out/boot-id.txt"
printf '{"implementation":"%s","order":%s,"sizes":[%s],"cases":3,"subject_cpu":1,"client_cpu":0,"phase_delays_seconds":[1,5],"small_payload_bytes":16}\n' "$implementation" "$order" "$json_sizes" > "$out/meta.json"
printf 'payload_bytes,phase,delay_seconds,daemon_pid,vmrss_kb,rssanon_kb,vmdata_kb,pss_kb,fds\n' > "$out/memory.csv"

process_identity() {
    awk -v expected="$daemon" '{
        pid=$1; sub(/^.*\) /, "")
        if (NR != 1 || pid != expected || NF < 20 || $1 !~ /^[RSDTtIW]$/ || $20 !~ /^[0-9]+$/) exit 1
        print pid, $20
    } END { if (NR != 1) exit 1 }' "$1"
}

status_values() {
    awk -v expected="$daemon" '
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
        }' "$1"
}

fd_count() {
    # Kernel FD names are decimal numbers, not arbitrary filenames.
    # shellcheck disable=SC2012
    ls -1 "/proc/$daemon/fd" | wc -l
}

sample() {
    phase=$1; delay=$2; expected_fds=$3
    current_phase=$phase-$delay
    prefix=$case_dir/$current_phase
    cat /proc/uptime > "$prefix-uptime.txt"
    cat "/proc/$daemon/stat" > "$prefix-stat-before.txt"
    cat "/proc/$daemon/status" > "$prefix-status.txt"
    values=$(status_values "$prefix-status.txt")
    ls -1 "/proc/$daemon/fd" > "$prefix-fds.txt"
    fds=$(wc -l < "$prefix-fds.txt")
    [ "$fds" -eq "$expected_fds" ]
    sha256sum "/proc/$daemon/exe" > "$prefix-exe.sha256"
    [ "$(awk 'NR == 1 {print $1}' "$prefix-exe.sha256")" = "$binary_sha" ]
    tr '\000' '\n' < "/proc/$daemon/cmdline" > "$prefix-cmdline.txt"
    [ "$(wc -l < "$prefix-cmdline.txt")" -eq 3 ]
    [ "$(sed -n '1p' "$prefix-cmdline.txt")" = /sbin/ubusd ]
    [ "$(sed -n '2p' "$prefix-cmdline.txt")" = -s ]
    [ "$(sed -n '3p' "$prefix-cmdline.txt")" = "$socket" ]
    pss=NA
    if [ -r "/proc/$daemon/smaps_rollup" ]; then
        if cat "/proc/$daemon/smaps_rollup" > "$prefix-smaps-rollup.txt" 2> "$prefix-smaps-error.txt"; then
            pss=$(awk '/^Pss:/ {seen++; value=$2; if (NF != 3 || $2 !~ /^[0-9]+$/ || $3 != "kB") bad=1}
                END {if (bad || seen > 1) exit 1; if (seen == 1) print value; else print "NA"}' "$prefix-smaps-rollup.txt")
        fi
    fi
    cat "/proc/$daemon/stat" > "$prefix-stat-after.txt"
    [ "$(process_identity "$prefix-stat-before.txt")" = "$daemon_identity" ]
    [ "$(process_identity "$prefix-stat-after.txt")" = "$daemon_identity" ]
    printf '%s,%s,%s,%s,%s,%s,%s\n' "$bytes" "$phase" "$delay" "$daemon" "$values" "$pss" "$fds" >> "$out/memory.csv"
}

sample_phase() {
    phase=$1; expected_fds=$2
    cat /proc/uptime > "$case_dir/$phase-start-uptime.txt"
    sleep 1
    sample "$phase" 1 "$expected_fds"
    sleep 4
    sample "$phase" 5 "$expected_fds"
}

# The exact image's BusyBox sleep accepts integer seconds only.
wait_phase() {
    awaiting=$1
    current_phase=wait-$awaiting
    tries=0
    until grep -q "\"phase\":\"$awaiting\"" "$case_dir/helper.jsonl"; do
        kill -0 "$daemon"
        if ! kill -0 "$helper" 2>/dev/null; then
            # The final phase may have been flushed after grep, just before
            # helper exit. Its caller still checks the exit status with wait.
            grep -q "\"phase\":\"$awaiting\"" "$case_dir/helper.jsonl" || return 1
            break
        fi
        [ "$tries" -lt 10 ]
        sleep 1
        tries=$((tries + 1))
    done
    kill -0 "$daemon"
    [ "$(grep -c "\"phase\":\"$awaiting\"" "$case_dir/helper.jsonl")" -eq 1 ]
}

for bytes in $sizes; do
    case_dir=$out/$bytes
    mkdir "$case_dir"
    current_phase=start-daemon
    rm -f "$socket"
    "$bench" exec-cpu-as 1 "$bin" /sbin/ubusd -s "$socket" > "$case_dir/daemon.log" 2>&1 & daemon=$!
    tries=0
    until /tmp/bin/guard 2 ubus -s "$socket" -t 1 list > "$case_dir/ready-$tries.txt" 2> "$case_dir/ready-$tries.log"; do
        kill -0 "$daemon"
        [ "$tries" -lt 4 ]
        sleep 1
        tries=$((tries + 1))
    done
    [ ! -s "$case_dir/ready-$tries.txt" ]
    sleep 1
    cat "/proc/$daemon/stat" > "$case_dir/stat-start.txt"
    daemon_identity=$(process_identity "$case_dir/stat-start.txt")
    baseline_fds=$(fd_count)
    [ "$baseline_fds" -gt 0 ]
    printf '%s\n' "$baseline_fds" > "$case_dir/baseline-fds.txt"
    sample empty 0 "$baseline_fds"

    # Keep FIFOs outside raw evidence: archive extraction rejects special
    # files. The parent's RDWR open avoids startup-open races, not timeouts.
    control=/tmp/r124-event-control-$bytes
    mkfifo -m 600 "$control"
    exec 3<>"$control"
    "$bench" event-memory "$socket" "$bytes" "$daemon" "$baseline_fds" 3<&- < "$control" > "$case_dir/helper.jsonl" 2> "$case_dir/helper.log" & helper=$!
    wait_phase READY
    sample_phase connected "$((baseline_fds + 2))"
    kill -0 "$helper"
    printf 'SEND\n' >&3
    wait_phase DELIVERED
    sample_phase held "$((baseline_fds + 2))"
    kill -0 "$helper"
    printf 'CLOSE\n' >&3
    wait_phase CLOSED
    code=0; wait "$helper" || code=$?
    printf '%s\n' "$code" > "$case_dir/helper-exit.txt"
    [ "$code" -eq 0 ]
    [ "$(wc -l < "$case_dir/helper.jsonl")" -eq 3 ]
    [ ! -s "$case_dir/helper.log" ]
    exec 3>&-
    rm "$control"
    current_phase=wait-disconnect
    tries=0
    while [ "$(fd_count)" -ne "$baseline_fds" ]; do
        kill -0 "$daemon"
        [ "$tries" -lt 5 ]
        sleep 1
        tries=$((tries + 1))
    done
    sample_phase disconnected "$baseline_fds"
    [ "$(process_identity "/proc/$daemon/stat")" = "$daemon_identity" ]
    current_phase=stop-daemon
    kill "$daemon"
    code=0; wait "$daemon" || code=$?
    printf '%s\n' "$code" > "$case_dir/daemon-exit.txt"
    [ "$code" -eq 0 ] || [ "$code" -eq 143 ]
    touch "$case_dir/COMPLETE"
done
sha256sum -c "$out/libraries.sha256" > "$out/libraries-verified.txt"
[ "$(wc -l < "$out/memory.csv")" -eq 22 ]
touch "$out/COMPLETE"
