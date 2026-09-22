#!/bin/sh
# R130: normalized registration timing plus bounded shared-send fixture guards.
# The outer runner owns the physical-router recovery gate and namespace cleanup.
set -eu
export OWRT_UBUSD_NORMALIZED=1
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$#" -eq 4 ] && [ "$2" = ubusd ] && [ "$4" = 5000 ] || exit 125
case "$3" in c) bin=/sbin/ubusd ;; rs) bin=/tmp/bin/ubusd-rs ;; *) exit 125 ;; esac
n=5000
warmup=20
guard_n=5000
bench=/tmp/bin/owrt-benchmark
out=/tmp/out
socket=/var/run/ubus/ubus.sock
bus=''
provider=''
cleanup() {
    if [ -n "$provider" ]; then kill "$provider" 2>/dev/null || :; wait "$provider" 2>/dev/null || :; fi
    if [ -n "$bus" ]; then kill "$bus" 2>/dev/null || :; wait "$bus" 2>/dev/null || :; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p /var/run/ubus
sha256sum "$bin" > "$out/binary-sha256.txt"
sha256sum "$bench" /tmp/bin/ns-exec > "$out/benchmark-sha256.txt"
sha256sum /tmp/workload.sh > "$out/harness-sha256.txt"
cat /proc/cpuinfo > "$out/cpuinfo.txt"
cat /sys/devices/system/cpu/online > "$out/cpus-online.txt"
cat /proc/sys/kernel/random/boot_id > "$out/boot-id.txt"
uname -r > "$out/kernel.txt"
printf '/sbin/ubusd\000-s\000%s\000' "$socket" > "$out/daemon-expected.cmdline"

daemon_identity() {
    phase=$1
    kill -0 "$bus"
    cat "/proc/$bus/status" > "$out/daemon-$phase.status"
    cat "/proc/$bus/stat" > "$out/daemon-$phase.stat"
    cat "/proc/$bus/cmdline" > "$out/daemon-$phase.cmdline"
    cat "/proc/$bus/maps" > "$out/daemon-$phase.maps"
    readlink "/proc/$bus/exe" > "$out/daemon-$phase.exe"
    sha256sum "/proc/$bus/exe" > "$out/daemon-$phase.exe-sha256"
    [ "$(awk '/^Cpus_allowed_list:/ {print $2}' "$out/daemon-$phase.status")" = 1 ]
    [ "$(awk '/^Threads:/ {print $2}' "$out/daemon-$phase.status")" = 1 ]
    cmp "$out/daemon-expected.cmdline" "$out/daemon-$phase.cmdline"
    [ "$(awk '{print $1}' "$out/daemon-$phase.exe-sha256")" = "$(awk '{print $1}' "$out/binary-sha256.txt")" ]
    # Removing pid/comm leaves starttime (original stat field 22) at field 20.
    awk '{sub(/^.*\) /, ""); print $20}' "$out/daemon-$phase.stat" > "$out/daemon-$phase.starttime"
    [ -s "$out/daemon-$phase.starttime" ]
    if [ -r "/proc/$bus/smaps_rollup" ]; then
        cat "/proc/$bus/smaps_rollup" > "$out/daemon-$phase.smaps_rollup"
    fi
}

empty_registry() {
    ubus -s "$socket" -t 1 list > "$out/objects-$1.txt"
    [ ! -s "$out/objects-$1.txt" ]
}

run_client() {
    # These benchmark modes do not pin themselves. The launcher validates its
    # own CPU0 mask with sched_getaffinity. Record that mask in the disposable
    # shell immediately before exec replaces it with the timed benchmark.
    label=$1
    shift
    # shellcheck disable=SC2016 # Expand only inside the pinned child shell.
    "$bench" exec-cpu-as 0 /bin/sh /bin/sh -c '
        set -eu
        out=$1; label=$2; shift 2
        cat /proc/$$/status > "$out/caller-$label.status"
        cat /proc/$$/stat > "$out/caller-$label.stat"
        cat /proc/$$/cmdline > "$out/caller-$label.launcher-cmdline"
        [ "$(awk "/^Cpus_allowed_list:/ {print \$2}" "$out/caller-$label.status")" = 0 ]
        printf "%s\000" "$@" > "$out/caller-$label.exec-cmdline"
        exec "$@"
    ' r130-caller "$out" "$label" "$bench" "$@"
}

provider_identity() {
    phase=$1
    kill -0 "$provider"
    cat "/proc/$provider/status" > "$out/provider-$phase.status"
    cat "/proc/$provider/stat" > "$out/provider-$phase.stat"
    cat "/proc/$provider/cmdline" > "$out/provider-$phase.cmdline"
    sha256sum "/proc/$provider/exe" > "$out/provider-$phase.exe-sha256"
    [ "$(awk '/^Cpus_allowed_list:/ {print $2}' "$out/provider-$phase.status")" = 0 ]
    [ "$(awk '{print $1}' "$out/provider-$phase.exe-sha256")" = "$(awk 'NR == 1 {print $1}' "$out/benchmark-sha256.txt")" ]
    awk '{sub(/^.*\) /, ""); print $20}' "$out/provider-$phase.stat" > "$out/provider-$phase.starttime"
}

# This actual exec, not just the exported normalized flag, pins both subjects
# to CPU1 and gives them identical argv0. Exec preserves the background PID.
"$bench" exec-cpu-as 1 "$bin" /sbin/ubusd -s "$socket" > "$out/bus.log" 2>&1 & bus=$!
tries=0
until ubus -s "$socket" -t 1 list >/dev/null 2>&1; do
    kill -0 "$bus"; [ "$tries" -lt 20 ]; sleep 1; tries=$((tries + 1))
done
daemon_identity before
empty_registry before
"$bench" snapshot "$bus" > "$out/before.json"
for scenario in 1:8 16:8; do
    methods=${scenario%:*}
    bytes=${scenario#*:}
    run_client "register_${methods}_${bytes}" register-cycle "$socket" "$methods" "$bytes" "$n" "$warmup" "$bus" > "$out/register_${methods}_${bytes}.json"
done
empty_registry after-registration
"$bench" snapshot "$bus" > "$out/after-registration.json"

# These lanes guard complete-wire lookup/invoke behavior and shared reply
# helper timing with the same 5000/20 count; no concurrent/fanout matrix here.
"$bench" exec-cpu-as 0 "$bench" "$bench" serve "$socket" 64 > "$out/provider.log" 2>&1 & provider=$!
tries=0
until ubus -s "$socket" -t 1 list bench.filler0063 2>/dev/null | grep -qx bench.filler0063; do
    kill -0 "$bus"; kill -0 "$provider"; [ "$tries" -lt 20 ]; sleep 1; tries=$((tries + 1))
done
provider_identity before
monitors=$bus,$provider
run_client guard_lookup_exact lookup-fixture "$socket" bench.target 64 "$guard_n" "$warmup" "$monitors" > "$out/guard_lookup_exact.json"
run_client guard_lookup_all lookup-fixture "$socket" '*' 64 "$guard_n" "$warmup" "$monitors" > "$out/guard_lookup_all.json"
run_client guard_lookup_prefix lookup-fixture "$socket" 'bench.*' 64 "$guard_n" "$warmup" "$monitors" > "$out/guard_lookup_prefix.json"
run_client guard_invoke rpc-fixture "$socket" "$guard_n" "$warmup" "$monitors" > "$out/guard_invoke.json"
provider_identity after
cmp "$out/provider-before.starttime" "$out/provider-after.starttime"
cmp "$out/provider-before.cmdline" "$out/provider-after.cmdline"
cmp "$out/provider-before.exe-sha256" "$out/provider-after.exe-sha256"
kill "$provider"
wait "$provider" 2>/dev/null || :
provider=''
tries=0
while :; do
    kill -0 "$bus"
    ubus -s "$socket" -t 1 list > "$out/objects-after.txt"
    [ -s "$out/objects-after.txt" ] || break
    [ "$tries" -lt 20 ]; sleep 1; tries=$((tries + 1))
done
"$bench" snapshot "$bus" > "$out/after.json"
daemon_identity after
cmp "$out/daemon-before.starttime" "$out/daemon-after.starttime"
cmp "$out/daemon-before.exe" "$out/daemon-after.exe"
cmp "$out/daemon-before.exe-sha256" "$out/daemon-after.exe-sha256"
sha256sum "$bin" > "$out/binary-after-sha256.txt"
sha256sum "$bench" /tmp/bin/ns-exec > "$out/benchmark-after-sha256.txt"
cmp "$out/binary-sha256.txt" "$out/binary-after-sha256.txt"
cmp "$out/benchmark-sha256.txt" "$out/benchmark-after-sha256.txt"
printf '{"subject_pid":%s,"iterations":%s,"warmup":%s,"daemon_cpu":1,"caller_cpu":0,"provider_cpu":0,"guard_iterations":%s,"guard_fixture_objects":64,"daemon_argv0":"/sbin/ubusd"}\n' "$bus" "$n" "$warmup" "$guard_n" > "$out/meta.json"
kill "$bus"
wait "$bus" 2>/dev/null || :
bus=''
touch "$out/COMPLETE"
