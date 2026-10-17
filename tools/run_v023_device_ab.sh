#!/bin/sh
# One frozen router batch. Bundles are verified by the caller before launch.
# BASE contains fw4/, netifd/ and this script; BASE/out must never exist before.
set -eu
start_ticks() {
    sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'
}
if [ "${1:-}" = --owned ]; then
    out=$2
    shift 2
    born=$(start_ticks "$$")
    [ -n "$born" ]
    printf '%s %s\n' "$$" "$born" >> "$out/owned-pids"
    exec "$@"
fi
base=$1
case "$base" in /tmp/v023-ab-*) ;; *) exit 2;; esac
[ "$#" = 1 ] && [ ! -e "$base/out" ]
mkdir "$base/out"
out=$base/out
a= b= f= watchdog=
stop_registered() {
    while read -r pid born; do
        current=$(start_ticks "$pid")
        if [ -n "$current" ] && [ "$current" = "$born" ]; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done < "$out/owned-pids"
}
cleanup() {
    trap - EXIT HUP INT TERM
    for child in "$a" "$b" "$f" "$watchdog"; do
        [ -z "$child" ] || kill "$child" 2>/dev/null || true
    done
    for child in "$a" "$b" "$f" "$watchdog"; do
        [ -z "$child" ] || wait "$child" 2>/dev/null || true
    done
}
trap cleanup EXIT
trap 'exit 124' HUP INT TERM
parent=$$
parent_start=$(start_ticks "$parent")
: > "$out/owned-pids"
(
    sleeper=
    trap 'test -z "$sleeper" || kill "$sleeper" 2>/dev/null || true; stop_registered; exit 0' HUP INT TERM
    sleep 600 & sleeper=$!
    wait "$sleeper"
    printf '600 second limit\n' > "$out/TIMEOUT"
    # This independent guard also handles a controller killed without its trap.
    # Start times prevent a stale PID from targeting an unrelated process.
    stop_registered
    if [ "$(start_ticks "$parent")" = "$parent_start" ]; then
        kill -TERM "$parent" 2>/dev/null || true
    fi
) & watchdog=$!
cat /proc/uptime > "$out/uptime-before"
cat /proc/sys/kernel/random/boot_id > "$out/boot-before"
readlink /proc/self/ns/net > "$out/parent-netns"
cat /proc/meminfo > "$out/meminfo-before"

wait_file() {
    file=$1 process=$2 limit=$3
    count=0
    while [ ! -f "$file" ]; do
        kill -0 "$process"
        [ "$count" -lt "$limit" ]
        count=$((count+1))
        sleep 1
    done
}

mkdir "$out/floor"
for number in 1 2 3 4 5 6; do
    "$base/fw4/exec-sample" "$out/floor/$number.json" /dev/null "$out/floor/$number.stderr" /bin/busybox true
done
printf 'floor complete\n'

sh "$base/run.sh" --owned "$out" sh "$base/netifd/driver.sh" / "$base/netifd" netifd-v022 "$out/netifd-A" A > "$out/netifd-A.log" 2>&1 & a=$!
sh "$base/run.sh" --owned "$out" sh "$base/netifd/driver.sh" / "$base/netifd" netifd-v023 "$out/netifd-B" B > "$out/netifd-B.log" 2>&1 & b=$!
wait_file "$out/netifd-A/READY" "$a" 20
wait_file "$out/netifd-B/READY" "$b" 20
[ "$(cat "$out/netifd-A/netns")" != "$(cat "$out/parent-netns")" ]
[ "$(cat "$out/netifd-B/netns")" != "$(cat "$out/parent-netns")" ]
[ "$(cat "$out/netifd-A/netns")" != "$(cat "$out/netifd-B/netns")" ]
t0=$("$base/netifd/netifd-renewal-cpu" now)
t0=$((t0+5000000000))
printf '%s\n' "$t0" > "$out/netifd-A/start.fifo"
printf '%s\n' "$t0" > "$out/netifd-B/start.fifo"
printf 'netifd fixed eight-pair schedule started\n'
wait "$a"; a=
wait "$b"; b=
[ -f "$out/netifd-A/COMPLETE" ] && [ -f "$out/netifd-B/COMPLETE" ]
printf 'netifd complete\n'

sh "$base/run.sh" --owned "$out" sh "$base/fw4/driver.sh" / "$base/fw4" "$out/fw4" > "$out/fw4.log" 2>&1 & f=$!
wait_file "$out/fw4/READY" "$f" 20
[ "$(cat "$out/fw4/netns.txt")" != "$(cat "$out/parent-netns")" ]
for scene in unchanged changed start check print; do
    number=0
    for side in A B B A A B A B B A B A A B; do
        number=$((number+1))
        phase=cal
        [ "$number" -le 6 ] || phase=formal
        id=$scene-$phase-$number-$side
        printf '%s %s %s\n' "$scene" "$side" "$id" > "$out/fw4/control"
        wait_file "$out/fw4/$id/COMPLETE" "$f" 20
    done
    printf 'fw4 %s complete\n' "$scene"
done
printf 'stop\n' > "$out/fw4/control"
wait "$f"; f=
cat /proc/uptime > "$out/uptime-after"
cat /proc/sys/kernel/random/boot_id > "$out/boot-after"
cmp "$out/boot-before" "$out/boot-after"
cat /proc/meminfo > "$out/meminfo-after"
printf 'complete\n' > "$out/COMPLETE"
printf 'fixed batch complete\n'
