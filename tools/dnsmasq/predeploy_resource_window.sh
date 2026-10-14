#!/bin/sh
# Only called with an owned /tmp root. The local controller verifies socket
# bindings before creating GO. No production PID is ever signalled.
set -eu
root=$1
name=$2
implementation=$3
profile=$4
idle=$5
warm=$6
measure=$7
post=$8
case "$root" in /tmp/dnsmasq-audit-c-*) ;; *) exit 2;; esac
out=$root/$name
mkdir "$out"
chmod 777 "$out"
identities=""
daemon=""
starttime() {
    [ -r "/proc/$1/stat" ] || return 1
    identity_line=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
    identity_fields=${identity_line##*) }
    set -- $identity_fields
    [ "$#" -ge 20 ] || return 1
    shift 19
    printf '%s\n' "$1"
}
track() {
    identity_start=$(starttime "$1") || return 0
    identities="$identities $1:$identity_start"
}
signal_owned() {
    owned_pid=${1%%:*}
    owned_start=${1#*:}
    case "$owned_pid" in ''|*[!0-9]*|0|1) return;; esac
    current_start=$(starttime "$owned_pid") || return 0
    [ "$current_start" = "$owned_start" ] || return 0
    kill -"$2" "$owned_pid" 2>/dev/null || :
}
pause() {
    sleep "$1" &
    pause_pid=$!
    track "$pause_pid"
    wait "$pause_pid"
}
cleanup() {
    trap - EXIT
    trap '' HUP INT TERM
    if [ -f "$out/watchsleep.pid" ]; then identities="$identities $(cat "$out/watchsleep.pid")"; fi
    # TCP children may be absent from /proc/PID/task/PID/children on OpenWrt.
    # Discover only processes whose argv contains this exclusively owned root.
    # Capture starttime now, then revalidate it immediately before each signal.
    for file in /proc/[0-9]*/cmdline; do
        owned_pid=${file#/proc/}; owned_pid=${owned_pid%/cmdline}
        [ "$owned_pid" = "$$" ] && continue
        [ "$owned_pid" = "$PPID" ] && continue
        case "$(tr '\000' ' ' < "$file" 2>/dev/null)" in
            *"$root/"*) track "$owned_pid";;
        esac
    done
    for identity in $identities; do signal_owned "$identity" TERM; done
    sleep 1
    for identity in $identities; do signal_owned "$identity" KILL; done
    wait 2>/dev/null || :
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
cp "$root/$profile.conf" "$out/config"
sed -i "s|@OUT@|$out|g" "$out/config"
cp "$root/$profile.leases" "$out/leases"
chmod 666 "$out/leases"
if [ "$implementation" = C ]; then binary=/usr/sbin/dnsmasq; else binary=$root/dnsmasq-rs; fi
# Detached test process is tracked by its dedicated PID file.
"$root/bind" "$out/daemon.pid" "$out/bind.jsonl" -- "$binary" -k -C "$out/config" >"$out/daemon.log" 2>&1
daemon=$(cat "$out/daemon.pid")
track "$daemon"
# Hard lifetime cap survives loss of the SSH controller. It signals only
# the script, whose trap owns the exact test PIDs; never killall/pkill.
parent=$$
parent_start=$(starttime "$parent")
(sleep 225 & sleeper=$!; sleeper_start=$(starttime "$sleeper");
 echo "$sleeper:$sleeper_start" >"$out/watchsleep.pid";
 wait "$sleeper"; signal_owned "$parent:$parent_start" TERM) &
watchdog=$!
track "$watchdog"
echo "$daemon" >"$out/READY"
i=0
while [ ! -f "$out/GO" ]; do
    i=$((i+1)); [ "$i" -lt 20 ] || exit 3
    pause 1
done
"$root/upstream" --port 15354 --output "$out/upstream.json" --ready-file "$out/upstream.ready" --epoch-file "$out/udp.epoch" --steady-seconds "$measure" >"$out/upstream.log" 2>&1 &
upstream=$!; track "$upstream"; upstream_start=$(starttime "$upstream")
while [ ! -f "$out/upstream.ready" ]; do pause 1; done
seconds=$((idle+warm+measure+post))
"$root/probe" monitor "$daemon" "$seconds" >"$out/metrics.jsonl" 2>"$out/monitor.log" &
monitor=$!; track "$monitor"
pause "$idle"
if [ "$profile" = daily ]; then udp=19; tcp=1; dhcp=0.1; bank=100; else udp=990; tcp=10; dhcp=2; bank=800; fi
"$root/loadgen" --mode udp --host 127.0.0.1 --port 15353 --clients 20 --duration-seconds "$measure" --warmup-seconds "$warm" --rate "$udp" --profile mixed --qtype mix --cache-names "$bank" --name-prefix audit.example --output "$out/udp" --epoch-file "$out/udp.epoch" >"$out/udp.log" 2>&1 &
udp_pid=$!; track "$udp_pid"
"$root/loadgen" --mode tcp --host 127.0.0.1 --port 15353 --clients 2 --duration-seconds "$measure" --warmup-seconds "$warm" --rate "$tcp" --profile mixed --qtype mix --cache-names "$bank" --name-prefix tcp.audit.example --output "$out/tcp" >"$out/tcp.log" 2>&1 &
tcp_pid=$!; track "$tcp_pid"
"$root/loadgen" --mode dhcp --host 127.0.0.1 --port 15467 --client-port 15467 --interface lo --dhcp-first-address 127.0.0.100 --clients 20 --duration-seconds "$measure" --warmup-seconds "$warm" --rate "$dhcp" --output "$out/dhcp" >"$out/dhcp.log" 2>&1 &
dhcp_pid=$!; track "$dhcp_pid"
# Each role's own /proc CPU at start/end, separate from daemon-tree accounting.
for p in "$upstream" "$udp_pid" "$tcp_pid" "$dhcp_pid"; do
    "$root/probe" monitor "$p" "$((warm+measure))" >"$out/worker-$p.jsonl" 2>/dev/null &
    track "$!"
done
wait "$udp_pid"; wait "$tcp_pid"; wait "$dhcp_pid"
pause "$post"
wait "$monitor"
signal_owned "$upstream:$upstream_start" TERM; wait "$upstream"
cat "$out/leases" >"$out/leases-final"
echo complete >"$out/COMPLETE"
