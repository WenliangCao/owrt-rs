#!/bin/sh
# Three bounded windows retain one daemon and its heap. The controller checks
# production health and socket isolation before creating GO and each segment GO.
set -eu
[ "$#" -eq 3 ] || [ "$#" -eq 7 ] || exit 2
root=$1
name=$2
implementation=$3
idle=${4:-20}
warm=${5:-20}
measure=${6:-120}
post=${7:-20}
case "$root" in /tmp/dnsmasq-audit-c-*) ;; *) exit 2;; esac
case "$root" in *[!A-Za-z0-9_./-]*|*/../*|*/..|*/./*|*/.) exit 2;; esac
case "$name" in ''|*[!A-Za-z0-9_-]*) exit 2;; esac
case "$implementation" in C|R) ;; *) exit 2;; esac
for duration in "$idle" "$warm" "$measure" "$post"; do
    case "$duration" in ''|*[!0-9]*|0?*|????*) exit 2;; esac
    [ "$duration" -le 180 ] || exit 2
done
seconds=$((idle+warm+measure+post))
[ "$measure" -gt 0 ] && [ "$seconds" -le 180 ] || exit 2
out=$root/$name
mkdir "$out"
chmod 777 "$out"
identities=""
segment_identities=""
segment_active=0
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
    if [ "$segment_active" -eq 1 ]; then
        segment_identities="$segment_identities $1:$identity_start"
    fi
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
    for sleeper_file in "$out/watchsleep.pid" "$out"/segment*/watchsleep.pid; do
        if [ -f "$sleeper_file" ]; then identities="$identities $(cat "$sleeper_file")"; fi
    done
    # Same owned-root discovery as the single-window runner; never signal a
    # process without revalidating the captured PID starttime.
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
cleanup_segment() {
    if [ -f "$segment/watchsleep.pid" ]; then
        segment_identities="$segment_identities $(cat "$segment/watchsleep.pid")"
    fi
    # Segment helpers name their segment directory in argv. The daemon and
    # its TCP children use out/config and deliberately survive this cleanup.
    for file in /proc/[0-9]*/cmdline; do
        owned_pid=${file#/proc/}; owned_pid=${owned_pid%/cmdline}
        [ "$owned_pid" = "$$" ] && continue
        [ "$owned_pid" = "$PPID" ] && continue
        [ "$owned_pid" = "$daemon" ] && continue
        case "$(tr '\000' ' ' < "$file" 2>/dev/null)" in
            *"$segment/"*) track "$owned_pid";;
        esac
    done
    for identity in $segment_identities; do signal_owned "$identity" TERM; done
    sleep 1
    for identity in $segment_identities; do signal_owned "$identity" KILL; done
    for identity in $segment_identities; do wait "${identity%%:*}" 2>/dev/null || :; done
    segment_active=0
    segment_identities=""
}
daemon_alive() {
    current_daemon_start=$(starttime "$daemon") || return 1
    [ "$current_daemon_start" = "$daemon_start" ] || return 1
    daemon_stat=$(cat "/proc/$daemon/stat" 2>/dev/null) || return 1
    daemon_fields=${daemon_stat##*) }
    case "$daemon_fields" in Z\ *|X\ *) return 1;; esac
    kill -0 "$daemon" 2>/dev/null
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
parent=$$
parent_start=$(starttime "$parent")
# Covers startup, all GO waits, all three windows, and final convergence.
(sleep 615 & sleeper=$!; sleeper_start=$(starttime "$sleeper");
 echo "$sleeper:$sleeper_start" >"$out/watchsleep.pid";
 wait "$sleeper"; signal_owned "$parent:$parent_start" TERM) &
track "$!"
cp "$root/busy.conf" "$out/config"
sed -i "s|@OUT@|$out|g" "$out/config"
cp "$root/busy.leases" "$out/leases"
chmod 666 "$out/leases"
if [ "$implementation" = C ]; then binary=/usr/sbin/dnsmasq; else binary=$root/dnsmasq-rs; fi
"$root/bind" "$out/daemon.pid" "$out/bind.jsonl" -- "$binary" -k -C "$out/config" >"$out/daemon.log" 2>&1
daemon=$(cat "$out/daemon.pid")
track "$daemon"
daemon_start=$(starttime "$daemon")
printf '%s:%s\n' "$daemon" "$daemon_start" >"$out/daemon.identity"
echo "$daemon" >"$out/READY"
i=0
while [ ! -f "$out/GO" ]; do
    i=$((i+1)); [ "$i" -lt 20 ] || exit 3
    daemon_alive || exit 4
    pause 1
done
for number in 1 2 3; do
    segment=$out/segment$number
    mkdir "$segment"
    chmod 777 "$segment"
    segment_active=1
    segment_identities=""
    (sleep 225 & sleeper=$!; sleeper_start=$(starttime "$sleeper");
     echo "$sleeper:$sleeper_start" >"$segment/watchsleep.pid";
     wait "$sleeper"; signal_owned "$parent:$parent_start" TERM) &
    track "$!"
    daemon_alive || exit 4
    printf '%s:%s\n' "$daemon" "$daemon_start" >"$segment/daemon.identity"
    echo "$daemon" >"$segment/SEGMENT_READY"
    i=0
    while [ ! -f "$segment/GO" ]; do
        i=$((i+1)); [ "$i" -lt 20 ] || exit 3
        daemon_alive || exit 4
        pause 1
    done
    "$root/upstream" --port 15354 --output "$segment/upstream.json" --ready-file "$segment/upstream.ready" --epoch-file "$segment/udp.epoch" --steady-seconds "$measure" >"$segment/upstream.log" 2>&1 &
    upstream=$!; track "$upstream"; upstream_start=$(starttime "$upstream")
    while [ ! -f "$segment/upstream.ready" ]; do
        [ "$(starttime "$upstream")" = "$upstream_start" ] || exit 5
        pause 1
    done
    "$root/probe" monitor "$daemon" "$seconds" >"$segment/metrics.jsonl" 2>"$segment/monitor.log" &
    monitor=$!; track "$monitor"
    pause "$idle"
    "$root/loadgen" --mode udp --host 127.0.0.1 --port 15353 --clients 20 --duration-seconds "$measure" --warmup-seconds "$warm" --rate 990 --seed "$number" --profile mixed --qtype mix --cache-names 800 --name-prefix audit.example --output "$segment/udp" --epoch-file "$segment/udp.epoch" >"$segment/udp.log" 2>&1 &
    udp_pid=$!; track "$udp_pid"
    "$root/loadgen" --mode tcp --host 127.0.0.1 --port 15353 --clients 2 --duration-seconds "$measure" --warmup-seconds "$warm" --rate 10 --seed "$number" --profile mixed --qtype mix --cache-names 800 --name-prefix tcp.audit.example --output "$segment/tcp" >"$segment/tcp.log" 2>&1 &
    tcp_pid=$!; track "$tcp_pid"
    "$root/loadgen" --mode dhcp --host 127.0.0.1 --port 15467 --client-port 15467 --interface lo --dhcp-first-address 127.0.0.100 --clients 20 --duration-seconds "$measure" --warmup-seconds "$warm" --rate 2 --seed "$number" --output "$segment/dhcp" >"$segment/dhcp.log" 2>&1 &
    dhcp_pid=$!; track "$dhcp_pid"
    for p in "$upstream" "$udp_pid" "$tcp_pid" "$dhcp_pid"; do
        "$root/probe" monitor "$p" "$((warm+measure))" >"$segment/worker-$p.jsonl" 2>/dev/null &
        track "$!"
    done
    wait "$udp_pid"; wait "$tcp_pid"; wait "$dhcp_pid"
    pause "$post"
    wait "$monitor"
    signal_owned "$upstream:$upstream_start" TERM; wait "$upstream"
    daemon_alive || exit 4
    cat "$out/leases" >"$segment/leases-final"
    cleanup_segment
    daemon_alive || exit 4
    echo complete >"$segment/COMPLETE"
done
cat "$out/leases" >"$out/leases-final"
echo complete >"$out/COMPLETE"
