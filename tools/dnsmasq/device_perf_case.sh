#!/bin/sh
# Run only via device_perf_netns inside the task's independently guarded group.
# No production configuration, interfaces, Unix sockets or DHCP hooks are used.
set -eu
root=$1
side=$2
label=$3
mode=$4
profile=$5
rate=$6
warm=$7
seconds=$8
dhcp_clients=${9:-150}
case "$dhcp_clients" in 6|150) ;; *) exit 2;; esac
case "$root:$side:$label" in /tmp/dnsmasq-perf-20261014-v3:c:*|/tmp/dnsmasq-perf-20261014-v3:rust:*) ;; *) exit 2;; esac
case "$label" in *[!a-zA-Z0-9_-]*|'') exit 2;; esac
[ ! -e "$root/STOP" ]
[ "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)" ]
kill -0 "$(cat "$root/guard.pid")"
out=$root/runs/$label
mkdir "$out"
daemon= upstream= observer= timer= client= client_timer=
daemon_start= upstream_start= observer_start= timer_start= client_start= client_timer_start=
starttime() {
    # An empty PID otherwise reads /proc//stat, the system-wide stat file.
    case "$1" in ''|*[!0-9]*) return 1;; esac
    awk '{print $22}' "/proc/$1/stat" 2>/dev/null
}
reap_observer() {
    [ -n "$observer" ] || return 0
    observer_status=0
    wait "$observer" || observer_status=$?
    printf '%s\n' "$observer_status" > "$out/observer.exit"
    observer=
}
owned_signal() {
    target=$1 expected=$2 signal=$3
    [ -n "$target" ] && [ -n "$expected" ] || return 0
    [ "$(starttime "$target")" = "$expected" ] || return 0
    [ "$(awk '{print $5}' "/proc/$target/stat" 2>/dev/null)" = "$$" ] || return 0
    kill "-$signal" "$target" 2>/dev/null || :
}
cleanup() {
    trap - EXIT INT TERM
    if [ -z "$upstream" ] && [ -n "$timer" ] && [ "$(starttime "$timer")" = "$timer_start" ] && [ -f "$out/upstream.pid" ]; then
        candidate=$(cat "$out/upstream.pid")
        if [ "$(awk '{print $4}' "/proc/$candidate/stat" 2>/dev/null)" = "$timer" ]; then upstream=$candidate; upstream_start=$(starttime "$upstream"); fi
    fi
    if [ -z "$client" ] && [ -n "$client_timer" ] && [ "$(starttime "$client_timer")" = "$client_timer_start" ] && [ -f "$out/client.pid" ]; then
        candidate=$(cat "$out/client.pid")
        if [ "$(awk '{print $4}' "/proc/$candidate/stat" 2>/dev/null)" = "$client_timer" ]; then client=$candidate; client_start=$(starttime "$client"); fi
    fi
    owned_signal "$client" "$client_start" TERM
    owned_signal "$observer" "$observer_start" TERM
    owned_signal "$daemon" "$daemon_start" TERM
    owned_signal "$upstream" "$upstream_start" TERM
    sleep 1
    owned_signal "$observer" "$observer_start" KILL
    owned_signal "$daemon" "$daemon_start" KILL
    owned_signal "$upstream" "$upstream_start" KILL
    owned_signal "$client" "$client_start" KILL
    owned_signal "$client_timer" "$client_timer_start" TERM
    owned_signal "$timer" "$timer_start" TERM
    reap_observer
    for pid in $daemon $upstream $timer $client_timer; do wait "$pid" 2>/dev/null || :; done
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
printf '%s\n' "$side $mode $profile $rate $warm $seconds dhcp_clients=$dhcp_clients" > "$out/parameters.txt"
date -u > "$out/start.txt"
readlink /proc/self/ns/net > "$out/netns.txt"
elf=$root/dnsmasq-$side
sha256sum "$elf" > "$out/elf.sha256"
sha256sum "$root/m6a_loadgen" "$root/m6a_upstream" "$root/device_perf_resource_probe" "$root/device_perf_lifecycle" "$root/device_perf_case.sh" > "$out/tools.sha256"
case "$mode" in
life-startup|life-hup|life-config)
    # The lifecycle helper keeps every child inside this guarded process group.
    # profile=non-marker hosts; rate=leases; warm=repeats; seconds=period ms.
    /usr/bin/time -f '%U %S %e' -o "$out/client.time" "$root/device_perf_lifecycle" "${mode#life-}" "$elf" "$out" "$profile" "$warm" "$seconds" "$rate" > "$out/lifecycle.jsonl" 2> "$out/lifecycle.stderr"
    date -u > "$out/end.txt"
    printf 'complete\n' > "$out/COMPLETE"
    exit 0
    ;;
esac
cat > "$out/config" <<EOF
no-hosts
no-resolv
no-poll
user=root
group=root
interface=lo
bind-interfaces
listen-address=127.0.0.1
port=15353
cache-size=1000
edns-packet-max=1232
dns-forward-max=150
server=127.0.0.1#15354
host-record=ready.device-perf.test,192.0.2.1
pid-file=$out/dnsmasq.pid
log-facility=$out/daemon.log
EOF
if [ "$mode" = dhcp ]; then
    cat >> "$out/config" <<EOF
no-ping
dhcp-authoritative
dhcp-range=127.0.0.10,127.0.0.$((9+dhcp_clients)),255.0.0.0,127.255.255.255,12h
dhcp-lease-max=$dhcp_clients
dhcp-leasefile=$out/leases
domain=device-perf.test
EOF
    i=0
    while [ "$i" -lt "$dhcp_clients" ]; do
        printf 'dhcp-host=02:00:00:6a:00:%02x,127.0.0.%s,lease%03d\n' "$i" "$((i+10))" "$i" >> "$out/config"
        i=$((i+1))
    done
fi
sha256sum "$out/config" > "$out/config.sha256"
/usr/bin/time -f '%U %S %e' -o "$out/upstream.time" /bin/sh -c 'echo $$ > "$1.tmp" && mv "$1.tmp" "$1" || exit 1; shift; exec "$@"' sh "$out/upstream.pid" "$root/m6a_upstream" --port 15354 --delay-us 1000 --ttl 120 --output "$out/upstream.json" --ready-file "$out/upstream.ready" --epoch-file "$out/epoch" --steady-seconds "$seconds" > "$out/upstream.stdout" 2> "$out/upstream.stderr" &
timer=$!
timer_start=$(starttime "$timer")
i=0
while [ ! -f "$out/upstream.ready" ]; do [ "$i" -lt 5 ]; kill -0 "$timer"; sleep 1; i=$((i+1)); done
upstream=$(cat "$out/upstream.pid")
upstream_start=$(starttime "$upstream")
"$elf" --keep-in-foreground --conf-file="$out/config" > "$out/daemon.stdout" 2> "$out/daemon.stderr" &
daemon=$!
daemon_start=$(starttime "$daemon")
printf '%s\n' "$daemon" > "$out/actual.pid"
sleep 1
kill -0 "$daemon"
sha256sum /proc/$daemon/exe > "$out/live.sha256"
cat /proc/$daemon/maps > "$out/live.maps"
readlink /proc/$daemon/ns/net > "$out/daemon.netns"
# Seed the parent cache through UDP; TCP child-only warming is insufficient.
if [ "$mode" != dhcp ] && [ "$profile" != miss ]; then
    "$root/m6a_loadgen" --mode udp --host 127.0.0.1 --port 15353 --clients 32 --duration-seconds 5 --warmup-seconds 0 --rate 200 --seed 0x293001 --name-prefix m6a.test --profile hit --qtype aaaa30 --cache-names 800 --timeout-ms 1000 --output "$out/prewarm" > "$out/prewarm.stdout" 2> "$out/prewarm.stderr"
fi
"$root/device_perf_resource_probe" monitor "$daemon" 1 > "$out/before.jsonl"
clients=32
[ "$mode" != tcp ] || clients=8
extra=
port=15353
if [ "$mode" = dhcp ]; then
    clients=$dhcp_clients; port=67
    extra="--client-port 68 --interface lo --dhcp-first-address 127.0.0.10 --dhcp-renew-only"
fi
/usr/bin/time -f '%U %S %e' -o "$out/client.time" /bin/sh -c 'echo $$ > "$1.tmp" && mv "$1.tmp" "$1" || exit 1; shift; exec "$@"' sh "$out/client.pid" "$root/m6a_loadgen" --mode "$mode" --host 127.0.0.1 --port "$port" --clients "$clients" --duration-seconds "$seconds" --warmup-seconds "$warm" --rate "$rate" --seed 0x293001 --name-prefix m6a.test --profile "$profile" --qtype aaaa30 --cache-names 800 --timeout-ms 1000 --output "$out/client" --epoch-file "$out/epoch" --epoch-output "$out/epoch.json" $extra > "$out/client.stdout" 2> "$out/client.stderr" &
client_timer=$!
client_timer_start=$(starttime "$client_timer")
i=0
while [ ! -f "$out/client.pid" ]; do [ "$i" -lt 5 ]; kill -0 "$client_timer"; sleep 1; i=$((i+1)); done
client=$(cat "$out/client.pid")
client_start=$(starttime "$client")
# Known helper PIDs are sampled directly, separately from the service tree.
printf '%s\n' "$daemon" "$((warm+seconds+5))" "$client" "$upstream" > "$out/observer.args"
"$root/device_perf_resource_probe" monitor "$daemon" "$((warm+seconds+5))" "$client" "$upstream" > "$out/resources.jsonl" 2> "$out/resources.stderr" &
observer=$!
printf '%s\n' "$observer" > "$out/observer.pid"
observer_start=$(starttime "$observer")
printf '%s\n' "$observer_start" > "$out/observer.starttime"
wait "$client_timer"
client= client_timer=
sleep 1
"$root/device_perf_resource_probe" monitor "$daemon" 1 > "$out/after.jsonl"
cat /proc/$daemon/stat > "$out/final.stat"
owned_signal "$observer" "$observer_start" TERM
reap_observer
# The sampler returns 1 on our normal SIGTERM, 0 if its duration elapsed.
[ "$observer_status" -le 1 ]
[ -s "$out/resources.jsonl" ]
[ ! -s "$out/resources.stderr" ]
owned_signal "$upstream" "$upstream_start" TERM
wait "$timer"
upstream= timer=
if [ "$mode" = dhcp ]; then wc -l "$out/leases" > "$out/lease-count.txt"; fi
owned_signal "$daemon" "$daemon_start" TERM
wait "$daemon"
daemon=
date -u > "$out/end.txt"
printf 'complete\n' > "$out/COMPLETE"
