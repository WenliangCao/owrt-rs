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
case "$root:$side:$label" in /tmp/dnsmasq-perf-20261014:c:*|/tmp/dnsmasq-perf-20261014:rust:*) ;; *) exit 2;; esac
case "$label" in *[!a-zA-Z0-9_-]*|'') exit 2;; esac
[ ! -e "$root/STOP" ]
[ "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)" ]
kill -0 "$(cat "$root/guard.pid")"
out=$root/runs/$label
mkdir "$out"
daemon= upstream= observer= timer=
daemon_start= upstream_start= observer_start= timer_start=
starttime() { awk '{print $22}' "/proc/$1/stat" 2>/dev/null; }
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
    owned_signal "$observer" "$observer_start" TERM
    owned_signal "$daemon" "$daemon_start" TERM
    owned_signal "$upstream" "$upstream_start" TERM
    sleep 1
    owned_signal "$observer" "$observer_start" KILL
    owned_signal "$daemon" "$daemon_start" KILL
    owned_signal "$upstream" "$upstream_start" KILL
    owned_signal "$timer" "$timer_start" TERM
    for pid in $observer $daemon $upstream $timer; do wait "$pid" 2>/dev/null || :; done
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
printf '%s\n' "$side $mode $profile $rate $warm $seconds" > "$out/parameters.txt"
date -u > "$out/start.txt"
readlink /proc/self/ns/net > "$out/netns.txt"
elf=$root/dnsmasq-$side
sha256sum "$elf" > "$out/elf.sha256"
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
dhcp-range=127.0.0.10,127.0.0.159,255.0.0.0,127.255.255.255,12h
dhcp-lease-max=150
dhcp-leasefile=$out/leases
domain=device-perf.test
EOF
    i=0
    while [ "$i" -lt 150 ]; do
        printf 'dhcp-host=02:00:00:6a:00:%02x,127.0.0.%s,lease%03d\n' "$i" "$((i+10))" "$i" >> "$out/config"
        i=$((i+1))
    done
fi
sha256sum "$out/config" > "$out/config.sha256"
/usr/bin/time -f '%U %S %e' -o "$out/upstream.time" /bin/sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$out/upstream.pid" "$root/m6a_upstream" --port 15354 --delay-us 1000 --ttl 120 --output "$out/upstream.json" --ready-file "$out/upstream.ready" --epoch-file "$out/epoch" --steady-seconds "$seconds" > "$out/upstream.stdout" 2> "$out/upstream.stderr" &
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
readlink /proc/$daemon/ns/net > "$out/daemon.netns"
# Seed the parent cache through UDP; TCP child-only warming is insufficient.
if [ "$mode" != dhcp ] && [ "$profile" != miss ]; then
    "$root/m6a_loadgen" --mode udp --host 127.0.0.1 --port 15353 --clients 32 --duration-seconds 5 --warmup-seconds 0 --rate 200 --seed 0x293001 --name-prefix m6a.test --profile hit --qtype aaaa30 --cache-names 800 --timeout-ms 1000 --output "$out/prewarm" > "$out/prewarm.stdout" 2> "$out/prewarm.stderr"
fi
"$root/predeploy_resource_probe" monitor "$daemon" 1 > "$out/before.jsonl"
"$root/predeploy_resource_probe" monitor "$daemon" "$((warm+seconds+5))" > "$out/resources.jsonl" 2> "$out/resources.stderr" &
observer=$!
observer_start=$(starttime "$observer")
clients=32
[ "$mode" != tcp ] || clients=8
extra=
port=15353
if [ "$mode" = dhcp ]; then
    clients=150; port=67
    extra="--client-port 68 --interface lo --dhcp-first-address 127.0.0.10 --dhcp-renew-only"
fi
/usr/bin/time -f '%U %S %e' -o "$out/client.time" "$root/m6a_loadgen" --mode "$mode" --host 127.0.0.1 --port "$port" --clients "$clients" --duration-seconds "$seconds" --warmup-seconds "$warm" --rate "$rate" --seed 0x293001 --name-prefix m6a.test --profile "$profile" --qtype aaaa30 --cache-names 800 --timeout-ms 1000 --output "$out/client" --epoch-file "$out/epoch" --epoch-output "$out/epoch.json" $extra > "$out/client.stdout" 2> "$out/client.stderr"
sleep 1
"$root/predeploy_resource_probe" monitor "$daemon" 1 > "$out/after.jsonl"
cat /proc/$daemon/stat > "$out/final.stat"
kill "$observer" 2>/dev/null || :
wait "$observer" 2>/dev/null || :
observer=
kill "$upstream"
wait "$timer"
upstream= timer=
if [ "$mode" = dhcp ]; then wc -l "$out/leases" > "$out/lease-count.txt"; fi
kill "$daemon"
wait "$daemon"
daemon=
date -u > "$out/end.txt"
printf 'complete\n' > "$out/COMPLETE"
