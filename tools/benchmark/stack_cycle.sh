#!/bin/sh
# Real configuration delivery on the active, authorized whole stack.
# Uses only a newly-created probe configuration and service. Never edits LAN,
# WAN, wireless or firewall configuration. Raw results must remain private.
set -eu
mode=${1:?stock|rust}; out=${2:?private output}; repeats=${3:-3}; count=${4:-10}
case "$mode" in stock|rust) ;; *) exit 2 ;; esac
case "$out" in /tmp/owrt-stack-*) ;; *) exit 2 ;; esac
for n in "$repeats" "$count"; do
    case "$n" in ''|*[!0-9]*) exit 2 ;; esac
    [ "$n" -gt 0 ]
done
[ ! -e "$out" ]
for p in /etc/config/owrtstackprobe /var/run/uci/owrtstackprobe /tmp/.uci/owrtstackprobe /etc/init.d/owrt-stack-probe /tmp/owrt-stack-probe; do
    [ ! -e "$p" ] || { echo "probe path already exists: $p" >&2; exit 2; }
done
umask 077
mkdir "$out" /tmp/owrt-stack-probe
bench=/root/r84/bins/owrt-benchmark
/bin/sh /root/r84/stack-switch.sh verify "$mode" > "$out/running-hashes.txt"
monitors=$(awk '$2 != "-" {if (sep) printf ","; printf "%s", $2; sep=1}' "$out/running-hashes.txt")
sha256sum /etc/config/* > "$out/config-before.sha256"
cleanup() {
    if [ -f /etc/init.d/owrt-stack-probe ]; then
        /etc/init.d/owrt-stack-probe stop > "$out/stop.log" 2>&1 || return 1
    fi
    rm -f /etc/init.d/owrt-stack-probe /etc/config/owrtstackprobe /tmp/.uci/owrtstackprobe
    rm -rf /tmp/owrt-stack-probe
    /sbin/reload_config > "$out/cleanup-reload.stdout" 2> "$out/cleanup-reload.stderr"
}
trap 'cleanup' EXIT
trap 'exit 130' INT TERM
cp /root/r84/tools/benchmark/stack_probe.init /etc/init.d/owrt-stack-probe
chmod 755 /etc/init.d/owrt-stack-probe
printf "config probe 'state'\n\toption value '0'\n" > /etc/config/owrtstackprobe
printf '0\n' > /tmp/owrt-stack-probe/sequence
: > /tmp/owrt-stack-probe/deliveries
: > "$out/empty.bytes"
/etc/init.d/owrt-stack-probe start > "$out/start.log" 2>&1
/sbin/reload_config > "$out/seed.stdout" 2> "$out/seed.stderr"
ubus call service list '{"name":"owrt-stack-probe","verbose":true}' > "$out/service.json"
"$bench" snapshot "$monitors" > "$out/before.json"
r=1
while [ "$r" -le "$repeats" ]; do
    "$bench" snapshot "$monitors" > "$out/$r-unchanged-before.json"
    "$bench" exec 20 1 "$out/empty.bytes" "$monitors" -- /sbin/reload_config > "$out/$r-unchanged.json"
    "$bench" snapshot "$monitors" > "$out/$r-unchanged-after.json"
    expected=$(((r - 1) * (count + 1)))
    [ "$(wc -l < /tmp/owrt-stack-probe/deliveries)" -eq "$expected" ]
    "$bench" snapshot "$monitors" > "$out/$r-cycle-before.json"
    "$bench" exec "$count" 1 "$out/empty.bytes" "$monitors" -- /root/r84/bins/stack-config-cycle "$out" > "$out/$r-cycle.json"
    "$bench" snapshot "$monitors" > "$out/$r-cycle-after.json"
    expected=$((r * (count + 1)))
    [ "$(wc -l < /tmp/owrt-stack-probe/deliveries)" -eq "$expected" ]
    printf 'configuration round %s complete\n' "$r"
    r=$((r + 1))
done
cp /tmp/owrt-stack-probe/deliveries "$out/deliveries.txt"
cp /etc/config/owrtstackprobe "$out/final-probe-config"
cleanup
trap - EXIT INT TERM
sha256sum /etc/config/* > "$out/config-after.sha256"
cmp "$out/config-before.sha256" "$out/config-after.sha256"
ubus call service list '{"name":"owrt-stack-probe"}' > "$out/service-after.json"
"$bench" idle 10 "$monitors" > "$out/after-cleanup.jsonl"
/bin/sh /root/r84/stack-switch.sh verify "$mode" > "$out/final-running-hashes.txt"
cmp "$out/running-hashes.txt" "$out/final-running-hashes.txt"
printf '{"mode":"%s","repeats":%s,"count":%s,"warmup_per_round":1,"poll_interval_ms":5,"default_trigger_delay_ms":1000}\n' "$mode" "$repeats" "$count" > "$out/meta.json"
touch "$out/COMPLETE"
