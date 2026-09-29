#!/bin/sh
# Whole control-plane workload on the router after a verified reboot.
# Usage: sh live.sh stock|rust OUT [N=10000] [REPEATS=5] [IDLE_SECONDS=120]
# Both modes use the same client and unchanged kernel/drivers/execution plane.
# Requires /root/r84/bins/owrt-benchmark and stack-switch.sh's hash manifests.
# OUT contains private configuration responses; never commit it.
set -eu
mode=${1:?stock|rust}; out=${2:?private output directory}
n=${3:-10000}; repeats=${4:-5}; idle=${5:-120}
case "$mode" in stock|rust) ;; *) exit 2 ;; esac
for number in "$n" "$repeats" "$idle"; do
    case "$number" in ''|*[!0-9]*) exit 2 ;; esac
done
[ "$n" -gt 0 ] && [ "$repeats" -gt 0 ]
umask 077
mkdir -p "$out"
[ ! -e "$out/STARTED" ] || { echo 'refusing to mix benchmark runs' >&2; exit 2; }
touch "$out/STARTED"
bench=/root/r84/bins/owrt-benchmark
# Fail before collecting loads when an older, frozen client lacks this gate.
"$bench" fw4-compare /dev/null /dev/null
sha256sum "$bench" > "$out/benchmark-sha256.txt"
/bin/sh /root/r84/stack-switch.sh verify "$mode" > "$out/running-hashes.txt"
monitors=$(awk '$2 != "-" {if (sep) printf ","; printf "%s", $2; sep=1}' "$out/running-hashes.txt")
socket=/var/run/ubus/ubus.sock
cat /proc/sys/kernel/random/boot_id > "$out/boot-id.txt"
cat /proc/cpuinfo > "$out/cpuinfo.txt"
uname -r > "$out/kernel.txt"
sha256sum /etc/config/* > "$out/config-before.sha256"
ubus list > "$out/objects.txt"
ubus call service list > "$out/services.json"
ubus call network.interface dump > "$out/network.json"
ubus call network.wireless status > "$out/wireless.json"
ubus call system watchdog > "$out/watchdog.json"
for name in dnsmasq odhcpd hostapd wpa_supplicant; do
    for pid in $(pidof "$name" 2>/dev/null || true); do
        printf '%s %s ' "$name" "$pid"
        sha256sum /proc/"$pid"/exe
    done
done > "$out/execution-plane.txt"
printf '{}\n' > "$out/empty.json"
printf '{"interface":[]}\n' > "$out/expect-network.json"
printf '{"config":"network"}\n' > "$out/input-uci.json"
printf '{"values":{"lan":{}}}\n' > "$out/expect-uci.json"
printf '{"lines":100,"stream":false}\n' > "$out/input-log.json"
printf '{"log":[{}]}\n' > "$out/expect-log.json"
: > "$out/empty.bytes"
/rom/sbin/uci -S -n export network > "$out/expected-uci.bytes"
/rom/sbin/fw4 print > "$out/expected-fw4.bytes" 2> "$out/fw4-stderr.txt"
css=/luci-static/bootstrap/cascade.css
cp "/www$css" "$out/expected-css.bytes"

# A short-lived, explicitly granted session exercises the real authenticated
# /ubus path. Its token and all responses remain in the private output dir.
sid=$(ubus call session create '{"timeout":3600}' | jsonfilter -e '@.ubus_rpc_session')
[ "${#sid}" = 32 ]
cleanup() {
    ubus -t 3 call session destroy "{\"ubus_rpc_session\":\"$sid\"}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
ubus call session grant "{\"ubus_rpc_session\":\"$sid\",\"scope\":\"ubus\",\"objects\":[[\"uci\",\"get\"]]}" >/dev/null
# The HTTP bridge adds the session to the UCI request. Its method permission
# and its configuration read permission are independent ACL scopes.
ubus call session grant "{\"ubus_rpc_session\":\"$sid\",\"scope\":\"uci\",\"objects\":[[\"network\",\"read\"]]}" >/dev/null
printf '{"jsonrpc":"2.0","id":1,"method":"call","params":["%s","uci","get",{"config":"network"}]}\n' "$sid" > "$out/http-post.json"
printf '{"id":1,"result":[0,{"values":{"lan":{}}}]}\n' > "$out/http-expect.json"

rpc() { # file object method input expected count
    file=$1; object=$2; method=$3; input=$4; expected=$5; count=$6
    "$bench" snapshot "$monitors" > "$out/$file-system-before.json"
    "$bench" rpc "$socket" "$object" "$method" "$out/$input" "$out/$expected" "$count" 30 "$monitors" > "$out/$file.json"
    "$bench" snapshot "$monitors" > "$out/$file-system-after.json"
}

measured() { # name command...
    label=$1; shift
    "$bench" snapshot "$monitors" > "$out/$label-system-before.json" || return $?
    "$@" > "$out/$label.json" || return $?
    "$bench" snapshot "$monitors" > "$out/$label-system-after.json"
}

fw4_round() {
    local oracle="$out/$r-fw4-oracle" rc=0
    mkdir "$oracle" "$oracle/samples"
    ubus call network.interface dump > "$oracle/network-before.json"
    /rom/sbin/fw4 print > "$oracle/before.stdout" 2> "$oracle/before.stderr"
    [ -s "$oracle/before.stdout" ]
    # The C reference calls are outside the target CPU and latency intervals.
    # Retain every actual stdout, including a failed warm-up or measurement.
    if OWRT_BENCH_EXEC_JOURNAL="$oracle/samples.jsonl" \
       OWRT_BENCH_EXEC_ARTIFACTS="$oracle/samples" \
       measured "$r-fw4" "$bench" exec-fw4 30 3 "$oracle/before.stdout" "$monitors" -- /sbin/fw4 print; then
        rc=0
    else
        rc=$?
    fi
    /rom/sbin/fw4 print > "$oracle/after.stdout" 2> "$oracle/after.stderr"
    [ -s "$oracle/after.stdout" ]
    ubus call network.interface dump > "$oracle/network-after.json"
    if ! "$bench" fw4-compare "$oracle/before.stdout" "$oracle/after.stdout"; then
        echo 'fw4 window INVALID_ENV: original output changed during this round' >&2
        return 1
    fi
    return "$rc"
}

# Fault in the code/data used by the same warm-up workload in both systems.
rpc warm-network network.interface dump empty.json expect-network.json 100
rpc warm-uci uci get input-uci.json expect-uci.json 100
rpc warm-procd service list empty.json empty.json 100
rpc warm-log log read input-log.json expect-log.json 100
"$bench" http 127.0.0.1:80 GET "$css" - "$out/expected-css.bytes" 100 20 "$monitors" bytes > "$out/warm-http.json"
"$bench" http 127.0.0.1:80 POST /ubus "$out/http-post.json" "$out/http-expect.json" 100 20 "$monitors" json > "$out/warm-jsonrpc.json"
"$bench" idle "$idle" "$monitors" > "$out/idle-before.jsonl"

cat > "$out/mixed.sh" <<'EOF'
#!/bin/sh
set -eu
bench=$1; socket=$2; out=$3; n=$4; monitors=$5; prefix=$6
# The common workload was already warmed before the idle window. Per-lane
# warmups here would otherwise be counted in the outer interval but omitted
# from its successful-operation denominator. Startup/connection cost remains
# part of the mixed window, identically for both implementations.
"$bench" rpc "$socket" service list "$out/empty.json" "$out/empty.json" "$n" 0 "$monitors" > "$out/$prefix-procd.json" & p1=$!
"$bench" rpc "$socket" network.interface dump "$out/empty.json" "$out/expect-network.json" "$n" 0 "$monitors" > "$out/$prefix-network.json" & p2=$!
"$bench" rpc "$socket" uci get "$out/input-uci.json" "$out/expect-uci.json" "$n" 0 "$monitors" > "$out/$prefix-rpcd.json" & p3=$!
"$bench" http 127.0.0.1:80 POST /ubus "$out/http-post.json" "$out/http-expect.json" "$n" 0 "$monitors" json > "$out/$prefix-http.json" & p4=$!
# Wait for every owned process, retaining failure even when another succeeds.
rc=0
for pid in "$p1" "$p2" "$p3" "$p4"; do wait "$pid" || rc=1; done
exit "$rc"
EOF

r=1
while [ "$r" -le "$repeats" ]; do
    # Reverse read-query order every other round to expose order effects.
    if [ "$((r % 2))" -eq 1 ]; then order='network rpcd procd log'; else order='log procd rpcd network'; fi
    for workload in $order; do
        case "$workload" in
            network) rpc "$r-network" network.interface dump empty.json expect-network.json "$n" ;;
            rpcd) rpc "$r-rpcd" uci get input-uci.json expect-uci.json "$n" ;;
            procd) rpc "$r-procd" service list empty.json empty.json "$n" ;;
            log) rpc "$r-log" log read input-log.json expect-log.json "$n" ;;
        esac
    done
    measured "$r-uci" "$bench" exec 100 5 "$out/expected-uci.bytes" "$monitors" -- /sbin/uci -S -n export network
    fw4_round
    measured "$r-http-static" "$bench" http 127.0.0.1:80 GET "$css" - "$out/expected-css.bytes" "$n" 30 "$monitors" bytes
    measured "$r-http-jsonrpc" "$bench" http 127.0.0.1:80 POST /ubus "$out/http-post.json" "$out/http-expect.json" "$n" 30 "$monitors" json
    # The outer measurement supplies a single, non-overlapping CPU interval
    # for all four lanes. Do not add their overlapping daemon CPU counters.
    measured "$r-mixed-total" "$bench" exec 1 0 "$out/empty.bytes" "$monitors" -- /bin/sh "$out/mixed.sh" "$bench" "$socket" "$out" "$n" "$monitors" "$r-mixed"
    printf 'round %s complete\n' "$r"
    r=$((r + 1))
done
"$bench" idle "$idle" "$monitors" > "$out/idle-after.jsonl"
sha256sum /etc/config/* > "$out/config-after.sha256"
cmp -s "$out/config-before.sha256" "$out/config-after.sha256"
/bin/sh /root/r84/stack-switch.sh verify "$mode" > "$out/final-running-hashes.txt"
cmp -s "$out/running-hashes.txt" "$out/final-running-hashes.txt"
printf '{"mode":"%s","iterations":%s,"repeats":%s,"idle_seconds":%s,"mixed_lanes":4}\n' "$mode" "$n" "$repeats" "$idle" > "$out/meta.json"
touch "$out/COMPLETE"
