#!/bin/sh
# R98 independent query recheck, including repeated identical baseline.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] || exit 125
case "$3" in c) bin=/sbin/ubusd ;; rs) bin=/tmp/bin/ubusd-rs ;; *) exit 125 ;; esac
n=$4
bench=/tmp/bin/owrt-benchmark
out=/tmp/out
socket=/var/run/ubus/ubus.sock
mkdir -p /var/run/ubus
sha256sum "$bin" > "$out/binary-sha256.txt"
sha256sum "$bench" /tmp/bin/ns-exec > "$out/benchmark-sha256.txt"
uname -r > "$out/kernel.txt"
"$bin" -s "$socket" > "$out/bus.log" 2>&1 & bus=$!
tries=0
until ubus -t 1 list >/dev/null 2>&1; do
    kill -0 "$bus"; [ "$tries" -lt 20 ]; sleep 1; tries=$((tries + 1))
done
"$bench" serve "$socket" 64 > "$out/provider.log" 2>&1 & provider=$!
tries=0
until ubus -t 1 list bench.filler0063 | grep -qx bench.filler0063; do
    kill -0 "$provider"; [ "$tries" -lt 20 ]; sleep 1; tries=$((tries + 1))
done
i=1
: > /tmp/expected-objects
while [ "$i" -lt 64 ]; do
    printf 'bench.filler%04d\n' "$i" >> /tmp/expected-objects
    i=$((i + 1))
done
printf 'bench.target\n' >> /tmp/expected-objects
ubus list 'bench.*' > "$out/objects-before.txt"
cmp /tmp/expected-objects "$out/objects-before.txt"
"$bench" snapshot "$bus,$provider" > "$out/before.json"
# The frozen client validates bench.target for each request. Complete object
# sets are additionally checked before/after; timing does not replace the
# separate full wire/protocol correctness gates.
    rpc_four() { # label object method input expected [total iterations]
        label=$1; object=$2; method=$3; input=$4; expected=$5; total=${6:-$n}
        printf '%s\n' "$input" > /tmp/input.json
        printf '%s\n' "$expected" > /tmp/expect.json
        count=$((total / 4)); [ "$count" -gt 0 ] || count=1
        mkdir "$out/$label"
        printf '{"clients":4,"iterations_per_client":%s,"warmup_per_client":20}\n' "$count" > "$out/$label/group.json"
        "$bench" snapshot "$monitors" > "$out/$label/before.json"
        clients=''; j=1
        while [ "$j" -le 4 ]; do
            "$bench" "$rpc_mode" "$socket" "$object" "$method" /tmp/input.json /tmp/expect.json "$count" 20 "$monitors" > "$out/$label/client-$j.json" &
            clients="$clients $!"; j=$((j + 1))
        done
        failed=0
        for client in $clients; do wait "$client" || failed=1; done
        "$bench" snapshot "$monitors" > "$out/$label/after.json"
        [ "$failed" = 0 ]
    }
    lookup_four() { # label path total; same outer CPU interval as rpc_four
        label=$1; lookup_path=$2; total=$3
        count=$((total / 4)); [ "$count" -gt 0 ] || count=1
        mkdir "$out/$label"
        printf '{"clients":4,"iterations_per_client":%s,"warmup_per_client":20}\n' "$count" > "$out/$label/group.json"
        "$bench" snapshot "$monitors" > "$out/$label/before.json"
        clients=''; j=1
        while [ "$j" -le 4 ]; do
            "$bench" lookup "$socket" "$lookup_path" "$count" 20 "$monitors" > "$out/$label/client-$j.json" &
            clients="$clients $!"; j=$((j + 1))
        done
        failed=0
        for client in $clients; do wait "$client" || failed=1; done
        "$bench" snapshot "$monitors" > "$out/$label/after.json"
        [ "$failed" = 0 ]
    }
monitors=$bus,$provider
rpc_mode=rpc
"$bench" lookup "$socket" bench.target "$n" 20 "$monitors" > "$out/lookup.json"
lookup_four lookup_c4 bench.target "$n"
"$bench" lookup "$socket" 'bench.*' "$n" 20 "$monitors" > "$out/lookup_prefix_64.json"
rpc_four invoke_c4 bench.target ping '{"n":1}' '{"ok":1}' "$n"
"$bench" snapshot "$bus,$provider" > "$out/after.json"
ubus list 'bench.*' > "$out/objects-after.txt"
cmp /tmp/expected-objects "$out/objects-after.txt"
printf '{"subject_pid":%s,"provider_pid":%s,"iterations":%s,"pilot_only":true}\n' "$bus" "$provider" "$n" > "$out/meta.json"
touch "$out/COMPLETE"
