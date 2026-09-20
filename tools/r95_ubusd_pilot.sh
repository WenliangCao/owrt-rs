#!/bin/sh
# Exploratory lookup costs only. Run through the guarded router collector.
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
"$bench" serve "$socket" 128 > "$out/provider.log" 2>&1 & provider=$!
tries=0
until ubus -t 1 list bench.filler0127 | grep -qx bench.filler0127; do
    kill -0 "$provider"; [ "$tries" -lt 20 ]; sleep 1; tries=$((tries + 1))
done
i=1
: > /tmp/expected-objects
while [ "$i" -lt 128 ]; do
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
"$bench" lookup "$socket" '*' "$n" 100 "$bus,$provider" > "$out/lookup_all_128.json"
"$bench" snapshot "$bus,$provider" > "$out/after.json"
ubus list 'bench.*' > "$out/objects-after.txt"
cmp /tmp/expected-objects "$out/objects-after.txt"
printf '{"subject_pid":%s,"provider_pid":%s,"iterations":%s,"pilot_only":true}\n' "$bus" "$provider" "$n" > "$out/meta.json"
touch "$out/COMPLETE"
