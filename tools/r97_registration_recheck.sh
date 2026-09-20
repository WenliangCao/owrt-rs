#!/bin/sh
# Independent small-signature follow-up; preserves the initial four-arm data.
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
ubus list > "$out/objects-before.txt"
[ ! -s "$out/objects-before.txt" ]
"$bench" snapshot "$bus" > "$out/before.json"
for scenario in 1:8 16:8; do
    methods=${scenario%:*}
    bytes=${scenario#*:}
    "$bench" register-cycle "$socket" "$methods" "$bytes" "$n" 20 "$bus" > "$out/register_${methods}_${bytes}.json"
done
"$bench" snapshot "$bus" > "$out/after.json"
ubus list > "$out/objects-after.txt"
[ ! -s "$out/objects-after.txt" ]
printf '{"subject_pid":%s,"iterations":%s,"pilot_only":true}\n' "$bus" "$n" > "$out/meta.json"
touch "$out/COMPLETE"
