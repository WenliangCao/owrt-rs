#!/bin/sh
# Requested heap diagnostic only; reuse the guarded disposable namespace.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] && [ "$3" = rs ] || exit 125
sha256sum /tmp/bin/ubusd-rs > /tmp/out/binary-sha256.txt
sha256sum /tmp/bin/owrt-benchmark /tmp/bin/ns-exec > /tmp/out/benchmark-sha256.txt
uname -r > /tmp/out/kernel.txt
/tmp/bin/owrt-benchmark > /tmp/out/requested-heap.csv
touch /tmp/out/COMPLETE
