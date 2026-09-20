#!/bin/sh
# Requested Rust heap of actual registration dispatch; not RSS/PSS or timing.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] && [ "$3" = rs ] || exit 125
sha256sum /tmp/bin/ubusd-rs > /tmp/out/binary-sha256.txt
/tmp/bin/ubusd-rs > /tmp/out/methods.csv
touch /tmp/out/COMPLETE
