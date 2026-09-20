#!/bin/sh
# Dispatch/socket-pair diagnostics, never an end-to-end daemon benchmark.
set -eu
if [ "${1:-}" = --namespace ]; then
    exec /bin/sh "$(dirname "$0")/isolated.sh" "$@"
fi
[ "${1:-}" = --workload ] && [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$2" = ubusd ] && [ "$3" = rs ] || exit 125
sha256sum /tmp/bin/ubusd-rs > /tmp/out/binary-sha256.txt
/tmp/bin/ubusd-rs "$4" lookup_ > /tmp/out/profile.csv
touch /tmp/out/COMPLETE
