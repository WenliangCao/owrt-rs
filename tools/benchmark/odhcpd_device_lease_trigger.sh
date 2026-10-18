#!/bin/sh
# Both isolated subjects use the same inert lease callback. No production
# dnsmasq or service bus is reachable; callback CPU is outside the subject.
set -eu
[ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
printf 'lease-change\n' >> /tmp/out/leasetrigger.log
