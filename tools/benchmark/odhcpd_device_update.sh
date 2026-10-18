#!/bin/sh
# Invoked by the instrument after it has armed its packet receiver.
set -eu
[ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
[ "$(cat /proc/1/comm)" = ns-exec ] || exit 125
case "${1:-}" in 1|2|3|4|5|6|7|8) sequence=$1 ;; *) exit 2 ;; esac
reply=$(ubus -S -t 2 call fixture change "{\"sequence\":$sequence}")
printf '%s\n' "$reply"
[ "$(printf '%s' "$reply" | jsonfilter -e '@.subscribed')" = true ]
[ "$(printf '%s' "$reply" | jsonfilter -e '@.sequence')" = "$sequence" ]
