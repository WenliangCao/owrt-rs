#!/bin/sh
# Session leader for one frozen case. No child detaches from this group.
set -eu
root=/tmp/dnsmasq-perf-20261015
[ "$(awk '{print $5}' /proc/$$/stat)" = "$$" ]
[ ! -e "$root/STOP" ]
guard_alive() {
    read guard guard_start < "$root/guard.identity"
    [ "$(readlink /proc/$guard/exe)" = "$root/device_perf_guard" ]
    [ "$(awk '{print $22}' /proc/$guard/stat)" = "$guard_start" ]
    kill -0 "$guard"
}
guard_alive
printf '%s %s\n' "$$" "$(awk '{print $22}' /proc/$$/stat)" > "$root/active.group.new"
mv "$root/active.group.new" "$root/active.group"
[ ! -e "$root/STOP" ]
guard_alive
exec "$root/nice10" "$root/device_perf_netns" /bin/sh "$root/device_perf_case.sh" "$root" "$@"
