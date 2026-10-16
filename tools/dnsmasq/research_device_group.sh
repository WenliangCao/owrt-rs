#!/bin/sh
# Session leader for one research case or the bounded CPU-clock capability helper. No child detaches from this group.
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
if [ "${1:-}" = cpu-clock-capability ]; then
    [ "$#" = 1 ]
    exec "$root/nice10" "$root/device_perf_netns" "$root/research_cpu_clock_probe" selftest
fi
exec "$root/nice10" "$root/device_perf_netns" /bin/sh "$root/research_device_case.sh" "$root" "$@"
