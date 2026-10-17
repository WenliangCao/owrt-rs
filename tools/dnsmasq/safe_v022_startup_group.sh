#!/bin/sh
# Same owned-session and guard boundary as the recovered traffic group.
set -eu
root=/tmp/dnsmasq-perf-v022-20261017
[ "$#" = 3 ]
case "$1:$2" in helper:k|helper:candidate|resolver:k|resolver:candidate) ;; *) exit 2;; esac
case "$3" in ''|*[!a-z0-9-]*) exit 2;; esac
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
exec "$root/nice10" "$root/device_perf_netns" /bin/sh "$root/safe_v022_startup_case.sh" "$@"
