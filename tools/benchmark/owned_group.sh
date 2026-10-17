#!/bin/sh
# Keep the guard root in the session leader's argv while waiting for the harness.
# Usage: owned_group.sh ROOT run GUARD_PID GUARD_START RECEIPT COMMAND
#        owned_group.sh ROOT stop RECEIPT
set -eu
[ "$#" -ge 3 ] || exit 2
root=$1
operation=$2
shift 2
case "$root" in /tmp/dnsmasq-perf-*) ;; *) exit 2;; esac
suffix=${root#/tmp/dnsmasq-perf-}
case "$suffix" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
[ ! -L "$root" ]
[ -d "$root" ]
[ "$(stat -c %u "$root")" = "$(id -u)" ]

starttime() {
    case "$1" in ''|*[!0-9]*) return 1;; esac
    awk '{print $22}' "/proc/$1/stat" 2>/dev/null
}
receipt_valid() {
    [ "${1%/*}" = "${0%/*}" ] || return 1
    name=${1##*/}
    number=${name#group-}
    number=${number%.identity}
    case "$number" in ''|*[!0-9]*) return 1;; esac
    [ "$name" = "group-$number.identity" ]
}
guard_alive() {
    [ ! -e "$root/STOP" ]
    [ ! -L "$root/guard.identity" ]
    read live_guard live_start extra < "$root/guard.identity"
    [ -z "$extra" ]
    [ "$live_guard:$live_start" = "$guard:$guard_start" ]
    [ "$(readlink "/proc/$guard/exe")" = "$root/device_perf_guard" ]
    [ "$(starttime "$guard")" = "$guard_start" ]
    kill -0 "$guard"
}
stop_group() {
    receipt=$1
    receipt_valid "$receipt"
    # Also close the pre-publication race: a delayed launch must not start after
    # the host has cancelled this exact window. This is only task-owned metadata.
    [ ! -L "$receipt.stop" ]
    if [ ! -e "$receipt.stop" ]; then (set -C; printf 'cancelled\n' > "$receipt.stop"); fi
    [ ! -L "$receipt" ]
    [ -e "$receipt" ] || return 0
    [ -f "$receipt" ]
    [ "$(stat -c %u "$receipt")" = "$(id -u)" ]
    read leader expected extra < "$receipt"
    case "$leader:$expected" in *[!0-9:]*|:*|*:) return 2;; esac
    [ -z "$extra" ] && [ "$leader" -gt 1 ] && [ "$expected" -gt 0 ] || return 2
    [ ! -L "$root/active.group" ]
    [ -f "$root/active.group" ] || return 0
    [ "$(cat "$root/active.group")" = "$leader $expected" ]
    [ "$(starttime "$leader")" = "$expected" ] || return 0
    [ "$(awk '{print $5}' "/proc/$leader/stat")" = "$leader" ]
    tr '\000' '\n' < "/proc/$leader/cmdline" | grep -Fx -- "$root" > /dev/null
    tr '\000' '\n' < "/proc/$leader/cmdline" | grep -Fx -- "$0" > /dev/null
    tr '\000' '\n' < "/proc/$leader/cmdline" | grep -Fx -- "$receipt" > /dev/null
    [ "$(starttime "$leader")" = "$expected" ]
    [ "$(awk '{print $5}' "/proc/$leader/stat")" = "$leader" ]
    kill -KILL -- "-$leader"
}
case "$operation" in
    stop)
        [ "$#" = 1 ]
        stop_group "$1"
        exit 0
        ;;
    run)
        [ "$#" = 4 ]
        guard=$1 guard_start=$2 receipt=$3 command=$4
        ;;
    *) exit 2;;
esac
case "$guard:$guard_start" in *[!0-9:]*|:*|*:) exit 2;; esac
[ "$guard" -gt 1 ] && [ "$guard_start" -gt 0 ] || exit 2
receipt_valid "$receipt"
[ -n "$command" ]
[ "$(awk '{print $5}' /proc/$$/stat)" = "$$" ]
leader_start=$(starttime "$$")
[ "$leader_start" -gt 0 ]
[ ! -e "$receipt.stop" ] && [ ! -L "$receipt.stop" ] || exit 2
[ ! -e "$receipt" ] && [ ! -L "$receipt" ] || exit 2
[ ! -e "$root/active.group" ] && [ ! -L "$root/active.group" ] || exit 2
guard_alive
# Noclobber temporary publication too; concurrent owners cannot share it.
(set -C; printf '%s %s\n' "$$" "$leader_start" > "$receipt.new")
mv "$receipt.new" "$receipt"
(set -C; printf '%s %s\n' "$$" "$leader_start" > "$root/active.group.new")
[ ! -e "$root/active.group" ] && [ ! -L "$root/active.group" ] || exit 2
mv "$root/active.group.new" "$root/active.group"
# Kill only this verified session. The existing lifetime/ns-exec parent-death
# chain destroys descendants, including detached namespace processes.
trap 'kill -KILL -- "-$$"' HUP INT TERM
guard_alive
[ ! -e "$receipt.stop" ] && [ ! -L "$receipt.stop" ] || exit 2
/bin/sh -c "$command" &
child=$!
status=0
wait "$child" || status=$?
guard_alive
[ "$(cat "$root/active.group")" = "$$ $leader_start" ]
rm "$root/active.group"
exit "$status"
