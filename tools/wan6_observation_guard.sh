#!/bin/sh
# One explicitly approved runtime wan6 down/up observation. No UCI writes.
# /sbin/ifup is intentionally not used: this image's script reloads network.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
BASE=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)
ACTION=${1:?check or start}
TOKEN=${2:?token}
BOOT=${3:?expected boot}
MANIFEST=${4:?bundle manifest SHA256}
HELPER_SHA=21609fa0e03e4a4595e74d266235a9566f2cc37f71571ad9315900d3def5cb49
LOCK=/tmp/owrt-wan6-observation.lock
now() { cut -d. -f1 /proc/uptime; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
record() { printf 'uptime=%s %s\n' "$(now)" "$*" >> "$BASE/events.log"; }
put() { printf '%s\n' "$2" > "$BASE/$1.new"; mv -f "$BASE/$1.new" "$BASE/$1"; }
call() { "$BASE/bounded" bounded 5 ubus -S -t 3 call "$@"; }
field() { jsonfilter -i "$1" -e "@.$2"; }

[ "$(id -u)" = 0 ]
case "$TOKEN" in ''|*[!a-f0-9-]*) exit 2;; esac
[ "$BASE" = "/tmp/owrt-wan6-observation-$TOKEN" ]
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$BOOT" ]
[ "$(sha "$BASE/bundle.sha256")" = "$MANIFEST" ]
(cd "$BASE"; sha256sum -c bundle.sha256 >/dev/null)
[ "$(sha "$BASE/bounded")" = "$HELPER_SHA" ]

preflight() {
    sha256sum -c "$BASE/config.sha256" >/dev/null || return 1
    [ ! -e /root/owrt-native-trial/armed ] || return 1
    [ ! -e /tmp/owrt-native-guard-lock ] || return 1
    for interface in wan wan6 lan; do
        call "network.interface.$interface" status > "$BASE/before-$interface.json" || return 1
        [ "$(field "$BASE/before-$interface.json" up)" = true ] || return 1
        [ "$(field "$BASE/before-$interface.json" pending)" = false ] || return 1
    done
    [ "$(field "$BASE/before-wan.json" proto)" = dhcp ] || return 1
    [ "$(field "$BASE/before-wan6.json" proto)" = dhcpv6 ] || return 1
    [ "$(field "$BASE/before-wan.json" l3_device)" = wan ] || return 1
    [ "$(field "$BASE/before-wan6.json" l3_device)" = wan ] || return 1
    [ "$(field "$BASE/before-lan.json" l3_device)" = br-lan ] || return 1
    call network.device status '{"name":"wan"}' > "$BASE/device-before.json" || return 1
    [ "$(field "$BASE/device-before.json" carrier)" = true ] || return 1
    [ "$(field "$BASE/device-before.json" up)" = true ] || return 1
}

restore() {
    restore_done=1
    trap '' HUP INT TERM
    put state restoring || true
    record 'restoring wan6; no other interface is touched' || true
    for attempt in 1 2 3 4; do
        [ "$(now)" -lt "$hard_deadline" ] || break
        # Repeated up is idempotent in netifd; never repeat down or reload.
        call network.interface.wan6 up '{}' > "$BASE/up-$attempt.json" 2> "$BASE/up-$attempt.stderr" || true
        end=$(( $(now) + 45 ))
        while [ "$(now)" -lt "$end" ] && [ "$(now)" -lt "$hard_deadline" ]; do
            if call network.interface.wan6 status > "$BASE/restored-wan6.json" 2>/dev/null &&
               [ "$(field "$BASE/restored-wan6.json" up)" = true ] &&
               [ "$(field "$BASE/restored-wan6.json" pending)" = false ] &&
               [ "$(field "$BASE/restored-wan6.json" l3_device)" = wan ] &&
               [ "$(field "$BASE/restored-wan6.json" autostart)" = true ] &&
               [ -n "$(jsonfilter -i "$BASE/restored-wan6.json" -e '@["ipv6-prefix"][0].address')" ]; then
                call network.interface.wan status > "$BASE/restored-wan.json" || return 1
                call network.interface.lan status > "$BASE/restored-lan.json" || return 1
                [ "$(field "$BASE/restored-wan.json" up)" = true ] || return 1
                [ "$(field "$BASE/restored-lan.json" up)" = true ] || return 1
                sha256sum -c "$BASE/config.sha256" >/dev/null || return 1
                put state restored
                record 'wan6 restored; wan/lan up; configuration unchanged'
                return 0
            fi
            sleep 2
        done
    done
    put state recovery-failed || true
    record 'wan6 recovery not proved after bounded attempts; no wider action taken' || true
    return 1
}

case "$ACTION" in
    check)
        [ ! -e "$LOCK" ]
        preflight
        printf '%s\n' 'read-only preflight passed'
        ;;
    start)
        [ ! -e "$LOCK" ] && [ ! -e "$BASE/state" ]
        preflight
        setsid /bin/sh "$BASE/guard.sh" run "$TOKEN" "$BOOT" "$MANIFEST" \
            </dev/null >> "$BASE/guard.log" 2>&1 &
        printf '%s\n' 'detached guard launched; inspect state/events.log'
        ;;
    run)
        mkdir "$LOCK"
        printf '%s %s\n' "$$" "$TOKEN" > "$LOCK/owner"
        restore_done=0
        mutated=0
        restore_requested=0
        began=$(now)
        # Four attempts plus their observation windows normally take <225s.
        # Do not begin another bounded command in the last five seconds.
        hard_deadline=$((began + 290))
        trap '' HUP
        trap 'restore_requested=1' INT TERM
        trap 'rc=$?; trap - EXIT; if [ "$mutated" = 1 ] && [ "$restore_done" = 0 ]; then restore || true; fi; if [ "$(cat "$BASE/state" 2>/dev/null || true)" = restored ] || [ "$mutated" = 0 ]; then rm -f "$LOCK/owner"; rmdir "$LOCK"; else put state recovery-failed || true; fi; exit "$rc"' EXIT
        preflight
        put state armed
        put guard.pid "$$"
        down_until=$(( $(now) + 20 ))
        mutated=1
        record 'one runtime wan6 down requested; automatic up at 20 seconds'
        call network.interface.wan6 down '{}' > "$BASE/down.json" 2> "$BASE/down.stderr" || true
        put state observing
        while [ "$(now)" -lt "$down_until" ] && [ "$restore_requested" = 0 ]; do sleep 1; done
        restore
        ;;
    *) printf '%s\n' 'usage: guard.sh check|start TOKEN BOOT MANIFEST_SHA' >&2; exit 2;;
esac
