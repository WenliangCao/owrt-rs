#!/bin/sh
# Temporary configuration trial only: no firmware, network, or Wi-Fi commands.
# Start before modifying either configuration file. The boot service is early
# and independent of ubus; confirmation belongs to the external client tester.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
BASE=/root/owrt-offload-trial
INIT=/etc/init.d/owrt-offload-trial
LINK=/etc/rc.d/S01owrt-offload-trial
LOCK=/tmp/owrt-offload-decision
RUNLOCK=/tmp/owrt-offload-running

now() { cut -d. -f1 /proc/uptime; }
boot() { cat /proc/sys/kernel/random/boot_id; }
put() {
    printf '%s\n' "$2" > "$BASE/$1.new"
    sync
    mv -f "$BASE/$1.new" "$BASE/$1"
    sync
}
record() {
    printf 'boot=%s uptime=%s %s\n' "$(boot)" "$(now)" "$*" >> "$BASE/events.log"
}
state() { cat "$BASE/state" 2>/dev/null || true; }
originals_valid() {
    (cd "$BASE"; sha256sum -c originals.sha256 >/dev/null) || return 1
    [ -f "$BASE/original/firewall" ] && [ ! -L "$BASE/original/firewall" ] || return 1
    case "$(cat "$BASE/modules-presence")" in
        present) [ -f "$BASE/original/modules.conf" ] && [ ! -L "$BASE/original/modules.conf" ] ;;
        absent) [ ! -e "$BASE/original/modules.conf" ] ;;
        *) return 1 ;;
    esac
}
originals_match() {
    [ ! -L /etc/config/firewall ] && cmp -s "$BASE/original/firewall" /etc/config/firewall || return 1
    if [ "$(cat "$BASE/modules-presence")" = present ]; then
        [ ! -L /etc/modules.conf ] && cmp -s "$BASE/original/modules.conf" /etc/modules.conf
    else
        [ ! -e /etc/modules.conf ] && [ ! -L /etc/modules.conf ]
    fi
}
restore() {
    mkdir "$LOCK" 2>/dev/null || return 75
    trap 'rmdir "$LOCK"' EXIT
    case "$(state)" in accepted|rolled-back) return 0;; esac
    if [ -f "$BASE/rollback-reboot" ]; then
        record 'rollback reboot already requested; refusing a second request'
        return 1
    fi
    originals_valid || { record 'rollback refused: original identity mismatch'; return 1; }
    put state restoring
    cp -p "$BASE/original/firewall" /etc/config/firewall.offload-restore
    cmp -s "$BASE/original/firewall" /etc/config/firewall.offload-restore
    mv -f /etc/config/firewall.offload-restore /etc/config/firewall
    if [ "$(cat "$BASE/modules-presence")" = present ]; then
        cp -p "$BASE/original/modules.conf" /etc/modules.conf.offload-restore
        cmp -s "$BASE/original/modules.conf" /etc/modules.conf.offload-restore
        mv -f /etc/modules.conf.offload-restore /etc/modules.conf
    else
        rm -f /etc/modules.conf
    fi
    originals_match
    # Persist the one-shot fuse only after exact originals have been restored.
    put rollback-reboot "$(boot)"
    put state rollback-requested
    record 'original configuration restored; one forced recovery reboot requested'
    sync
    /sbin/reboot -f
}

[ "$(id -u)" = 0 ]
case "${1:-}" in
    check)
        originals_valid
        originals_match
        [ -s "$BASE/config-backup.tar.gz" ]
        tar -tzf "$BASE/config-backup.tar.gz" >/dev/null
        [ -x "$INIT" ] && [ "$(readlink "$LINK")" = ../init.d/owrt-offload-trial ]
        [ ! -e "$BASE/state" ] && [ ! -e "$RUNLOCK" ] && [ ! -e "$LOCK" ]
        [ ! -e /root/owrt-native-trial/armed ]
        ;;
    arm)
        token=${2:?token required}; origin=${3:?boot required}; seconds=${4:?deadline required}
        expected_wed=${5:-Y}
        case "$token" in ''|*[!a-f0-9-]*) exit 2;; esac
        case "$seconds" in ''|*[!0-9]*) exit 2;; esac
        case "$expected_wed" in Y|N) ;; *) exit 2;; esac
        [ "$seconds" -ge 300 ] && [ "$seconds" -le 1200 ]
        [ "$(boot)" = "$origin" ]
        /bin/sh "$BASE/guard.sh" check
        put token "$token"
        put origin-boot "$origin"
        put origin-deadline "$(( $(now) + 180 ))"
        put trial-seconds "$seconds"
        put expected-wed "$expected_wed"
        put state armed
        setsid /bin/sh "$BASE/guard.sh" run </dev/null >> "$BASE/stderr.log" 2>&1 &
        record 'armed; configuration modification and initial reboot belong to caller'
        ;;
    run)
        case "$(state)" in ''|accepted|rolled-back) exit 0;; esac
        mkdir "$RUNLOCK" 2>/dev/null || exit 0
        printf '%s\n' "$$" > "$RUNLOCK/pid"
        trap 'rm -f "$RUNLOCK/pid"; rmdir "$RUNLOCK"' EXIT
        # Normal shutdown must not undo the caller's first intentional reboot.
        trap '' HUP INT TERM
        current=$(boot)
        if [ -f "$BASE/rollback-reboot" ]; then
            [ "$(cat "$BASE/rollback-reboot")" != "$current" ] || exit 1
            originals_valid && originals_match
            put state rolled-back
            record 'recovery boot; original files verified; guard is idle'
            exit 0
        fi
        if [ "$current" = "$(cat "$BASE/origin-boot")" ]; then
            deadline=$(cat "$BASE/origin-deadline")
        elif [ ! -f "$BASE/trial-boot" ]; then
            put trial-boot "$current"
            put trial-deadline "$(( $(now) + $(cat "$BASE/trial-seconds") ))"
            put state observing
            deadline=$(cat "$BASE/trial-deadline")
            record 'trial boot; waiting for external client confirmation'
        elif [ "$current" = "$(cat "$BASE/trial-boot")" ]; then
            deadline=$(cat "$BASE/trial-deadline")
        else
            record 'another unconfirmed boot; restoring immediately'
            /bin/sh "$BASE/guard.sh" restore
            exit $?
        fi
        while [ "$(state)" != accepted ]; do
            if [ "$(now)" -ge "$deadline" ]; then
                record 'confirmation deadline expired'
                rc=0
                /bin/sh "$BASE/guard.sh" restore || rc=$?
                [ "$rc" = 75 ] || exit "$rc"
            fi
            sleep 2
        done
        record 'client explicitly accepted; guard exiting'
        ;;
    confirm)
        token=${2:?token required}; current=${3:?boot required}
        mkdir "$LOCK"
        trap 'rmdir "$LOCK"' EXIT
        [ "$token" = "$(cat "$BASE/token")" ]
        [ "$current" = "$(boot)" ] && [ "$current" = "$(cat "$BASE/trial-boot")" ]
        [ "$(state)" = observing ] && [ ! -f "$BASE/rollback-reboot" ]
        [ "$(now)" -lt "$(cat "$BASE/trial-deadline")" ]
        # Trials armed by the original version expected WED enabled.
        expected_wed=$(cat "$BASE/expected-wed" 2>/dev/null || printf 'Y\n')
        case "$expected_wed" in Y|N) ;; *) exit 2;; esac
        [ "$(cat /sys/module/mt7915e/parameters/wed_enable)" = "$expected_wed" ]
        (cd /; sha256sum -c "$BASE/trial-config.sha256" >/dev/null)
        put state accepted
        record 'caller confirmed benefit and 180-second client health window'
        ;;
    restore) restore ;;
    *) echo 'usage: guard.sh check | arm TOKEN BOOT SECONDS [Y|N] | run | confirm TOKEN BOOT | restore' >&2; exit 2;;
esac
