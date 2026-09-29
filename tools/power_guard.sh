#!/bin/sh
# Persistent trial guard. Confirmation never removes this guard. The recorder
# and its data live outside the component bundle and survive a stock rollback.
set -eu
umask 077
BASE=/root/owrt-power-test
HELPER=$BASE/power-recorder

uptime_seconds() { cut -d. -f1 /proc/uptime; }
record() {
    printf 'boot=%s uptime=%s %s\n' "$(cat /proc/sys/kernel/random/boot_id)" "$(uptime_seconds)" "$*" >> "$BASE/guard.log"
    sync
}
put() {
    printf '%s\n' "$2" > "$BASE/$1.new"
    sync
    mv "$BASE/$1.new" "$BASE/$1"
    sync
}

restore() {
    mkdir /tmp/owrt-power-restore-lock 2>/dev/null || return 0
    record 'restore-start: retaining all evidence'
    boot=$(cat /proc/sys/kernel/random/boot_id)
    mkdir -p "$BASE/boots/$boot"
    "$HELPER" bounded 12 /bin/sh "$BASE/power_snapshot.sh" > "$BASE/boots/$boot/before-restore.txt" 2>&1 || true
    # Immutable C identities, independent of current Rust programs and bundle.
    sha256sum -c "$BASE/original.sha256" > "$BASE/restore-identities.log" 2>&1 || {
        record 'restore-refused: original identity mismatch'
        rmdir /tmp/owrt-power-restore-lock
        return 1
    }
    for component in uci reload-config logd httpd fw4 rpcd; do
        rm -f "/etc/owrt-$component.boot-enable"
        for link in /etc/rc.d/[SK]*; do
            [ "$(readlink "$link" 2>/dev/null || true)" != "../init.d/owrt-$component" ] || rm -f "$link"
        done
    done
    ln -sf ../init.d/log /etc/rc.d/S12log
    ln -sf ../init.d/rpcd /etc/rc.d/S12rpcd
    ln -sf ../init.d/uhttpd /etc/rc.d/S50uhttpd
    for component in procd ubusd netifd; do
        dst=/sbin/$component
        cp "/rom/sbin/$component" "$dst.power-restore"
        chmod 755 "$dst.power-restore"
        cmp -s "/rom/sbin/$component" "$dst.power-restore"
        sync
        mv -f "$dst.power-restore" "$dst"
    done
    rm -f /etc/r84-pending /etc/r84-reverting /etc/init.d/r84-canary /etc/rc.d/S99r84-canary
    put restored "$(cat /proc/sys/kernel/random/boot_id)"
    record 'restore-staged: exact C next boot, configuration and evidence retained'
    sync
    reboot
}

case "${1:-}" in
    health)
        [ "$(cat /sys/class/net/wan/carrier 2>/dev/null)" = 1 ]
        ip -4 route show default | awk '$1=="default" {for(i=1;i<NF;i++) if($i=="dev" && $(i+1)=="wan") ok=1} END {exit !ok}'
        [ "$(/bin/ubus -S -t 2 call network.interface.wan status | jsonfilter -e '@.up')" = true ]
        [ "$(/bin/ubus -S -t 2 call network.interface.lan status | jsonfilter -e '@.up')" = true ]
        ping -4 -I wan -c 1 -W 2 -w 3 1.1.1.1 >/dev/null 2>&1 || ping -4 -I wan -c 1 -W 2 -w 3 9.9.9.9 >/dev/null 2>&1
        ;;
    run)
        [ -f "$BASE/armed" ] || exit 0
        mkdir /tmp/owrt-power-guard-lock 2>/dev/null || exit 0
        # A C recovery boot still records evidence but never loops in rollback.
        if cmp -s /proc/1/exe /rom/sbin/procd; then record 'stock-boot: guard idle'; exit 0; fi
        token=$(cat "$BASE/armed")
        boot=$(cat /proc/sys/kernel/random/boot_id)
        count=0
        [ ! -f "$BASE/unhealthy-boots" ] || count=$(cat "$BASE/unhealthy-boots")
        case "$count" in ''|*[!0-9]*) record 'invalid-boot-counter'; restore; exit 1 ;; esac
        count=$((count + 1))
        put unhealthy-boots "$count"
        put current-boot "$boot"
        record "rust-boot pending_count=$count"
        if [ "$count" -ge 3 ]; then record 'third-unconfirmed-boot'; restore; exit 0; fi
        bad_since=$(uptime_seconds)
        good=0
        accepted=0
        while [ -f "$BASE/armed" ] && [ "$(cat "$BASE/armed")" = "$token" ]; do
            if "$HELPER" bounded 12 /bin/sh "$BASE/power_guard.sh" health >/dev/null 2>&1; then
                good=$((good + 1))
                if [ "$good" -ge 3 ]; then
                    bad_since=$(uptime_seconds)
                    if [ "$accepted" -eq 0 ]; then
                        put unhealthy-boots 0
                        put healthy-boot "$boot"
                        record 'WAN health stable; persistent guard remains armed'
                        accepted=1
                    fi
                fi
            else
                good=0
                if [ "$accepted" -eq 1 ]; then
                    accepted=0
                    bad_since=$(uptime_seconds)
                    put unhealthy-boots 1
                    record 'WAN health lost; 600-second recovery window started'
                fi
            fi
            now=$(uptime_seconds)
            if [ "$accepted" -eq 0 ] && [ $((now - bad_since)) -ge 600 ]; then
                record 'WAN health deadline expired'
                restore
                exit 0
            fi
            sleep 15
        done
        record 'guard explicitly disarmed'
        ;;
    restore) restore ;;
    *) echo 'usage: power_guard.sh health|run|restore' >&2; exit 2 ;;
esac
