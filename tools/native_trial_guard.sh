#!/bin/sh
# Temporary deployment protection, carried only in a private config archive.
# Roll back the complete firmware and original config to the verified previous version. A verified C
# bridge is allowed once if the current PID1/bus cannot hand off sysupgrade.
set -eu
umask 077
BASE=/root/owrt-native-trial
HELPER=$BASE/bounded
STAGE=/tmp/owrt-native-rollback

uptime_seconds() { cut -d. -f1 /proc/uptime; }
record() {
    printf 'boot=%s uptime=%s %s\n' "$(cat /proc/sys/kernel/random/boot_id)" "$(uptime_seconds)" "$*" >> "$BASE/guard.log" &&
    sync
}
put() {
    printf '%s\n' "$2" > "$BASE/$1.new" &&
    sync &&
    mv -f "$BASE/$1.new" "$BASE/$1" &&
    sync
}
restore() {
    if [ -f "$BASE/rollback-requested" ]; then
        record 'rollback already submitted; refusing another automatic flash'
        return 1
    fi
    mkdir /tmp/owrt-native-decision-lock 2>/dev/null || return 75
    record 'restore-start' || return 1
    # Validate both persistent inputs before copying to RAM. sysupgrade must
    # not read its image from an overlay that it is about to replace.
    if ! sha256sum -c "$BASE/rollback.sha256" >> "$BASE/restore.log" 2>&1 ||
       ! sha256sum -c "$BASE/recovery.sha256" >> "$BASE/restore.log" 2>&1 ||
       ! mkdir "$STAGE" ||
       ! cp "$BASE/rollback.bin" "$STAGE/image.bin" ||
       ! cp "$BASE/rollback-config.tar.gz" "$STAGE/config.tar.gz" ||
       ! cmp -s "$BASE/rollback.bin" "$STAGE/image.bin" ||
       ! cmp -s "$BASE/rollback-config.tar.gz" "$STAGE/config.tar.gz"; then
        record 'restore-refused: input identity, RAM staging or sysupgrade preflight failed'
        rmdir /tmp/owrt-native-decision-lock
        return 1
    fi
    # Carry the reason across the rollback without carrying the guard, its
    # startup service, or either firmware image. Original config members are
    # unchanged; the only addition is this private receipt directory.
    receipt=$STAGE/config/root/owrt-native-rollback-receipt
    if ! mkdir "$STAGE/config" ||
       ! tar -xzf "$BASE/rollback-config.tar.gz" -C "$STAGE/config" ||
       ! mkdir -p "$receipt" ||
       ! cp "$BASE/guard.log" "$receipt/guard.log" ||
       ! cp "$BASE/rollback.sha256" "$receipt/inputs.sha256" ||
       ! cp "$BASE/recovery.sha256" "$receipt/recovery.sha256" ||
       ! printf '%s\n' 'Prepared for full firmware rollback; this receipt is not proof of completed flashing.' > "$receipt/status.txt" ||
       ! tar -czf "$STAGE/config.tar.gz" -C "$STAGE/config" -T "$BASE/rollback-members.txt" root/owrt-native-rollback-receipt ||
       ! "$HELPER" bounded-no-file-limit 90 /sbin/sysupgrade -T -f "$STAGE/config.tar.gz" "$STAGE/image.bin" >> "$BASE/restore.log" 2>&1; then
        record 'restore-refused: receipt archive or sysupgrade preflight failed'
        rmdir /tmp/owrt-native-decision-lock
        return 1
    fi
    boot=$(cat /proc/sys/kernel/random/boot_id)
    if "$HELPER" bounded 15 ubus -S -t 3 call system board > "$STAGE/board.json" 2>> "$BASE/restore.log" &&
       [ "$(jsonfilter -i "$STAGE/board.json" -e '@.board_name')" = xiaomi,mi-router-ax3000t ]; then
        put rollback-requested "$boot" || return 1
        record 'firmware rollback requested with original configuration' || return 1
        # The request may be accepted while PID1 is still stopping services.
        # A client timeout or return is not proof that flash has not begun.
        # Never force a reboot or start another upgrade after this boundary.
        rc=0
        "$HELPER" bounded-no-file-limit 60 /sbin/sysupgrade -f "$STAGE/config.tar.gz" "$STAGE/image.bin" >> "$BASE/restore.log" 2>&1 || rc=$?
        record "sysupgrade handoff uncertain (client rc=$rc); no automatic second action"
        return 0
    fi
    record 'control bus/PID1 pre-handoff check failed; no sysupgrade request sent'
    if [ -f "$BASE/c-bridge-used" ]; then
        record 'rollback failed after one C bridge; refusing any further reboot or flash loop'
        return 1
    fi
    # Persist the one-shot fuse before staging any C target or rebooting.
    put c-bridge-used "$boot" || return 1
    if ! sha256sum -c "$BASE/recovery.sha256" >> "$BASE/restore.log" 2>&1 ||
       ! /usr/sbin/owrt-recover-c >> "$BASE/restore.log" 2>&1; then
        record 'C bridge refused: recovery identity or operation failed'
        return 1
    fi
    put c-bridge-staged "$boot" || return 1
    record 'C bridge staged; this is not a completed firmware rollback' || return 1
    sync
    reboot -f
}

case "${1:-}" in
    health)
        health_dir=$(mktemp -d /tmp/owrt-native-health.XXXXXX)
        trap 'rm -f "$health_dir/luci.css"; rmdir "$health_dir"' EXIT
        [ "$(cat /sys/class/net/wan/carrier 2>/dev/null)" = 1 ]
        ip -4 route show default | awk '$1=="default" {for(i=1;i<NF;i++) if($i=="dev" && $(i+1)=="wan") ok=1} END {exit !ok}'
        for name in lan wan; do
            [ "$(ubus -S -t 2 call network.interface.$name status | jsonfilter -e '@.up')" = true ]
        done
        wireless=$(ubus -S -t 2 call network.wireless status)
        for name in radio0 radio1; do
            [ "$(printf '%s' "$wireless" | jsonfilter -e "@.$name.up")" = true ]
            [ "$(printf '%s' "$wireless" | jsonfilter -e "@.$name.pending")" = false ]
        done
        ping -4 -I wan -c 1 -W 2 -w 3 1.1.1.1 >/dev/null 2>&1 || ping -4 -I wan -c 1 -W 2 -w 3 9.9.9.9 >/dev/null 2>&1
        nslookup example.com 127.0.0.1 >/dev/null 2>&1
        uclient-fetch -q -T 4 -O "$health_dir/luci.css" http://127.0.0.1/luci-static/bootstrap/cascade.css
        cmp -s "$health_dir/luci.css" /www/luci-static/bootstrap/cascade.css
        ;;
    confirm)
        token=${2:?trial token required}
        boot=${3:?current boot required}
        mkdir /tmp/owrt-native-decision-lock
        trap 'rmdir /tmp/owrt-native-decision-lock' EXIT
        [ "$(cat "$BASE/armed")" = "$token" ]
        [ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot" ]
        [ ! -f "$BASE/rollback-requested" ]
        sha256sum -c /usr/share/owrt-control-plane/rust.sha256 >/dev/null
        "$HELPER" bounded 25 /bin/sh "$BASE/native_trial_guard.sh" health
        put accepted "$token $boot"
        record 'client confirmed this boot; every future boot still needs fresh confirmation'
        ;;
    run)
        [ -f "$BASE/armed" ] || exit 0
        mkdir /tmp/owrt-native-guard-lock 2>/dev/null || exit 0
        echo "$$" > /tmp/owrt-native-guard-lock/pid
        trap '[ "$(cat /tmp/owrt-native-guard-lock/pid 2>/dev/null)" != "$$" ] || { rm -f /tmp/owrt-native-guard-lock/pid; rmdir /tmp/owrt-native-guard-lock; }' EXIT
        if [ -f "$BASE/rollback-requested" ]; then
            record 'previous handoff unresolved; refusing another automatic flash after reboot'
            exit 1
        fi
        if [ -f "$BASE/c-bridge-used" ]; then
            # The bridge retains this private archive for one more startup;
            # the final rollback flash restores the original archive without it.
            if [ -f "$BASE/c-bridge-rollback-attempted" ] ||
               ! cmp -s /proc/1/exe /usr/libexec/owrt-stock/sbin/procd; then
                record 'C bridge retry refused: already attempted or PID1 is not verified C'
                exit 1
            fi
            put c-bridge-rollback-attempted "$(cat /proc/sys/kernel/random/boot_id)"
            record 'C bridge boot: retrying complete firmware rollback once'
            restore
            exit $?
        fi
        token=$(cat "$BASE/armed")
        boot=$(cat /proc/sys/kernel/random/boot_id)
        count=0
        [ ! -f "$BASE/unhealthy-boots" ] || count=$(cat "$BASE/unhealthy-boots")
        case "$count" in ''|*[!0-9]*) record 'invalid-boot-counter'; restore; exit 1 ;; esac
        [ "$count" -lt 1000 ] || { restore; exit 1; }
        count=$((count + 1))
        put unhealthy-boots "$count"
        record "Rust-boot pending_count=$count"
        if [ "$count" -ge 3 ]; then record 'third-unhealthy-boot'; restore; exit 0; fi
        bad_since=$(uptime_seconds)
        good=0
        healthy=0
        while [ -f "$BASE/armed" ] && [ "$(cat "$BASE/armed")" = "$token" ]; do
            accepted=$(cat "$BASE/accepted" 2>/dev/null || true)
            if "$HELPER" bounded 25 /bin/sh "$BASE/native_trial_guard.sh" health >/dev/null 2>&1; then
                good=$((good + 1))
                if [ "$good" -ge 3 ] && [ "$accepted" = "$token $boot" ]; then
                    bad_since=$(uptime_seconds)
                    if [ "$healthy" -eq 0 ]; then
                        put unhealthy-boots 0
                        put healthy-boot "$(cat /proc/sys/kernel/random/boot_id)"
                        record 'LAN/WAN/radios stable; boot counter reset'
                        healthy=1
                    fi
                fi
            else
                good=0
                if [ "$healthy" -eq 1 ]; then
                    healthy=0
                    bad_since=$(uptime_seconds)
                    put unhealthy-boots 1
                    record 'health lost; 300-second recovery window'
                fi
            fi
            limit=600
            [ "$accepted" != "$token $boot" ] || limit=300
            now=$(uptime_seconds)
            if [ "$healthy" -eq 0 ] && [ $((now - bad_since)) -ge "$limit" ]; then
                record "deadline expired after $limit seconds"
                if restore; then
                    exit 0
                else
                    status=$?
                    # A simultaneous confirm owns the decision lock. Re-read
                    # its result next iteration instead of losing the guard.
                    [ "$status" -eq 75 ] || exit "$status"
                fi
            fi
            sleep 15
        done
        record 'explicitly disarmed'
        ;;
    restore) restore ;;
    *) echo 'usage: native_trial_guard.sh run|health|confirm TOKEN BOOT|restore' >&2; exit 2 ;;
esac
