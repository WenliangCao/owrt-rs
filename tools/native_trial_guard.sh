#!/bin/sh
# Temporary native-image deployment protection, carried in the private config
# backup. Uses saved C originals, never /rom/sbin/* (which are Rust here).
set -eu
umask 077
BASE=/root/owrt-native-trial
HELPER=$BASE/bounded

uptime_seconds() { cut -d. -f1 /proc/uptime; }
record() {
    printf 'boot=%s uptime=%s %s\n' "$(cat /proc/sys/kernel/random/boot_id)" "$(uptime_seconds)" "$*" >> "$BASE/guard.log"
    sync
}
put() {
    printf '%s\n' "$2" > "$BASE/$1.new"
    sync
    mv -f "$BASE/$1.new" "$BASE/$1"
    sync
}
restore() {
    mkdir /tmp/owrt-native-decision-lock 2>/dev/null || return 1
    record 'restore-start'
    if ! sha256sum -c "$BASE/recovery.sha256" >> "$BASE/restore.log" 2>&1 ||
       ! /usr/sbin/owrt-recover-c >> "$BASE/restore.log" 2>&1; then
        record 'restore-refused: originals or recovery operation failed'
        rmdir /tmp/owrt-native-decision-lock
        return 1
    fi
    put restored "$(cat /proc/sys/kernel/random/boot_id)"
    record 'all-nine-C-staged; force-reboot without a working Rust bus'
    sync
    reboot -f
}

case "${1:-}" in
    health)
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
        ;;
    confirm)
        token=${2:?trial token required}
        boot=${3:?current boot required}
        mkdir /tmp/owrt-native-decision-lock
        trap 'rmdir /tmp/owrt-native-decision-lock' EXIT
        [ "$(cat "$BASE/armed")" = "$token" ]
        [ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot" ]
        [ ! -f "$BASE/restored" ]
        sha256sum -c /usr/share/owrt-control-plane/rust.sha256 >/dev/null
        "$HELPER" bounded 15 /bin/sh "$BASE/native_trial_guard.sh" health
        put accepted "$token"
        record 'client-confirmed; future-boot protection remains armed'
        ;;
    run)
        [ -f "$BASE/armed" ] || exit 0
        mkdir /tmp/owrt-native-guard-lock 2>/dev/null || exit 0
        echo "$$" > /tmp/owrt-native-guard-lock/pid
        if cmp -s /proc/1/exe /usr/libexec/owrt-stock/sbin/procd; then
            record 'C-boot: guard idle'
            exit 0
        fi
        token=$(cat "$BASE/armed")
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
            if "$HELPER" bounded 15 /bin/sh "$BASE/native_trial_guard.sh" health >/dev/null 2>&1; then
                good=$((good + 1))
                if [ "$good" -ge 3 ] && [ "$accepted" = "$token" ]; then
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
            [ "$accepted" != "$token" ] || limit=300
            now=$(uptime_seconds)
            if [ "$healthy" -eq 0 ] && [ $((now - bad_since)) -ge "$limit" ]; then
                record "deadline expired after $limit seconds"
                restore
                exit 0
            fi
            sleep 15
        done
        record 'explicitly disarmed'
        ;;
    restore) restore ;;
    *) echo 'usage: native_trial_guard.sh run|health|confirm TOKEN BOOT|restore' >&2; exit 2 ;;
esac
