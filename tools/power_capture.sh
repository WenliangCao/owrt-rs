#!/bin/sh
# Persistent, bounded captures. Never rotate or delete earlier boot evidence.
set -eu
umask 077
BASE=/root/owrt-power-test
HELPER=$BASE/power-recorder
boot=$(cat /proc/sys/kernel/random/boot_id)
OUT=$BASE/boots/$boot

case "${1:-}" in
    start)
        mkdir -p "$OUT"
        mkdir /tmp/owrt-power-capture-lock 2>/dev/null || exit 0
        du_kib=$(du -sk "$BASE/boots" | awk '{print $1}')
        free_kib=$(df -k /overlay | awk 'NR==2 {print $4}')
        # Reserve 3.5 MiB for this boot's bounded files before admission.
        if [ "$du_kib" -ge 6656 ] || [ "$free_kib" -lt 8192 ]; then
            echo "capture refused: evidence quota or storage reserve reached" > "$OUT/capture-limit.txt"
            sync
            exit 1
        fi
        printf 'boot=%s\n' "$boot" > "$OUT/identity.txt"
        date -Iseconds >> "$OUT/identity.txt"
        cat /proc/uptime /etc/openwrt_release >> "$OUT/identity.txt"
        for component in procd ubusd netifd; do
            sha256sum "/sbin/$component" "/rom/sbin/$component" >> "$OUT/identity.txt"
        done
        "$HELPER" bounded 5 dmesg > "$OUT/dmesg-start.txt" 2>&1 || true
        sync
        "$HELPER" events "$OUT" wan 0 </dev/null > "$OUT/events-stderr.txt" 2>&1 &
        echo "$!" > /tmp/owrt-power-events.pid
        /bin/sh "$BASE/power_capture.sh" snapshots </dev/null > "$OUT/sampler.log" 2>&1 &
        echo "$!" > /tmp/owrt-power-snapshots.pid
        ;;
    snapshots)
        count=0
        while [ -e "$BASE/capture-enabled" ]; do
            size=0
            [ ! -f "$OUT/snapshots.log" ] || size=$(wc -c < "$OUT/snapshots.log")
            total=$(du -sk "$BASE/boots" | awk '{print $1}')
            free=$(df -k /overlay | awk 'NR==2 {print $4}')
            if [ "$size" -ge 2097152 ] || [ "$total" -ge 10240 ] || [ "$free" -lt 8192 ]; then
                echo 'snapshot quota or storage reserve reached; prior evidence retained'
                sync
                exit 0
            fi
            count=$((count + 1))
            rc=0
            "$HELPER" bounded 10 /bin/sh "$BASE/power_snapshot.sh" > "$OUT/snapshot.partial" 2>&1 || rc=$?
            {
                printf '\n=== snapshot %s exit=%s ===\n' "$count" "$rc"
                cat "$OUT/snapshot.partial"
            } >> "$OUT/snapshots.log"
            rm -f "$OUT/snapshot.partial"
            sync
            uptime=$(cut -d. -f1 /proc/uptime)
            if [ "$uptime" -lt 900 ]; then sleep 10; else sleep 60; fi
        done
        ;;
    *) echo 'usage: power_capture.sh start|snapshots' >&2; exit 2 ;;
esac
