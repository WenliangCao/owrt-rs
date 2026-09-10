#!/bin/sh
# F03/F09/F10: shutdown ownership, 30-second timeout and reload during setup, using
# the exact rootfs's wireless-device.uc and a deterministic fixture driver.
# Usage: r83_wireless_deadline.sh <rootfs> <netifd-rs> [outdir]
set -eu
rootfs=$1; candidate=$2; out=${3:-/tmp/r83-wireless}
mkdir -p "$out"
work=$(mktemp -d /tmp/r83-wireless.XXXXXX)
trap 'sudo -n rm -rf "$work"' EXIT
cat > "$work/handler" <<'HANDLER'
#!/bin/sh
if [ "$1" = dump ] || [ "${2:-}" = dump ]; then
    echo '{"name":"mac80211","device":[["channel",3]],"iface":[["ssid",3]]}'
    exit 0
fi
echo "$2 $4" >> /tmp/out/handler.log
[ "$2" = setup ] || exit 0
echo $$ > /tmp/out/handler.pid
touch /tmp/out/started
if [ "$MODE" != reload ]; then
    ubus call network.wireless notify '{"command":4,"device":"radio0","data":{"retry":0}}'
    trap '' TERM
    exec sleep 600
fi
while [ ! -f /tmp/out/release ]; do sleep 1; done
ubus call network.wireless notify '{"command":0,"device":"radio0","data":{}}'
HANDLER

for mode in reload timeout shutdown; do
    for side in c rs; do
        root=$work/$mode-$side
        sudo -n cp -a "$rootfs" "$root"
        sudo -n chown -R root:root "$root/usr/share/acl.d"
        sudo -n mkdir -p "$root/etc/config" "$root/tmp/out"
        sudo -n cp "$candidate" "$root/sbin/netifd-rs"
        sudo -n cp "$work/handler" "$root/lib/netifd/wireless/mac80211.sh"
        sudo -n chmod 755 "$root/sbin/netifd-rs" "$root/lib/netifd/wireless/mac80211.sh"
        sudo -n tee "$root/etc/config/network" >/dev/null <<'NETWORK'
config interface 'loopback'
    option device 'lo'
    option proto 'static'
    option ipaddr '127.0.0.1/8'
NETWORK
        sudo -n tee "$root/etc/config/wireless" >/dev/null <<'WIRELESS'
config wifi-device 'radio0'
    option type 'mac80211'
    option channel '1'
config wifi-iface 'ap0'
    option device 'radio0'
    option ssid 'deadline-fixture'
WIRELESS
        sudo -n env MODE="$mode" timeout 48 unshare --mount --net --pid --fork sh -eu -c '
            root=$1; side=$2; out=$3
            mount --make-rprivate /
            mount -t proc proc "$root/proc"
            mount -t sysfs sysfs "$root/sys"
            mount -t tmpfs tmpfs "$root/dev"
            mknod -m 666 "$root/dev/null" c 1 3
            mkdir -p "$root/var/run/ubus"
            ip link set lo up
            chroot "$root" /sbin/ubusd >"$root/tmp/out/bus.log" 2>&1 &
            sleep 1
            if [ "$side" = c ]; then bin=/sbin/netifd; else bin=/sbin/netifd-rs; fi
            chroot "$root" "$bin" >"$root/tmp/out/daemon.log" 2>&1 &
            daemon=$!
            start=$(date +%s)
            i=0
            while [ ! -f "$root/tmp/out/started" ] && [ $i -lt 8 ]; do i=$((i+1)); sleep 1; done
            test -f "$root/tmp/out/started"
            chroot "$root" ubus -t 1 call network.wireless status > "$out/$side-$MODE-before.json"
            if [ "$MODE" = shutdown ]; then
                handler=$(cat "$root/tmp/out/handler.pid")
                kill -TERM "$daemon"
                i=0
                while kill -0 "$daemon" 2>/dev/null && [ "$i" -lt 4 ]; do
                    i=$((i+1)); sleep 1
                done
                ! kill -0 "$daemon" 2>/dev/null
                wait "$daemon"
                if kill -0 "$handler" 2>/dev/null &&
                    ! grep -q "State:.*Z" "$root/proc/$handler/status"; then
                    echo running > "$out/$side-shutdown-handler.txt"
                else
                    echo stopped > "$out/$side-shutdown-handler.txt"
                fi
                cp "$root/tmp/out/daemon.log" "$out/$side-$MODE-daemon.log"
                exit 0
            fi
            if [ "$MODE" = reload ]; then
                chroot "$root" uci set wireless.radio0.channel=6
                chroot "$root" uci commit wireless
                chroot "$root" ubus -t 1 call network reload
                touch "$root/tmp/out/release"
            fi
            i=0
            while [ $i -lt 36 ]; do
                kill -0 "$daemon"
                # A hung handler must not block unrelated interface requests.
                chroot "$root" ubus -t 1 call network.interface.loopback status > /dev/null
                chroot "$root" ubus -t 1 call network.wireless status > "$out/$side-$MODE-after.json"
                if [ "$MODE" = timeout ]; then
                    grep -q "\"retry_setup_failed\": true" "$out/$side-$MODE-after.json" && break
                else
                    grep -q "\"up\": true" "$out/$side-$MODE-after.json" &&
                    [ "$(grep -c "^setup " "$root/tmp/out/handler.log")" -eq 2 ] && break
                fi
                i=$((i+1)); sleep 1
            done
            test "$i" -lt 36
            echo "$(( $(date +%s) - start ))" > "$out/$side-$MODE-seconds.txt"
            cp "$root/tmp/out/handler.log" "$out/$side-$MODE-handler.txt"
            cp "$root/tmp/out/daemon.log" "$out/$side-$MODE-daemon.log"
        ' sh "$root" "$side" "$out"
    done
done

python3 - "$out" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
def check(ok, message):
    if not ok: raise SystemExit(message)
for mode in ('reload', 'timeout'):
    results = []
    for side in ('c', 'rs'):
        before = json.loads((p / f'{side}-{mode}-before.json').read_text())['radio0']
        after = json.loads((p / f'{side}-{mode}-after.json').read_text())['radio0']
        check(before['pending'] is True, f'{side}: reload/timeout did not start during setup')
        elapsed = int((p / f'{side}-{mode}-seconds.txt').read_text())
        calls = [(line.split(' ', 1)[0], json.loads(line.split(' ', 1)[1]))
                 for line in (p / f'{side}-{mode}-handler.txt').read_text().splitlines()]
        if mode == 'reload':
            channels = [args['config']['channel'] for action, args in calls if action == 'setup']
            check(channels == ['1', '6'], f'{side}: pending reload lost, channels={channels}')
            check(after['up'] and not after['pending'], f'{side}: reconfigured radio did not finish')
        else:
            check(29 <= elapsed <= 36, f'{side}: handler timeout took {elapsed}s')
            check(after['retry_setup_failed'] and not after['pending'] and not after['up'],
                  f'{side}: timeout did not finish wireless teardown')
        results.append((after, calls))
        print(f'{side} {mode}: completed in {elapsed}s, event loop responsive')
    check(results[0] == results[1], f'{mode}: wireless state/handler arguments differ')
print('r83 wireless deadline/reload: PASS')
ownership = [(p / f'{side}-shutdown-handler.txt').read_text().strip() for side in ('c', 'rs')]
for side in ('c', 'rs'):
    check(json.loads((p / f'{side}-shutdown-before.json').read_text())['radio0']['pending'],
          f'{side}: shutdown did not interrupt a running wireless handler')
check(ownership == ['stopped', 'stopped'],
      f'wireless handler survived daemon shutdown: C={ownership[0]}, Rust={ownership[1]}')
print(f'r83 wireless shutdown: PASS (handler {ownership[0]} on both sides)')
PY
