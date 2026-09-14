#!/bin/sh
# Same-version APK replacement with an old daemon still running. Linux host only.
# Usage (sudo): r92_apk_upgrade_selftest.sh ROOTFS OLD_BUNDLE NEW_BUNDLE OUT
set -eu
[ ! -f /etc/openwrt_release ] || { echo 'offline build-host test only' >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || exit 2
image=$(cd "$1" && pwd); old=$(cd "$2" && pwd); new=$(cd "$3" && pwd)
[ ! -e "$4" ] || { echo 'output already exists' >&2; exit 2; }
mkdir -p "$4"; out=$(cd "$4" && pwd)
work=$(mktemp -d /tmp/r92-apk-upgrade.XXXXXX)
trap 'rm -rf "$work"' EXIT INT TERM
cp -a "$image" "$work/root"
mkdir -p "$work/root/tmp/old" "$work/root/tmp/new"
cp -a "$old/." "$work/root/tmp/old/"
cp -a "$new/." "$work/root/tmp/new/"
cat > "$work/root/tmp/test.sh" <<'EOF'
#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mkdir -p /var/lock /var/run/ubus
apk --no-scripts --no-network add --allow-untrusted /tmp/old/apk/*.apk
sha256sum -c /tmp/old/installed.sha256
for c in uci reload-config logd httpd fw4 rpcd; do
    : > "/etc/owrt-$c.boot-enable"
    "/etc/init.d/owrt-$c" enable
done
for c in rpcd log uhttpd; do "/etc/init.d/$c" disable; done
# Model the accepted router's active CLI bind mounts as well as its daemon.
mount --bind /usr/sbin/uci-rs /sbin/uci
mount --bind /usr/sbin/fw4-rs /sbin/fw4
mount --bind /usr/sbin/reload_config_rs /sbin/reload_config
snapshot() {
    sha256sum /etc/config/* /sbin/procd /sbin/ubusd /sbin/netifd
    sha256sum /sbin/uci /sbin/fw4 /sbin/reload_config
    ls -l /etc/rc.d/ /etc/owrt-*.boot-enable
}
snapshot > /tmp/before
/sbin/ubusd -s /var/run/ubus/ubus.sock > /tmp/bus.log 2>&1 & bus=$!
count=0
until ubus -t 1 list >/dev/null 2>&1; do
    kill -0 "$bus"; [ "$count" -lt 10 ]; sleep 1; count=$((count + 1))
done
/usr/sbin/rpcd-rs -s /var/run/ubus/ubus.sock > /tmp/rpcd.log 2>&1 & daemon=$!
count=0
until ubus -t 1 list session | grep -qx session; do
    kill -0 "$daemon"; [ "$count" -lt 10 ]; sleep 1; count=$((count + 1))
done
old_hash=$(sha256sum /proc/"$daemon"/exe | awk '{print $1}')
[ "$old_hash" = "$(sha256sum /tmp/old/bins/rpcd-rs | awk '{print $1}')" ]
ubus call session list '{}' > /tmp/session-before.json
echo 'PASS: old APKs installed, boot flags enabled, old rpcd serving the private bus'

apk --no-scripts --no-network add --allow-untrusted --force-reinstall /tmp/new/apk/*.apk
sha256sum -c /tmp/new/installed.sha256
snapshot > /tmp/after
cmp /tmp/before /tmp/after
echo 'PASS: six installed hashes replaced; active CLI mounts, configuration and boot flags unchanged'

kill -0 "$daemon"
[ "$(sha256sum /proc/"$daemon"/exe | awk '{print $1}')" = "$old_hash" ]
[ "$(sha256sum /usr/sbin/rpcd-rs | awk '{print $1}')" != "$old_hash" ]
ubus call session list '{}' > /tmp/session-after.json
cmp /tmp/session-before.json /tmp/session-after.json
echo 'PASS: existing rpcd retains its old executable identity and still serves requests'
kill "$daemon"; wait "$daemon" 2>/dev/null || true
/usr/sbin/rpcd-rs -s /var/run/ubus/ubus.sock > /tmp/new-rpcd.log 2>&1 & daemon=$!
count=0
until ubus -t 1 list session | grep -qx session; do
    kill -0 "$daemon"; [ "$count" -lt 10 ]; sleep 1; count=$((count + 1))
done
[ "$(sha256sum /proc/"$daemon"/exe | awk '{print $1}')" = "$(sha256sum /tmp/new/bins/rpcd-rs | awk '{print $1}')" ]
ubus call session list '{}' > /tmp/session-new.json
cmp /tmp/session-before.json /tmp/session-new.json
echo 'PASS: a fresh rpcd process uses the new formal executable and serves the private bus'
EOF
"$new/bins/ns-exec" /bin/sh -c '
    set -eu
    root=$1
    mount --bind /proc "$root/proc"
    mount -t tmpfs tmpfs "$root/dev"
    mknod -m 666 "$root/dev/null" c 1 3
    mknod -m 666 "$root/dev/zero" c 1 5
    mknod -m 666 "$root/dev/urandom" c 1 9
    mount --bind "$root/dev/null" "$root/proc/kmsg"
    ip link set lo up
    chroot "$root" /bin/sh /tmp/test.sh
' sh "$work/root" > "$out/test.log" 2>&1
grep '^PASS:' "$out/test.log"
touch "$out/COMPLETE"
