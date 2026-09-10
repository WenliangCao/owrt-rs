#!/bin/sh
# Offline APK-install and all-stack rollback test, on the Linux build host.
# Usage (sudo): r84_switch_selftest.sh ROOTFS DEPLOYMENT_BUNDLE OUT
# Refuses to run on OpenWrt itself. No physical router, firmware or live bus.
set -eu
[ ! -f /etc/openwrt_release ] || { echo 'offline build-host test only' >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || exit 2
image=$(cd "$1" && pwd); bundle=$(cd "$2" && pwd)
mkdir -p "$3"; out=$(cd "$3" && pwd)
work=$(mktemp -d /tmp/r84-switch-test.XXXXXX)
trap 'rm -rf "$work"' EXIT INT TERM
cp -a "$image" "$work/root"
mkdir -p "$work/root/root/r84" "$work/root/rom"
cp -a "$bundle/." "$work/root/root/r84/"
cat > "$work/root/tmp/test.sh" <<'EOF'
#!/bin/sh
set -eu
export PATH=/tmp/test-bin:/usr/sbin:/usr/bin:/sbin:/bin
mkdir -p /tmp/test-bin /var/lock /var/run
cat > /tmp/test-bin/reboot <<'REBOOT'
#!/bin/sh
echo reboot >> /tmp/test-rebooted
REBOOT
chmod 755 /tmp/test-bin/reboot
apk --no-scripts --no-network add --allow-untrusted /root/r84/apk/*.apk
sha256sum -c /root/r84/installed.sha256
for c in uci reload-config logd httpd fw4 rpcd; do
    [ ! -e "/etc/owrt-$c.boot-enable" ]
done
echo 'PASS: APK installation is inert and all six shipped binary hashes match'

switch=/root/r84/stack-switch.sh
sh "$switch" stage rust
for c in procd ubusd netifd; do
    cmp -s "/sbin/$c" "/root/r84/bins/$c-rs"
    cmp -s "/sbin/$c.c-orig" "/rom/sbin/$c"
done
for c in uci reload-config logd httpd fw4 rpcd; do
    [ -e "/etc/owrt-$c.boot-enable" ]
    "/etc/init.d/owrt-$c" enabled
done
for c in rpcd log uhttpd; do
    if "/etc/init.d/$c" enabled; then echo 'stock daemon still enabled' >&2; exit 1; fi
done
[ -L /etc/rc.d/S99r84-canary ]
if sh "$switch" confirm; then echo 'confirmed without a reboot' >&2; exit 1; fi
token=$(cat /etc/r84-pending)
sh "$switch" rollback obsolete-token
[ "$(cat /etc/r84-pending)" = "$token" ]
[ ! -e /tmp/test-rebooted ]
echo 'PASS: cold stage preserves originals; early confirmation and stale timer rejected'

cp /root/r84/original.sha256 /tmp/good-original.sha256
printf '%064d  /rom/sbin/procd\n' 0 > /root/r84/original.sha256
if sh "$switch" rollback "$token"; then echo 'corrupt recovery identity accepted' >&2; exit 1; fi
[ -f /etc/r84-pending ] && [ ! -e /etc/r84-reverting ]
[ ! -e /tmp/test-rebooted ]
echo 'PASS: failed restore remains pending and never reboots'
cp /tmp/good-original.sha256 /root/r84/original.sha256

sh "$switch" rollback "$token"
[ "$(cat /tmp/test-rebooted)" = reboot ]
[ ! -e /etc/r84-pending ] && [ ! -e /etc/r84-reverting ]
[ ! -e /etc/rc.d/S99r84-canary ]
for c in procd ubusd netifd; do cmp -s "/sbin/$c" "/rom/sbin/$c"; done
for c in uci reload-config logd httpd fw4 rpcd; do
    [ ! -e "/etc/owrt-$c.boot-enable" ]
    if "/etc/init.d/owrt-$c" enabled; then echo 'Rust boot service remains enabled' >&2; exit 1; fi
done
for c in rpcd log uhttpd; do "/etc/init.d/$c" enabled; done
echo 'PASS: automatic rollback restores the entire original next boot'

sh "$switch" stage rust
sh "$switch" rescue
for c in procd ubusd netifd; do cmp -s "/sbin/$c" "/rom/sbin/$c"; done
[ ! -e /etc/r84-pending ] && [ ! -e /etc/r84-reverting ]
echo 'PASS: offline failsafe rescue requires no ubus or running Rust'
EOF

"$bundle/bins/ns-exec" /bin/sh -c '
    set -eu
    root=$1; image=$2
    mount --bind "$image" "$root/rom"
    mount -o remount,bind,ro "$root/rom"
    mount --bind /proc "$root/proc"
    mount -t tmpfs tmpfs "$root/dev"
    mknod -m 666 "$root/dev/null" c 1 3
    mknod -m 666 "$root/dev/zero" c 1 5
    mknod -m 666 "$root/dev/urandom" c 1 9
    mount --bind "$root/dev/null" "$root/proc/kmsg"
    chroot "$root" /bin/sh /tmp/test.sh
' sh "$work/root" "$image" > "$out/test.log" 2>&1
grep '^PASS:' "$out/test.log"
touch "$out/COMPLETE"
