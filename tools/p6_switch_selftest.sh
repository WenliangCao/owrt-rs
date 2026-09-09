#!/bin/bash
# Run the device switch with the shipped BusyBox in a disposable root/PID
# namespace. Reboot is a recorder. Shorten only the two canary sleeps.
# Usage: p6_switch_selftest.sh <exact-rootfs> [output]
set -eu
rootfs=$1; out=${2:-/tmp/p6-switch-selftest}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"

for mode in revert confirm undo changed; do
	tmp=$(mktemp -d /tmp/p6-switch-test-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n cp "$here/p6_switch.sh" "$root/tmp/p6-switch.sh"
	sudo -n mkdir -p "$root/root" "$root/tmp/out" "$root/usr/sbin"
	sudo -n tee "$root/tmp/candidate" >/dev/null <<'EOF'
#!/bin/sh
[ "$1" = -V ] && echo 'netifd-rs selftest'
EOF
	sudo -n tee "$root/usr/sbin/reboot" >/dev/null <<'EOF'
#!/bin/sh
touch /tmp/out/reboot
EOF
	sudo -n tee "$root/usr/sbin/sleep" >/dev/null <<'EOF'
#!/bin/sh
case "$1" in 300) exec /bin/busybox sleep 1 ;; 900) exec /bin/busybox sleep 2 ;; esac
exec /bin/busybox sleep "$@"
EOF
	# A stuck diagnostic command must not postpone restoring the network.
	sudo -n tee "$root/usr/sbin/ubus" >/dev/null <<'EOF'
#!/bin/sh
exec /bin/busybox sleep 30
EOF
	sudo -n chmod 755 "$root/tmp/candidate" "$root/usr/sbin/reboot" "$root/usr/sbin/sleep" "$root/usr/sbin/ubus"
	rc=0
	sudo -n timeout -s KILL 15 unshare --mount --pid --fork --mount-proc /bin/bash -s -- "$root" "$mode" <<'EOF' > "$out/$mode.log" 2>&1 || rc=$?
set -eu
root=$1; mode=$2
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
chroot "$root" /bin/sh -s -- "$mode" <<'INNER'
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mode=$1
original=$(md5sum /sbin/netifd | cut -d' ' -f1)
candidate=$(md5sum /tmp/candidate | cut -d' ' -f1)
sh /tmp/p6-switch.sh stage /tmp/candidate
test -e /etc/p6-pending
test "$(md5sum /sbin/netifd.c-orig | cut -d' ' -f1)" = "$original"
. /etc/init.d/p6-canary
start
case "$mode" in
confirm) sh /tmp/p6-switch.sh confirm ;;
undo) sh /tmp/p6-switch.sh undo ;;
changed)
	echo '# changed' >> /sbin/netifd
	if sh /tmp/p6-switch.sh confirm; then echo 'incorrectly confirmed changed binary'; exit 1; fi
	;;
esac
/bin/busybox sleep 4
actual=$(md5sum /sbin/netifd | cut -d' ' -f1)
case "$mode" in
confirm)
	test "$actual" = "$candidate"
	test -e /sbin/netifd.c-orig
	test -e /etc/p6-confirm
	test ! -e /tmp/out/reboot
	;;
revert|changed)
	test "$actual" = "$original"
	test -e /tmp/out/reboot
	test ! -e /sbin/netifd.c-orig
	test ! -e /etc/p6-confirm
	# The atomic decision prevents a late confirmation from reporting success.
	if sh /tmp/p6-switch.sh confirm; then exit 1; fi
	;;
undo)
	test "$actual" = "$original"
	test ! -e /tmp/out/reboot
	;;
esac
test ! -e /etc/p6-pending
test ! -e /etc/rc.d/S99p6-canary
echo "PASS: $mode"
INNER
EOF
	sudo -n rm -rf "$tmp"
	[ "$rc" -eq 0 ] || { cat "$out/$mode.log"; exit 1; }
	tail -1 "$out/$mode.log"
done
echo 'p6-switch-selftest: all passed, including stalled diagnostics'
