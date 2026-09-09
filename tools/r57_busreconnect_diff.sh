#!/bin/bash
# R57: what happens to netifd when ubusd goes away and comes back.
#
# The plan's §2.3 asks for it, and the C answers clearly:
# `ubus_ctx->connection_lost = netifd_ubus_connection_lost` retries
# `ubus_reconnect` every 2 seconds until it succeeds, and libubus re-registers
# every object on the new connection. A daemon that exits instead is only
# survivable because procd restarts it, and it loses all interface state.
#
# ubusd is killed and restarted; the comparison is whether the objects are
# back, whether the interfaces are still up, and whether the kernel state
# survived untouched.
#
# Usage: r57_busreconnect_diff.sh <rootfs-files> <netifd-rs musl binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r57-out}
mkdir -p "$out"

CFG='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config interface "one"
	option device "veth1"
	option proto "static"
	option ipaddr "10.1.1.1/24"

config interface "two"
	option device "veth3"
	option proto "static"
	option ipaddr "10.2.2.1/24"
'

run_one() {
	tag=$1
	tmp=$(mktemp -d /tmp/owrt-r57-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n mkdir -p "$root/tmp/out" "$root/etc/config"
	printf '%s' "$CFG" | sudo -n tee "$root/etc/config/network" >/dev/null

	sudo -n mv "$root/sbin/hotplug-call" "$root/sbin/hotplug-call.real" 2>/dev/null || true
	sudo -n tee "$root/sbin/hotplug-call" >/dev/null <<'HP'
#!/bin/sh
printf 'hotplug ACTION=%s INTERFACE=%s\n' "${ACTION:-}" "${INTERFACE:-}" \
	>> "${0%/sbin/hotplug-call}/tmp/out/hotplug.txt"
exit 0
HP
	sudo -n chmod 755 "$root/sbin/hotplug-call"

	sudo -n tee "$root/tmp/bus.sh" >/dev/null <<'BUS'
set -u
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out
/sbin/ubusd >>/tmp/out/ubusd.log 2>&1 &
echo $! > /tmp/out/ubusd.pid
sleep 1
BUS

	sudo -n tee "$root/tmp/cnetifd.sh" >/dev/null <<'CN'
set -u
/sbin/netifd >/tmp/out/netifd.log 2>&1 &
echo $! > /tmp/out/netifd.pid
CN
	sudo -n cp "$cand" "$root/sbin/netifd-rs"
	sudo -n chmod 755 "$root/sbin/netifd-rs"
	sudo -n tee "$root/tmp/rsnetifd.sh" >/dev/null <<'RN'
set -u
/sbin/netifd-rs > /tmp/out/netifd.log 2>&1 &
echo $! > /tmp/out/cand.pid
RN

	sudo -n tee "$root/tmp/probe.sh" >/dev/null <<'PROBE'
set -u
echo "--- objects"
ubus list 2>&1 | sort
echo "--- interface dump"
ubus call network.interface dump 2>&1
PROBE

	sudo -n unshare --mount --net --fork /bin/sh -c '
		root=$1; tag=$2; out=$3
		mount --make-rprivate /
		mount -t sysfs sysfs /sys
		mount -t proc proc "$root/proc"; mount -t sysfs sysfs "$root/sys"
		mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		trap "umount $root/dev 2>/dev/null; umount $root/sys 2>/dev/null; umount $root/proc 2>/dev/null" EXIT

		ip link set lo up
		i=0
		while [ $i -lt 4 ]; do
			ip link add veth$i address 02:00:00:00:00:0$i type veth \
				peer name veth$((i+1)) address 02:00:00:00:00:1$i
			ip link set veth$i up; ip link set veth$((i+1)) up
			i=$((i+2))
		done

		chroot "$root" /bin/sh /tmp/bus.sh
		if [ "$tag" = c ]; then
			chroot "$root" /bin/sh /tmp/cnetifd.sh
			dpid=$(cat "$root/tmp/out/netifd.pid")
		else
			chroot "$root" /bin/sh /tmp/rsnetifd.sh
			dpid=$(cat "$root/tmp/out/cand.pid")
		fi
		sleep 4
		chroot "$root" /bin/sh /tmp/probe.sh > "$out/$tag-before.txt" 2>&1 || true

		# take the bus away
		kill -9 "$(cat "$root/tmp/out/ubusd.pid")" 2>/dev/null || true
		rm -f "$root/var/run/ubus/ubus.sock"
		sleep 3
		if [ -d "/proc/$dpid" ]; then
			echo "daemon still running without the bus" > "$out/$tag-survived.txt"
		else
			echo "daemon exited when the bus went away" > "$out/$tag-survived.txt"
		fi

		# and bring it back
		chroot "$root" /bin/sh /tmp/bus.sh
		sleep 6
		chroot "$root" /bin/sh /tmp/probe.sh > "$out/$tag-after.txt" 2>&1 || true
		if [ -d "/proc/$dpid" ]; then
			echo "daemon still running after the bus returned" \
				>> "$out/$tag-survived.txt"
		else
			echo "daemon gone after the bus returned" >> "$out/$tag-survived.txt"
		fi
		{
			echo "--- ip addr"
			ip -o -4 addr show | sed -E "s/^[0-9]+: //"
		} > "$out/$tag-kernel.txt" 2>&1 || true

		cp "$root/tmp/out/netifd.log" "$out/$tag-daemon.log" 2>/dev/null || true
		cp "$root/tmp/out/hotplug.txt" "$out/$tag-hotplug.txt" 2>/dev/null || \
			: > "$out/$tag-hotplug.txt"
		for f in netifd ubusd cand; do
			p=$(cat "$root/tmp/out/$f.pid" 2>/dev/null || true)
			[ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
		done
		kill -9 "$dpid" 2>/dev/null || true
		' sh "$root" "$tag" "$out" > "$out/$tag-outer.log" 2>&1 || true

	sudo -n chown "$(id -u):$(id -g)" "$out"/$tag-* 2>/dev/null || true
	sudo -n rm -rf "$tmp"
}

run_one c
run_one rs

echo "=== did the daemon survive"
for t in c rs; do
	printf '%-3s %s\n' "$t" "$(tr '\n' '; ' < "$out/$t-survived.txt" 2>/dev/null)"
done

rc=0
if [ ! -s "$out/c-before.txt" ]; then
	echo "RESULT: NOTHING CAPTURED from the reference -- untested"
	exit 1
fi
# A DELIBERATE DIVERGENCE, named here rather than filtered silently.
#
# Before the bus restart both daemons publish `network.wireless`. After it,
# the C does NOT: that object is registered from inside the ucode VM, and the
# C's reconnect path re-registers only its own objects, so it silently
# disappears and never comes back. Measured, not assumed -- 217 objects before
# and 216 after on the C, 217 both times here.
#
# netifd-rs re-registers it, which is strictly the better behaviour and cannot
# break a caller: an object that exists where the reference lost one. It is
# excluded from the AFTER comparison only, and the exclusion is printed.
norm() {
	sed -E 's/"uptime": [0-9]+/"uptime": N/' "$1"
}
norm_after() {
	norm "$1" | grep -v '^network\.wireless$'
}
for phase in before after; do
	echo "=== $phase the bus restart"
	if [ "$phase" = after ]; then
		cw=$(grep -c '^network\.wireless$' "$out/c-after.txt" || true)
		rw=$(grep -c '^network\.wireless$' "$out/rs-after.txt" || true)
		echo "NOTE: network.wireless after the restart -- C:$cw netifd-rs:$rw"
		echo "      the C does not re-register it (registered from ucode);"
		echo "      netifd-rs does. Excluded from this phase only."
		f() { norm_after "$1"; }
	else
		f() { norm "$1"; }
	fi
	if diff -u <(f "$out/c-$phase.txt") <(f "$out/rs-$phase.txt") \
		> "$out/$phase.diff"; then
		echo "RESULT($phase): identical"
	else
		head -30 "$out/$phase.diff"; rc=1
	fi
done
echo "=== kernel state"
if diff -u "$out/c-kernel.txt" "$out/rs-kernel.txt" > "$out/kernel.diff"; then
	echo "RESULT(kernel): identical"
else
	head -20 "$out/kernel.diff"; rc=1
fi
exit $rc
