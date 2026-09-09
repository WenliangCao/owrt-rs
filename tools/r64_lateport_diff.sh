#!/bin/bash
# R64: bridge ports that appear AFTER the daemon starts, C against netifd-rs.
#
# The P6 device incident in one sandbox case: on the AX3000T the DSA ports can
# register after netifd is already running. The C's bridge_member_cb enslaves
# a late port and the first present member makes the bridge present, which
# makes the interface on it available and brings it up. netifd-rs used to
# enslave only at create_devices() time and never look at bridge ports again:
# br-lan stayed DOWN with no address -- wifi beaconing (hostapd bridges the
# vifs itself) but no DHCP, no LAN. Synthetic config, so it can sit in the
# default suite; r63 with PORT_STATE=late covers the same class on the real
# device config.
#
# Usage: r64_lateport_diff.sh <rootfs-files> <netifd-rs> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r64-out}
mkdir -p "$out"

NETCFG='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config device
	option name "br-test"
	option type "bridge"
	list ports "late0"
	list ports "late1"

config interface "lan"
	option device "br-test"
	option proto "static"
	option ipaddr "192.168.77.1/24"
'

run_one() {
	tag=$1
	tmp=$(mktemp -d /tmp/owrt-r64-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n mkdir -p "$root/tmp/out" "$root/etc/config"
	printf '%s' "$NETCFG" | sudo -n tee "$root/etc/config/network" >/dev/null
	sudo -n rm -f "$root/etc/config/wireless"

	sudo -n tee "$root/tmp/probe.sh" >/dev/null <<'PROBE'
set -u
echo "--- interface lan status"
ubus call network.interface.lan status
echo "--- device status br-test"
ubus call network.device status '{"name":"br-test"}'
PROBE

	sudo -n cp "$cand" "$root/sbin/netifd-rs"
	sudo -n chmod 755 "$root/sbin/netifd-rs"
	if [ "$tag" = c ]; then daemon=/sbin/netifd; else daemon=/sbin/netifd-rs; fi

	sudo -n unshare --mount --net --fork /bin/sh -c '
		root=$1; daemon=$2; out=$3; tag=$4
		mount --make-rprivate /
		mount -t sysfs sysfs /sys
		mount -t proc proc "$root/proc"; mount -t sysfs sysfs "$root/sys"
		mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		trap "umount $root/dev 2>/dev/null; umount $root/sys 2>/dev/null; umount $root/proc 2>/dev/null" EXIT
		ip link set lo up

		chroot "$root" /bin/sh -c "mkdir -p /var/run/ubus /var/lock /var/state /tmp/out; /sbin/ubusd >/tmp/out/ubusd.log 2>&1 & echo \$! > /tmp/out/ubusd.pid; sleep 1"
		chroot "$root" /bin/sh -c "$daemon >/tmp/out/netifd.log 2>&1 & echo \$! > /tmp/out/netifd.pid"
		sleep 4

		# the interface must be waiting, not up, while the ports are absent
		chroot "$root" /bin/sh -c "ubus call network.interface.lan status" \
			> "$out/$tag-before.txt" 2>&1 || true

		ip link add late0 address 02:00:00:00:00:40 type dummy
		ip link set late0 up
		sleep 3
		ip link add late1 address 02:00:00:00:00:41 type dummy
		ip link set late1 up
		sleep 4

		chroot "$root" /bin/sh /tmp/probe.sh > "$out/$tag-ubus.txt" 2>&1 || true
		{
			echo "--- ip -d link br-test"
			ip -d link show br-test
			echo "--- ip addr br-test"
			ip -o addr show br-test
			echo "--- bridge"
			bridge link show
		} > "$out/$tag-kernel.txt" 2>&1 || true
		cp "$root/tmp/out/netifd.log" "$out/$tag-daemon.log" 2>/dev/null || true
		for f in netifd ubusd; do
			p=$(cat "$root/tmp/out/$f.pid" 2>/dev/null || true)
			[ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
		done
		' sh "$root" "$daemon" "$out" "$tag" > "$out/$tag-outer.log" 2>&1 || true

	sudo -n chown "$(id -u):$(id -g)" "$out"/$tag-* 2>/dev/null || true
	sudo -n rm -rf "$tmp"
}

run_one c
run_one rs

norm() {
	sed -E \
		-e 's/^[0-9]+: /N: /' \
		-e 's/\bif[0-9]+\b/ifN/g' \
		-e 's/@[0-9a-f]{8}/@ID/g' \
		-e 's/"uptime": [0-9]+/"uptime": N/g' \
		-e 's/("[a-z_]*(packets|bytes|errors|dropped|collisions|multicast)": )[0-9]+/\1N/g' \
		-e 's/valid_lft [0-9]+sec/valid_lft Lsec/g' \
		-e 's/preferred_lft [0-9]+sec/preferred_lft Lsec/g' \
		-e 's/\bnumtxqueues [0-9]+\b/numtxqueues N/g' \
		-e 's/\bnumrxqueues [0-9]+\b/numrxqueues N/g' \
		-e 's/\bgso_max_[a-z]+ [0-9]+\b/gso_max N/g' \
		-e 's/\btso_max_[a-z]+ [0-9]+\b/tso_max N/g' \
		-e 's/\bgro_max_size [0-9]+\b/gro_max_size N/g' \
		-e 's/\b(bridge_id|designated_root|root_id|designated_bridge) [0-9a-f.:]+/\1 ID/g' \
		-e 's/\b([a-z_]*timer)[ ]+[0-9.]+/\1 T/g'
}

fail=0
for f in before ubus kernel; do
	diff -u <(norm < "$out/c-$f.txt") <(norm < "$out/rs-$f.txt") > "$out/$f.diff" || fail=1
done
# the end state must actually show the bridge carrying the late ports: a diff
# of two equally broken sides is not a pass
grep -q '"up": true' "$out/c-ubus.txt" || { echo "r64: C side never came up -- fixture broken"; fail=1; }
grep -q "192.168.77.1" "$out/c-kernel.txt" || { echo "r64: C side has no address -- fixture broken"; fail=1; }

if [ $fail -eq 0 ]; then
	echo "r64: identical (lan waits, then comes up on late ports)"
	exit 0
fi
echo "r64: DIFFERS"
head -40 "$out"/*.diff
exit 1
