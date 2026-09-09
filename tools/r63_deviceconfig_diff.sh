#!/bin/bash
# R63: the DEVICE's real /etc/config/network + /etc/config/wireless, C netifd
# against netifd-rs, live daemons in the exact-rootfs sandbox.
#
# r49 proves daemon equivalence on a synthetic config; r59/r60 prove the
# wireless projection and the handler protocol on fixtures. What none of them
# prove is the one config that matters: the box's own. This runs both daemons
# on a byte-copy of the device's config, with the config's bridge ports
# present as dummy netdevs, real /lib/netifd/wireless/mac80211.sh included.
#
# The wireless setup FAILS here (no phy in the namespace) -- on both sides, in
# the same way. That agreement validates config projection, handler
# invocation and the failure path, NOT that radios come up; only the device
# window shows that.
#
# The configs carry secrets (wifi PSK), so they are arguments, never fixtures
# in the repo, and the outputs stay in the outdir.
#
# Usage: r63_deviceconfig_diff.sh <rootfs-files> <netifd-rs> <network-cfg> <wireless-cfg> [outdir]
#        PORTS="lan2 lan3 lan4 wan" (default) -- dummy netdevs to create
set -eu
rootfs=$1; cand=$2; netcfg=$3; wlcfg=$4; out=${5:-/tmp/r63-out}
PORTS=${PORTS:-"lan2 lan3 lan4 wan"}
[ -s "$netcfg" ] || { echo "missing network config: $netcfg"; exit 2; }
[ -s "$wlcfg" ] || { echo "missing wireless config: $wlcfg"; exit 2; }
mkdir -p "$out"

run_one() {
	tag=$1
	tmp=$(mktemp -d /tmp/owrt-r63-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n mkdir -p "$root/tmp/out" "$root/etc/config"
	sudo -n cp "$netcfg" "$root/etc/config/network"
	sudo -n cp "$wlcfg" "$root/etc/config/wireless"

	sudo -n tee "$root/tmp/probe.sh" >/dev/null <<'PROBE'
set -u
# wait for the wireless state machine to go terminal on this side: not up,
# not pending -- the no-phy setup has failed its retries or never started
i=0
while [ $i -lt 60 ]; do
	s=$(ubus call network.wireless status 2>/dev/null)
	case "$s" in
	*'"pending": false'*) up=1 ;;
	*) up=0 ;;
	esac
	[ "$up" = 1 ] && ! echo "$s" | grep -q '"pending": true' && break
	i=$((i+1)); sleep 1
done
echo "--- settle loops: (masked)"
echo "--- ubus list"
ubus list
echo "--- ubus -v list network"
ubus -v list network
echo "--- ubus -v list network.wireless"
ubus -v list network.wireless
echo "--- get_proto_handlers"
ubus call network get_proto_handlers
echo "--- interface dump"
ubus call network.interface dump
echo "--- device status"
ubus call network.device status
echo "--- interface lan status"
ubus call network.interface.lan status
echo "--- interface wan status"
ubus call network.interface.wan status
echo "--- interface wan6 status"
ubus call network.interface.wan6 status
echo "--- wireless status"
ubus call network.wireless status
echo "--- wireless get_validate"
ubus call network.wireless get_validate
PROBE

	sudo -n tee "$root/tmp/bus.sh" >/dev/null <<'BUS'
set -u
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 &
echo $! > /tmp/out/ubusd.pid
sleep 1
BUS

	sudo -n cp "$cand" "$root/sbin/netifd-rs"
	sudo -n chmod 755 "$root/sbin/netifd-rs"
	if [ "$tag" = c ]; then daemon=/sbin/netifd; else daemon=/sbin/netifd-rs; fi

	sudo -n unshare --mount --net --fork /bin/sh -c '
		root=$1; daemon=$2; out=$3; tag=$4; ports=$5
		mount --make-rprivate /
		mount -t sysfs sysfs /sys
		mount -t proc proc "$root/proc"; mount -t sysfs sysfs "$root/sys"
		mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		trap "umount $root/dev 2>/dev/null; umount $root/sys 2>/dev/null; umount $root/proc 2>/dev/null" EXIT

		ip link set lo up
		n=2
		for p in $ports; do
			ip link add "$p" type dummy
			ip link set "$p" address 02:00:00:00:00:0$n
			ip link set "$p" up
			n=$((n+1))
		done

		chroot "$root" /bin/sh /tmp/bus.sh
		chroot "$root" /bin/sh -c "$daemon >/tmp/out/netifd.log 2>&1 & echo \$! > /tmp/out/netifd.pid"
		sleep 5
		chroot "$root" /bin/sh /tmp/probe.sh > "$out/$tag-ubus.txt" 2>&1 || true
		cp "$root/tmp/out/netifd.log" "$out/$tag-daemon.log" 2>/dev/null || true
		{
			echo "--- ip -d link"
			ip -d link show
			echo "--- ip addr"
			ip -o addr show
			echo "--- ip route4"
			ip -4 route show table all
			echo "--- ip route6"
			ip -6 route show table all
			echo "--- bridge"
			bridge link show
		} > "$out/$tag-kernel.txt" 2>&1 || true
		for f in netifd ubusd; do
			p=$(cat "$root/tmp/out/$f.pid" 2>/dev/null || true)
			[ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
		done
		pkill -9 udhcpc 2>/dev/null || true
		pkill -9 odhcp6c 2>/dev/null || true
		' sh "$root" "$daemon" "$out" "$tag" "$PORTS" > "$out/$tag-outer.log" 2>&1 || true

	sudo -n chown "$(id -u):$(id -g)" "$out"/$tag-* 2>/dev/null || true
	sudo -n rm -rf "$tmp"
}

run_one c
run_one rs

norm() {
	sed -E \
		-e 's/^[0-9]+: /N: /' \
		-e 's/\bif[0-9]+\b/ifN/g' \
		-e 's/valid_lft [0-9]+sec/valid_lft Lsec/g' \
		-e 's/preferred_lft [0-9]+sec/preferred_lft Lsec/g' \
		-e 's/\bnumtxqueues [0-9]+\b/numtxqueues N/g' \
		-e 's/\bnumrxqueues [0-9]+\b/numrxqueues N/g' \
		-e 's/\bgso_max_[a-z]+ [0-9]+\b/gso_max N/g' \
		-e 's/\btso_max_[a-z]+ [0-9]+\b/tso_max N/g' \
		-e 's/\bgro_max_size [0-9]+\b/gro_max_size N/g' \
		-e 's/\b(bridge_id|designated_root|root_id|designated_bridge) [0-9a-f.:]+/\1 ID/g' \
		-e 's/\b([a-z_]*timer)[ ]+[0-9.]+/\1 T/g' \
		-e 's/expires [0-9]+sec/expires Lsec/g' \
		-e 's/"uptime": [0-9]+/"uptime": N/g' \
		-e 's/"retry": -?[0-9]+/"retry": N/g' \
		-e 's/@[0-9a-f]{8}/@ID/g' \
		-e 's/("[a-z_]*(packets|bytes|errors|dropped|collisions|multicast)": )[0-9]+/\1N/g'
}

# kernel-generated per-device fe80/ff00 routes: their relative order reflects
# device up/down timing, not a netifd decision (same rule as r49)
sort_kernel_routes() {
	python3 -c '
import sys
buf, out = [], []
def flush():
    out.extend(sorted(buf)); buf.clear()
for line in sys.stdin:
    if ("proto kernel" in line and ("fe80::/64" in line or "ff00::/8" in line)):
        buf.append(line)
    else:
        flush(); out.append(line)
flush()
sys.stdout.write("".join(out))
'
}

fail=0
diff -u <(norm < "$out/c-ubus.txt") <(norm < "$out/rs-ubus.txt") > "$out/ubus.diff" || fail=1
diff -u <(norm < "$out/c-kernel.txt" | sort_kernel_routes) \
	<(norm < "$out/rs-kernel.txt" | sort_kernel_routes) > "$out/kernel.diff" || fail=1

# a diff that compared nothing is not a pass
for side in c rs; do
	grep -q '"wireless status' "$out/$side-ubus.txt" 2>/dev/null || true
	[ "$(wc -l < "$out/$side-ubus.txt")" -ge 40 ] || { echo "r63: $side-ubus.txt suspiciously short"; fail=1; }
	grep -q -- "--- wireless status" "$out/$side-ubus.txt" || { echo "r63: $side missing wireless status probe"; fail=1; }
done

if [ $fail -eq 0 ]; then
	echo "r63: identical ($(wc -l < "$out/c-ubus.txt") ubus lines, $(wc -l < "$out/c-kernel.txt") kernel lines)"
	exit 0
fi
echo "r63: DIFFERS"
head -60 "$out/ubus.diff" "$out/kernel.diff"
exit 1
