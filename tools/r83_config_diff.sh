#!/bin/bash
# R83: configuration semantics against the C netifd (R81 F05, F06, F08, F12,
# F13, F14), in one sandbox with a static lan bridge and a DHCP wan.
#
#   baseline   config route/route6 (interface + interface-less), a `config
#              device` with ipv6/promisc/multicast/mtu6, `defaultroute 0`
#              and `peerdns 0` on the DHCP wan with its own `list dns`, an
#              interface with `disabled 1`, an unsupported `config rule`
#   dns        `list dns` on lan changes -> resolv.conf follows, no ifdown/ifup
#   metric     wan metric changes -> routes re-installed, lease kept
#   route      the static route moves -> kernel follows, no ifdown/ifup
#   hotplug    add_device/remove_device on the bridge interface
#   rule       adding a `config rule` does not refuse the reload
#
# Snapshots are the kernel state (routes, link flags, sysctls), the status
# dumps, resolv.conf.auto and the hotplug call log; the two sides must match.
#
# Usage: r83_config_diff.sh <rootfs-files> <netifd-rs musl binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r83c-out}
mkdir -p "$out"
here=$(cd "$(dirname "$0")" && pwd)
. "$here/netifd_test_ns.sh"
netifd_test_ns_init "$here" "$out"

CFG_HEAD='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config device
	option name "br-lan"
	option type "bridge"
	list ports "veth5"

config device
	option name "veth1"
	option promisc "1"
	option multicast "0"
	option mtu6 "1400"

config device
	option name "veth5"
	option ipv6 "0"

config interface "wan"
	option device "veth1"
	option proto "dhcp"
	option defaultroute "0"
	option peerdns "0"
	list dns "9.9.9.9"
	option metric "METRIC"

config interface "ghost"
	option device "veth3"
	option proto "static"
	option ipaddr "10.7.0.1/24"
	option disabled "1"

config route
	option interface "lan"
	option target "10.50.0.0/16"
	option gateway "10.9.0.254"
	option metric "7"

config route
	option target "10.60.0.0/16"
	option type "unreachable"

config route6
	option interface "lan"
	option target "2001:db8:60::/48"
	option gateway "fd00:9::fe"
'
CFG_LAN='config interface "lan"
	option device "br-lan"
	option proto "static"
	option ipaddr "10.9.0.1/24"
	option ip6addr "fd00:9::1/64"
	list dns "DNS"
'
mkcfg() { # <metric> <dns> [extra]
	printf '%s' "$CFG_HEAD" | sed "s/METRIC/$1/"
	printf '\n%s' "$CFG_LAN" | sed "s/DNS/$2/"
	[ $# -ge 3 ] && printf '\n%s\n' "$3"
	return 0
}

run_one() {
	tag=$1
	tmp=$(mktemp -d /tmp/owrt-r83c-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n mkdir -p "$root/tmp/out" "$root/etc/config" "$root/tmp/resolv.conf.d"
	mkcfg 0 10.9.0.53 | sudo -n tee "$root/etc/config/network" >/dev/null
	mkcfg 0 10.9.0.54 | sudo -n tee "$root/tmp/net.dns" >/dev/null
	mkcfg 30 10.9.0.54 | sudo -n tee "$root/tmp/net.metric" >/dev/null
	mkcfg 30 10.9.0.54 | sed 's#10.50.0.0/16#10.51.0.0/16#' | sudo -n tee "$root/tmp/net.route" >/dev/null
	mkcfg 30 10.9.0.54 'config rule
	option in "lan"
	option lookup "100"' | sed 's#10.50.0.0/16#10.51.0.0/16#' | sudo -n tee "$root/tmp/net.rule" >/dev/null

	sudo -n mv "$root/sbin/hotplug-call" "$root/sbin/hotplug-call.real" 2>/dev/null || true
	sudo -n tee "$root/sbin/hotplug-call" >/dev/null <<'HP'
#!/bin/sh
printf 'hotplug %s ACTION=%s INTERFACE=%s\n' "$1" "${ACTION:-}" "${INTERFACE:-}" >> "${0%/sbin/hotplug-call}/tmp/out/hotplug.txt"
exit 0
HP
	sudo -n chmod 755 "$root/sbin/hotplug-call"
	sudo -n tee "$root/tmp/bus.sh" >/dev/null <<'BUS'
set -u
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out /tmp/resolv.conf.d
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 &
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
echo $! > /tmp/out/netifd.pid
RN
	cat > "$tmp/udhcpd.conf" <<UD
start 10.0.0.100
end 10.0.0.100
interface veth0
max_leases 1
option subnet 255.255.255.0
option router 10.0.0.1
option dns 10.0.0.9
option lease 3600
lease_file $tmp/udhcpd.leases
pidfile $tmp/udhcpd.pid
UD
	: > "$tmp/udhcpd.leases"

	side_rc=0
	sudo -n "$NETIFD_TEST_NS_EXEC" /bin/sh -eu -c '
		root=$1; tag=$2; tmp=$3; out=$4
		for ns in pid net mnt; do readlink "/proc/self/ns/$ns"; done > "$out/$tag-namespace.txt"
		mount --make-rprivate /
		mount -t sysfs sysfs /sys
		mount -t proc proc "$root/proc"; mount -t sysfs sysfs "$root/sys"
		mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5

		ip link set lo up
		ip link add veth0 address 02:00:00:00:00:00 type veth peer name veth1 address 02:00:00:00:00:01
		ip link set veth0 up; ip link set veth1 up
		ip link add veth2 address 02:00:00:00:00:02 type veth peer name veth3 address 02:00:00:00:00:03
		ip link set veth2 up; ip link set veth3 up
		ip link add veth4 address 02:00:00:00:00:04 type veth peer name veth5 address 02:00:00:00:00:05
		ip link set veth4 up; ip link set veth5 up
		ip link add veth6 address 02:00:00:00:00:06 type veth peer name veth7 address 02:00:00:00:00:07
		ip link set veth6 up; ip link set veth7 up
		ip addr add 10.0.0.1/24 dev veth0
		busybox udhcpd -f "$tmp/udhcpd.conf" > "$out/$tag-udhcpd.log" 2>&1 &
		sleep 1

		chroot "$root" /bin/sh /tmp/bus.sh
		if [ "$tag" = c ]; then chroot "$root" /bin/sh /tmp/cnetifd.sh; else chroot "$root" /bin/sh /tmp/rsnetifd.sh; fi

		st() { chroot "$root" ubus call network.interface.$1 status 2>/dev/null; }
		i=0; while [ $i -lt 30 ]; do st wan | grep -q "10.0.0.100" && break; i=$((i+1)); sleep 1; done
		sleep 2

		device_flags() {
			device=$1; phase=$2; code=0
			file="$out/$tag-$phase-device-$device"
			chroot "$root" ubus call network.device status "{\"name\":\"$device\"}" \
				> "$file.json" 2> "$file.err" || code=$?
			printf "%s\n" "$code" > "$file.rc"
			echo "$device status rc=$code"
			if [ "$code" -eq 0 ]; then
				grep -E "\"up\"|\"present\"" "$file.json"
			else
				# Disabled ghost has no device object in the exact C registry.
				[ "$device" = veth3 ]
				[ "$code" -eq 254 ]
				grep -q "Invalid argument" "$file.err"
				[ ! -s "$file.json" ]
			fi
		}
		snap() {
			f="$out/$tag-$1.txt"
			{
			echo "--- objects"; chroot "$root" ubus list 2>/dev/null | grep "^network.interface" | sort
			echo "--- v4 routes"; ip -4 route show table all | grep -v "^local\|^broadcast" | sort
			echo "--- v6 routes"; ip -6 route show table all | grep -v "^fe80\|^local\|^multicast\|^anycast\|^unreachable default\|^ff00" | sed -E "s/ expires [0-9]+sec//" | sort
			echo "--- veth1 flags"; ip -o link show veth1 | sed -E "s/^[0-9]+: //; s/ mtu.*//"
			echo "--- sysctls"; for k in veth1/mtu veth5/disable_ipv6; do printf "%s=%s\n" "$k" "$(cat /proc/sys/net/ipv6/conf/$k 2>/dev/null)"; done
			echo "--- resolv"; cat "$root/tmp/resolv.conf.d/resolv.conf.auto" 2>/dev/null
			echo "--- lan status"; st lan
			echo "--- wan status"; st wan
			echo "--- device status"; device_flags veth3 "$1"; device_flags veth1 "$1"
			echo "--- br-lan members"; ip -o link show master br-lan | sed -E "s/^[0-9]+: ([^:@]+).*/\1/" | sort
			echo "--- udhcpc"; pgrep -xc -P "$(cat "$root/tmp/out/netifd.pid")" udhcpc || true
			} > "$f" 2>&1
		}
		hp() { cp "$root/tmp/out/hotplug.txt" "$out/$tag-hotplug-$1.txt" 2>/dev/null || : > "$out/$tag-hotplug-$1.txt"; : > "$root/tmp/out/hotplug.txt"; }
		snap baseline; hp baseline
		udhcpc_pid=$(pgrep -x -P "$(cat "$root/tmp/out/netifd.pid")" udhcpc | head -1)

		reload() { cp "$root/tmp/$1" "$root/etc/config/network"; rc=0; chroot "$root" ubus call network reload >/dev/null 2>&1 || rc=$?; echo "reload rc=$rc" >> "$out/$tag-rc.txt"; sleep 3; }
		: > "$out/$tag-rc.txt"
		reload net.dns;    snap dns;    hp dns
		reload net.metric; snap metric; hp metric
		echo "udhcpc same pid: $([ "$(pgrep -x -P "$(cat "$root/tmp/out/netifd.pid")" udhcpc | head -1)" = "$udhcpc_pid" ] && echo yes || echo no)" >> "$out/$tag-metric.txt"
		reload net.route;  snap route;  hp route
		reload net.rule;   snap rule;   hp rule

		# add_device/remove_device return-code agreement only. The actual
		# enslavement is racy on BOTH daemons at this timescale (the C
		# alternates rc 0 and rc 2 between runs), so the member list is not
		# asserted -- only that C and rs answer each call the same way, and
		# that a configured member and an unknown device are handled alike.
		ad() { rc=0; chroot "$root" ubus call network.interface.$1 $2 "{\"name\":\"$3\"}" >/dev/null 2>&1 || rc=$?; echo "$2 $1 $3 rc=$rc"; }
		{
			ad lan remove_device veth5   # configured member: stays (C rc 0)
			ad lan remove_device nosuch  # unknown device
			ad wan add_device veth7      # non-bridge main device: NOT_SUPPORTED
		} > "$out/$tag-hotplug.txt"

		cp "$root/tmp/out/netifd.log" "$out/$tag-daemon.log" 2>/dev/null || true
		# ns-exec destroys every remaining descendant when this shell exits.
		exit 0
		' sh "$root" "$tag" "$tmp" "$out" > "$out/$tag-outer.log" 2>&1 || side_rc=$?
	printf "%s\n" "$side_rc" > "$out/$tag-namespace-exit.txt"
	if [ "$side_rc" -ne 0 ]; then
		printf "%s\n" "$tmp" > "$out/$tag-failed-root.txt"
		echo "RESULT($tag): namespace failed (rc=$side_rc); preserved $tmp" >&2
		return "$side_rc"
	fi

	sudo -n chown "$(id -u):$(id -g)" "$out"/$tag-* 2>/dev/null || true
	sudo -n rm -rf "$tmp"
}

run_one c
run_one rs

rc=0
mask() {
	# sampled at different moments: uptime, lease countdown, RA/lease lifetimes
	sed -E -e 's/"uptime": [0-9]+/"uptime": N/' \
	       -e 's/"leasetime": [0-9]+/"leasetime": N/' \
	       -e 's/"(valid|preferred)": [0-9]+/"\1": N/'
}
# the reference must have leased, and must have installed the static route
if ! grep -q '"address": "10.0.0.100"' "$out/c-baseline.txt" 2>/dev/null; then
	echo "RESULT: the reference never got its lease -- untested"; exit 1
fi
if ! grep -q '^10.50.0.0/16 via 10.9.0.254' "$out/c-baseline.txt"; then
	echo "RESULT: the reference has no static route -- fixture broken"; exit 1
fi
for case in baseline dns metric route rule hotplug rc; do
	echo "=== $case"
	if [ ! -s "$out/c-$case.txt" ]; then echo "RESULT($case): NOTHING CAPTURED from the reference"; rc=1; continue; fi
	if diff -u <(mask < "$out/c-$case.txt") <(mask < "$out/rs-$case.txt") > "$out/$case.diff"; then
		echo "RESULT($case): identical"
	else
		head -40 "$out/$case.diff"; rc=1
	fi
done
echo "=== hotplug calls per step"
for step in baseline dns metric route rule; do
	c=$(sort "$out/c-hotplug-$step.txt" | uniq -c | sed 's/^ *//' | tr '\n' ';')
	r=$(sort "$out/rs-hotplug-$step.txt" | uniq -c | sed 's/^ *//' | tr '\n' ';')
	printf '%-9s c=[%s]  rs=[%s]\n' "$step" "$c" "$r"
	[ "$c" = "$r" ] || { echo "RESULT(hotplug-$step): differs"; rc=1; }
done
exit $rc
