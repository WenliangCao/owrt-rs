#!/bin/bash
# R53: the fault cases the plan's §2.3 asks for, against the C netifd.
#
# All four run against one live `proto dhcp` interface with a real udhcpd on
# the peer end, because that is the only configuration where the faults have
# anywhere to go: a helper to kill, a carrier to lose, a device to delete.
#
#   A  the helper dies on its own (SIGKILL to udhcpc)
#   B  the link loses carrier (the peer goes down, then comes back)
#   C  the device disappears and comes back (ip link delete, then re-add)
#   D  repeated commands (ifup twice, ifdown twice)
#
# Each case writes its own evidence file, so a difference names one case
# instead of one big diff.
#
# Usage: r53_fault_diff.sh <rootfs-files> <netifd-rs musl binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r53-out}
mkdir -p "$out"

CFG='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config interface "wan"
	option device "veth1"
	option proto "dhcp"

config interface "checkup"
	option device "veth3"
	option proto "dhcp"
	option checkup_interval "3"
'

run_one() {
	tag=$1
	tmp=$(mktemp -d /tmp/owrt-r53-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n mkdir -p "$root/tmp/out" "$root/etc/config"
	printf '%s' "$CFG" | sudo -n tee "$root/etc/config/network" >/dev/null

	sudo -n mv "$root/sbin/hotplug-call" "$root/sbin/hotplug-call.real" 2>/dev/null || true
	sudo -n tee "$root/sbin/hotplug-call" >/dev/null <<'HP'
#!/bin/sh
printf 'hotplug %s ACTION=%s INTERFACE=%s DEVICE=%s\n' \
	"$1" "${ACTION:-}" "${INTERFACE:-}" "${DEVICE:-}" \
	>> "${0%/sbin/hotplug-call}/tmp/out/hotplug.txt"
exit 0
HP
	sudo -n chmod 755 "$root/sbin/hotplug-call"

	sudo -n tee "$root/tmp/bus.sh" >/dev/null <<'BUS'
set -u
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out
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
echo $! > /tmp/out/cand.pid
RN

	cat > "$tmp/udhcpd.conf" <<UD
start 10.0.0.100
end 10.0.0.100
interface veth0
max_leases 1
option subnet 255.255.255.0
option router 10.0.0.1
option lease 3600
lease_file $tmp/udhcpd.leases
pidfile $tmp/udhcpd.pid
UD
	: > "$tmp/udhcpd.leases"

	sudo -n unshare --mount --net --fork /bin/sh -c '
		root=$1; tag=$2; tmp=$3; out=$4
		mount --make-rprivate /
		mount -t sysfs sysfs /sys
		mount -t proc proc "$root/proc"; mount -t sysfs sysfs "$root/sys"
		mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		trap "umount $root/dev 2>/dev/null; umount $root/sys 2>/dev/null; umount $root/proc 2>/dev/null" EXIT

		ip link set lo up
		ip link add veth0 address 02:00:00:00:00:00 type veth \
			peer name veth1 address 02:00:00:00:00:01
		ip link set veth0 up; ip link set veth1 up
		# no server on this pair: `checkup` never comes up, and the
		# checkup interval is what decides what happens next
		ip link add veth2 address 02:00:00:00:00:02 type veth \
			peer name veth3 address 02:00:00:00:00:03
		ip link set veth2 up; ip link set veth3 up
		ip addr add 10.0.0.1/24 dev veth0

		start_server() {
			busybox udhcpd -f "$tmp/udhcpd.conf" > "$out/$tag-udhcpd.log" 2>&1 &
			echo $! > "$tmp/udhcpd.hostpid"
		}
		start_server
		sleep 1

		chroot "$root" /bin/sh /tmp/bus.sh
		if [ "$tag" = c ]; then
			chroot "$root" /bin/sh /tmp/cnetifd.sh
		else
			chroot "$root" /bin/sh /tmp/rsnetifd.sh
		fi

		wait_lease() {
			i=0
			while [ $i -lt 20 ]; do
				chroot "$root" ubus call network.interface.wan status 2>/dev/null \
					| grep -q "10.0.0.100" && return 0
				i=$((i+1)); sleep 1
			done
			return 1
		}
		# a marker in the hotplug log, so a difference in the sequence
		# names the case it happened in
		mark() { echo "== $1" >> "$root/tmp/out/hotplug.txt"; }
		snap() {
			echo "--- wan status"
			chroot "$root" ubus call network.interface.wan status 2>/dev/null
			echo "--- veth1"
			ip -o link show dev veth1 2>/dev/null \
				| sed -E -e "s/^[0-9]+: //" -e "s/qdisc [a-z_]+/qdisc Q/"
			ip -o addr show dev veth1 2>/dev/null | sed -E "s/^[0-9]+: //"
			echo "--- default route"
			ip -4 route show default 2>/dev/null
		}

		wait_lease
		chroot "$root" ubus call network.interface.wan status > "$out/$tag-initial-lease.json"

		# E: an interface that never comes up, with a checkup interval
		{
			echo "--- checkup status"
			chroot "$root" ubus call network.interface.checkup status 2>/dev/null
			echo "--- is odhcp6c/udhcpc still running for it"
			p=$(cat "$root/var/run/udhcpc-veth3.pid" 2>/dev/null || true)
			if [ -n "$p" ] && [ -d "/proc/$p" ]; then
				echo "helper still running"
			else
				echo "helper gone"
			fi
		} > "$out/$tag-E-checkup.txt" 2>&1 || true

		mark "A helper killed"
		# ---- A: the helper dies on its own
		# Record whether the kill actually landed: a case that did not
		# happen on the reference side must not read as agreement.
		p=$(cat "$root/var/run/udhcpc-veth1.pid" 2>/dev/null || true)
		{
			if [ -z "$p" ]; then
				echo "no pid file, the helper was never found"
			elif [ ! -d "/proc/$p" ]; then
				echo "pid file names a dead process"
			else
				kill -9 "$p" 2>/dev/null || true
				sleep 1
				if [ -d "/proc/$p" ]; then
					echo "kill did not take effect"
				else
					echo "helper killed"
				fi
			fi
		} > "$out/$tag-A-kill.txt" 2>&1
		sleep 3
		snap > "$out/$tag-A-helper-killed.txt" 2>&1 || true
		# and does it recover on its own within another few seconds
		sleep 5
		snap > "$out/$tag-A2-after-wait.txt" 2>&1 || true

		mark "B carrier"
		# ---- B: carrier loss, then return
		chroot "$root" ubus call network.interface.wan down >/dev/null 2>&1 || true
		sleep 2
		chroot "$root" ubus call network.interface.wan up >/dev/null 2>&1 || true
		wait_lease
		chroot "$root" ubus call network.interface.wan status > "$out/$tag-renewed-lease.json"
		ip link set veth0 down
		sleep 3
		snap > "$out/$tag-B-carrier-lost.txt" 2>&1 || true
		ip link set veth0 up
		sleep 4
		snap > "$out/$tag-B2-carrier-back.txt" 2>&1 || true

		mark "C device"
		# ---- C: the device disappears and comes back
		ip link delete veth0 2>/dev/null || true
		sleep 3
		{
			echo "--- wan status"
			chroot "$root" ubus call network.interface.wan status 2>/dev/null
			echo "--- veth1 present"
			ip -o link show dev veth1 >/dev/null 2>&1 && echo yes || echo no
		} > "$out/$tag-C-device-gone.txt" 2>&1 || true
		ip link add veth0 address 02:00:00:00:00:00 type veth \
			peer name veth1 address 02:00:00:00:00:01 2>/dev/null || true
		ip link set veth0 up 2>/dev/null || true
		ip addr add 10.0.0.1/24 dev veth0 2>/dev/null || true
		sleep 4
		snap > "$out/$tag-C2-device-back.txt" 2>&1 || true

		mark "D repeated"
		# ---- D: repeated commands
		chroot "$root" ubus call network.interface.wan up >/dev/null 2>&1 || true
		chroot "$root" ubus call network.interface.wan up >/dev/null 2>&1 || true
		sleep 2
		chroot "$root" ubus call network.interface.wan down >/dev/null 2>&1 || true
		chroot "$root" ubus call network.interface.wan down >/dev/null 2>&1 || true
		sleep 3
		snap > "$out/$tag-D-repeated.txt" 2>&1 || true

		cp "$root/tmp/out/netifd.log" "$out/$tag-daemon.log" 2>/dev/null || true
		cp "$root/tmp/out/hotplug.txt" "$out/$tag-hotplug.txt" 2>/dev/null || \
			: > "$out/$tag-hotplug.txt"

		p=$(cat "$tmp/udhcpd.hostpid" 2>/dev/null || true)
		[ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
		for f in netifd ubusd cand; do
			p=$(cat "$root/tmp/out/$f.pid" 2>/dev/null || true)
			[ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
		done
		' sh "$root" "$tag" "$tmp" "$out" > "$out/$tag-outer.log" 2>&1 || true

	sudo -n chown "$(id -u):$(id -g)" "$out"/$tag-* 2>/dev/null || true
	sudo -n rm -rf "$tmp"
}

run_one c
run_one rs

python3 "$(dirname "$0")/audit_checks.py" r53 "$out"

rc=0
mask() {
	# uptime and the lease countdown are sampled at different moments
	sed -E -e 's/"uptime": [0-9]+/"uptime": N/' \
	       -e 's/"leasetime": [0-9]+/"leasetime": N/'
}
echo "=== A: did the kill land"
for t in c rs; do printf '%-3s %s\n' "$t" "$(cat "$out/$t-A-kill.txt" 2>/dev/null)"; done
case "$(cat "$out/c-A-kill.txt" 2>/dev/null)" in
	"helper killed") ;;
	*) echo "RESULT(A): the reference never lost its helper -- case A is untested"; rc=1 ;;
esac

for case in E-checkup A-helper-killed A2-after-wait B-carrier-lost B2-carrier-back \
	    C-device-gone C2-device-back D-repeated; do
	echo "=== $case"
	if [ ! -s "$out/c-$case.txt" ]; then
		echo "RESULT($case): NOTHING CAPTURED from the reference -- untested"
		rc=1
		continue
	fi
	if diff -u <(mask < "$out/c-$case.txt") <(mask < "$out/rs-$case.txt") \
		> "$out/$case.diff"; then
		echo "RESULT($case): identical"
	else
		head -30 "$out/$case.diff"; rc=1
	fi
done

echo "=== hotplug over the whole run"
# Whether a repeated IFEV_DOWN becomes one hotplug call or two depends on
# whether the second lands while the first call is still running, and the C
# itself does not always land the same way: one run of case C produced one
# ifdown where every other run produced two. So consecutive identical lines
# are collapsed -- a different sequence still fails, a different count of the
# same line does not -- and both raw counts are printed so a real change in
# volume is still visible.
squash() { awk '$0 != prev { print } { prev = $0 }' "$1"; }
printf 'raw lines  c=%s  rs=%s\n' \
	"$(wc -l < "$out/c-hotplug.txt")" "$(wc -l < "$out/rs-hotplug.txt")"
if diff -u <(squash "$out/c-hotplug.txt") <(squash "$out/rs-hotplug.txt") \
	> "$out/hotplug.diff"; then
	echo "RESULT(hotplug): identical sequence"
else
	head -40 "$out/hotplug.diff"; rc=1
fi
exit $rc
