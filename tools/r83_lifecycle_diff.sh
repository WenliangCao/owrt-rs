#!/bin/bash
# R83: process lifecycle against the C netifd (R81 F03, F04, F09).
#
# One `proto slow` interface whose handler runs a helper (`sleep 1<tag>`, an
# integer: the rootfs busybox sleep takes no fractions)
# through proto_run_command, and one `proto slowsetup` interface whose setup
# script ignores SIGTERM. Then, in order:
#
#   remove    the interface leaves the config and `network reload` runs:
#             the helper must die with its interface (F04)
#   teardown  ifdown while the teardown script hangs: the C SIGKILLs script
#             and helper 5 s in and the interface is down (F09)
#   abort     ifdown during a setup whose script traps TERM: SIGKILL at 1 s (F09)
#   sigterm   SIGTERM to the daemon: it exits and every process it started is
#             killed first (F03)
#
# Each side writes one line per step; the two files must be identical, and
# the reference must have reached `up` first or nothing was tested.
#
# Usage: r83_lifecycle_diff.sh <rootfs-files> <netifd-rs musl binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r83-out}
mkdir -p "$out"

CFG='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config interface "slow"
	option device "veth1"
	option proto "slow"

config interface "abort"
	option device "veth3"
	option proto "slowsetup"
'
CFG_NOSLOW='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config interface "abort"
	option device "veth3"
	option proto "slowsetup"
'

run_one() {
	tag=$1; tagnum=$2
	tmp=$(mktemp -d /tmp/owrt-r83-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n mkdir -p "$root/tmp/out" "$root/etc/config"
	printf '%s' "$CFG" | sudo -n tee "$root/etc/config/network" >/dev/null
	printf '%s' "$CFG_NOSLOW" | sudo -n tee "$root/tmp/network.noslow" >/dev/null
	printf '%s' "$CFG" | sudo -n tee "$root/tmp/network.full" >/dev/null
	echo "$tagnum" | sudo -n tee "$root/tmp/out/tagnum" >/dev/null

	sudo -n mv "$root/sbin/hotplug-call" "$root/sbin/hotplug-call.real" 2>/dev/null || true
	printf '#!/bin/sh\nexit 0\n' | sudo -n tee "$root/sbin/hotplug-call" >/dev/null
	sudo -n chmod 755 "$root/sbin/hotplug-call"

	# the two handlers: a helper that lives until killed, and a setup that
	# refuses SIGTERM
	sudo -n tee "$root/lib/netifd/proto/slow.sh" >/dev/null <<'PS'
#!/bin/sh
. /lib/functions.sh
. ../netifd-proto.sh
init_proto "$@"
proto_slow_init_config() { :; }
proto_slow_setup() {
	local cfg="$1" iface="$2"
	proto_run_command "$cfg" sleep "1$(cat /tmp/out/tagnum)"
	proto_init_update "$iface" 1
	proto_add_ipv4_address 10.9.0.1 24
	proto_send_update "$cfg"
}
proto_slow_teardown() {
	local cfg="$1"
	if [ -e /tmp/out/hang ]; then sleep 30; else proto_kill_command "$cfg"; fi
}
add_protocol slow
PS
	sudo -n tee "$root/lib/netifd/proto/slowsetup.sh" >/dev/null <<'PS'
#!/bin/sh
. /lib/functions.sh
. ../netifd-proto.sh
init_proto "$@"
proto_slowsetup_init_config() { :; }
proto_slowsetup_setup() { trap '' TERM; sleep "6$(cat /tmp/out/tagnum)"; }
proto_slowsetup_teardown() { :; }
add_protocol slowsetup
PS
	sudo -n chmod 755 "$root/lib/netifd/proto/slow.sh" "$root/lib/netifd/proto/slowsetup.sh"

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

	sudo -n unshare --mount --net --fork /bin/sh -c '
		root=$1; tag=$2; tmp=$3; out=$4; tagnum=$5
		mount --make-rprivate /
		mount -t sysfs sysfs /sys
		mount -t proc proc "$root/proc"; mount -t sysfs sysfs "$root/sys"
		mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		trap "umount $root/dev 2>/dev/null; umount $root/sys 2>/dev/null; umount $root/proc 2>/dev/null" EXIT

		ip link set lo up
		ip link add veth0 address 02:00:00:00:00:00 type veth peer name veth1 address 02:00:00:00:00:01
		ip link set veth0 up; ip link set veth1 up
		ip link add veth2 address 02:00:00:00:00:02 type veth peer name veth3 address 02:00:00:00:00:03
		ip link set veth2 up; ip link set veth3 up

		chroot "$root" /bin/sh /tmp/bus.sh
		if [ "$tag" = c ]; then chroot "$root" /bin/sh /tmp/cnetifd.sh; else chroot "$root" /bin/sh /tmp/rsnetifd.sh; fi
		pid=$(cat "$root/tmp/out/netifd.pid")
		res="$out/$tag-steps.txt"; : > "$res"

		st() { chroot "$root" ubus call network.interface.$1 status 2>/dev/null | tr -d " \n"; }
		helpers() { pgrep -fc "^sleep 1$tagnum\$" || true; }
		scripts() { pgrep -fc "slowsetup.sh" || true; }
		wait_up() {
			i=0
			while [ $i -lt 30 ]; do
				st slow | grep -q "\"up\":true" && return 0
				i=$((i+1)); sleep 0.5
			done
			return 1
		}
		# seconds until the interface is neither up nor pending, capped
		time_to_down() {
			t0=$(date +%s%N); i=0
			while [ $i -lt 30 ]; do
				s=$(st $1)
				case "$s" in *\"up\":false*\"pending\":false*) echo $(( ($(date +%s%N) - t0) / 1000000 )); return 0 ;; esac
				i=$((i+1)); sleep 0.5
			done
			echo stuck
		}
		bucket() { case "$1" in stuck) echo stuck ;; *) if [ "$1" -le "$2" ]; then echo "<=$2ms"; else echo ">$2ms"; fi ;; esac; }

		if wait_up; then echo "initial: up helpers=$(helpers)" >> "$res"; else echo "initial: NOT UP" >> "$res"; fi

		# --- remove: the interface leaves the config
		cp "$root/tmp/network.noslow" "$root/etc/config/network"
		chroot "$root" ubus call network reload >/dev/null 2>&1 || true
		sleep 3
		obj=gone; chroot "$root" ubus list 2>/dev/null | grep -q "^network.interface.slow$" && obj=present
		echo "remove: helpers=$(helpers) object=$obj" >> "$res"

		# --- back in, then a teardown whose script hangs
		cp "$root/tmp/network.full" "$root/etc/config/network"
		chroot "$root" ubus call network reload >/dev/null 2>&1 || true
		if wait_up; then
			touch "$root/tmp/out/hang"
			chroot "$root" ubus call network.interface.slow down >/dev/null 2>&1 || true
			ms=$(time_to_down slow)
			sleep 1
			echo "teardown-deadline: $(bucket "$ms" 7000) helpers=$(helpers)" >> "$res"
			rm -f "$root/tmp/out/hang"
		else
			echo "teardown-deadline: NOT UP AGAIN" >> "$res"
		fi

		# --- abort: ifdown during a setup that ignores SIGTERM
		sleep 1
		s=$(st abort); case "$s" in *\"pending\":true*) pend=yes ;; *) pend=no ;; esac
		chroot "$root" ubus call network.interface.abort down >/dev/null 2>&1 || true
		ms=$(time_to_down abort)
		sleep 0.5
		echo "abort-deadline: was-pending=$pend $(bucket "$ms" 3000) scripts=$(scripts)" >> "$res"

		# --- sigterm: bring both back, then terminate the daemon
		chroot "$root" ubus call network.interface.slow up >/dev/null 2>&1 || true
		chroot "$root" ubus call network.interface.abort up >/dev/null 2>&1 || true
		wait_up || true
		sleep 1
		before="helpers=$(helpers) scripts=$(scripts)"
		kill -TERM "$pid" 2>/dev/null || true
		sleep 2
		alive=no; kill -0 "$pid" 2>/dev/null && alive=yes
		echo "sigterm: before[$before] alive=$alive helpers=$(helpers) scripts=$(scripts)" >> "$res"

		cp "$root/tmp/out/netifd.log" "$out/$tag-daemon.log" 2>/dev/null || true
		pkill -9 -f "^sleep 1$tagnum\$" 2>/dev/null || true
		pkill -9 -f "^sleep 6$tagnum\$" 2>/dev/null || true
		pkill -9 -f "slowsetup.sh" 2>/dev/null || true
		for f in netifd ubusd; do
			p=$(cat "$root/tmp/out/$f.pid" 2>/dev/null || true)
			[ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
		done
		' sh "$root" "$tag" "$tmp" "$out" "$tagnum" > "$out/$tag-outer.log" 2>&1 || true

	sudo -n chown "$(id -u):$(id -g)" "$out"/$tag-* 2>/dev/null || true
	sudo -n rm -rf "$tmp"
}

run_one c 111
run_one rs 222

rc=0
echo "=== steps"
for t in c rs; do echo "--- $t"; cat "$out/$t-steps.txt" 2>/dev/null; done
# the reference must have been alive and up, with a helper to lose
if ! grep -q '^initial: up helpers=1' "$out/c-steps.txt" 2>/dev/null; then
	echo "RESULT: the reference never came up with its helper -- untested"; exit 1
fi
if diff -u "$out/c-steps.txt" "$out/rs-steps.txt" > "$out/steps.diff"; then
	echo "RESULT: identical"
else
	cat "$out/steps.diff"; rc=1
fi
exit $rc
