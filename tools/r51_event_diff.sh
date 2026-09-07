#!/bin/sh
# R51: the event stream, from both daemons.
#
# Three separate channels, all of which a live system depends on:
#   * the `network.interface` broadcast, captured with `ubus listen`
#   * the `interface.update` / `interface.down` notifications, captured with
#     `ubus subscribe network.interface`
#   * the hotplug.d call, captured by replacing /sbin/hotplug-call with a
#     script that appends its environment to a file
#
# The same sequence is driven against each daemon and the three transcripts are
# compared. A missing event is not visible in `network.interface dump`, so this
# is the only place it shows up.
#
# Usage: r51_event_diff.sh <rootfs-files> <netifd-rs binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r51-out}
mkdir -p "$out"

CFG='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config interface "lan"
	option device "veth0"
	option proto "static"
	option ipaddr "192.168.1.1/24"

config interface "wired"
	option device "veth1"
	option proto "static"
	option ipaddr "10.0.0.1/24"
	option gateway "10.0.0.254"
	option metric "13"

config interface "dhcp_no_server"
	option device "veth2"
	option proto "dhcp"
'

run_one() {
	tag=$1
	tmp=$(mktemp -d /tmp/owrt-r51-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n mkdir -p "$root/tmp/out" "$root/etc/config"
	printf '%s' "$CFG" | sudo -n tee "$root/etc/config/network" >/dev/null

	# hotplug-call, replaced by a recorder. The real one is kept aside so the
	# replacement is obviously a test artefact and not a lost file.
	sudo -n mv "$root/sbin/hotplug-call" "$root/sbin/hotplug-call.real" 2>/dev/null || true
	sudo -n tee "$root/sbin/hotplug-call" >/dev/null <<'HP'
#!/bin/sh
{
	printf 'hotplug %s ACTION=%s INTERFACE=%s DEVICE=%s' \
		"$1" "${ACTION:-}" "${INTERFACE:-}" "${DEVICE:-}"
	for v in IFUPDATE_ADDRESSES IFUPDATE_ROUTES IFUPDATE_PREFIXES IFUPDATE_DATA; do
		eval "val=\${$v:-}"
		[ -n "$val" ] && printf ' %s=%s' "$v" "$val"
	done
	printf '\n'
} >> "${0%/sbin/hotplug-call}/tmp/out/hotplug.txt"
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

	sudo -n tee "$root/tmp/listen.sh" >/dev/null <<'LI'
set -u
ubus listen network.interface > /tmp/out/listen.txt 2>&1 &
echo $! > /tmp/out/listen.pid
ubus subscribe network.interface > /tmp/out/subscribe.txt 2>&1 &
echo $! > /tmp/out/subscribe.pid
LI

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

	# One deliberate sequence: two clean cycles on each of two interfaces,
	# plus a down on an interface that is already down.
	sudo -n tee "$root/tmp/drive.sh" >/dev/null <<'DR'
set -u
for f in lan wired; do
	ubus call network.interface.$f down >/dev/null 2>&1
	sleep 1
	ubus call network.interface.$f up >/dev/null 2>&1
	sleep 1
done
# already down: must produce no second ifdown
ubus call network.interface.dhcp_no_server down >/dev/null 2>&1
sleep 1
DR

	sudo -n unshare --mount --net --fork /bin/sh -c '
		root=$1; tag=$2; cand=$3; out=$4
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
			ip link add veth$i type veth peer name veth$((i+1))
			ip link set veth$i address 02:00:00:00:00:0$i
			ip link set veth$((i+1)) address 02:00:00:00:00:1$i
			ip link set veth$i up; ip link set veth$((i+1)) up
			i=$((i+2))
		done

		chroot "$root" /bin/sh /tmp/bus.sh
		# the broadcast listener can start early; the subscriber cannot,
		# because the object it subscribes to does not exist yet
		chroot "$root" /bin/sh -c "ubus listen network.interface > /tmp/out/listen.txt 2>&1 & echo \$! > /tmp/out/listen.pid"
		sleep 1
		if [ "$tag" = c ]; then
			chroot "$root" /bin/sh /tmp/cnetifd.sh
		else
			# inside the chroot, like the C: the protocol scripts live at
			# /lib/netifd/proto and source each other by absolute path, so a
			# candidate running outside it discovers no handlers at all --
			# which used to make this harness compare a build that refused
			# every shell protocol
			chroot "$root" /bin/sh /tmp/rsnetifd.sh
		fi
		sleep 4
		chroot "$root" /bin/sh -c "ubus subscribe network.interface > /tmp/out/subscribe.txt 2>&1 & echo \$! > /tmp/out/subscribe.pid"
		sleep 1
		chroot "$root" /bin/sh /tmp/drive.sh
		sleep 2

		for f in listen subscribe; do
			p=$(cat "$root/tmp/out/$f.pid" 2>/dev/null || true)
			[ -n "$p" ] && kill "$p" 2>/dev/null || true
		done
		sleep 1
		for f in listen subscribe hotplug; do
			cp "$root/tmp/out/$f.txt" "$out/$tag-$f.txt" 2>/dev/null || \
				: > "$out/$tag-$f.txt"
		done

		cp "$root/tmp/out/netifd.log" "$out/$tag-daemon.log" 2>/dev/null || true
		for f in netifd ubusd cand; do
			p=$(cat "$root/tmp/out/$f.pid" 2>/dev/null || true)
			[ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
		done
		' sh "$root" "$tag" "$cand" "$out" > "$out/$tag-outer.log" 2>&1 || true

	sudo -n chown "$(id -u):$(id -g)" "$out"/$tag-*.txt 2>/dev/null || true
	sudo -n rm -rf "$tmp"
}

run_one c
run_one rs

# Nothing is filtered any more. `dhcp_no_server` uses proto dhcp with no
# server on the link, so it sits in IFS_SETUP waiting for a lease -- which is
# exactly the case that used to be exempted, and is now compared.
filter_known() {
	cat
}

rc=0
for ch in listen hotplug; do
	echo "=== $ch"
	if [ ! -s "$out/c-$ch.txt" ]; then
		echo "RESULT($ch): NOTHING CAPTURED from the reference -- the channel is untested"
		rc=1
		continue
	fi
	if diff -u <(filter_known < "$out/c-$ch.txt") \
		<(filter_known < "$out/rs-$ch.txt") > "$out/$ch.diff"; then
		echo "RESULT($ch): identical, $(wc -l < "$out/c-$ch.txt") lines"
	else
		head -40 "$out/$ch.diff"
		rc=1
	fi
done

# The subscribe channel carries the whole status blob, whose `uptime` moves;
# compare the event names and interface names in order instead.
echo "=== subscribe (event order)"
for t in c rs; do
	grep -oE '"(interface\.update|interface\.down)": \{"interface":"[a-z]+"' \
		"$out/$t-subscribe.txt" | filter_known > "$out/$t-subscribe.seq" \
		2>/dev/null || : > "$out/$t-subscribe.seq"
done
if [ ! -s "$out/c-subscribe.seq" ]; then
	echo "RESULT(subscribe): NOTHING CAPTURED from the reference -- the channel is untested"
	head -3 "$out/c-subscribe.txt"
	rc=1
elif diff -u "$out/c-subscribe.seq" "$out/rs-subscribe.seq" > "$out/subscribe.diff"; then
	echo "RESULT(subscribe): identical, $(wc -l < "$out/c-subscribe.seq") notifications"
else
	head -40 "$out/subscribe.diff"
	rc=1
fi
exit $rc
