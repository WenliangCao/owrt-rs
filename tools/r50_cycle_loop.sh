#!/bin/bash
# R50: several hundred ifdown/ifup cycles against each daemon, then check that
# nothing grew and that the final state still matches the reference.
#
# The single-shot R49 exercises setup once. This exercises the teardown and
# re-setup paths repeatedly, which is where a leak or a "second time round is
# different" bug lives. Both daemons run the same cycle count with the same
# client, and RSS, open descriptors and thread count are sampled before and
# after.
#
# Usage: r50_cycle_loop.sh <rootfs-files> <netifd-rs binary> [cycles] [outdir]
set -eu
rootfs=$1; cand=$2; cycles=${3:-200}; out=${4:-/tmp/r50-out}
case "$cycles" in ''|*[!0-9]*|0) echo "r50: cycles must be a positive integer" >&2; exit 2 ;; esac
mkdir -p "$out"

CFG='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config globals "globals"
	option ula_prefix "fd11:2233:4455::/48"

config device
	option name "br-lan"
	option type "bridge"
	list ports "veth0"
	list ports "veth2"

config interface "lan"
	option device "br-lan"
	option proto "static"
	option ipaddr "192.168.1.1/24"
	option ip6addr "fd11:2233:4455:aaaa::1/64"
	option ip6assign "60"

config interface "wired"
	option device "veth1"
	option proto "static"
	option ipaddr "10.0.0.1"
	option netmask "255.255.255.0"
	option gateway "10.0.0.254"
	option metric "13"
	list dns "10.0.0.53"
'

run_one() {
	tag=$1
	tmp=$(mktemp -d /tmp/owrt-r50-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n mkdir -p "$root/tmp/out" "$root/etc/config"
	printf '%s' "$CFG" | sudo -n tee "$root/etc/config/network" >/dev/null

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

	# The cycle: down then up, every interface, N times. Errors are counted
	# rather than ignored -- a call that starts failing halfway through is
	# exactly the kind of thing this is looking for.
	printf 'set -u\nN=%s\nfail=0\ni=0\nwhile [ $i -lt $N ]; do\n  for f in lan wired; do\n    ubus call network.interface.$f down >/dev/null 2>&1 || fail=$((fail+1))\n    ubus call network.interface.$f up   >/dev/null 2>&1 || fail=$((fail+1))\n  done\n  i=$((i+1))\ndone\necho "cycles: $i"\necho "failed calls: $fail"\n' "$cycles" \
		| sudo -n tee "$root/tmp/cycle.sh" >/dev/null

	sudo -n tee "$root/tmp/final.sh" >/dev/null <<'FIN'
set -u
ubus call network.interface dump
FIN

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
		if [ "$tag" = c ]; then
			chroot "$root" /bin/sh /tmp/cnetifd.sh
			pid=$(cat "$root/tmp/out/netifd.pid")
		else
			# inside the rootfs, like the C. This config is all `static`, so
			# nothing here needs the protocol scripts -- but a candidate
			# started outside the chroot finds no handlers at all, and a
			# config change would then silently test nothing.
			chroot "$root" /bin/sh /tmp/rsnetifd.sh
			pid=$(cat "$root/tmp/out/cand.pid")
		fi
		sleep 4

		sample() {
			# One listing, used for both the count and the attribution: a
			# separate `ls | wc -l` caught a transient /proc/sys read as an
			# extra descriptor, which reads as a leak and is not one.
			list=""
			for d in /proc/$pid/fd/*; do
				list="$list    fd ${d##*/} -> $(readlink "$d" 2>/dev/null)
"
			done 2>/dev/null
			echo "$1 rss_kb=$(awk "/^VmRSS:/{print \$2}" /proc/$pid/status 2>/dev/null)" \
			     "fds=$(printf '%s' "$list" | grep -c "fd ")" \
			     "threads=$(awk "/^Threads:/{print \$2}" /proc/$pid/status 2>/dev/null)"
			printf '%s' "$list"
		}
		{
			sample before
			chroot "$root" /bin/sh /tmp/cycle.sh
			# settle first: sampling while a rescan is in flight catches a
			# transient /proc/sys read as an extra descriptor
			sleep 3
			sample after
			echo "alive: $(kill -0 $pid 2>/dev/null && echo yes || echo no)"
		} > "$out/$tag-resource.txt" 2>&1 || true

		sleep 3
		chroot "$root" /bin/sh /tmp/final.sh > "$out/$tag-final.json" 2>&1 || true
		{
			echo "--- ip addr"
			ip -o addr show
			echo "--- ip route4"
			ip -4 route show table all
			echo "--- ip route6"
			ip -6 route show table all
		} > "$out/$tag-kernel.txt" 2>&1 || true

		cp "$root/tmp/out/netifd.log" "$out/$tag-daemon.log" 2>/dev/null || true
		for f in netifd ubusd cand; do
			p=$(cat "$root/tmp/out/$f.pid" 2>/dev/null || true)
			[ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
		done
		' sh "$root" "$tag" "$cand" "$out" > "$out/$tag-outer.log" 2>&1 || true

	sudo -n chown "$(id -u):$(id -g)" "$out"/$tag-* 2>/dev/null || true
	sudo -n rm -rf "$tmp"
}

run_one c
run_one rs

python3 "$(dirname "$0")/audit_checks.py" r50 "$out" "$cycles"

echo "=== resource use across $cycles cycles ==="
for t in c rs; do
	echo "-- $t"
	grep -E "^(before|after|cycles|failed|alive)" "$out/$t-resource.txt"
done
echo "--- descriptors held by netifd-rs after the cycles"
awk '/^after/{p=1} p&&/^ *fd /' "$out/rs-resource.txt"

norm() {
	sed -E \
		-e 's/valid_lft [0-9]+sec/valid_lft Lsec/g' \
		-e 's/preferred_lft [0-9]+sec/preferred_lft Lsec/g' \
		-e 's/^[0-9]+: /N: /' \
		-e 's/ tentative//g' \
		-e 's/expires [0-9]+sec/expires Lsec/g' \
	| python3 -c '
import sys
buf, out = [], []
def flush():
    out.extend(sorted(buf)); buf.clear()
for line in sys.stdin:
    if "proto kernel" in line and ("fe80::/64" in line or "ff00::/8" in line):
        buf.append(line)
    else:
        flush(); out.append(line)
flush()
sys.stdout.write("".join(out))
'
}

rc=0
echo "=== kernel state after the cycles ==="
if diff -u <(norm < "$out/c-kernel.txt") <(norm < "$out/rs-kernel.txt") > "$out/kernel.diff"; then
	echo "RESULT(kernel): identical"
else
	head -40 "$out/kernel.diff"
	rc=1
fi

echo "=== interface dump after the cycles ==="
python3 - "$out/c-final.json" "$out/rs-final.json" <<'PY' || rc=1
import json, sys, collections

def load(p):
    return json.load(open(p), object_pairs_hook=collections.OrderedDict)

def mask(o):
    if isinstance(o, dict):
        return collections.OrderedDict(
            (k, "N" if k == "uptime" else mask(v)) for k, v in o.items())
    if isinstance(o, list):
        return [mask(x) for x in o]
    return o

c, r = mask(load(sys.argv[1])), mask(load(sys.argv[2]))
if c == r:
    print(f"RESULT(dump): identical for {len(c['interface'])} interfaces")
else:
    cm = {i["interface"]: i for i in c["interface"]}
    rm = {i["interface"]: i for i in r["interface"]}
    for n in cm:
        if cm[n] != rm.get(n):
            print(f"{n} differs")
            print("  C:    " + json.dumps(cm[n])[:600])
            print("  rust: " + json.dumps(rm.get(n))[:600])
    sys.exit(1)
PY

exit $rc
