#!/bin/sh
# R49: netifd-rs as a daemon against the device's own C netifd.
#
# Two runs, each in its own mount+network namespace with its own copy of the
# exact device rootfs and the same /etc/config/network. Run "c" starts the C
# netifd inside the chroot; run "rs" copies the musl-built netifd-rs into the
# same rootfs and starts it the same way -- it has to be inside, because the
# protocol scripts source /lib/functions.sh by absolute path and live in
# /lib/netifd/proto. Both runs are then interrogated identically -- the ubus
# object list, the full signatures, both status objects -- and the resulting
# kernel state is dumped with iproute2.
#
# The candidate must therefore be a musl binary for this target:
#   cargo build --release --target aarch64-unknown-linux-musl
#
# A difference here is a real behavioural difference: same kernel, same rootfs,
# same config, same clients.
#
# Usage: r49_daemon_diff.sh <rootfs-files> <netifd-rs binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r49-out}
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

config interface "guest"
	option device "veth3"
	option proto "static"
	option ipaddr "192.168.9.1/24"
	option ip6assign "60"

config interface "wired"
	option device "veth1"
	option proto "static"
	option ipaddr "10.0.0.1"
	option netmask "255.255.255.0"
	option gateway "10.0.0.254"
	option metric "13"
	list dns "10.0.0.53"
	list dns_search "example.invalid"

config interface "nodev"
	option device "missing0"
	option proto "static"
	option ipaddr "10.9.9.1/24"

config interface "manual"
	option device "veth5"
	option proto "static"
	option ipaddr "10.7.7.1/24"
	option auto "0"
'

run_one() {
	# $1 = tag (c|rs)
	tag=$1
	tmp=$(mktemp -d /tmp/owrt-r49-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n mkdir -p "$root/tmp/out" "$root/etc/config"
	printf '%s' "$CFG" | sudo -n tee "$root/etc/config/network" >/dev/null

	# The client script: identical for both runs, so the candidate server is
	# never interrogated by a different client than the reference.
	sudo -n tee "$root/tmp/probe.sh" >/dev/null <<'PROBE'
set -u
echo "--- ubus list"
ubus list
echo "--- ubus -v list network"
ubus -v list network
echo "--- ubus -v list network.device"
ubus -v list network.device
echo "--- ubus -v list network.interface"
ubus -v list network.interface
echo "--- get_proto_handlers"
ubus call network get_proto_handlers
echo "--- interface dump"
ubus call network.interface dump
echo "--- resolv.conf.auto"
cat /tmp/resolv.conf.d/resolv.conf.auto
echo "--- device status"
ubus call network.device status
echo "--- interface lan status"
ubus call network.interface.lan status
PROBE

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

	# The candidate runs inside the rootfs too: the protocol scripts source
	# /lib/functions.sh by absolute path and live in /lib/netifd/proto, so a
	# daemon outside the chroot finds neither and silently discovers no
	# handlers at all.
	sudo -n cp "$cand" "$root/sbin/netifd-rs"
	sudo -n chmod 755 "$root/sbin/netifd-rs"
	sudo -n tee "$root/tmp/rsnetifd.sh" >/dev/null <<'RN'
set -u
/sbin/netifd-rs > /tmp/out/netifd.log 2>&1 &
echo $! > /tmp/out/cand.pid
RN

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
		while [ $i -lt 6 ]; do
			ip link add veth$i type veth peer name veth$((i+1))
			ip link set veth$i address 02:00:00:00:00:0$i
			ip link set veth$((i+1)) address 02:00:00:00:00:1$i
			ip link set veth$i up; ip link set veth$((i+1)) up
			i=$((i+2))
		done

		# the bus first, identically for both runs
		chroot "$root" /bin/sh /tmp/bus.sh
		if [ "$tag" = c ]; then
			chroot "$root" /bin/sh /tmp/cnetifd.sh
		else
			chroot "$root" /bin/sh /tmp/rsnetifd.sh
		fi
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

# Normalise only what cannot be equal by construction.
norm_kernel() {
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
		-e 's/expires [0-9]+sec/expires Lsec/g'
}

sort_kernel_routes() {
	python3 -c '
import sys
buf, out = [], []
def flush():
    # kernel-generated per-device routes only: their relative order reflects
    # device up/down history, not a netifd decision
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

diff -u <(norm_kernel < "$out/c-kernel.txt" | sort_kernel_routes) \
	<(norm_kernel < "$out/rs-kernel.txt" | sort_kernel_routes) \
	> "$out/kernel.diff" || true

(python3 - "$out/c-ubus.txt" "$out/rs-ubus.txt" "$out/ubus.diff" <<'PY'
import json, re, sys, collections

def sections(path):
    out, cur = collections.OrderedDict(), None
    for line in open(path):
        if line.startswith("--- "):
            cur = line[4:].strip()
            out[cur] = []
        elif cur is not None:
            out[cur].append(line)
    return collections.OrderedDict((k, "".join(v)) for k, v in out.items())

c, r = sections(sys.argv[1]), sections(sys.argv[2])
report = open(sys.argv[3], "w")
bad = 0

def mask(o):
    """Drop the values that legitimately differ between two runs."""
    if isinstance(o, dict):
        m = collections.OrderedDict()
        for k, v in o.items():
            if k == "uptime":
                m[k] = "N"
            elif k == "statistics" and isinstance(v, dict):
                m[k] = collections.OrderedDict((sk, "N") for sk in v)
            else:
                m[k] = mask(v)
        return m
    if isinstance(o, list):
        return [mask(x) for x in o]
    return o

# `network.wireless` used to sit here: this build did not register it, so the
# object list differed by that one name. It is registered now and compared
# like everything else.
KNOWN_GAPS = {}
gaps = []

for name in c:
    a, b = c[name], r.get(name, "")
    if name in KNOWN_GAPS:
        expected = KNOWN_GAPS[name]
        if expected is None:
            gaps.append(f"{name}: this build reports only the handlers it can run")
            continue
        missing = [x for x in expected if x in a and x not in b]
        extra = [
            l.strip() for l in b.splitlines()
            if l.strip() and l.strip() not in a
        ]
        left = [
            l.strip() for l in a.splitlines()
            if l.strip() and l.strip() not in b and l.strip() not in expected
        ]
        if missing:
            gaps.append(f"{name}: absent as expected: {missing}")
        if extra or left:
            print(f"{name}: unexpected difference", file=report)
            if left: print(f"  only in C:    {left}", file=report)
            if extra: print(f"  only in rust: {extra}", file=report)
            bad += 1
        continue
    if name in ("get_proto_handlers", "interface dump", "device status",
                "interface lan status"):
        try:
            ja, jb = json.loads(a, object_pairs_hook=collections.OrderedDict), \
                     json.loads(b, object_pairs_hook=collections.OrderedDict)
        except Exception as e:
            print(f"{name}: cannot parse both sides as JSON ({e})", file=report)
            print(f"  C:    {a[:200]}", file=report)
            print(f"  rust: {b[:200]}", file=report)
            bad += 1
            continue
        ja, jb = mask(ja), mask(jb)
        if ja != jb:
            print(f"{name}: DIFFERS", file=report)
            print("  C:    " + json.dumps(ja)[:2000], file=report)
            print("  rust: " + json.dumps(jb)[:2000], file=report)
            bad += 1
        continue
    a = re.sub(r"@[0-9a-f]{8}", "@ID", a)
    b = re.sub(r"@[0-9a-f]{8}", "@ID", b)
    if a.strip() != b.strip():
        print(f"{name}: DIFFERS", file=report)
        for line in __import__("difflib").unified_diff(
                a.splitlines(), b.splitlines(), "C", "rust", lineterm=""):
            print("  " + line, file=report)
        bad += 1

for g in gaps:
    print("KNOWN GAP " + g, file=report)
print(f"sections compared: {len(c)}", file=report)
report.close()
sys.exit(1 if bad else 0)
PY
) && ubus_rc=0 || ubus_rc=$?

echo "=== ubus surface ==="
if [ $ubus_rc -eq 0 ]; then
	echo "RESULT(ubus): identical"
else
	head -80 "$out/ubus.diff"
fi
echo "=== kernel state ==="
if [ ! -s "$out/kernel.diff" ]; then
	echo "RESULT(kernel): identical"
else
	head -60 "$out/kernel.diff"
fi
[ $ubus_rc -eq 0 ] && [ ! -s "$out/kernel.diff" ]
