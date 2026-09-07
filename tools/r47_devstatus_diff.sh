#!/bin/sh
# R47: `network.device status` from netifd-rs against the device's own C netifd,
# on the same kernel, in the same network namespace, for the same devices.
#
# The C netifd runs inside a copy of the exact device rootfs (it is musl-linked
# and will not run outside it); the Rust probe runs outside the chroot but
# inside the same namespaces, so /proc/sys/net and the netlink view are the
# ones the C daemon just configured.
#
# Usage: r47_devstatus_diff.sh <rootfs-files> <devstatus binary> [outdir]
set -eu
rootfs=$1; probe=$2; out=${3:-/tmp/r47-out}
mkdir -p "$out"
tmp=$(mktemp -d /tmp/owrt-r47-XXXXXX); root=$tmp/root
sudo -n cp -a "$rootfs" "$root"
sudo -n chown -R root:root "$root/usr/share/acl.d"
sudo -n mkdir -p "$root/tmp/out"

sudo -n tee "$root/tmp/inner.sh" >/dev/null <<'INNER'
set -u
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out /etc/config
cat > /etc/config/network <<CFG
config interface loopback
	option device lo
	option proto static
	option ipaddr 127.0.0.1/8

config device
	option name br-lan
	option type bridge
	list ports veth0
	list ports veth2

config interface lan
	option device br-lan
	option proto static
	option ipaddr 192.168.1.1/24
	option ip6assign 60

config interface plain
	option device veth1
	option proto static
	option ipaddr 10.0.0.1/24
CFG
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 &
echo $! > /tmp/out/ubusd.pid
sleep 1
/sbin/netifd >/tmp/out/netifd.log 2>&1 &
echo $! > /tmp/out/netifd.pid
sleep 4
ubus call network.device status > /tmp/out/c-status.json 2>/tmp/out/c-status.err
echo done > /tmp/out/ready
# hold the namespace open while the outside probe runs
sleep 15
INNER

self_probe=$probe
sudo -n unshare --mount --net --fork /bin/sh -c '
	root=$1; probe=$2; out=$3
	mount --make-rprivate /
	# sysfs shows the network devices of the namespace it was mounted in, and
	# the outer /sys predates this netns. The Rust probe reads /sys directly,
	# so give this mount namespace a fresh sysfs as well -- without it the
	# probe silently reports the build host'"'"'s devices.
	mount -t sysfs sysfs /sys
	mount -t proc proc "$root/proc"; mount -t sysfs sysfs "$root/sys"
	mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
	mknod -m 666 "$root/dev/null" c 1 3
	mknod -m 666 "$root/dev/urandom" c 1 9
	mknod -m 666 "$root/dev/zero" c 1 5
	trap "umount $root/dev 2>/dev/null; umount $root/sys 2>/dev/null; umount $root/proc 2>/dev/null" EXIT

	ip link set lo up
	# deterministic MACs so nothing derived from them differs by run
	ip link add veth0 type veth peer name veth1
	ip link add veth2 type veth peer name veth3
	ip link set veth0 address 02:00:00:00:00:0a
	ip link set veth1 address 02:00:00:00:00:0b
	ip link set veth2 address 02:00:00:00:00:0c
	ip link set veth3 address 02:00:00:00:00:0d
	ip link set veth1 up; ip link set veth3 up

	chroot "$root" /bin/sh /tmp/inner.sh &
	inner=$!
	i=0; while [ $i -lt 40 ] && [ ! -f "$root/tmp/out/ready" ]; do i=$((i+1)); sleep 1; done
	cp "$root/tmp/out/c-status.json" "$out/c-status.json" 2>/dev/null || true
	cp "$root/tmp/out/netifd.log" "$out/netifd.log" 2>/dev/null || true
	if [ -s "$out/c-status.json" ]; then
		"$probe" "$out/c-status.json" > "$out/rs-status.json" 2> "$out/rs.err" || true
	fi
	# the daemons hold the namespace open; kill them by the pids they
	# recorded, never by pattern -- a pattern kill here has matched the
	# harness'"'"'s own command line before
	for f in netifd ubusd; do
		p=$(cat "$root/tmp/out/$f.pid" 2>/dev/null || true)
		[ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
	done
	kill $inner 2>/dev/null || true
	' sh "$root" "$self_probe" "$out" > "$out/outer.log" 2>&1 || true

sudo -n chown "$(id -u):$(id -g)" "$out"/*.json 2>/dev/null || true
sudo -n rm -rf "$tmp"

[ -s "$out/c-status.json" ] || { echo "RESULT: no C status captured"; cat "$out/outer.log"; exit 1; }
[ -s "$out/rs-status.json" ] || { echo "RESULT: no Rust status captured"; cat "$out/rs.err" 2>/dev/null; exit 1; }

python3 - "$out/c-status.json" "$out/rs-status.json" <<'PY'
import json, sys, collections

def load(p):
    return json.load(open(p), object_pairs_hook=collections.OrderedDict)

c, r = load(sys.argv[1]), load(sys.argv[2])

def mask_stats(d):
    # the counters move between the two reads; the key set is what matters
    out = collections.OrderedDict()
    for k, v in d.items():
        if k == "statistics" and isinstance(v, dict):
            out[k] = collections.OrderedDict((sk, "N") for sk in v)
        else:
            out[k] = v
    return out

bad = 0
if list(c) != list(r):
    print("device sets differ:", list(c), "vs", list(r)); bad += 1
for name in c:
    if name not in r:
        continue
    cd, rd = mask_stats(c[name]), mask_stats(r[name])
    if list(cd) != list(rd):
        only_c = [k for k in cd if k not in rd]
        only_r = [k for k in rd if k not in cd]
        print(f"{name}: field set/order differs")
        if only_c: print(f"  only in C:    {only_c}")
        if only_r: print(f"  only in rust: {only_r}")
        if not only_c and not only_r:
            print(f"  C order:    {list(cd)}")
            print(f"  rust order: {list(rd)}")
        bad += 1
    for k in cd:
        if k not in rd:
            continue
        if cd[k] != rd[k]:
            print(f"{name}.{k}: C={cd[k]!r} rust={rd[k]!r}")
            bad += 1

if bad:
    print(f"RESULT: DIFFERENT ({bad} differences)")
    sys.exit(1)
print(f"RESULT: identical for {len(c)} devices, {sum(len(v) for v in c.values())} fields")
PY
