#!/bin/sh
# R48: `network.interface dump` from netifd-rs against the device's own C
# netifd, for a static-only configuration, on the same kernel.
#
# Same shape as R47: the C daemon runs inside a copy of the exact device
# rootfs, and the Rust projection is built from the same /etc/config/network.
#
# Usage: r48_ifstatus_diff.sh <rootfs-files> <ifstatus binary> [outdir]
set -eu
rootfs=$1; probe=$2; out=${3:-/tmp/r48-out}
mkdir -p "$out"
tmp=$(mktemp -d /tmp/owrt-r48-XXXXXX); root=$tmp/root
sudo -n cp -a "$rootfs" "$root"
sudo -n chown -R root:root "$root/usr/share/acl.d"
sudo -n mkdir -p "$root/tmp/out" "$root/etc/config"

# One config, written once, read by both sides.
sudo -n tee "$root/etc/config/network" >/dev/null <<'CFG'
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1/8'

config globals 'globals'
	option ula_prefix 'fd11:2233:4455::/48'
	option packet_steering '1'

config device
	option name 'br-lan'
	option type 'bridge'
	list ports 'veth0'
	list ports 'veth2'

config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option ipaddr '192.168.1.1/24'
	option ip6addr 'fd11:2233:4455::1/60'
	option ip6assign '60'

config interface 'wired'
	option device 'veth1'
	option proto 'static'
	option ipaddr '10.0.0.1'
	option netmask '255.255.255.0'
	option gateway '10.0.0.254'
	option metric '13'
	option dns_metric '7'
	list dns '10.0.0.53'
	list dns '10.0.0.54'
	list dns_search 'example.invalid'

config interface 'nodev'
	option device 'missing0'
	option proto 'static'
	option ipaddr '10.9.9.1/24'
CFG

sudo -n tee "$root/tmp/inner.sh" >/dev/null <<'INNER'
set -u
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 &
echo $! > /tmp/out/ubusd.pid
sleep 1
/sbin/netifd >/tmp/out/netifd.log 2>&1 &
echo $! > /tmp/out/netifd.pid
sleep 4
ubus call network.interface dump > /tmp/out/c-dump.json 2>/tmp/out/c-dump.err
echo done > /tmp/out/ready
sleep 15
INNER

sudo -n unshare --mount --net --fork /bin/sh -c '
	root=$1; probe=$2; out=$3
	mount --make-rprivate /
	mount -t sysfs sysfs /sys
	mount -t proc proc "$root/proc"; mount -t sysfs sysfs "$root/sys"
	mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
	mknod -m 666 "$root/dev/null" c 1 3
	mknod -m 666 "$root/dev/urandom" c 1 9
	mknod -m 666 "$root/dev/zero" c 1 5
	trap "umount $root/dev 2>/dev/null; umount $root/sys 2>/dev/null; umount $root/proc 2>/dev/null" EXIT

	ip link set lo up
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
	cp "$root/tmp/out/c-dump.json" "$out/c-dump.json" 2>/dev/null || true
	cp "$root/tmp/out/netifd.log" "$out/netifd.log" 2>/dev/null || true
	if [ -s "$out/c-dump.json" ]; then
		"$probe" "$root/etc/config" "$out/c-dump.json" \
			> "$out/rs-dump.json" 2> "$out/rs.err" || true
	fi
	# the daemons hold the namespace open; kill them by the pids they
	# recorded, never by pattern -- a pattern kill here has matched the
	# harness'"'"'s own command line before
	for f in netifd ubusd; do
		p=$(cat "$root/tmp/out/$f.pid" 2>/dev/null || true)
		[ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
	done
	kill $inner 2>/dev/null || true
	' sh "$root" "$probe" "$out" > "$out/outer.log" 2>&1 || true

sudo -n chown "$(id -u):$(id -g)" "$out"/*.json 2>/dev/null || true
sudo -n cp "$root/etc/config/network" "$out/network.conf" 2>/dev/null || true
sudo -n chown "$(id -u):$(id -g)" "$out/network.conf" 2>/dev/null || true
sudo -n rm -rf "$tmp"

[ -s "$out/c-dump.json" ] || { echo "RESULT: no C dump captured"; cat "$out/outer.log"; exit 1; }
[ -s "$out/rs-dump.json" ] || { echo "RESULT: no Rust dump captured"; cat "$out/rs.err" 2>/dev/null; exit 1; }

python3 - "$out/c-dump.json" "$out/rs-dump.json" <<'PY'
import json, sys, collections

def load(p):
    return json.load(open(p), object_pairs_hook=collections.OrderedDict)

c = load(sys.argv[1])["interface"]
r = load(sys.argv[2])["interface"]
cmap = {i["interface"]: i for i in c}
rmap = {i["interface"]: i for i in r}

bad = 0
if [i["interface"] for i in c] != [i["interface"] for i in r]:
    print("interface lists differ:", [i["interface"] for i in c],
          "vs", [i["interface"] for i in r])
    bad += 1

def walk(path, a, b):
    global bad
    if isinstance(a, dict) and isinstance(b, dict):
        if list(a) != list(b):
            only_a = [k for k in a if k not in b]
            only_b = [k for k in b if k not in a]
            print(f"{path}: field set/order differs")
            if only_a: print(f"  only in C:    {only_a}")
            if only_b: print(f"  only in rust: {only_b}")
            if not only_a and not only_b:
                print(f"  C order:    {list(a)}")
                print(f"  rust order: {list(b)}")
            bad += 1
        for k in a:
            if k in b:
                walk(f"{path}.{k}", a[k], b[k])
        return
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            print(f"{path}: length {len(a)} vs {len(b)}")
            print(f"  C:    {json.dumps(a)}")
            print(f"  rust: {json.dumps(b)}")
            bad += 1
            return
        for n, (x, y) in enumerate(zip(a, b)):
            walk(f"{path}[{n}]", x, y)
        return
    if a != b:
        print(f"{path}: C={a!r} rust={b!r}")
        bad += 1

for name in cmap:
    if name in rmap:
        walk(name, cmap[name], rmap[name])

if bad:
    print(f"RESULT: DIFFERENT ({bad} differences)")
    sys.exit(1)
print(f"RESULT: identical for {len(cmap)} interfaces")
PY
