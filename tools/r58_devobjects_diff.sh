#!/bin/sh
# R58: the device-object registry, and a dynamic interface's whole life.
#
# Two things r47-r57 never covered:
#
#   * `network.device status` with no name lists EVERY present device object,
#     not just the ones the config mentions -- including a device netifd only
#     has an object for because it is another device's `iflink` parent. r47
#     and r49 agreed by accident: in their topologies every parent happened to
#     be config-named too.
#
#   * `add_dynamic` with a real device, which comes up, and then `remove`,
#     which takes it away again. r55's dynamic interface has no device, so it
#     never leaves DOWN and its removal proves nothing.
#
# Usage: r58_devobjects_diff.sh <rootfs-files> <netifd-rs musl binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r58-out}
mkdir -p "$out"

# veth1 is configured; veth0 is its peer and gets an object only as its parent
CFG='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config interface "wired"
	option device "veth1"
	option proto "static"
	option ipaddr "10.0.0.9/24"
'

run_one() {
	tag=$1
	tmp=$(mktemp -d /tmp/owrt-r58-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n mkdir -p "$root/tmp/out" "$root/etc/config"
	printf '%s' "$CFG" | sudo -n tee "$root/etc/config/network" >/dev/null

	sudo -n mv "$root/sbin/hotplug-call" "$root/sbin/hotplug-call.real" 2>/dev/null || true
	sudo -n tee "$root/sbin/hotplug-call" >/dev/null <<'HP'
#!/bin/sh
printf 'hotplug ACTION=%s INTERFACE=%s\n' "${ACTION:-}" "${INTERFACE:-}" \
	>> "${0%/sbin/hotplug-call}/tmp/out/hotplug.txt"
exit 0
HP
	sudo -n chmod 755 "$root/sbin/hotplug-call"

	sudo -n tee "$root/tmp/bus.sh" >/dev/null <<'BUS'
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 & echo $! > /tmp/out/ubusd.pid
sleep 1
BUS
	sudo -n tee "$root/tmp/cn.sh" >/dev/null <<'CN'
/sbin/netifd >/tmp/out/netifd.log 2>&1 & echo $! > /tmp/out/netifd.pid
CN
	sudo -n cp "$cand" "$root/sbin/netifd-rs"
	sudo -n chmod 755 "$root/sbin/netifd-rs"
	sudo -n tee "$root/tmp/rs.sh" >/dev/null <<'RN'
/sbin/netifd-rs >/tmp/out/netifd.log 2>&1 & echo $! > /tmp/out/cand.pid
RN

	sudo -n tee "$root/tmp/drive.sh" >/dev/null <<'DR'
set -u
snap() {
	echo "===== $1"
	echo "--- devices"
	ubus call network.device status 2>&1
	echo "--- interfaces"
	ubus call network.interface dump 2>&1
}
snap startup
echo "===== add a dynamic interface with a real device"
ubus call network add_dynamic \
	'{"name":"dyn0","proto":"static","device":"veth3","ipaddr":"10.3.3.1","netmask":"255.255.255.0"}' 2>&1
sleep 2
snap after-add
echo "===== remove it again"
ubus call network.interface.dyn0 remove 2>&1
sleep 2
snap after-remove
echo "===== remove a config interface, which must survive"
ubus call network.interface.wired remove 2>&1
sleep 2
snap after-config-remove
DR

	sudo -n unshare --mount --net --fork /bin/sh -c '
		root=$1; tag=$2; out=$3
		mount --make-rprivate /; mount -t sysfs sysfs /sys
		mount -t proc proc "$root/proc"; mount -t sysfs sysfs "$root/sys"
		mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		trap "umount $root/dev 2>/dev/null; umount $root/sys 2>/dev/null; umount $root/proc 2>/dev/null" EXIT

		ip link set lo up
		i=0
		while [ $i -lt 4 ]; do
			ip link add veth$i address 02:00:00:00:00:0$i type veth \
				peer name veth$((i+1)) address 02:00:00:00:00:1$i
			ip link set veth$i up; ip link set veth$((i+1)) up
			i=$((i+2))
		done

		chroot "$root" /bin/sh /tmp/bus.sh
		[ "$tag" = c ] && chroot "$root" /bin/sh /tmp/cn.sh \
			|| chroot "$root" /bin/sh /tmp/rs.sh
		sleep 4
		chroot "$root" /bin/sh /tmp/drive.sh > "$out/$tag-calls.txt" 2>&1 || true
		{
			echo "--- ip addr"
			ip -o -4 addr show | sed -E "s/^[0-9]+: //"
		} > "$out/$tag-kernel.txt" 2>&1 || true
		cp "$root/tmp/out/netifd.log" "$out/$tag-daemon.log" 2>/dev/null || true
		cp "$root/tmp/out/hotplug.txt" "$out/$tag-hotplug.txt" 2>/dev/null || \
			: > "$out/$tag-hotplug.txt"
		for f in netifd ubusd cand; do
			p=$(cat "$root/tmp/out/$f.pid" 2>/dev/null || true)
			[ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
		done
		' sh "$root" "$tag" "$out" > "$out/$tag-outer.log" 2>&1 || true

	sudo -n chown "$(id -u):$(id -g)" "$out"/$tag-* 2>/dev/null || true
	sudo -n rm -rf "$tmp"
}

run_one c
run_one rs

rc=0
python3 - "$out/c-calls.txt" "$out/rs-calls.txt" <<'PY' || rc=1
import json, sys, collections

def blocks(path):
    out, key, cur = collections.OrderedDict(), None, None
    for line in open(path):
        if line.startswith("===== "):
            key = line[6:].strip(); out[key] = collections.OrderedDict(); cur = None
        elif line.startswith("--- "):
            cur = line[4:].strip(); out[key][cur] = []
        elif key is not None and cur is not None:
            out[key][cur].append(line)
    return collections.OrderedDict(
        (k, collections.OrderedDict((s, "".join(v)) for s, v in b.items()))
        for k, b in out.items())

def parse(t):
    t = t.strip()
    if not t:
        return ""
    try:
        return json.loads(t, object_pairs_hook=collections.OrderedDict)
    except Exception:
        return t

# traffic counters depend on how many packets each run happened to send
SKIP = ("uptime", "rx_packets", "tx_packets", "rx_bytes", "tx_bytes",
        "rx_dropped", "tx_dropped", "multicast", "collisions")

def walk(a, b, path, hits):
    if path.rsplit(".", 1)[-1] in SKIP:
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for k in list(a.keys()) + [k for k in b if k not in a]:
            walk(a.get(k, "<missing>"), b.get(k, "<missing>"), f"{path}.{k}", hits)
        return
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            hits.append((path, f"{len(a)} entries", f"{len(b)} entries"))
            return
        for i, (x, y) in enumerate(zip(a, b)):
            walk(x, y, f"{path}[{i}]", hits)
        return
    if a != b:
        hits.append((path, json.dumps(a)[:200], json.dumps(b)[:200]))

def by_name(o):
    if isinstance(o, dict) and isinstance(o.get("interface"), list):
        return collections.OrderedDict((i.get("interface", "?"), i) for i in o["interface"])
    return o

c, r = blocks(sys.argv[1]), blocks(sys.argv[2])
if not c:
    print("NOTHING CAPTURED from the reference -- untested")
    sys.exit(1)
bad = 0
for label in c:
    hits = []
    for section in c[label]:
        a, b = parse(c[label][section]), parse(r.get(label, {}).get(section, ""))
        if section == "interfaces":
            a, b = by_name(a), by_name(b)
        walk(a, b, section, hits)
    if not hits:
        print(f"RESULT({label}): identical")
        continue
    bad += 1
    print(f"{label}: DIFFERS")
    for path, x, y in hits[:10]:
        print(f"    {path}")
        print(f"      C:    {x}")
        print(f"      rust: {y}")
    if len(hits) > 10:
        print(f"    ... and {len(hits) - 10} more")
sys.exit(1 if bad else 0)
PY

echo "=== kernel state"
if diff -u "$out/c-kernel.txt" "$out/rs-kernel.txt" > "$out/kernel.diff"; then
	echo "RESULT(kernel): identical"
else
	head -20 "$out/kernel.diff"; rc=1
fi
echo "=== hotplug"
if diff -u "$out/c-hotplug.txt" "$out/rs-hotplug.txt" > "$out/hotplug.diff"; then
	echo "RESULT(hotplug): identical"
else
	head -20 "$out/hotplug.diff"; rc=1
fi
exit $rc
