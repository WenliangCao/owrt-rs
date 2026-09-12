#!/bin/sh
# R54: what a config reload disturbs.
#
# Three static interfaces plus one dhcp interface. The config is then changed
# in one place at a time and `network reload` is called, and the comparison is
# which interfaces bounced -- not just the state afterwards. A reload that
# rebuilds everything reaches the same final state as one that touches only
# what changed, so the final state alone cannot tell them apart; the hotplug
# and event sequences can.
#
# Usage: r54_reload_diff.sh <rootfs-files> <netifd-rs musl binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r54-out}
mkdir -p "$out"

CFG='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config interface "one"
	option device "veth1"
	option proto "static"
	option ipaddr "10.1.1.1/24"

config interface "two"
	option device "veth3"
	option proto "static"
	option ipaddr "10.2.2.1/24"

config interface "three"
	option device "veth5"
	option proto "static"
	option ipaddr "10.3.3.1/24"
'

# only interface `two` changes
CFG2='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config interface "one"
	option device "veth1"
	option proto "static"
	option ipaddr "10.1.1.1/24"

config interface "two"
	option device "veth3"
	option proto "static"
	option ipaddr "10.2.2.9/24"

config interface "three"
	option device "veth5"
	option proto "static"
	option ipaddr "10.3.3.1/24"
'

# a section is added; nothing existing changes
CFG3='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config interface "one"
	option device "veth1"
	option proto "static"
	option ipaddr "10.1.1.1/24"

config interface "two"
	option device "veth3"
	option proto "static"
	option ipaddr "10.2.2.9/24"

config interface "three"
	option device "veth5"
	option proto "static"
	option ipaddr "10.3.3.1/24"

config interface "four"
	option device "veth7"
	option proto "static"
	option ipaddr "10.4.4.1/24"
'

run_one() {
	tag=$1
	tmp=$(mktemp -d /tmp/owrt-r54-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n mkdir -p "$root/tmp/out" "$root/etc/config"
	printf '%s' "$CFG" | sudo -n tee "$root/etc/config/network" >/dev/null
	printf '%s' "$CFG2" | sudo -n tee "$root/tmp/network.2" >/dev/null
	printf '%s' "$CFG3" | sudo -n tee "$root/tmp/network.3" >/dev/null

	sudo -n mv "$root/sbin/hotplug-call" "$root/sbin/hotplug-call.real" 2>/dev/null || true
	sudo -n tee "$root/sbin/hotplug-call" >/dev/null <<'HP'
#!/bin/sh
printf 'hotplug ACTION=%s INTERFACE=%s DEVICE=%s\n' \
	"${ACTION:-}" "${INTERFACE:-}" "${DEVICE:-}" \
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

	sudo -n tee "$root/tmp/probe.sh" >/dev/null <<'PROBE'
set -u
ubus call network.interface dump
PROBE

	sudo -n unshare --mount --net --fork /bin/sh -c '
		root=$1; tag=$2; out=$3
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
		while [ $i -lt 8 ]; do
			ip link add veth$i address 02:00:00:00:00:0$i type veth \
				peer name veth$((i+1)) address 02:00:00:00:00:1$i
			ip link set veth$i up; ip link set veth$((i+1)) up
			i=$((i+2))
		done

		chroot "$root" /bin/sh /tmp/bus.sh
		if [ "$tag" = c ]; then
			chroot "$root" /bin/sh /tmp/cnetifd.sh
		else
			chroot "$root" /bin/sh /tmp/rsnetifd.sh
		fi
		sleep 4
		echo "== after startup" >> "$root/tmp/out/hotplug.txt"

		# reload with no change at all
		chroot "$root" ubus call network reload >/dev/null 2>&1 || true
		sleep 3
		echo "== after a no-op reload" >> "$root/tmp/out/hotplug.txt"
		chroot "$root" /bin/sh /tmp/probe.sh > "$out/$tag-dump1.txt" 2>&1 || true

		# reload with one interface changed
		cp "$root/tmp/network.2" "$root/etc/config/network"
		chroot "$root" ubus call network reload >/dev/null 2>&1 || true
		sleep 3
		echo "== after changing one interface" >> "$root/tmp/out/hotplug.txt"
		chroot "$root" /bin/sh /tmp/probe.sh > "$out/$tag-dump2.txt" 2>&1 || true

		# reload with a section added
		cp "$root/tmp/network.3" "$root/etc/config/network"
		chroot "$root" ubus call network reload >/dev/null 2>&1 || true
		sleep 3
		echo "== after adding a section" >> "$root/tmp/out/hotplug.txt"
		chroot "$root" /bin/sh /tmp/probe.sh > "$out/$tag-dump3.txt" 2>&1 || true

		{
			echo "--- ip addr"
			ip -o addr show | sed -E "s/^[0-9]+: //"
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
echo "=== what each reload disturbed"
if [ ! -s "$out/c-hotplug.txt" ]; then
	echo "RESULT(hotplug): NOTHING CAPTURED from the reference -- untested"
	rc=1
elif diff -u "$out/c-hotplug.txt" "$out/rs-hotplug.txt" > "$out/hotplug.diff"; then
	echo "RESULT(hotplug): identical"
	sed -n '1,40p' "$out/c-hotplug.txt"
else
	head -50 "$out/hotplug.diff"; rc=1
fi

for n in 1 2 3; do
	echo "=== interface dump $n"
	python3 - "$out/c-dump$n.txt" "$out/rs-dump$n.txt" <<'PY' || rc=1
import json, sys, collections

def mask(o):
    if isinstance(o, dict):
        return collections.OrderedDict(
            (k, "N" if k == "uptime" else mask(v)) for k, v in o.items())
    if isinstance(o, list):
        return [mask(x) for x in o]
    return o

try:
    a = mask(json.load(open(sys.argv[1]), object_pairs_hook=collections.OrderedDict))
    b = mask(json.load(open(sys.argv[2]), object_pairs_hook=collections.OrderedDict))
except Exception as e:
    print(f"cannot parse both sides ({e})")
    sys.exit(1)
if not a:
    print("NOTHING CAPTURED from the reference -- untested")
    sys.exit(1)
if a == b:
    print("RESULT: identical")
    sys.exit(0)
print("DIFFERS")
print("  C:    " + json.dumps(a)[:1400])
print("  rust: " + json.dumps(b)[:1400])
sys.exit(1)
PY
done

echo "=== kernel state"
if diff -u "$out/c-kernel.txt" "$out/rs-kernel.txt" > "$out/kernel.diff"; then
	echo "RESULT(kernel): identical"
else
	head -30 "$out/kernel.diff"; rc=1
fi

# Compare elapsed-time relationships on each side before masking uptime.
# Exact seconds differ between runs, but a changed interface must restart
# its clock while unaffected interfaces survive reload and list reordering.
python3 - "$out" <<'PY' || rc=1
import json, sys
from pathlib import Path

out = Path(sys.argv[1])
for side in ("c", "rs"):
    samples = []
    for n in (1, 2, 3):
        rows = json.loads((out / f"{side}-dump{n}.txt").read_text())["interface"]
        expected = ["loopback", "one", "three", "two"]
        if n == 3:
            expected.insert(0, "four")
        assert [i["interface"] for i in rows] == expected, (side, n, rows)
        assert all(i["up"] and type(i.get("uptime")) is int for i in rows)
        samples.append({i["interface"]: i["uptime"] for i in rows})
    before, changed, added = samples
    assert min(before.values()) >= 3, (side, "initial elapsed time", samples)
    for name in ("loopback", "one", "three"):
        assert changed[name] >= before[name] + 2, (side, "unaffected reload", name, samples)
    assert changed["two"] < before["two"], (side, "changed interface did not restart", samples)
    for name in before:
        assert added[name] >= changed[name] + 2, (side, "sort moved uptime", name, samples)
    assert added["four"] < min(added[name] for name in before), (side, "new interface", samples)
    print(f"RESULT(uptime {side}): live clocks, reload reset and reorder preservation passed")
PY
exit $rc
