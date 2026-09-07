#!/bin/sh
# R55: the ubus write methods this build has not implemented.
#
# Each method is called on both daemons with the same arguments, and both the
# return status and what it did to `network.interface dump` /
# `network.device status` are compared. The point is to find out which of
# these actually do something in this configuration before implementing any
# of them -- and to have evidence for the ones that turn out to be no-ops.
#
# Usage: r55_writemethods_diff.sh <rootfs-files> <netifd-rs musl binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r55-out}
mkdir -p "$out"

CFG='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config device
	option name "br-lan"
	option type "bridge"
	list ports "veth0"

config interface "lan"
	option device "br-lan"
	option proto "static"
	option ipaddr "192.168.1.1/24"

config interface "wired"
	option device "veth2"
	option proto "static"
	option ipaddr "10.0.0.1/24"
'

# One call per line: <label> <object> <method> <json>
CALLS='setdata_wired|network.interface.wired|set_data|{"hello":"world","n":7}
setdata_again|network.interface.wired|set_data|{"hello":"world","n":7}
setdata_change|network.interface.wired|set_data|{"hello":"other"}
prepare_wired|network.interface.wired|prepare|{}
adddev_wired|network.interface.wired|add_device|{"name":"veth4"}
removedev_wired|network.interface.wired|remove_device|{"name":"veth4"}
remove_wired|network.interface.wired|remove|{}
setalias|network.device|set_alias|{"alias":["al0"],"device":"veth6"}
setstate_down|network.device|set_state|{"name":"veth6","defer":true}
setstate_up|network.device|set_state|{"name":"veth6","defer":false}
stpinit|network.device|stp_init|{}
adddynamic|network|add_dynamic|{"name":"dyn0"}
netns_updown|network|netns_updown|{"jail":"j0","start":true}'

run_one() {
	tag=$1
	tmp=$(mktemp -d /tmp/owrt-r55-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n mkdir -p "$root/tmp/out" "$root/etc/config"
	printf '%s' "$CFG" | sudo -n tee "$root/etc/config/network" >/dev/null
	printf '%s\n' "$CALLS" | sudo -n tee "$root/tmp/calls.txt" >/dev/null

	sudo -n mv "$root/sbin/hotplug-call" "$root/sbin/hotplug-call.real" 2>/dev/null || true
	sudo -n tee "$root/sbin/hotplug-call" >/dev/null <<'HP'
#!/bin/sh
printf 'hotplug ACTION=%s INTERFACE=%s\n' "${ACTION:-}" "${INTERFACE:-}" \
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

	# Each call: the exit status, ubus's own message, then the two dumps.
	sudo -n tee "$root/tmp/drive.sh" >/dev/null <<'DR'
set -u
while IFS='|' read -r label obj method args; do
	[ -n "$label" ] || continue
	echo "===== $label"
	echo "--- call"
	ubus call "$obj" "$method" "$args" 2>&1
	echo "--- status $?"
	# let anything the call armed actually happen before looking: `remove`
	# runs off a 100ms timer, and reading before it fires reads nothing
	sleep 2
	echo "--- interface dump"
	ubus call network.interface dump 2>&1
	echo "--- device status veth6"
	ubus call network.device status '{"name":"veth6"}' 2>&1
done < /tmp/calls.txt
DR

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
		chroot "$root" /bin/sh /tmp/drive.sh > "$out/$tag-calls.txt" 2>&1 || true
		{
			echo "--- ip addr"
			ip -o addr show | sed -E "s/^[0-9]+: //"
			echo "--- ip link"
			ip -o link show | sed -E -e "s/^[0-9]+: //" -e "s/qdisc [a-z_]+/qdisc Q/"
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

def parse(text):
    t = text.strip()
    if not t:
        return ""
    try:
        return json.loads(t, object_pairs_hook=collections.OrderedDict)
    except Exception:
        return t

def walk(a, b, path, hits):
    # uptime moves between the two runs and is not a difference
    if path.endswith(".uptime"):
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
        hits.append((path, json.dumps(a)[:160], json.dumps(b)[:160]))

# the dump is keyed by interface name, so a difference names the interface
def by_name(o):
    if isinstance(o, dict) and isinstance(o.get("interface"), list):
        return collections.OrderedDict(
            (i.get("interface", "?"), i) for i in o["interface"])
    return o

c, r = blocks(sys.argv[1]), blocks(sys.argv[2])
if not c:
    print("NOTHING CAPTURED from the reference -- untested")
    sys.exit(1)
bad = 0
for label in c:
    hits = []
    for section in c[label]:
        a = parse(c[label][section])
        b = parse(r.get(label, {}).get(section, ""))
        if section == "interface dump":
            a, b = by_name(a), by_name(b)
        walk(a, b, section, hits)
    if not hits:
        print(f"RESULT({label}): identical")
        continue
    bad += 1
    print(f"{label}: DIFFERS")
    for path, x, y in hits[:12]:
        print(f"    {path}")
        print(f"      C:    {x}")
        print(f"      rust: {y}")
    if len(hits) > 12:
        print(f"    ... and {len(hits) - 12} more")
sys.exit(1 if bad else 0)
PY

echo "=== kernel state"
if diff -u "$out/c-kernel.txt" "$out/rs-kernel.txt" > "$out/kernel.diff"; then
	echo "RESULT(kernel): identical"
else
	head -25 "$out/kernel.diff"; rc=1
fi
echo "=== hotplug"
if diff -u "$out/c-hotplug.txt" "$out/rs-hotplug.txt" > "$out/hotplug.diff"; then
	echo "RESULT(hotplug): identical"
else
	head -25 "$out/hotplug.diff"; rc=1
fi
exit $rc
