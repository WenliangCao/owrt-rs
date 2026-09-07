#!/bin/sh
# R52: a real DHCP exchange through proto-shell, against the C netifd.
#
# This is the end-to-end test of the whole proto-shell path: netifd runs
# /lib/netifd/proto/dhcp.sh, the script asks netifd to start `udhcpc` via
# notify_proto action 1, udhcpc talks to a real server, and the script reports
# the lease back through action 0. Nothing here is stubbed.
#
# The server is the build host's `busybox udhcpd` on the peer end of the veth,
# outside the chroot but in the same namespace. The pool is a single address so
# both runs get the same lease and the comparison stays exact.
#
# The candidate must be a musl binary for this target and runs inside the
# rootfs, because the protocol scripts need it.
#
# Usage: r52_dhcp_diff.sh <rootfs-files> <netifd-rs musl binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r52-out}
mkdir -p "$out"

CFG='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config interface "wan"
	option device "veth1"
	option proto "dhcp"
	option hostname "probe"
'

run_one() {
	tag=$1
	tmp=$(mktemp -d /tmp/owrt-r52-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n mkdir -p "$root/tmp/out" "$root/etc/config"
	printf '%s' "$CFG" | sudo -n tee "$root/etc/config/network" >/dev/null

	# a recorder in place of hotplug-call, so the event sequence is visible
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

	sudo -n tee "$root/tmp/probe.sh" >/dev/null <<'PROBE'
set -u
echo "--- interface dump"
ubus call network.interface dump
echo "--- wan status"
ubus call network.interface.wan status
PROBE

	# A single-address pool: both runs must get 10.0.0.100.
	cat > "$tmp/udhcpd.conf" <<UD
start 10.0.0.100
end 10.0.0.100
interface veth0
max_leases 1
option subnet 255.255.255.0
option router 10.0.0.1
option dns 10.0.0.53
option domain lan.invalid
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
		ip link add veth0 type veth peer name veth1
		ip link set veth0 address 02:00:00:00:00:00
		ip link set veth1 address 02:00:00:00:00:01
		ip link set veth0 up; ip link set veth1 up
		ip addr add 10.0.0.1/24 dev veth0

		# the DHCP server, on the host side of the veth
		busybox udhcpd -f "$tmp/udhcpd.conf" > "$out/$tag-udhcpd.log" 2>&1 &
		echo $! > "$tmp/udhcpd.hostpid"
		sleep 1

		# veth0 is the server side and is in no config section: whether the
		# daemon wipes its address anyway is part of what this compares
		ip -o addr show dev veth0 > "$out/$tag-veth0-before.txt" 2>&1 || true

		chroot "$root" /bin/sh /tmp/bus.sh
		if [ "$tag" = c ]; then
			chroot "$root" /bin/sh /tmp/cnetifd.sh
		else
			chroot "$root" /bin/sh /tmp/rsnetifd.sh
		fi

		sleep 1
		ip -o addr show dev veth0 > "$out/$tag-veth0-after.txt" 2>&1 || true

		# wait for the lease rather than sleeping a fixed time
		i=0
		while [ $i -lt 30 ]; do
			if chroot "$root" ubus call network.interface.wan status 2>/dev/null \
				| grep -q "10.0.0.100"; then
				break
			fi
			i=$((i+1)); sleep 1
		done
		echo "waited: ${i}s" > "$out/$tag-wait.txt"

		chroot "$root" /bin/sh /tmp/probe.sh > "$out/$tag-ubus.txt" 2>&1 || true

		# ifdown must stop the helper and take the lease off the device, and
		# ifup must get it back. A teardown command that never runs leaves
		# udhcpc alive, which only a real cycle shows.
		chroot "$root" ubus call network.interface.wan down >/dev/null 2>&1 || true
		j=0
		while [ $j -lt 15 ]; do
			chroot "$root" ubus call network.interface.wan status 2>/dev/null \
				| grep -q "10.0.0.100" || break
			j=$((j+1)); sleep 1
		done
		{
			echo "--- after ifdown: is the DHCP helper still alive"
			# by pid file, not by parsing ps: busybox ps repeats lines
			p=$(cat "$root/var/run/udhcpc-veth1.pid" 2>/dev/null || true)
			if [ -n "$p" ] && [ -d "/proc/$p" ]; then
				echo "udhcpc still running"
			else
				echo "udhcpc gone"
			fi
			echo "--- after ifdown: veth1"
			# the C sets the state and emits the event before it touches the
			# kernel, so give both sides the same chance to finish
			sleep 1
			ip -o link show dev veth1 | sed -E -e "s/^[0-9]+: //" -e "s/qdisc [a-z_]+/qdisc Q/"
			ip -o addr show dev veth1 | sed -E "s/^[0-9]+: //"
			echo "--- after ifdown: wan status"
			chroot "$root" ubus call network.interface.wan status 2>/dev/null
		} > "$out/$tag-down.txt" 2>&1 || true

		chroot "$root" ubus call network.interface.wan up >/dev/null 2>&1 || true
		j=0
		while [ $j -lt 20 ]; do
			chroot "$root" ubus call network.interface.wan status 2>/dev/null \
				| grep -q "10.0.0.100" && break
			j=$((j+1)); sleep 1
		done
		echo "reup: ${j}s" > "$out/$tag-reup.txt"
		chroot "$root" ubus call network.interface.wan status \
			> "$out/$tag-reup-status.txt" 2>&1 || true
		{
			echo "--- ip addr"
			ip -o addr show
			echo "--- ip link"
			ip -o link show
			echo "--- ip route4"
			ip -4 route show table all
		} > "$out/$tag-kernel.txt" 2>&1 || true
		cp "$root/tmp/out/netifd.log" "$out/$tag-daemon.log" 2>/dev/null || true
		cp "$root/tmp/out/hotplug.txt" "$out/$tag-hotplug.txt" 2>/dev/null || \
			: > "$out/$tag-hotplug.txt"
		# every process the daemon started, so nothing outlives the run
		chroot "$root" /bin/sh -c "ps 2>/dev/null | grep -c udhcpc" \
			> "$out/$tag-udhcpc-count.txt" 2>&1 || true

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

echo "=== lease acquired after"
for t in c rs; do printf '%-3s %s\n' "$t" "$(cat "$out/$t-wait.txt" 2>/dev/null)"; done

rc=0
echo "=== kernel state"
norm() { sed -E -e 's/^[0-9]+: /N: /' -e 's/valid_lft [0-9]+sec/valid_lft Lsec/g' \
	-e 's/preferred_lft [0-9]+sec/preferred_lft Lsec/g'; }
if diff -u <(norm < "$out/c-kernel.txt") <(norm < "$out/rs-kernel.txt") > "$out/kernel.diff"; then
	echo "RESULT(kernel): identical"
else
	head -30 "$out/kernel.diff"; rc=1
fi

echo "=== veth0, the unconfigured server-side device"
for t in c rs; do
	printf '%-3s before: %s\n' "$t" "$(cat "$out/$t-veth0-before.txt" 2>/dev/null | tr '\n' ' ')"
	printf '%-3s after:  %s\n' "$t" "$(cat "$out/$t-veth0-after.txt" 2>/dev/null | tr '\n' ' ')"
done

echo "=== ifdown, then ifup again"
for t in c rs; do printf '%-3s %s\n' "$t" "$(cat "$out/$t-reup.txt" 2>/dev/null)"; done
if diff -u "$out/c-down.txt" "$out/rs-down.txt" > "$out/down.diff"; then
	echo "RESULT(after ifdown): identical"
else
	head -30 "$out/down.diff"; rc=1
fi
python3 - "$out/c-reup-status.txt" "$out/rs-reup-status.txt" <<'REUP' || rc=1
import json, sys, collections

def mask(o):
    if isinstance(o, dict):
        return collections.OrderedDict(
            (k, "N" if k in ("uptime", "leasetime") else mask(v)) for k, v in o.items())
    if isinstance(o, list):
        return [mask(x) for x in o]
    return o

try:
    a = mask(json.load(open(sys.argv[1]), object_pairs_hook=collections.OrderedDict))
    b = mask(json.load(open(sys.argv[2]), object_pairs_hook=collections.OrderedDict))
except Exception as e:
    print(f"re-up status: cannot parse both sides ({e})")
    sys.exit(1)
if not a:
    print("re-up status: NOTHING CAPTURED from the reference -- untested")
    sys.exit(1)
if a == b:
    print("RESULT(status after ifup): identical")
    sys.exit(0)
print("status after ifup: DIFFERS")
print("  C:    " + json.dumps(a)[:1200])
print("  rust: " + json.dumps(b)[:1200])
sys.exit(1)
REUP

echo "=== interface dump"
python3 - "$out/c-ubus.txt" "$out/rs-ubus.txt" <<'PY' || rc=1
import json, sys, collections

def sections(path):
    out, cur = collections.OrderedDict(), None
    for line in open(path):
        if line.startswith("--- "):
            cur = line[4:].strip(); out[cur] = []
        elif cur is not None:
            out[cur].append(line)
    return collections.OrderedDict((k, "".join(v)) for k, v in out.items())

def mask(o):
    if isinstance(o, dict):
        m = collections.OrderedDict()
        for k, v in o.items():
            # uptime moves, and the lease countdown is sampled at different
            # moments in the two runs
            m[k] = "N" if k in ("uptime", "leasetime") else mask(v)
        return m
    if isinstance(o, list):
        return [mask(x) for x in o]
    return o

c, r = sections(sys.argv[1]), sections(sys.argv[2])
bad = 0
for name in ("interface dump", "wan status"):
    if name not in c or not c[name].strip():
        print(f"{name}: NOTHING CAPTURED from the reference -- untested")
        bad += 1
        continue
    try:
        a = mask(json.loads(c[name], object_pairs_hook=collections.OrderedDict))
        b = mask(json.loads(r[name], object_pairs_hook=collections.OrderedDict))
    except Exception as e:
        print(f"{name}: cannot parse both sides ({e})")
        print("  C:    " + c[name][:300])
        print("  rust: " + r.get(name, "")[:300])
        bad += 1
        continue
    if a == b:
        print(f"RESULT({name}): identical")
    else:
        print(f"{name}: DIFFERS")
        print("  C:    " + json.dumps(a)[:1500])
        print("  rust: " + json.dumps(b)[:1500])
        bad += 1
sys.exit(1 if bad else 0)
PY

echo "=== hotplug"
if diff -u "$out/c-hotplug.txt" "$out/rs-hotplug.txt" > "$out/hotplug.diff"; then
	echo "RESULT(hotplug): identical, $(wc -l < "$out/c-hotplug.txt") lines"
else
	head -20 "$out/hotplug.diff"; rc=1
fi
exit $rc
