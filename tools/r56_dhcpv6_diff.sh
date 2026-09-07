#!/bin/sh
# R56: a real DHCPv6 exchange through proto-shell, against the C netifd.
#
# The IPv6 half of `apply_proto_link` -- `ip6addr` as an array of tables with
# lifetimes and a class, `ip6prefix`, the v6 gateway, the v6 subnet route --
# was written from the C source and never run. r52 exercised the proto-shell
# machinery with IPv4 only.
#
# The server is `odhcpd` from the same rootfs -- the image's dnsmasq is built
# without DHCPv6. odhcpd is the device's real DHCPv6 server, and it finds its
# interfaces by calling `network.interface dump` on the daemon under test, so
# this also exercises a real consumer of that surface.
#
# The server side is itself a netifd interface (`srv` on the peer veth), which
# sidesteps `system_if_clear_state` wiping an address someone else put there
# (see r52) -- netifd owns this one.
#
# Usage: r56_dhcpv6_diff.sh <rootfs-files> <netifd-rs musl binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r56-out}
mkdir -p "$out"

CFG='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config interface "srv"
	option device "veth0"
	option proto "static"
	option ip6addr "fd00:5678::1/64"

config interface "wan6"
	option device "veth1"
	option proto "dhcpv6"
	option reqaddress "try"
	option reqprefix "auto"
'

run_one() {
	tag=$1
	tmp=$(mktemp -d /tmp/owrt-r56-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n mkdir -p "$root/tmp/out" "$root/etc/config"
	printf '%s' "$CFG" | sudo -n tee "$root/etc/config/network" >/dev/null
	sudo -n tee "$root/etc/config/dhcp" >/dev/null <<'DHCPCFG'
config odhcpd 'odhcpd'
	option maindhcp '0'
	option leasefile '/tmp/hosts/odhcpd'
	option leasetrigger '/bin/true'
	option loglevel '7'

config dhcp 'srv'
	option interface 'srv'
	option ra 'server'
	option dhcpv6 'server'
	option ra_management '1'
	option ra_default '1'
	option start '100'
	option limit '150'
	option leasetime '12h'
DHCPCFG

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

	# The server, inside the same rootfs so it is the same binary on both
	# sides. --port=0 keeps DNS out of it; --conf-file=/dev/null keeps the
	# image's own dnsmasq config out of it.
	sudo -n tee "$root/tmp/server.sh" >/dev/null <<'SV'
set -u
mkdir -p /tmp/hosts
/usr/sbin/odhcpd > /tmp/out/server.log 2>&1 &
echo $! > /tmp/out/server.pid
SV

	sudo -n tee "$root/tmp/probe.sh" >/dev/null <<'PROBE'
set -u
echo "--- wan6 status"
ubus call network.interface.wan6 status
echo "--- interface dump"
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
		ip link add veth0 address 02:00:00:00:00:00 type veth \
			peer name veth1 address 02:00:00:00:00:01
		ip link set veth0 up; ip link set veth1 up
		sysctl -qw net.ipv6.conf.veth0.forwarding=1 2>/dev/null || true

		chroot "$root" /bin/sh /tmp/bus.sh
		if [ "$tag" = c ]; then
			chroot "$root" /bin/sh /tmp/cnetifd.sh
		else
			chroot "$root" /bin/sh /tmp/rsnetifd.sh
		fi
		# let the daemon bring `srv` up before the server looks for it
		sleep 4
		chroot "$root" /bin/sh /tmp/server.sh
		sleep 2

		i=0
		while [ $i -lt 30 ]; do
			chroot "$root" ubus call network.interface.wan6 status 2>/dev/null \
				| grep -q "fd00:5678" && break
			i=$((i+1)); sleep 1
		done
		echo "waited: ${i}s" > "$out/$tag-wait.txt"

		chroot "$root" /bin/sh /tmp/probe.sh > "$out/$tag-ubus.txt" 2>&1 || true
		{
			echo "--- ip -6 addr veth1"
			ip -o -6 addr show dev veth1 | sed -E \
				-e "s/^[0-9]+: //" \
				-e "s/valid_lft [0-9]+sec/valid_lft Lsec/" \
				-e "s/preferred_lft [0-9]+sec/preferred_lft Lsec/"
			echo "--- ip -6 route"
			ip -6 route show table all dev veth1 | sed -E \
				-e "s/expires [0-9]+sec//" -e "s/ +$//"
		} > "$out/$tag-kernel.txt" 2>&1 || true

		cp "$root/tmp/out/netifd.log" "$out/$tag-daemon.log" 2>/dev/null || true
		cp "$root/tmp/out/server.log" "$out/$tag-server.log" 2>/dev/null || true
		cp "$root/tmp/out/hotplug.txt" "$out/$tag-hotplug.txt" 2>/dev/null || \
			: > "$out/$tag-hotplug.txt"

		for f in server netifd ubusd cand; do
			p=$(cat "$root/tmp/out/$f.pid" 2>/dev/null || true)
			[ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
		done
		' sh "$root" "$tag" "$out" > "$out/$tag-outer.log" 2>&1 || true

	sudo -n chown "$(id -u):$(id -g)" "$out"/$tag-* 2>/dev/null || true
	sudo -n rm -rf "$tmp"
}

run_one c
run_one rs

echo "=== lease acquired after"
for t in c rs; do printf '%-3s %s\n' "$t" "$(cat "$out/$t-wait.txt" 2>/dev/null)"; done
# A case the reference never reached is untested, not agreement.
case "$(cat "$out/c-wait.txt" 2>/dev/null)" in
	"waited: 30s"|"") echo "RESULT: the reference never got an address -- untested"; exit 1 ;;
esac

# odhcpd picks the IA_NA address from a hash of the client's DUID, which is
# generated per run, so the two sides get different addresses. Each side's own
# leased address is replaced with a placeholder -- the same token everywhere it
# appears, derived from that side's output, so a real difference still shows.
for t in c rs; do
	lease=$(grep -oE 'fd00:5678::[0-9a-f]+/128' "$out/$t-kernel.txt" 2>/dev/null \
		| head -1 | cut -d/ -f1)
	if [ -z "$lease" ]; then
		echo "RESULT: $t never got an IA_NA address -- untested"
		exit 1
	fi
	echo "$t leased $lease"
	for f in "$out/$t-kernel.txt" "$out/$t-ubus.txt"; do
		sed -i "s/$lease/fd00:5678::LEASE/g" "$f"
	done
done

rc=0
echo "=== kernel state"
if diff -u "$out/c-kernel.txt" "$out/rs-kernel.txt" > "$out/kernel.diff"; then
	echo "RESULT(kernel): identical"
else
	head -30 "$out/kernel.diff"; rc=1
fi

echo "=== ubus"
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
        return collections.OrderedDict(
            (k, "N" if k in ("uptime", "preferred", "valid") else mask(v))
            for k, v in o.items())
    if isinstance(o, list):
        return [mask(x) for x in o]
    return o

c, r = sections(sys.argv[1]), sections(sys.argv[2])
bad = 0
for name in ("wan6 status", "interface dump"):
    if name not in c or not c[name].strip():
        print(f"{name}: NOTHING CAPTURED from the reference -- untested")
        bad += 1
        continue
    try:
        a = mask(json.loads(c[name], object_pairs_hook=collections.OrderedDict))
        b = mask(json.loads(r.get(name, ""), object_pairs_hook=collections.OrderedDict))
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
