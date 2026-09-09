#!/bin/sh
# R62: dynamic IPv6 prefix delegation, C against netifd-rs, no upstream needed.
#
# The sandbox has no ISP to delegate from, so the prefix is injected through
# the real entry point instead: a `notify_proto` carrying `ip6prefix`, exactly
# the array of strings `netifd-proto.sh` pushes from `proto_add_ipv6_prefix`.
# Nothing reaches an internal list directly.
#
# The sequence is the life of a delegation: first grant, renewal with the same
# prefix, replacement by a different one, and withdrawal when the uplink goes
# down. After each step both sides are read for the LAN's addresses and
# routes, the uplink's `ipv6-prefix`, and the assignment.
#
# wan6 is `auto 0` on purpose: with it starting normally the real odhcp6c runs,
# finds no server, and its exit takes the interface down -- which withdraws the
# assignment and leaves the C showing a DEPRECATED address from the first grant
# onward. That is the protocol process interfering, not the delegation path.
# Held down, the injected notify is the only thing acting on it.
#
# Usage: r62_pd_diff.sh <rootfs-files> <netifd-rs musl binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r62-out}
mkdir -p "$out"

CFG='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config interface "lan"
	option device "veth2"
	option proto "static"
	option ipaddr "192.168.9.1"
	option netmask "255.255.255.0"
	option ip6assign "64"

config interface "wan6"
	option device "veth0"
	option proto "dhcpv6"
	option auto "0"
'

run() {
	tag=$1
	w=$(mktemp -d /tmp/r62.XXXXXX); sudo -n cp -a "$rootfs"/. "$w"/ 2>/dev/null || true
	sudo -n mkdir -p "$w/etc/config" "$w/var/run"
	sudo -n chown -R root:root "$w/usr/share/acl.d" 2>/dev/null || true
	[ "$tag" = rs ] && { sudo -n cp "$cand" "$w/sbin/netifd-rs"; sudo -n chmod 755 "$w/sbin/netifd-rs"; }
	printf '%s' "$CFG" | sudo -n tee "$w/etc/config/network" >/dev/null

	sudo -n unshare --mount --net --pid --fork --mount-proc=/proc sh -c '
	  m=$1; t=$2; o=$3
	  mount --bind "$m" "$m"; mount --make-private "$m"
	  mount -t proc proc "$m/proc" 2>/dev/null || true
	  mount --rbind /sys "$m/sys" 2>/dev/null || true
	  mount -t tmpfs tmp "$m/tmp"; mkdir -p "$m/var/run"
	  mount -t tmpfs -o mode=0755 d "$m/dev" 2>/dev/null || true
	  mknod -m 666 "$m/dev/null" c 1 3 2>/dev/null || true
	  ip link set lo up
	  ip link add veth0 type veth peer name veth1; ip link set veth0 up; ip link set veth1 up
	  ip link add veth2 type veth peer name veth3; ip link set veth2 up; ip link set veth3 up
	  sysctl -qw net.ipv6.conf.veth0.accept_dad=0 2>/dev/null || true
	  sysctl -qw net.ipv6.conf.veth2.accept_dad=0 2>/dev/null || true
	  chroot "$m" /sbin/ubusd >/dev/null 2>&1 & sleep 1
	  # -S -l 7 on the C so its own view of the prefix path is on record;
	  # netifd-rs logs to stderr already
	  ip monitor address route > /tmp/mon.txt 2>&1 &
	  if [ "$t" = c ]; then chroot "$m" /sbin/netifd -S -l 7 >"$m/tmp/n.log" 2>&1 &
	  else chroot "$m" /sbin/netifd-rs >"$m/tmp/n.log" 2>&1 & fi
	  sleep 4

	  # the return code and any error text are evidence, not noise: swallowing
	  # them hid whether a first notify was refused or accepted
	  # `|| true` resets $?, so the rc printed after it was ALWAYS 0 -- the
	  # column said nothing and I read the refusal out of the text instead.
	  # Capture the status in the failure branch itself.
	  notify() {
	    rc=0
	    r=$(chroot "$m" ubus call network.interface.wan6 notify_proto \
	      "{\"action\":0,\"link-up\":true,\"ifname\":\"veth0\",\"ip6addr\":[{\"ipaddr\":\"2001:db8:ffff::2\",\"mask\":128}],\"ip6prefix\":[$1]}" 2>&1) || rc=$?
	    echo "--- notify rc=$rc out=[$r]"
	  }
	  snap() {
	    echo "--- $1 lan v6 addr"
	    # lifetimes are NOT normalised away here: `preferred 0` versus the
	    # granted value is exactly what separates a withdrawn assignment from a
	    # live one, and bucketing them hid the advisor'"'"'s counter-example.
	    ip -o -6 addr show dev veth2 scope global \
	      | sed -E -e "s/^[0-9]+: //" \
	               -e "s/valid_lft ([0-9]+)sec/valid_lft \\1s/" \
	               -e "s/preferred_lft ([0-9]+)sec/preferred_lft \\1s/" \
	      | awk "{ for (i=1;i<=NF;i++) if (\$i ~ /_lft/) { getline_ok=1 }; print }" \
	      | sed -E "s/(valid_lft )([0-9]+)s/\\1BUCKET/; s/(preferred_lft )0s/\\1ZERO/; s/(preferred_lft )[0-9]+s/\\1NONZERO/" \
	      | sort
	    echo "--- $1 lan v6 route"
	    ip -6 route show dev veth2 | grep -v "^fe80" | sed -E "s/expires [0-9]+sec//" | sort
	    # netifd installs an unreachable route for the whole delegated prefix
	    # at the lowest priority, on no device -- looking only at veth2 missed
	    # it, and withdrawing a prefix has to remove it
	    echo "--- $1 prefix null route"
	    ip -6 route show table all type unreachable 2>/dev/null \
	      | sed -E "s/expires [0-9]+sec//" | sort
	    echo "--- $1 wan6 prefix"
	    chroot "$m" ubus call network.interface.wan6 status 2>/dev/null \
	      | tr -d " \t\n" \
	      | grep -oE "\"ipv6-prefix\":\[[^]]*\]*|\"address\":\"2001[^\"]*\"" | head -3
	    echo ""
	  }

	  snap before-any
	  notify "\"2001:db8:1:2::/60,3600,7200\"" ; sleep 3; snap first-grant
	  notify "\"2001:db8:1:2::/60,3600,7200\"" ; sleep 3; snap renewal
	  notify "\"2001:db8:5:0::/60,1800,3600\"" ; sleep 3; snap replaced
	  # The advisor'"'"'s counter-example: the parent changes LENGTH only, so it is
	  # a different vlist node handing out the SAME local address. The old
	  # parent'"'"'s withdrawal lands on that address -- preferred 0 and the
	  # kernel'"'"'s own route -- while the ubus assignment list still shows the
	  # new lifetimes. Only the kernel state shows it.
	  notify "\"2001:db8:100::/56,300,600\"" ; sleep 3; snap parent56
	  notify "\"2001:db8:100::/60,1200,2400\"" ; sleep 3; snap parent60
	  chroot "$m" ubus call network.interface.wan6 down >/dev/null 2>&1 || true
	  sleep 3; snap after-down
	  cp "$m/tmp/n.log" "$o/$t-daemon.log" 2>/dev/null || true
	  cp /tmp/mon.txt "$o/$t-monitor.txt" 2>/dev/null || true
	' sh "$w" "$tag" "$out" > "$out/$tag.txt" 2>&1
	sudo -n rm -rf "$w"
}

run c
run rs

echo "=== C"
sed 's/^/  /' "$out/c.txt"
echo "=== netifd-rs"
sed 's/^/  /' "$out/rs.txt"
echo
if diff -u "$out/c.txt" "$out/rs.txt" > "$out/pd.diff"; then
	echo "R62: identical"
	exit 0
fi
echo "R62: DIFFERENCES"
cat "$out/pd.diff"
exit 1
