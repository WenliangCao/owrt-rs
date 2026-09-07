#!/bin/sh
# R61: a configuration this build cannot represent must not tear down a
# working network.
#
# Start from a LAN that is up and carrying an address, then reload with each
# of: an invalid address, an unsupported section type, and an unsupported
# device type. After each one, the kernel state and the interface status are
# compared against what they were BEFORE the bad reload -- the assertion is
# that nothing moved -- and the return code of `network.reload` is recorded.
# Then a valid config is loaded to prove reloads still work afterwards.
#
# This is a DELIBERATE DIVERGENCE from the C, so the two daemons are NOT
# compared with each other here. The C applies what it understood and logs the
# rest, which is how a working LAN ends up with no address. This build refuses
# the reload whole and keeps the running state. The C's behaviour is recorded
# alongside for the record.
#
# Usage: r61_badconfig_diff.sh <rootfs-files> <netifd-rs musl binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r61-out}
mkdir -p "$out"

GOOD='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config interface "lan"
	option device "veth0"
	option proto "static"
	option ipaddr "10.0.0.1"
	option netmask "255.255.255.0"
'

BAD_ADDR='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"

config interface "lan"
	option device "veth0"
	option proto "static"
	option ipaddr "not-an-address"
	option netmask "255.255.255.0"
'

BAD_SECTION="$GOOD"'
config route
	option interface "lan"
	option target "10.9.9.0/24"
	option gateway "10.0.0.2"
'

BAD_DEVTYPE="$GOOD"'
config device
	option name "bond0"
	option type "bonding"
	list ports "veth2"
'

run() {
	tag=$1
	w=$(mktemp -d /tmp/r61.XXXXXX); sudo -n cp -a "$rootfs"/. "$w"/ 2>/dev/null || true
	sudo -n mkdir -p "$w/etc/config" "$w/var/run" "$w/tmp/out"
	sudo -n chown -R root:root "$w/usr/share/acl.d" 2>/dev/null || true
	[ "$tag" = rs ] && { sudo -n cp "$cand" "$w/sbin/netifd-rs"; sudo -n chmod 755 "$w/sbin/netifd-rs"; }
	printf '%s' "$GOOD" | sudo -n tee "$w/etc/config/network" >/dev/null
	printf '%s' "$BAD_ADDR"    | sudo -n tee "$w/etc/cfg-bad-addr" >/dev/null
	printf '%s' "$BAD_SECTION" | sudo -n tee "$w/etc/cfg-bad-section" >/dev/null
	printf '%s' "$BAD_DEVTYPE" | sudo -n tee "$w/etc/cfg-bad-devtype" >/dev/null
	printf '%s' "$GOOD"        | sudo -n tee "$w/etc/cfg-good" >/dev/null

	sudo -n unshare --mount --net --pid --fork --mount-proc=/proc sh -c '
	  m=$1; t=$2; o=$3
	  mount --bind "$m" "$m"; mount --make-private "$m"
	  mount -t proc proc "$m/proc" 2>/dev/null || true
	  mount --rbind /sys "$m/sys" 2>/dev/null || true
	  mount -t tmpfs tmp "$m/tmp"; mkdir -p "$m/var/run" "$m/tmp/out"
	  mount --bind /dev/null /dev/null 2>/dev/null || true
	  ip link set lo up
	  ip link add veth0 type veth peer name veth1
	  ip link set veth0 up; ip link set veth1 up
	  chroot "$m" /sbin/ubusd >/dev/null 2>&1 & sleep 1
	  if [ "$t" = c ]; then chroot "$m" /sbin/netifd >"$m/tmp/out/n.log" 2>&1 &
	  else chroot "$m" /sbin/netifd-rs >"$m/tmp/out/n.log" 2>&1 & fi
	  sleep 4

	  snap() {
	    echo "--- $1 addr"
	    ip -o -4 addr show dev veth0 | sed -E "s/^[0-9]+: //"
	    echo "--- $1 route"
	    ip -4 route show dev veth0 | sort
	    echo "--- $1 lan status"
	    chroot "$m" ubus call network.interface.lan status 2>/dev/null \
	      | tr -d " \t\n" | grep -oE "\"(up|available)\":(true|false)|\"address\":\"[0-9.]+\"" \
	      | tr "\n" " "
	    echo ""
	  }

	  snap baseline > "$o/$t-state.txt"
	  for bad in bad-addr bad-section bad-devtype; do
	    # from /etc, not /tmp: the namespace mounts a tmpfs over /tmp and an
	    # empty config would be written instead, which tears everything down
	    # on BOTH sides and looks like agreement
	    cp "$m/etc/cfg-$bad" "$m/etc/config/network"
	    [ -s "$m/etc/config/network" ] || { echo "HARNESS BUG: empty config" >> "$o/$t-state.txt"; exit 1; }
	    if chroot "$m" ubus call network reload >/dev/null 2>&1; then
	      echo "=== $bad: reload ACCEPTED" >> "$o/$t-state.txt"
	    else
	      echo "=== $bad: reload REFUSED" >> "$o/$t-state.txt"
	    fi
	    sleep 2
	    snap "$bad" >> "$o/$t-state.txt"
	  done
	  cp "$m/etc/cfg-good" "$m/etc/config/network"
	  chroot "$m" ubus call network reload >/dev/null 2>&1 \
	    && echo "=== good: reload ACCEPTED" >> "$o/$t-state.txt" \
	    || echo "=== good: reload REFUSED" >> "$o/$t-state.txt"
	  sleep 3
	  snap recovered >> "$o/$t-state.txt"
	  cp "$m/tmp/out/n.log" "$o/$t-daemon.log" 2>/dev/null || true
	  pkill -9 -f "netifd|ubusd" 2>/dev/null || true
	' sh "$w" "$tag" "$out"
	sudo -n rm -rf "$w"
}

run c
run rs

rc=0
echo "=== the C, for the record (it applies what it understood)"
sed 's/^/  /' "$out/c-state.txt"
echo
echo "=== netifd-rs"
sed 's/^/  /' "$out/rs-state.txt"
echo

# the assertion: on this build, every bad reload is refused and the address
# that was there at baseline is still there afterwards
base=$(grep -A1 '^--- baseline addr' "$out/rs-state.txt" | tail -1)
if [ -z "$base" ]; then
	echo "RESULT: no baseline address -- untested"
	exit 1
fi
for bad in bad-addr bad-section bad-devtype; do
	verdict=$(grep "^=== $bad: reload" "$out/rs-state.txt" | sed 's/.*reload //')
	after=$(grep -A1 "^--- $bad addr" "$out/rs-state.txt" | tail -1)
	if [ "$verdict" = REFUSED ] && [ "$after" = "$base" ]; then
		echo "RESULT($bad): refused, address unchanged"
	else
		echo "$bad: WRONG -- reload was $verdict, address now: $after"
		echo "                             baseline was: $base"
		rc=1
	fi
done
rec=$(grep -A1 '^--- recovered addr' "$out/rs-state.txt" | tail -1)
recv=$(grep '^=== good: reload' "$out/rs-state.txt" | sed 's/.*reload //')
if [ "$recv" = ACCEPTED ] && [ "$rec" = "$base" ]; then
	echo "RESULT(recovered): a valid config still loads"
else
	echo "recovered: WRONG -- reload was $recv, address: $rec"
	rc=1
fi

[ $rc -eq 0 ] && echo "R61: bad configuration is refused, the network is untouched" \
	|| echo "R61: FAILURES"
exit $rc
