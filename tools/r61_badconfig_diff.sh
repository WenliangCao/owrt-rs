#!/bin/bash
# R61: a configuration the build only partly understands is applied as far as
# it goes, exactly as the C does -- it is never refused whole (R81 F14).
#
# Start from a LAN that is up and carrying an address, then reload with each
# of: an invalid address, a `config route` section (which this build now
# installs), and an unsupported device type (`bonding`). After each one the
# kernel state and the interface status are captured on BOTH daemons and
# compared with each other: netifd applies what it understood and logs the
# rest. An invalid address is how a working LAN ends up with no address --
# on both sides. Refusing the reload whole (the pre-F14 behaviour) reappears
# as a difference here, because the C never refuses.
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
mask() { sed -E -e 's/"uptime":[0-9]+/"uptime":N/'; }

# the reference must have come up with its address, and must have ACCEPTED
# every reload -- if the C refused one, the fixture is wrong, not the build
base=$(grep -A1 '^--- baseline addr' "$out/c-state.txt" | tail -1)
if ! echo "$base" | grep -q '10.0.0.1'; then
	echo "RESULT: the reference never came up with 10.0.0.1 -- untested"; exit 1
fi
if grep -q 'reload REFUSED' "$out/c-state.txt"; then
	echo "RESULT: the reference REFUSED a reload -- fixture broken"; exit 1
fi
# and the `config route` section must actually have installed its route on the
# C, or `bad-section` proves nothing
if ! grep -q '10.9.9.0/24 via 10.0.0.2' "$out/c-state.txt"; then
	echo "RESULT: the reference did not install the config route -- untested"; exit 1
fi

echo "=== C vs netifd-rs (must be identical: apply what is understood, log the rest)"
if diff -u <(mask < "$out/c-state.txt") <(mask < "$out/rs-state.txt") > "$out/state.diff"; then
	echo "R61: identical -- a partial config is applied, never refused"
else
	sed 's/^/  /' "$out/c-state.txt"; echo
	cat "$out/state.diff"; rc=1
	echo "R61: FAILURES"
fi
exit $rc
