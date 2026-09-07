#!/bin/sh
# Does netifd start a protocol handler before the device's IPv6 link-local
# address is usable? Both daemons, same namespace shape, one number each.
#
# This settles whether r56's "Address not available" was an asymmetry between
# the C and netifd-rs or a race both can lose. Measured: both spawn odhcp6c
# about 1.7s BEFORE the link-local finishes DAD, so either side can lose it --
# there is no asymmetry, and turning DAD off in r56 removes a sandbox window
# rather than hiding a behavioural difference.
#
# On real hardware this does not arise: a physical interface finished DAD long
# before netifd started.
#
# Usage: dad_timing_probe.sh <netifd-rs musl binary> <c|rs>
set -eu
rootfs=/home/ubuntu/h1-4-extract.JK5fNS/rootfs
cand=$1; tag=$2
w=$(mktemp -d /tmp/dadp.XXXXXX); cp -a "$rootfs"/. "$w"/
mkdir -p "$w/etc/config" "$w/var/run" "$w/tmp/out"
chown -R root:root "$w/usr/share/acl.d" 2>/dev/null || true
[ "$tag" = rs ] && { cp "$cand" "$w/sbin/netifd-rs"; chmod 755 "$w/sbin/netifd-rs"; }
cat > "$w/etc/config/network" <<'X'
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1/8'

config interface 'wan6'
	option device 'veth1'
	option proto 'dhcpv6'
X
unshare --mount --net --pid --fork --mount-proc=/proc sh -c '
  m=$1; tag=$2
  mount --bind "$m" "$m"; mount --make-private "$m"
  mount -t proc proc "$m/proc" 2>/dev/null||true
  mount --rbind /sys "$m/sys" 2>/dev/null||true
  mount -t tmpfs t "$m/tmp"; mkdir -p "$m/var/run" "$m/tmp/out"
  ip link set lo up
  ip link add veth0 address 02:00:00:00:00:00 type veth peer name veth1 address 02:00:00:00:00:01
  ip link set veth0 up; ip link set veth1 up
  chroot "$m" /sbin/ubusd >/dev/null 2>&1 & sleep 1
  t0=$(date +%s.%N)
  if [ "$tag" = c ]; then chroot "$m" /sbin/netifd >"$m/tmp/out/n.log" 2>&1 &
  else chroot "$m" /sbin/netifd-rs >"$m/tmp/out/n.log" 2>&1 & fi
  lla_ready=""; helper=""
  i=0
  while [ $i -lt 120 ]; do
    now=$(date +%s.%N)
    if [ -z "$lla_ready" ]; then
      if ip -o -6 addr show dev veth1 scope link 2>/dev/null | grep -q "fe80" \
         && ! ip -o -6 addr show dev veth1 scope link 2>/dev/null | grep -q tentative; then
        lla_ready=$(echo "$now $t0" | awk "{printf \"%.2f\", \$1-\$2}")
      fi
    fi
    if [ -z "$helper" ]; then
      if pgrep -f odhcp6c >/dev/null 2>&1; then
        helper=$(echo "$now $t0" | awk "{printf \"%.2f\", \$1-\$2}")
      fi
    fi
    [ -n "$lla_ready" ] && [ -n "$helper" ] && break
    i=$((i+1)); sleep 0.1
  done
  echo "$tag: lla_usable_at=${lla_ready:-never} helper_spawned_at=${helper:-never}"
  grep -c "Address not available" "$m/tmp/out/n.log" 2>/dev/null | sed "s/^/$tag: addr-not-available lines: /"
  pkill -9 -f "netifd|ubusd|odhcp6c" 2>/dev/null || true
' sh "$w" "$tag"
rm -rf "$w"
