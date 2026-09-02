#!/bin/sh
# Stage 9 precondition (plan 11.4): do the libubus clients present on the
# device re-register their objects after ubusd is killed and restarted?
# Runs netifd, dnsmasq (--ubus), odhcpd and logd-rs inside a copy of the exact
# rootfs in a private network + mount namespace (lo only). procd and hostapd
# cannot run here; they are covered by source reading (decision 0015).
# Usage: r22_ubus_clients_reconnect.sh <rootfs-files> <logd-rs-musl-binary>
set -eu
rootfs=$1; logd=$2
tmp=$(mktemp -d /tmp/owrt-r22-XXXXXX); root=$tmp/root
sudo -n cp -a "$rootfs" "$root"
sudo -n chown -R root:root "$root/usr/share/acl.d" "$root/etc/config"
sudo -n cp "$logd" "$root/tmp/logd-rs"; sudo -n chmod 755 "$root/tmp/logd-rs"
cat > "$tmp/inner.sh" <<'INNER'
set -u
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out /var/lib/misc /tmp/dhcp; chmod 1777 /var/run/ubus
ip link set lo up 2>/dev/null || true
objs() { ubus list 2>/dev/null | tr '\n' ' '; }
have() { ubus list "$1" >/dev/null 2>&1; }
printf 'config dnsmasq\n\toption domain lan\n\toption leasefile /tmp/dhcp.leases\n\toption ubus 1\n' > /etc/config/dhcp.r22
/sbin/ubusd >/tmp/out/ubusd1.log 2>&1 & u=$!
sleep 1
/sbin/netifd >/tmp/out/netifd.log 2>&1 & n=$!
/usr/sbin/dnsmasq -k --ubus --no-resolv --no-hosts --port=0 --leasefile-ro --user=root --pid-file=/tmp/dnsmasq.pid >/tmp/out/dnsmasq.log 2>&1 & d=$!
sleep 1; echo "dnsmasq_start_log: $(tr '\n' '|' < /tmp/out/dnsmasq.log | cut -c1-300)"
/usr/sbin/odhcpd >/tmp/out/odhcpd.log 2>&1 & o=$!
/tmp/logd-rs -S 16 --kmsg none --no-drop-privileges >/tmp/out/logd.log 2>&1 & l=$!
for i in 1 2 3 4 5 6 7 8; do have network && have dnsmasq && have dhcp && have log && break; sleep 1; done
echo "before: $(objs)"
echo "pids_before: netifd=$(kill -0 $n 2>/dev/null && echo up || echo down) dnsmasq=$(kill -0 $d 2>/dev/null && echo up || echo down) odhcpd=$(kill -0 $o 2>/dev/null && echo up || echo down) logd=$(kill -0 $l 2>/dev/null && echo up || echo down)"
kill $u; sleep 2
echo "ubusd_down: $(ubus list >/dev/null 2>&1 && echo still-up || echo gone)"
echo "pids_during: netifd=$(kill -0 $n 2>/dev/null && echo up || echo down) dnsmasq=$(kill -0 $d 2>/dev/null && echo up || echo down) odhcpd=$(kill -0 $o 2>/dev/null && echo up || echo down) logd=$(kill -0 $l 2>/dev/null && echo up || echo down)"
/sbin/ubusd >/tmp/out/ubusd2.log 2>&1 & u=$!
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do have network && have network.wireless && have dnsmasq && have log && break; sleep 1; done
echo "reregistered_after_s: $i"
sleep 5
echo "after: $(objs)"
echo "pids_after: netifd=$(kill -0 $n 2>/dev/null && echo up || echo down) dnsmasq=$(kill -0 $d 2>/dev/null && echo up || echo down) odhcpd=$(kill -0 $o 2>/dev/null && echo up || echo down) logd=$(kill -0 $l 2>/dev/null && echo up || echo down)"
echo "netifd_call: $(ubus -S call network.interface dump 2>&1 | cut -c1-60) rc=$?"
echo "dnsmasq_call: $(ubus -S -v list dnsmasq 2>&1 | head -2 | tr '\n' ' ')"
echo "logd_call: $(ubus -S call log read '{"lines":1,"stream":false}' 2>&1 | cut -c1-60) rc=$?"
echo "odhcpd_log: $(tail -n 3 /tmp/out/odhcpd.log | tr '\n' '|')"
echo "netifd_log: $(tail -n 3 /tmp/out/netifd.log | tr '\n' '|')"
kill $n $d $o $l $u 2>/dev/null; sleep 1
INNER
sudo -n cp "$tmp/inner.sh" "$root/tmp/inner.sh"
sudo -n setsid -w unshare --mount --net --fork /bin/sh -c '
root=$1; mount --make-rprivate /; mount -t proc proc "$root/proc"; mount -t sysfs sysfs "$root/sys"; mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3; mknod -m 666 "$root/dev/urandom" c 1 9; mknod -m 666 "$root/dev/zero" c 1 5; mkdir -p "$root/dev/net"; mknod -m 666 "$root/dev/net/tun" c 10 200
trap "umount $root/dev 2>/dev/null; umount $root/sys 2>/dev/null; umount $root/proc 2>/dev/null" EXIT
chroot "$root" /bin/sh /tmp/inner.sh' sh "$root"
sudo -n rm -rf "$tmp"
