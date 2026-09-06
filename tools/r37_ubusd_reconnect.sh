#!/bin/sh
# P1.2 reconnect item: run the decision-0015 (r22) scenario against a given
# ubusd binary, so the C daemon's known client defects can be told apart from
# any the candidate adds. Same clients, same timings as r22 so the results are
# directly comparable to what 0015 recorded.
#
# Usage: r37_ubusd_reconnect.sh <rootfs-files> <logd-rs-musl> <ubusd-binary> [tag] [outdir]
# The ubusd binary is copied to /sbin/ubusd-under-test inside the sandbox.
set -eu
rootfs=$1; logd=$2; daemon=$3; tag=${4:-run}; out=${5:-/tmp/r37-out}
mkdir -p "$out"
tmp=$(mktemp -d /tmp/owrt-r37-XXXXXX); root=$tmp/root
sudo -n cp -a "$rootfs" "$root"
# ubusd ignores acl.d files it does not see as root-owned
sudo -n chown -R root:root "$root/usr/share/acl.d" "$root/etc/config"
sudo -n cp "$logd" "$root/tmp/logd-rs"; sudo -n chmod 755 "$root/tmp/logd-rs"
sudo -n cp "$daemon" "$root/sbin/ubusd-under-test"; sudo -n chmod 755 "$root/sbin/ubusd-under-test"

cat > "$tmp/inner.sh" <<'INNER'
set -u
D=/sbin/ubusd-under-test
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out /var/lib/misc /tmp/dhcp
chmod 1777 /var/run/ubus
ip link set lo up 2>/dev/null || true
objs() { ubus list 2>/dev/null | sort | tr '\n' ' '; }
have() { ubus list "$1" >/dev/null 2>&1; }
printf 'config dnsmasq\n\toption domain lan\n\toption leasefile /tmp/dhcp.leases\n\toption ubus 1\n' > /etc/config/dhcp.r37

$D >/tmp/out/ubusd1.log 2>&1 & u=$!
sleep 1
/sbin/netifd >/tmp/out/netifd.log 2>&1 & n=$!
/usr/sbin/dnsmasq -k --enable-ubus --no-resolv --no-hosts --port=0 --leasefile-ro --user=root --pid-file=/tmp/dnsmasq.pid >/tmp/out/dnsmasq.log 2>&1 & d=$!
sleep 1
/usr/sbin/odhcpd >/tmp/out/odhcpd.log 2>&1 & o=$!
/tmp/logd-rs -S 16 --kmsg none --no-drop-privileges >/tmp/out/logd.log 2>&1 & l=$!
i=0; while [ $i -lt 8 ]; do have network && have dnsmasq && have dhcp && have log && break; i=$((i+1)); sleep 1; done
echo "before: $(objs)"
echo "alive_before: netifd=$(kill -0 $n 2>/dev/null && echo up || echo down) dnsmasq=$(kill -0 $d 2>/dev/null && echo up || echo down) odhcpd=$(kill -0 $o 2>/dev/null && echo up || echo down) logd=$(kill -0 $l 2>/dev/null && echo up || echo down)"

kill $u; sleep 2
echo "bus_down: $(ubus list >/dev/null 2>&1 && echo still-up || echo gone)"
echo "alive_during: netifd=$(kill -0 $n 2>/dev/null && echo up || echo down) dnsmasq=$(kill -0 $d 2>/dev/null && echo up || echo down) odhcpd=$(kill -0 $o 2>/dev/null && echo up || echo down) logd=$(kill -0 $l 2>/dev/null && echo up || echo down)"

$D >/tmp/out/ubusd2.log 2>&1 & u=$!
i=0
while [ $i -lt 60 ]; do
	i=$((i+1))
	have network && have network.wireless && have dnsmasq && have dhcp && have log && break
	[ $i -eq 5 ] && echo "at_5s: $(objs)"
	[ $i -eq 20 ] && echo "at_20s: $(objs)"
	sleep 1
done
echo "after_60s_or_complete: $(objs)"
echo "alive_after: netifd=$(kill -0 $n 2>/dev/null && echo up || echo down) dnsmasq=$(kill -0 $d 2>/dev/null && echo up || echo down) odhcpd=$(kill -0 $o 2>/dev/null && echo up || echo down) logd=$(kill -0 $l 2>/dev/null && echo up || echo down)"
echo "netifd_call_rc: $(ubus -S call network.interface dump >/dev/null 2>&1; echo $?)"
echo "logd_call_rc: $(ubus -S call log read '{"lines":1,"stream":false}' >/dev/null 2>&1; echo $?)"
echo "dnsmasq_visible: $(have dnsmasq && echo yes || echo no)"
echo "dhcp_visible: $(have dhcp && echo yes || echo no)"
echo "wireless_visible: $(have network.wireless && echo yes || echo no)"
kill $n $d $o $l $u 2>/dev/null; sleep 1
INNER

sudo -n cp "$tmp/inner.sh" "$root/tmp/inner.sh"
sudo -n setsid -w unshare --mount --net --fork /bin/sh -c '
	root=$1; mount --make-rprivate /
	mount -t proc proc "$root/proc"; mount -t sysfs sysfs "$root/sys"
	mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
	mknod -m 666 "$root/dev/null" c 1 3
	mknod -m 666 "$root/dev/urandom" c 1 9
	mknod -m 666 "$root/dev/zero" c 1 5
	mkdir -p "$root/dev/net"; mknod -m 666 "$root/dev/net/tun" c 10 200
	trap "umount $root/dev 2>/dev/null; umount $root/sys 2>/dev/null; umount $root/proc 2>/dev/null" EXIT
	chroot "$root" /bin/sh /tmp/inner.sh' sh "$root" > "$out/$tag.txt" 2>&1 || true
sudo -n rm -rf "$tmp"
echo "== $out/$tag.txt"
cat "$out/$tag.txt"
