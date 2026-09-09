#!/bin/bash
# P6 regression: a successful wireless handler must carry LAN traffic, not
# merely report radio up. A veth represents the AP and a separate network
# namespace represents a station. No physical device or wireless secrets.
# Usage: r79_wireless_bridge_diff.sh <exact-rootfs> <candidate> [output]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r79-out}
[ -x "$rootfs/sbin/netifd" ] && [ -x "$cand" ] || exit 2
mkdir -p "$out"
out=$(cd "$out" && pwd)
here=$(cd "$(dirname "$0")" && pwd)

run_one() {
	local tag=$1 tmp root rc=0
	tmp=$(mktemp -d /tmp/owrt-r79-XXXXXX); root=$tmp/root
	sudo -n cp -a "$rootfs" "$root"
	sudo -n mkdir -p "$root/tmp/out" "$root/etc/config"
	sudo -n chown -R root:root "$root/usr/share/acl.d"
	sudo -n cp "$cand" "$root/sbin/netifd-rs"
	sudo -n tee "$root/etc/config/network" >/dev/null <<'EOF'
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1/8'
config device
	option name 'br-test'
	option type 'bridge'
	option macaddr '02:00:00:00:79:01'
config interface 'lan'
	option device 'br-test'
	option proto 'static'
	option ipaddr '192.168.79.1/24'
EOF
	sudo -n tee "$root/etc/config/wireless" >/dev/null <<'EOF'
config wifi-device 'radio0'
	option type 'mac80211'
config wifi-iface 'ap'
	option device 'radio0'
	option network 'lan'
	option mode 'ap'
	option ssid 'r79-test'
	option encryption 'none'
EOF
	sudo -n tee "$root/lib/netifd/wireless/mac80211.sh" >/dev/null <<'EOF'
#!/bin/sh
if [ "${1:-}" = dump ] || [ "${2:-}" = dump ]; then
	echo '{"name":"mac80211","device":[],"iface":[["ssid",3],["encryption",3]],"vlan":[],"station":[]}'
	exit 0
fi
case "$2" in
setup)
	echo "$4" >> /tmp/out/setup.jsonl
	ubus -S -t 3 call network.interface.lan status >> /tmp/out/before-up.jsonl
	# wlan0 is supplied by the fixture; hostapd normally creates it.
	ubus call network.wireless notify '{"device":"radio0","command":1,"interface":"01","data":{"ifname":"wlan0"}}' || exit 1
	ubus call network.wireless notify '{"device":"radio0","command":0}' || exit 1
	;;
teardown) : ;;
esac
EOF
	sudo -n chmod 755 "$root/lib/netifd/wireless/mac80211.sh"
	sudo -n timeout -s KILL 100 unshare --mount --net --pid --fork --mount-proc /bin/bash -s -- "$root" "$tag" <<'EOF' > "$out/$tag-driver.log" 2>&1 || rc=$?
set -eu
root=$1; tag=$2
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount -t sysfs sysfs "$root/sys"
mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/urandom" c 1 9
mknod -m 666 "$root/dev/zero" c 1 5
ip link set lo up
ip link add wlan0 address 02:00:00:00:79:10 type veth peer name station0
ip link set wlan0 up
unshare --net /bin/sh -c 'echo $$ > "$1"; exec sleep 100' sh "$root/tmp/out/client.pid" &
for i in $(seq 1 5); do [ -s "$root/tmp/out/client.pid" ] && break; sleep 1; done
client=$(cat "$root/tmp/out/client.pid")
ip link set station0 netns "$client"
nsenter -t "$client" -n ip link set lo up
nsenter -t "$client" -n ip link set station0 address 02:00:00:00:79:20
nsenter -t "$client" -n ip addr add 192.168.79.2/24 dev station0
nsenter -t "$client" -n ip link set station0 up
mkdir -p "$root/var/run/ubus" "$root/var/lock" "$root/var/state"
chroot "$root" /sbin/ubusd > "$root/tmp/out/bus.log" 2>&1 &
sleep 1
daemon=/sbin/netifd; [ "$tag" != rs ] || daemon=/sbin/netifd-rs
chroot "$root" "$daemon" > "$root/tmp/out/daemon.log" 2>&1 &
pid=$!
snapshot() {
	local phase=$1
	chroot "$root" ubus -t 3 call network.interface.lan status > "$root/tmp/out/$phase-lan.json"
	chroot "$root" ubus -t 3 call network.wireless status > "$root/tmp/out/$phase-wireless.json"
	chroot "$root" ubus -t 3 call network.device status > "$root/tmp/out/$phase-devices.json"
	wc -l < "$root/tmp/out/setup.jsonl" > "$root/tmp/out/$phase-setups.txt"
	readlink "$root/sys/class/net/wlan0/master" > "$root/tmp/out/$phase-master.txt" || :
	ip -o -4 addr show br-test > "$root/tmp/out/$phase-address.txt" 2>/dev/null || :
	if nsenter -t "$client" -n ping -c 1 -W 1 192.168.79.1 > /dev/null 2>&1; then
		echo reachable > "$root/tmp/out/$phase-ping.txt"
	else
		echo unreachable > "$root/tmp/out/$phase-ping.txt"
	fi
	for attr in multicast_to_unicast hairpin_mode proxyarp_wifi isolated bpdu_filter; do
		printf '%s=' "$attr"
		cat "$root/sys/class/net/wlan0/brport/$attr" 2>/dev/null || echo absent
	done > "$root/tmp/out/$phase-port-settings.txt"
}
for i in $(seq 1 10); do
	kill -0 "$pid" || { echo 'daemon exited before readiness'; exit 1; }
	if chroot "$root" ubus -t 1 call network.wireless status 2>/dev/null | grep -q '"up": true'; then break; fi
	sleep 1
done
sleep 2
snapshot initial
chroot "$root" ubus -t 3 call network.interface.lan prepare > "$root/tmp/out/prepare.json"
cp "$root/etc/config/wireless" "$root/tmp/wireless.saved"
chroot "$root" ubus -t 3 call network reload
sleep 2
snapshot reload
chroot "$root" ubus -t 3 call network.wireless down
sleep 2
snapshot down
chroot "$root" ubus -t 3 call network.wireless up
sleep 3
snapshot up
chroot "$root" uci set wireless.ap.ssid=r79-changed
chroot "$root" uci commit wireless
chroot "$root" ubus -t 3 call network reload
sleep 3
snapshot changed
chroot "$root" uci delete wireless.radio0
chroot "$root" uci commit wireless
chroot "$root" ubus -t 3 call network reload
sleep 3
snapshot removed
cp "$root/tmp/wireless.saved" "$root/etc/config/wireless"
chroot "$root" ubus -t 3 call network reload
sleep 3
snapshot restored
EOF
	sudo -n cp -a "$root/tmp/out" "$out/$tag"
	sudo -n chown -R "$(id -u):$(id -g)" "$out/$tag"
	sudo -n rm -rf "$tmp"
	[ "$rc" -eq 0 ] || { echo "r79: $tag driver failed ($rc)"; return 1; }
}

failed=0
run_one c || failed=1
run_one rs || failed=1
python3 "$here/r79_wireless_bridge_check.py" "$out" || failed=1
[ "$failed" -eq 0 ] || { echo 'r79: FAILED'; exit 1; }
echo 'r79: identical; wireless bridge forwards before/after reload and radio restart'
