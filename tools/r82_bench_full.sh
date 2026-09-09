#!/bin/sh
# R82: full-system benchmark, runs ON the router. Every Rust component that
# replaced a C/ucode/shell original, against that original, on the same device
# at the same time (MT7981B, 2x A53), same inputs, same client.
#
#   one-shots  uci / fw4 / reload_config: /rom original vs live Rust, back to
#              back (tools/bench_device_side_by_side.sh)
#   ubusd      a second bus per side on /tmp sockets -- C from /rom (its
#              shared libs are the same /lib), Rust as a second instance --
#              driven by components/ubusd/examples/bench (the r39 load)
#   rpcd       C /rom/sbin/rpcd -s <c bus> vs rpcd-rs -s <rs bus>, `ubus call`
#              loops (the r36/BENCHMARK §6 method; the ubus CLI round trip is
#              the floor on both sides)
#   procd      supervisor mode (non-PID 1) on the two buses: C has -s;
#              procd-rs has no socket flag, so it runs in a chroot of / where
#              the rs bus socket is bind-mounted onto /var/run/ubus/ubus.sock
#   netifd/logd/PID 1: live Rust numbers + the boot timeline from dmesg; the C
#              side of these comes from recorded C boots (see the report)
#
# Usage: sh r82_bench_full.sh [N]      needs /tmp/bench and
#        /tmp/bench_device_side_by_side.sh uploaded first; output in /tmp/r82
set -u
N=${1:-50}
OUT=/tmp/r82; mkdir -p "$OUT"
C=$OUT/c.sock; R=$OUT/rs.sock
CB=; RB=; CS=; RS=; CP=; RP=; CD=; RD=
st() { echo "$(date +%T) $*" >> "$OUT/status"; }
cleanup() {
	for p in $CD $RD $CP $RP $CS $RS $CB $RB; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
	sleep 1
	for p in $CD $RD $CP $RP $CS $RS $CB $RB; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
	for p in $(pgrep -f "sleep 3600" 2>/dev/null); do kill "$p" 2>/dev/null; done
	umount "$OUT/root/tmp/run/ubus/ubus.sock" 2>/dev/null
	umount "$OUT/root/tmp" 2>/dev/null
	umount "$OUT/root" 2>/dev/null
	rm -f "$C" "$R"
}
trap cleanup EXIT INT TERM

# time N iterations; print per-op ms, wall and cpu of the CLIENT side
t() { # label impl n command...
	label=$1; impl=$2; n=$3; shift 3
	{ time sh -c "i=0; while [ \$i -lt $n ]; do $* >/dev/null 2>&1; i=\$((i+1)); done"; } 2>&1 \
	| awk -v l="$label" -v i="$impl" -v n="$n" '
		function sec(m, s) { sub("m","",m); sub("s","",s); return m*60 + s }
		/^real/ { r = sec($2,$3) } /^user/ { u = sec($2,$3) } /^sys/ { s = sec($2,$3) }
		END { printf "%-28s %-3s per_op=%.2fms real=%.2fs client_cpu=%.2fs n=%d\n", l, i, r*1000/n, r, u+s, n }'
}
rss() { awk '/VmRSS/{print $2}' "/proc/$1/status" 2>/dev/null; }
cpu() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null; }
waitobj() { # sock object [tries]
	i=0; while [ $i -lt "${3:-15}" ]; do ubus -s "$1" list 2>/dev/null | grep -q "^$2\$" && return 0; i=$((i+1)); sleep 1; done
	return 1
}

: > "$OUT/status"
st "begin N=$N $(cat /proc/sys/kernel/hostname) $(uname -r) up=$(cut -d' ' -f1 /proc/uptime)s"

# 0. sizes: C binaries + the shared libraries they need vs static Rust
{
	echo "# bytes path"
	for f in /rom/sbin/uci /rom/sbin/fw4 /rom/usr/share/ucode/fw4.uc /rom/sbin/reload_config /rom/sbin/ubusd \
		/rom/sbin/procd /rom/sbin/netifd /rom/sbin/logd /rom/sbin/rpcd /rom/usr/sbin/uhttpd \
		/rom/lib/libubox.so.* /rom/lib/libubus.so.* /rom/lib/libuci.so.* /rom/lib/libblobmsg_json.so.* \
		/rom/lib/libjson-c.so.* /rom/usr/lib/libucode.so.* /rom/usr/lib/rpcd/*.so /rom/usr/lib/libiwinfo.so* \
		/sbin/uci /usr/sbin/fw4-rs /sbin/reload_config /sbin/ubusd /sbin/procd /sbin/netifd \
		/usr/sbin/logd-rs /usr/sbin/rpcd-rs /usr/sbin/httpd-rs; do
		[ -e "$f" ] && ls -l "$f" | awk '{print $5, $NF}'
	done
	echo "# firewall4 templates (KiB): $(du -sk /rom/usr/share/firewall4 2>/dev/null | cut -f1)"
	echo "# ucode wifi-scripts (KiB): $(du -sk /rom/usr/share/ucode/wifi 2>/dev/null | cut -f1)"
} > "$OUT/sizes.txt"
st "sizes"

# 1. live Rust daemons: RSS and cumulative CPU since boot
{
	echo "# uptime_s $(cut -d' ' -f1 /proc/uptime)"
	for name in procd ubusd netifd rpcd-rs httpd-rs logd-rs; do
		pid=$(pidof "$name" | cut -d' ' -f1)
		[ -n "$pid" ] && echo "$name pid=$pid rss_kb=$(rss "$pid") cpu_ticks=$(cpu "$pid") fds=$(ls /proc/$pid/fd | wc -l)"
	done
} > "$OUT/live.txt"
st "live"

# 2. one-shots (existing script; its header line about sizes may print ls errors)
N=100 NFW=20 sh /tmp/bench_device_side_by_side.sh > "$OUT/oneshot.txt" 2>&1
st "oneshot rc=$?"

# 3. two extra buses
/rom/sbin/ubusd -s "$C" -A /usr/share/acl.d > "$OUT/c-bus.log" 2>&1 & CB=$!
/sbin/ubusd -s "$R" -A /usr/share/acl.d > "$OUT/rs-bus.log" 2>&1 & RB=$!
sleep 1
[ -S "$C" ] && [ -S "$R" ] || { st "bus start FAILED"; exit 1; }
st "buses up c=$CB rs=$RB"

# 4. ubusd under the r39 load
busbench() { # tag sock buspid
	tag=$1; S=$2; bus=$3
	/tmp/bench "$S" serve > "$OUT/$tag-serve.log" 2>&1 & srv=$!
	waitobj "$S" bench.target || { echo "$tag: provider did not register"; return 1; }
	c0=$(cpu "$bus"); r0=$(rss "$bus")
	{
		/tmp/bench "$S" lookup     3000
		/tmp/bench "$S" lookup_all 300
		/tmp/bench "$S" invoke     3000
		/tmp/bench "$S" notify     3000
		c1=$(cpu "$bus"); r1=$(rss "$bus")
		echo "daemon_cpu_ticks=$((c1 - c0)) rss_before_kb=$r0 rss_after_kb=$r1"
		c2=$(cpu "$bus"); pids=; j=0
		while [ $j -lt 4 ]; do /tmp/bench "$S" invoke 750 > "$OUT/$tag-con-$j.txt" 2>&1 & pids="$pids $!"; j=$((j+1)); done
		for p in $pids; do wait "$p" 2>/dev/null; done
		sed 's/^invoke /concurrent4_invoke /' "$OUT"/$tag-con-*.txt
		echo "concurrent_daemon_cpu_ticks=$(( $(cpu "$bus") - c2 )) rss_kb=$(rss "$bus")"
	} > "$OUT/ubusd-$tag.txt" 2>&1
	kill "$srv" 2>/dev/null; wait "$srv" 2>/dev/null
}
busbench c  "$C" "$CB"; st "ubusd c"
busbench rs "$R" "$RB"; st "ubusd rs"

# 5. rpcd: C from /rom vs rpcd-rs, each on its own bus
/rom/sbin/rpcd -s "$C" -t 30 > "$OUT/c-rpcd.log" 2>&1 & CP=$!
/usr/sbin/rpcd-rs -s "$R" -t 30 > "$OUT/rs-rpcd.log" 2>&1 & RP=$!
waitobj "$C" luci-rpc 20 || st "C rpcd did not register luci-rpc"
waitobj "$R" luci-rpc 20 || st "rpcd-rs did not register luci-rpc"
rpcbench() { # tag sock pid
	tag=$1; S=$2
	{
		echo "objects: $(ubus -s "$S" list | wc -l)"
		t session_list      "$tag" "$N" "ubus -s $S call session list '{\"ubus_rpc_session\":\"00000000000000000000000000000000\"}'"
		t uci_get_network   "$tag" "$N" "ubus -s $S call uci get '{\"config\":\"network\"}'"
		t uci_configs       "$tag" "$N" "ubus -s $S call uci configs"
		t file_stat         "$tag" "$N" "ubus -s $S call file stat '{\"path\":\"/etc/board.json\"}'"
		t file_read_board   "$tag" "$N" "ubus -s $S call file read '{\"path\":\"/etc/board.json\"}'"
		t lucirpc_boardjson "$tag" "$N" "ubus -s $S call luci-rpc getBoardJSON"
		t lucirpc_netdevs   "$tag" "$N" "ubus -s $S call luci-rpc getNetworkDevices"
		t lucirpc_dhcpleases "$tag" "$N" "ubus -s $S call luci-rpc getDHCPLeases"
		t lucirpc_wireless  "$tag" "$N" "ubus -s $S call luci-rpc getWirelessDevices"
		t iwinfo_info       "$tag" "$N" "ubus -s $S call iwinfo info '{\"device\":\"phy0-ap0\"}'"
		t iwinfo_assoclist  "$tag" "$N" "ubus -s $S call iwinfo assoclist '{\"device\":\"phy0-ap0\"}'"
		t rrdns_lookup      "$tag" "$N" "ubus -s $S call network.rrdns lookup '{\"addrs\":[\"192.168.1.1\"]}'"
		echo "rss_kb=$(rss "$3") cpu_ticks=$(cpu "$3")"
	} > "$OUT/rpcd-$tag.txt" 2>&1
}
rpcbench c  "$C" "$CP"; st "rpcd c"
rpcbench rs "$R" "$RP"; st "rpcd rs"
kill "$CP" "$RP" 2>/dev/null; wait "$CP" "$RP" 2>/dev/null; CP=; RP=

# 6. procd in supervisor mode
/rom/sbin/procd -s "$C" > "$OUT/c-procd.log" 2>&1 & CD=$!
mkdir -p "$OUT/root"
if mount --bind / "$OUT/root" && mount -t tmpfs tmpfs "$OUT/root/tmp" \
	&& mkdir -p "$OUT/root/tmp/run/ubus" && : > "$OUT/root/tmp/run/ubus/ubus.sock" \
	&& mount --bind "$R" "$OUT/root/tmp/run/ubus/ubus.sock"; then
	chroot "$OUT/root" /sbin/procd > "$OUT/rs-procd.log" 2>&1 & RD=$!
else
	st "procd-rs chroot setup FAILED"
fi
waitobj "$C" service 20 || st "C procd did not register service"
[ -n "$RD" ] && { waitobj "$R" service 20 || st "procd-rs did not register service"; }
procbench() { # tag sock pid
	tag=$1; S=$2
	{
		echo "objects: $(ubus -s "$S" list | tr '\n' ' ')"
		t service_list      "$tag" "$N" "ubus -s $S call service list"
		t service_list_verb "$tag" "$N" "ubus -s $S call service list '{\"verbose\":true}'"
		t system_board      "$tag" "$N" "ubus -s $S call system board"
		t system_info       "$tag" "$N" "ubus -s $S call system info"
		t service_set_del   "$tag" 20   "ubus -s $S call service set '{\"name\":\"r82bench\",\"instances\":{\"i\":{\"command\":[\"/bin/sleep\",\"3600\"]}}}' && ubus -s $S call service delete '{\"name\":\"r82bench\"}'"
		echo "rss_kb=$(rss "$3") cpu_ticks=$(cpu "$3") leftover_sleeps=$(pgrep -fc 'sleep 3600' 2>/dev/null || echo 0)"
	} > "$OUT/procd-$tag.txt" 2>&1
}
procbench c "$C" "$CD"; st "procd c"
[ -n "$RD" ] && { procbench rs "$R" "$RD"; st "procd rs"; }
kill "$CD" "$RD" 2>/dev/null; wait "$CD" "$RD" 2>/dev/null; CD=; RD=
umount "$OUT/root/tmp/run/ubus/ubus.sock" 2>/dev/null; umount "$OUT/root/tmp" 2>/dev/null; umount "$OUT/root" 2>/dev/null
kill "$CB" "$RB" 2>/dev/null; wait "$CB" "$RB" 2>/dev/null; CB=; RB=

# 7. netifd (live Rust; no second instance possible) + boot timeline
{
	pid=$(pidof netifd)
	t if_dump            rs "$N" "ubus call network.interface dump"
	t device_status      rs "$N" "ubus call network.device status"
	t wireless_status    rs "$N" "ubus call network.wireless status"
	t iface_lan_status   rs "$N" "ubus call network.interface.lan status"
	echo "rss_kb=$(rss "$pid") cpu_ticks=$(cpu "$pid") uptime_s=$(cut -d' ' -f1 /proc/uptime)"
	echo "# boot timeline (kernel seconds, this boot):"
	dmesg | grep -E "lan2: configuring|phy0-ap0\) entered forwarding|phy1-ap0\) entered forwarding|wan: Link is Up|init complete|- init -|- ubus -|- early -" \
		| sed -E 's/.*\[ *([0-9.]+)\] /\1 /'
} > "$OUT/netifd-rs.txt" 2>&1
st "netifd"

# 8. logd (live Rust)
{
	pid=$(pidof logd-rs)
	t log_read_100       rs "$N" "ubus call log read '{\"lines\":100,\"stream\":false}'"
	t logger_200msgs     rs 1    'i=0; while [ $i -lt 200 ]; do logger -t r82 "message $i"; i=$((i+1)); done'
	t logread_full       rs 10   logread
	echo "rss_kb=$(rss "$pid") cpu_ticks=$(cpu "$pid") lines=$(logread | wc -l)"
} > "$OUT/logd-rs.txt" 2>&1
st "logd"

st "done"
