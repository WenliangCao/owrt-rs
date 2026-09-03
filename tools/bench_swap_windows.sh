#!/bin/sh
# Runs on the Mac. Measures logd and rpcd with the Rust implementation, switches
# each to the C original for one short window (owrt-*-switch disable), measures
# again, and switches back (enable). Both directions of the switch were verified
# in R15/R17/R18. Each window is well under three minutes.
#   bench_swap_windows.sh [N]
set -eu
N=${1:-50}
R() { ssh -o ConnectTimeout=10 openwrt "$@"; }

# time N iterations of a command on the router; print per-op ms and cpu seconds
t() { # label impl n command...
	label=$1; impl=$2; n=$3; shift 3
	R "{ time sh -c 'i=0; while [ \$i -lt $n ]; do $* >/dev/null 2>&1; i=\$((i+1)); done'; } 2>&1" | awk -v l="$label" -v i="$impl" -v n="$n" '
		function sec(m, s) { sub("m","",m); sub("s","",s); return m*60 + s }
		/^real/ { r=sec($2,$3) } /^user/ { u=sec($2,$3) } /^sys/ { s=sec($2,$3) }
		END { printf "%-26s %-3s per_op=%.2fms real=%.2fs cpu=%.2fs\n", l, i, r*1000/n, r, u+s }'
}
rss() { R "pid=\$(pidof $1 | cut -d' ' -f1); [ -n \"\$pid\" ] && echo \"rss $1 \$(grep VmRSS /proc/\$pid/status | awk '{print \$2 \" kB\"}')\""; }

bench_logd() { # impl
	t logger_500msgs        $1 1  'i=0; while [ $i -lt 500 ]; do logger -t bench "message $i"; i=$((i+1)); done'
	t logread_full          $1 20 logread
	t ubus_log_read_100     $1 $N "ubus call log read '\"'\"'{\"lines\":100,\"stream\":false}'\"'\"'"
	rss "$2"
}
bench_rpcd() { # impl
	t session_list          $1 $N "ubus call session list '\"'\"'{\"ubus_rpc_session\":\"00000000000000000000000000000000\"}'\"'\"'"
	t uci_get_network       $1 $N "ubus call uci get '\"'\"'{\"config\":\"network\"}'\"'\"'"
	t uci_configs           $1 $N "ubus call uci configs"
	t file_stat             $1 $N "ubus call file stat '\"'\"'{\"path\":\"/etc/config/network\"}'\"'\"'"
	t file_read_board_json  $1 $N "ubus call file read '\"'\"'{\"path\":\"/etc/board.json\"}'\"'\"'"
	t luci_getFeatures      $1 $N "ubus call luci getFeatures"
	t lucirpc_getBoardJSON  $1 $N "ubus call luci-rpc getBoardJSON"
	t lucirpc_getNetDevices $1 $N "ubus call luci-rpc getNetworkDevices"
	t lucirpc_getDHCPLeases $1 $N "ubus call luci-rpc getDHCPLeases"
	t lucirpc_getWireless   $1 $N "ubus call luci-rpc getWirelessDevices"
	t iwinfo_info_phy0      $1 $N "ubus call iwinfo info '\"'\"'{\"device\":\"phy0-ap0\"}'\"'\"'"
	t iwinfo_assoclist_phy0 $1 $N "ubus call iwinfo assoclist '\"'\"'{\"device\":\"phy0-ap0\"}'\"'\"'"
	t rrdns_lookup_gw       $1 10 "ubus call network.rrdns lookup '\"'\"'{\"addrs\":[\"192.168.1.1\"],\"timeout\":200}'\"'\"'"
	t rc_list               $1 3  "ubus call rc list"
	rss "$2"
}

echo "# N=$N $(date -Iseconds)"
echo "## logd"
bench_logd rs logd-rs
R 'owrt-logd-switch disable >/dev/null && sleep 1 && ubus -t 10 wait_for log && echo "# C logd active"'
bench_logd c logd
R 'owrt-logd-switch enable >/dev/null && sleep 1 && ubus -t 10 wait_for log && owrt-switch status | grep logd'

echo "## rpcd"
bench_rpcd rs rpcd-rs
R 'owrt-rpcd-switch disable >/dev/null && sleep 2 && ubus -t 10 wait_for luci-rpc iwinfo && echo "# C rpcd active"'
bench_rpcd c rpcd
R 'owrt-rpcd-switch enable >/dev/null && sleep 2 && ubus -t 10 wait_for luci-rpc iwinfo && owrt-switch status | grep rpcd'
