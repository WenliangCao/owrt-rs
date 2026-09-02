#!/bin/sh
# R20 go-live device steps for owrt-rpcd 0.1.0-r4 (complete rpcd replacement) on the AX3000T.
# Run one step per SSH call:  ssh openwrt 'sh -s <step>' < tools/r20_go_live_device.sh
# Steps: install (APK must already be at /tmp) | gate-before | enable | gate-after | scan | probe | disable | rollback
set -u
APK=/tmp/owrt-rpcd-0.1.0-r4.apk
APK_SHA=dfaaf9648f937d188fbfa6bbe0eed2bdbdc455a1325319e0e6b63ca6d24ed720
CAND_SHA=76e720e4a0315620383923db88a0cb0909caf9336dcdedf66c1a92bcd807f125
SWITCH_SHA=e1ec940ad043757ebcfbd1dbaf654f9fccf370c03d694f889773b288c46642ec
INIT_SHA=685108834bdeb8622cd311f2c58b2be7eac6158354bc9389c40a0f33712d4341
SWITCH=/usr/sbin/owrt-rpcd-switch
GATE_BEFORE=/tmp/r20-gate-before.txt
GATE_AFTER=/tmp/r20-gate-after.txt
DEFAULT_SID=00000000000000000000000000000000
WIFI_DEVS="phy0-ap0 phy1-ap0"

sha() { sha256sum "$1" 2>/dev/null | cut -c1-64; }
# volatile fields: radio measurements, counters, expiries, per-run ids
mask() {
	sed -E -e 's/"expires":[0-9]*/"expires":N/g' -e "s/^('[a-z.-]*') @[0-9a-f]*$/\1 @T/" \
		-e 's/"(signal|noise|bitrate|quality|signal_avg|inactive|connected_time|thr|rate|mcs|mhz|nss|he_gi|he_dcm|eht_gi|packets|bytes|failed|retries|drop_misc|rx_bytes|tx_bytes|tx_errors|rx_errors|tx_packets|rx_packets|multicast|collisions|rx_dropped|tx_dropped|changes|up_count|down_count|active_time|busy_time|busy_time_ext|rx_time|tx_time|txpower|txpower_offset)":-?[0-9]+/"\1":N/g' \
		-e 's/"(40mhz|short_gi|ht|vht|he|eht)":(true|false)/"\1":B/g'
}
g() { name=$1; shift; out=$("$@" 2>&1); rc=$?; echo "$name: $(printf '%s' "$out" | mask | tr '\n' ' ') rc=$rc"; }
gh() { name=$1; shift; out=$("$@" 2>/dev/null); rc=$?; echo "$name: sha=$(printf '%s' "$out" | mask | sha256sum | cut -c1-16) bytes=$(printf '%s' "$out" | wc -c) rc=$rc"; }

# Contract C8 go-live gate: read-only calls whose masked answers must not
# change between the original rpcd plugins and rpcd-rs.
gate() {
	for o in luci-rpc iwinfo rpc-sys network.rrdns session uci rc file luci; do g sig_$o ubus -v list $o; done
	g objects sh -c 'ubus list | sort'
	g iw_devices ubus -S call iwinfo devices
	for d in $WIFI_DEVS; do
		g iw_info_$d ubus -S call iwinfo info "{\"device\":\"$d\"}"
		gh iw_freqlist_$d ubus -S call iwinfo freqlist "{\"device\":\"$d\"}"
		gh iw_txpowerlist_$d ubus -S call iwinfo txpowerlist "{\"device\":\"$d\"}"
		gh iw_countrylist_$d ubus -S call iwinfo countrylist "{\"device\":\"$d\"}"
		g iw_assoclist_$d ubus -S call iwinfo assoclist "{\"device\":\"$d\"}"
		g iw_survey_$d sh -c "ubus -S call iwinfo survey '{\"device\":\"$d\"}' | sed -E 's/:[0-9]+/:N/g'"
	done
	g iw_phyname_radio0 ubus -S call iwinfo phyname '{"section":"radio0"}'
	g iw_phyname_radio1 ubus -S call iwinfo phyname '{"section":"radio1"}'
	g iw_phyname_missing ubus -S call iwinfo phyname '{"section":"radio9"}'
	g iw_info_missing ubus -S call iwinfo info '{"device":"nosuch0"}'
	g iw_info_noargs ubus -S call iwinfo info '{}'
	g iw_assoclist_mac ubus -S call iwinfo assoclist '{"device":"phy0-ap0","mac":"00:11:22:33:44:55"}'
	g lr_wireless ubus -S call luci-rpc getWirelessDevices
	g lr_netdev ubus -S call luci-rpc getNetworkDevices
	g lr_hosthints_keys sh -c "ubus -S call luci-rpc getHostHints | sed -E 's/\"name\":\"[^\"]*\"/\"name\":S/g'"
	g lr_duid ubus -S call luci-rpc getDUIDHints
	gh lr_board ubus -S call luci-rpc getBoardJSON
	g lr_leases ubus -S call luci-rpc getDHCPLeases
	g lr_leases6 ubus -S call luci-rpc getDHCPLeases '{"family":6}'
	g lr_leases_bad ubus -S call luci-rpc getDHCPLeases '{"family":5}'
	gh sys_pkglist ubus -S call rpc-sys packagelist
	gh sys_pkglist_all ubus -S call rpc-sys packagelist '{"all":true}'
	g sys_upgrade_clean_missing ubus -S call rpc-sys upgrade_clean
	g sys_password_noargs ubus -S call rpc-sys password_set '{"user":"root"}'
	g rr_gateway ubus -S call network.rrdns lookup '{"addrs":["192.168.1.1"],"timeout":500}'
	g rr_bad ubus -S call network.rrdns lookup '{"addrs":["192.168.1.1"],"limit":0}'
	g session_list_default ubus -S call session list "{\"ubus_rpc_session\":\"$DEFAULT_SID\"}"
	g uci_get_lan ubus -S call uci get '{"config":"network","section":"lan"}'
	g uci_changes ubus -S call uci changes
	g rc_list_firewall ubus -S call rc list '{"name":"firewall","skip_running_check":true}'
	g luci_getVersion ubus -S call luci getVersion
	g luci_login_page wget -q -O /dev/null http://127.0.0.1/cgi-bin/luci/
}
state() {
	echo "== state $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "rpcd_pid=$(pidof rpcd) rpcd_rs_pid=$(pidof rpcd-rs) rpcd_rcd=$(ls /etc/rc.d/ 2>/dev/null | grep -c '^S12rpcd$')"
	echo "plugin_mount=$(awk '$5=="/usr/lib/rpcd"' /proc/self/mountinfo | wc -l)"
	echo "switch=$("$SWITCH" status 2>&1 | tr '\n' ' '; echo rc=$?)"
	echo "boot_enable=$("$SWITCH" boot-enable status 2>&1; echo rc=$?)"
	echo "package=$(apk query --from installed --fields version owrt-rpcd 2>/dev/null | awk '/^Version:/ { print $2 }')"
	echo "objects=$(ubus list 2>/dev/null | grep -cE '^(session|uci|rc|file|luci|rpc-sys|network.rrdns|luci-rpc|iwinfo)$')/9"
	echo "others: uci_mount=$(awk '$5=="/sbin/uci"' /proc/self/mountinfo | wc -l) reload_config_mount=$(awk '$5=="/sbin/reload_config"' /proc/self/mountinfo | wc -l) fw4_mount=$(awk '$5=="/sbin/fw4"' /proc/self/mountinfo | wc -l) logd_rs=$(pidof logd-rs) httpd_rs=$(pidof httpd-rs)"
	echo "recent_rpcd_log=$(logread 2>/dev/null | tail -n 300 | grep -ci 'rpcd')"
	echo "quick: iw_ssid=$(ubus -S call iwinfo info '{"device":"phy0-ap0"}' 2>&1 | sed -n 's/.*"ssid":"\([^"]*\)".*/\1/p') wireless_n=$(ubus -S call luci-rpc getWirelessDevices 2>/dev/null | grep -o '"ifname"' | wc -l) hosthints_n=$(ubus -S call luci-rpc getHostHints 2>/dev/null | grep -o '"ipaddrs"' | wc -l) session_access=$(ubus -S call session access "{\"ubus_rpc_session\":\"$DEFAULT_SID\",\"object\":\"luci\",\"function\":\"getFeatures\"}" 2>&1 | tr -d '\n') uci_lan=$(ubus -S call uci get '{"config":"network","section":"lan","option":"proto"}' 2>&1 | tr -d '\n') luci_page=$(wget -q -O /dev/null http://127.0.0.1/cgi-bin/luci/ >/dev/null 2>&1; echo rc=$?)"
}

case "${1:-}" in
install)
	state
	[ "$(sha "$APK")" = "$APK_SHA" ] || { echo "APK sha mismatch"; exit 2; }
	# r3 is live (rpcd-rs core + plugin-only rpcd): switch it off with the installed r3 switch first
	"$SWITCH" disable; echo "r3_disable_rc=$?"
	[ "$(awk '$5=="/usr/lib/rpcd"' /proc/self/mountinfo | wc -l)" = 0 ] || { echo "plugin mount still active, abort"; exit 2; }
	apk --no-network add --allow-untrusted "$APK"; echo "apk_rc=$?"
	rm -f "$APK"
	echo "cand=$(sha /usr/sbin/rpcd-rs) switch=$(sha "$SWITCH") init=$(sha /etc/init.d/owrt-rpcd)"
	if [ "$(sha /usr/sbin/rpcd-rs)" = "$CAND_SHA" ] && [ "$(sha "$SWITCH")" = "$SWITCH_SHA" ] &&
		[ "$(sha /etc/init.d/owrt-rpcd)" = "$INIT_SHA" ]; then echo FILES_OK; else echo FILES_MISMATCH; fi
	state
	;;
gate-before)
	state
	gate > "$GATE_BEFORE" 2>&1; echo "gate_before_lines=$(wc -l < "$GATE_BEFORE")"
	cat "$GATE_BEFORE"
	;;
enable)
	state
	"$SWITCH" enable; echo "enable_rc=$?"
	"$SWITCH" boot-enable on; echo "boot_enable_rc=$?"
	owrt-switch status
	state
	;;
gate-after)
	gate > "$GATE_AFTER" 2>&1; echo "gate_after_lines=$(wc -l < "$GATE_AFTER")"
	if cmp -s "$GATE_BEFORE" "$GATE_AFTER"; then echo GATE_IDENTICAL; else echo GATE_DIFFERS; diff "$GATE_BEFORE" "$GATE_AFTER"; fi
	;;
scan)
	# one scan per radio (results vary by environment: recorded, not compared)
	for d in $WIFI_DEVS; do echo "== scan $d"; ubus -S -t 30 call iwinfo scan "{\"device\":\"$d\"}" 2>&1 | cut -c1-1500; echo " rc=$?"; done
	;;
probe)
	state
	;;
disable)
	state
	"$SWITCH" disable; echo "disable_rc=$?"
	state
	;;
rollback)
	state
	"$SWITCH" disable; "$SWITCH" boot-enable off
	apk del owrt-rpcd; echo "apk_del_rc=$?"
	state
	;;
*)
	echo "usage: sh -s install|gate-before|enable|gate-after|scan|probe|disable|rollback" >&2
	exit 64
	;;
esac
