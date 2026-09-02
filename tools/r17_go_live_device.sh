#!/bin/sh
# R17 go-live device steps for owrt-rpcd 0.1.0-r3 (rpcd core objects) on the AX3000T.
# Run one step per SSH call:  ssh openwrt 'sh -s <step>' < tools/r17_go_live_device.sh
# Steps: install (APK must already be at /tmp) | gate-before | enable | gate-after | probe | disable | rollback
set -u
APK=/tmp/owrt-rpcd-0.1.0-r3.apk
APK_SHA=b7b83504495287c87acf2b195232bd7eca193dcc5ff9a57c0b44dc044d1b7f8b
CAND_SHA=573e69658bef477585f64dfb761fc78f54ab626d4acf413514bf1aa8c7fc3cc5
SWITCH_SHA=659999f4b0bcce3401b0e3219546b523e173071ade5847ab663b2724185b0dcd
INIT_SHA=4985c6f9c45a5f1b46e8600dba5477ca3918e7e6c9be22e52e4a1f2636453b2b
FILE_SO_SHA=f181c959ff0c44db1a9f2d96d053646fd6bf4d38426edc37702764a6e993584f
UCODE_SO_SHA=591c21eee13dcae91b75d039719e5733bcd2e1eeec7d0466104b1d2aa8d6c220
SWITCH=/usr/sbin/owrt-rpcd-switch
GATE_BEFORE=/tmp/r17-gate-before.txt
GATE_AFTER=/tmp/r17-gate-after.txt
DEFAULT_SID=00000000000000000000000000000000

sha() { sha256sum "$1" 2>/dev/null | cut -c1-64; }
mounted() { awk '$5=="/usr/lib/rpcd"' /proc/self/mountinfo | wc -l; }
mask() { sed -e 's/"expires":[0-9]*/"expires":N/g' -e "s/^\('[a-z-]*'\) @[0-9a-f]*$/\1 @T/"; }

# Contract C7 go-live gate: read-only calls whose answers must not change
# between the original rpcd and rpcd-rs (session ids masked). g prints the
# call output and its real exit status.
g() { name=$1; shift; out=$("$@" 2>&1); rc=$?; echo "$name: $(printf '%s' "$out" | mask | tr '\n' ' ') rc=$rc"; }
gh() { name=$1; shift; out=$("$@" 2>/dev/null); rc=$?; echo "$name: sha=$(printf '%s' "$out" | sha256sum | cut -c1-16) bytes=$(printf '%s' "$out" | wc -c) rc=$rc"; }
gate() {
	g sig_session ubus -v list session
	g sig_uci ubus -v list uci
	g sig_rc ubus -v list rc
	g session_list_default ubus -S call session list "{\"ubus_rpc_session\":\"$DEFAULT_SID\"}"
	g session_list_missing ubus -S call session list '{"ubus_rpc_session":"deadbeefdeadbeefdeadbeefdeadbeef"}'
	g session_access_yes ubus -S call session access "{\"ubus_rpc_session\":\"$DEFAULT_SID\",\"object\":\"luci\",\"function\":\"getFeatures\"}"
	g session_access_no ubus -S call session access "{\"ubus_rpc_session\":\"$DEFAULT_SID\",\"scope\":\"uci\",\"object\":\"network\",\"function\":\"read\"}"
	g session_access_dump ubus -S call session access "{\"ubus_rpc_session\":\"$DEFAULT_SID\"}"
	g session_access_noargs ubus -S call session access '{}'
	g session_login_bad ubus -S call session login '{"username":"root","password":"r17-not-the-password"}'
	g session_login_nouser ubus -S call session login '{"username":"r17-nobody","password":"x"}'
	g session_destroy_default ubus -S call session destroy "{\"ubus_rpc_session\":\"$DEFAULT_SID\"}"
	g uci_configs ubus -S call uci configs
	for pkg in network system dhcp firewall wireless dropbear uhttpd rpcd luci; do
		gh uci_get_$pkg ubus -S call uci get "{\"config\":\"$pkg\"}"
	done
	g uci_get_lan ubus -S call uci get '{"config":"network","section":"lan"}'
	g uci_get_zone1 ubus -S call uci get '{"config":"firewall","section":"@zone[1]","option":"name"}'
	gh uci_get_type ubus -S call uci get '{"config":"firewall","type":"zone","match":{"name":"lan"}}'
	g uci_get_missing ubus -S call uci get '{"config":"nosuchcfg"}'
	g uci_get_missing_sec ubus -S call uci get '{"config":"network","section":"nosuch"}'
	g uci_get_noconfig ubus -S call uci get '{}'
	g uci_get_denied ubus -S call uci get "{\"config\":\"network\",\"ubus_rpc_session\":\"$DEFAULT_SID\"}"
	g uci_get_missing_sid ubus -S call uci get '{"config":"network","ubus_rpc_session":"deadbeefdeadbeefdeadbeefdeadbeef"}'
	gh uci_state_network ubus -S call uci state '{"config":"network"}'
	g uci_state_lan ubus -S call uci state '{"config":"network","section":"lan"}'
	g uci_changes ubus -S call uci changes
	g uci_changes_network ubus -S call uci changes '{"config":"network"}'
	g uci_changes_missing ubus -S call uci changes '{"config":"nosuchcfg"}'
	g uci_confirm_nodata ubus -S call uci confirm "{\"ubus_rpc_session\":\"$DEFAULT_SID\"}"
	g uci_rollback_nodata ubus -S call uci rollback "{\"ubus_rpc_session\":\"$DEFAULT_SID\"}"
	g uci_apply_denied ubus -S call uci apply "{\"ubus_rpc_session\":\"$DEFAULT_SID\"}"
	gh rc_list_skip ubus -S call rc list '{"skip_running_check":true}'
	g rc_list_firewall ubus -S call rc list '{"name":"firewall"}'
	g rc_list_dropbear ubus -S call rc list '{"name":"dropbear"}'
	g rc_list_missing ubus -S call rc list '{"name":"nosuch"}'
	g rc_init_bad ubus -S call rc init '{"name":"cron","action":"bogus"}'
	g rc_init_missing ubus -S call rc init '{"name":"nosuch","action":"disable"}'
	g luci_getVersion ubus -S call luci getVersion
	gh luci_getFeatures ubus -S call luci getFeatures
	gh file_list_config ubus -S call file list '{"path":"/etc/config"}'
	g file_denied ubus -S call file read "{\"path\":\"/etc/board.json\",\"ubus_rpc_session\":\"$DEFAULT_SID\"}"
	gh luci_rpc_board ubus -S call luci-rpc getBoardJSON
	g luci_login_page wget -q -O /dev/null http://127.0.0.1/cgi-bin/luci/
	g objects sh -c 'ubus list | sort'
}
state() {
	echo "== state $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "rpcd_pid=$(pidof rpcd) rpcd_rs_pid=$(pidof rpcd-rs)"
	echo "mounted=$(mounted) plugins=$(ls /usr/lib/rpcd | tr '\n' ' ')"
	echo "switch=$("$SWITCH" status 2>&1 | tr '\n' ' '; echo rc=$?)"
	echo "boot_enable=$("$SWITCH" boot-enable status 2>&1; echo rc=$?)"
	echo "package=$(apk query --from installed --fields version owrt-rpcd 2>/dev/null | awk '/^Version:/ { print $2 }')"
	echo "rundir_rs=$(ls /var/run/rpcd-rs 2>/dev/null | tr '\n' ' ') rundir_c=$(ls /var/run/rpcd 2>/dev/null | tr '\n' ' ')"
	echo "others: uci_mount=$(awk '$5=="/sbin/uci"' /proc/self/mountinfo | wc -l) reload_config_mount=$(awk '$5=="/sbin/reload_config"' /proc/self/mountinfo | wc -l) fw4_mount=$(awk '$5=="/sbin/fw4"' /proc/self/mountinfo | wc -l) logd_rs=$(pidof logd-rs) httpd_rs=$(pidof httpd-rs)"
	echo "sessions_live=$(ubus -S call session list 2>/dev/null | grep -c ubus_rpc_session)"
	echo "recent_rpcd_log=$(logread 2>/dev/null | tail -n 300 | grep -ci 'rpcd')"
	echo "quick: session_access=$(ubus -S call session access "{\"ubus_rpc_session\":\"$DEFAULT_SID\",\"object\":\"luci\",\"function\":\"getFeatures\"}" 2>&1 | tr -d '\n') uci_lan=$(ubus -S call uci get '{"config":"network","section":"lan","option":"proto"}' 2>&1 | tr -d '\n') uci_changes=$(ubus -S call uci changes 2>&1 | tr -d '\n') rc_fw=$(ubus -S call rc list '{"name":"firewall","skip_running_check":true}' 2>&1 | tr -d '\n') luci_ver=$(ubus -S call luci getVersion >/dev/null 2>&1; echo rc=$?) luci_page=$(wget -q -O /dev/null http://127.0.0.1/cgi-bin/luci/ >/dev/null 2>&1; echo rc=$?)"
}

case "${1:-}" in
install)
	state
	[ "$(sha "$APK")" = "$APK_SHA" ] || { echo "APK sha mismatch"; exit 2; }
	# r2 is live: switch it off with the installed (r2) switch first, so the
	# package upgrade happens with the original rpcd fully in charge
	"$SWITCH" disable; echo "r2_disable_rc=$?"
	[ "$(mounted)" = 0 ] || { echo "mount still active, abort"; exit 2; }
	[ "$(sha /usr/lib/rpcd/file.so)" = "$FILE_SO_SHA" ] && [ "$(sha /usr/lib/rpcd/ucode.so)" = "$UCODE_SO_SHA" ] || { echo "original plugin sha mismatch"; exit 2; }
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
	echo "usage: sh -s install|gate-before|enable|gate-after|probe|disable|rollback" >&2
	exit 64
	;;
esac
