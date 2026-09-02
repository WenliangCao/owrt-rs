#!/bin/sh
# R13 go-live device steps for owrt-rpcd 0.1.0-r1 on the AX3000T.
# Run one step per SSH call:  ssh openwrt 'sh -s <step>' < tools/r13_go_live_device.sh
# Steps: install (APK must already be at /tmp) | enable | probe | disable | rollback
set -u
APK=/tmp/owrt-rpcd-0.1.0-r1.apk
APK_SHA=7c664b75af62dad422fd2a26c7a1783dbc70d90475e1afcdeee412c1c84d91a1
CAND_SHA=e34bb92d18eb0f62948406317d53dc1423d5cf4b56272f9b9b97a08da46b4f27
SWITCH_SHA=2184d7d05b3e68882fdebf80bb3b1c540889b140a151bb752f49feb676993851
INIT_SHA=3ddd28f0d4eb35e934d77f23d2bd503f6173d58314a389664faca71390343433
FILE_SO_SHA=f181c959ff0c44db1a9f2d96d053646fd6bf4d38426edc37702764a6e993584f
UCODE_SO_SHA=591c21eee13dcae91b75d039719e5733bcd2e1eeec7d0466104b1d2aa8d6c220
SWITCH=/usr/sbin/owrt-rpcd-switch

sha() { sha256sum "$1" 2>/dev/null | cut -c1-64; }
mounted() { awk '$5=="/usr/lib/rpcd"' /proc/self/mountinfo | wc -l; }
probe_objects() {
	echo "luci.getVersion=$(ubus -S call luci getVersion 2>&1 | tr -d '\n' | cut -c1-80)"
	echo "luci.getInitList.firewall=$(ubus -S call luci getInitList '{"name":"firewall"}' 2>&1 | tr -d '\n')"
	echo "luci.getBuiltinEthernetPorts=$(ubus -S call luci getBuiltinEthernetPorts 2>&1 | tr -d '\n' | cut -c1-120)"
	echo "luci.getFeatures.sha=$(ubus -S call luci getFeatures 2>/dev/null | sha256sum | cut -c1-16)"
	echo "luci.getConntrackHelpers.sha=$(ubus -S call luci getConntrackHelpers 2>/dev/null | sha256sum | cut -c1-16)"
	echo "luci.getTimezones.sha=$(ubus -S call luci getTimezones 2>/dev/null | sha256sum | cut -c1-16)"
	echo "luci.getMountPoints.n=$(ubus -S call luci getMountPoints 2>/dev/null | grep -o '"mount"' | wc -l)"
	echo "luci.getProcessList.n=$(ubus -S call luci getProcessList 2>/dev/null | grep -o '"PID"' | wc -l)"
	echo "file.stat.board=$(ubus -S call file stat '{"path":"/etc/board.json"}' 2>&1 | tr -d '\n' | cut -c1-100)"
	echo "file.list.config.n=$(ubus -S call file list '{"path":"/etc/config"}' 2>/dev/null | grep -o '"name"' | wc -l)"
	echo "file.md5.board=$(ubus -S call file md5 '{"path":"/etc/board.json"}' 2>&1 | tr -d '\n')"
	echo "file.exec.echo=$(ubus -S call file exec '{"command":"echo","params":["ok"]}' 2>&1 | tr -d '\n')"
	echo "file.denied=$(ubus -S call file read '{"path":"/etc/board.json","ubus_rpc_session":"00000000000000000000000000000000"}' 2>&1 | tr -d '\n'; echo " rc=$?")"
	echo "session.access=$(ubus -S call session access '{"ubus_rpc_session":"00000000000000000000000000000000","scope":"ubus","object":"luci","function":"getVersion"}' 2>&1 | tr -d '\n')"
}
state() {
	echo "== state $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "rpcd_pid=$(pgrep -x rpcd | tr '\n' ' ') rpcd_rs_pid=$(pgrep -x rpcd-rs | tr '\n' ' ')"
	echo "mounted=$(mounted) plugins=$(ls /usr/lib/rpcd | tr '\n' ' ')"
	echo "file_so=$(sha /usr/lib/rpcd/file.so | cut -c1-16) ucode_so=$(sha /usr/lib/rpcd/ucode.so | cut -c1-16)"
	echo "objects=$(ubus list 2>/dev/null | grep -c .) file_luci=$(ubus list file luci 2>/dev/null | tr '\n' ' ')"
	echo "switch=$("$SWITCH" status 2>&1 | tr '\n' ' '; echo rc=$?)"
	echo "boot_enable=$("$SWITCH" boot-enable status 2>&1; echo rc=$?)"
	echo "package=$(apk query --from installed --fields version owrt-rpcd 2>/dev/null | awk '/^Version:/ { print $2 }')"
	echo "rc_links=$(ls /etc/rc.d/ 2>/dev/null | grep owrt-rpcd | tr '\n' ' ')"
	echo "httpd_rs=$(pgrep -x httpd-rs | tr '\n' ' ') logd_rs=$(pgrep -x logd-rs | tr '\n' ' ') fw4_mount=$(awk '$5=="/sbin/fw4"' /proc/self/mountinfo | wc -l)"
	probe_objects
}

case "${1:-}" in
install)
	state
	[ "$(sha "$APK")" = "$APK_SHA" ] || { echo "APK sha mismatch"; exit 2; }
	[ "$(mounted)" = 0 ] || { echo "mount active, abort"; exit 2; }
	[ "$(sha /usr/lib/rpcd/file.so)" = "$FILE_SO_SHA" ] && [ "$(sha /usr/lib/rpcd/ucode.so)" = "$UCODE_SO_SHA" ] || { echo "original plugin sha mismatch"; exit 2; }
	apk --no-network add --allow-untrusted "$APK"; echo "apk_rc=$?"
	rm -f "$APK"
	echo "cand=$(sha /usr/sbin/rpcd-rs) switch=$(sha "$SWITCH") init=$(sha /etc/init.d/owrt-rpcd)"
	if [ "$(sha /usr/sbin/rpcd-rs)" = "$CAND_SHA" ] && [ "$(sha "$SWITCH")" = "$SWITCH_SHA" ] &&
		[ "$(sha /etc/init.d/owrt-rpcd)" = "$INIT_SHA" ]; then echo FILES_OK; else echo FILES_MISMATCH; fi
	state
	;;
enable)
	state
	"$SWITCH" enable; echo "enable_rc=$?"
	"$SWITCH" boot-enable on; echo "boot_enable_rc=$?"
	state
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
	echo "usage: sh -s install|enable|probe|disable|rollback"; exit 64
	;;
esac
