#!/bin/sh
# Closing window for all five Rust components on the AX3000T.
# Steps: install (owrt-switch APK at /tmp) | status | probe
set -u
APK=/tmp/owrt-switch-0.1.0-r1.apk
APK_SHA=5cc2ca5155623dc0c2497a05fd098b1324b5427945281553a5bc12750df63e44
SCRIPT_SHA=b53f996f44ebf07903a46a0a36858fbc71f214a5df6cef4382e16b9f00e893cb

sha() { sha256sum "$1" 2>/dev/null | cut -c1-64; }
mnt() { awk -v t="$1" '$5==t' /proc/self/mountinfo | wc -l; }
probe() {
	echo "== probe $(date -u +%Y-%m-%dT%H:%M:%SZ) uptime=$(cut -d' ' -f1 /proc/uptime) load=$(cut -d' ' -f1-3 /proc/loadavg) mem_free_kb=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)"
	owrt-switch status 2>&1
	echo "mounts: reload_config=$(mnt /sbin/reload_config) fw4=$(mnt /sbin/fw4) rpcd_plugins=$(mnt /usr/lib/rpcd)"
	echo "pids: logd_rs=$(pidof logd-rs) httpd_rs=$(pidof httpd-rs) rpcd_rs=$(pidof rpcd-rs) rpcd=$(pidof rpcd) logd_orig=$(pidof logd) uhttpd=$(pidof uhttpd)"
	echo "listen: $(netstat -tln 2>/dev/null | awk '$4 ~ /:(80|443)$/ {print $4}' | tr '\n' ' ')"
	echo "fw4_print=$(QUIET=1 /sbin/fw4 print 2>/dev/null | sha256sum | cut -c1-16) ruleset=$(nft list ruleset | sed -E 's/ packets [0-9]+ bytes [0-9]+//g' | sha256sum | cut -c1-16) lines=$(nft list ruleset | wc -l)"
	echo "ubus_objects=$(ubus list | grep -c .) luci_version=$(ubus -S call luci getVersion 2>/dev/null | tr -d '\n' | cut -c1-60)"
	echo "file_denied_rc=$(ubus -S call file read '{"path":"/etc/board.json","ubus_rpc_session":"00000000000000000000000000000000"}' >/dev/null 2>&1; echo $?)"
	echo "logread_lines=$(logread | wc -l) last_log=$(logread | tail -n1 | cut -c1-100)"
	echo "reload_config_traces=$(logread -e 'reload_config\[' 2>/dev/null | wc -l)"
	echo "http_calls: $(cat /tmp/owrt-httpd-calls.txt 2>/dev/null | tr '\n' ';' | cut -c1-600)"
	echo "config_tree=$(cd /etc/config && find . -type f -exec sha256sum {} \; | sort | sha256sum | cut -c1-16)"
}

case "${1:-}" in
install)
	[ "$(sha "$APK")" = "$APK_SHA" ] || { echo "APK sha mismatch"; exit 2; }
	apk --no-network add --allow-untrusted "$APK" 2>&1 | grep -v 'WARNING: opening from cache'; echo "apk_rc=$?"
	rm -f "$APK"
	echo "script=$(sha /usr/sbin/owrt-switch)"; [ "$(sha /usr/sbin/owrt-switch)" = "$SCRIPT_SHA" ] && echo FILES_OK || echo FILES_MISMATCH
	owrt-switch status; echo "status_rc=$?"
	owrt-switch boot-enable status; echo "boot_rc=$?"
	;;
status) owrt-switch status; echo "rc=$?" ;;
probe) probe ;;
*) echo "usage: sh -s install|status|probe"; exit 64 ;;
esac
