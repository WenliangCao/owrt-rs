#!/bin/sh
# R16 go-live device steps for owrt-uci 0.1.0-r1 (+ owrt-switch r2) on the AX3000T.
# Run one step per SSH call:  ssh openwrt 'sh -s <step>' < tools/r16_go_live_device.sh
# Steps: install (APKs must already be at /tmp) | gate | enable | probe | disable | rollback
set -u
APK=/tmp/owrt-uci-0.1.0-r1.apk
APK_SHA=4cb5dbf59e4e03339ce803cf0f75284b5f2a361162299ebcec60b593c8d6a1a1
SW_APK=/tmp/owrt-switch-0.1.0-r2.apk
SW_APK_SHA=2814f8fc5fcc2f4d19dc2781bc763689bcbf400a0d42fd0781d154650a8cd94b
CAND_SHA=f4b4e28c32051f8c2aa2e684339a1198a6cbe7b66bd52a30caa922819213ccfb
SWITCH_SHA=f3dc48711fbe60a52db3f76524b6d5550cbc8fe4e6ffba7e2665fd32179e4b12
INIT_SHA=736ee9a244e0c909cd49e71635524d9cc51e4af8b516d8f7e26e1650bf37e3e7
ORIG_UCI_SHA=050e9ab320b794f636174536ca4dbca2f615a1c6c37bc19e9ca06bfd6d6e7278
SWITCH=/usr/sbin/owrt-uci-switch

sha() { sha256sum "$1" 2>/dev/null | cut -c1-64; }
mounted() { awk '$5=="/sbin/uci"' /proc/self/mountinfo | wc -l; }
probe_uci() {
	# read-only probes through /sbin/uci (whichever implementation is mounted)
	echo "uci_show_sha=$(uci show 2>/dev/null | sha256sum | cut -c1-16) lines=$(uci show 2>/dev/null | wc -l)"
	echo "uci_export_sha=$(uci export 2>/dev/null | sha256sum | cut -c1-16)"
	echo "uci_changes=$(uci changes 2>&1 | wc -l)"
	echo "uci_get_hostname=$(uci -q get system.@system[0].hostname 2>&1)"
	echo "uci_get_missing_rc=$(uci -q get nonexist.a.b >/dev/null 2>&1; echo $?)"
	echo "uci_state_export=$(uci -P /var/state -S -n export network 2>/dev/null | sha256sum | cut -c1-16)"
	echo "uci_bin_size=$(wc -c < /sbin/uci)"
	echo "tmp_uci=$(ls -la /tmp/.uci 2>/dev/null | sha256sum | cut -c1-16) var_state=$(ls /var/state 2>/dev/null | tr '\n' ' ')"
}
state() {
	echo "== state $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "mounted=$(mounted) sbin_uci_sha=$(sha /sbin/uci | cut -c1-16)"
	echo "switch=$("$SWITCH" status 2>&1 | tr '\n' ' '; echo rc=$?)"
	echo "boot_enable=$("$SWITCH" boot-enable status 2>&1; echo rc=$?)"
	echo "package=$(apk query --from installed --fields version owrt-uci 2>/dev/null | awk '/^Version:/ { print $2 }') switchpkg=$(apk query --from installed --fields version owrt-switch 2>/dev/null | awk '/^Version:/ { print $2 }')"
	echo "rc_links=$(ls /etc/rc.d/ 2>/dev/null | grep owrt-uci | tr '\n' ' ')"
	echo "others: reload_config_mount=$(awk '$5=="/sbin/reload_config"' /proc/self/mountinfo | wc -l) fw4_mount=$(awk '$5=="/sbin/fw4"' /proc/self/mountinfo | wc -l) logd_rs=$(pidof logd-rs) httpd_rs=$(pidof httpd-rs) rpcd_rs=$(pidof rpcd-rs)"
	echo "recent_uci_errors=$(logread 2>/dev/null | tail -n 200 | grep -ci 'uci')"
	probe_uci
}

case "${1:-}" in
install)
	state
	[ "$(sha "$APK")" = "$APK_SHA" ] || { echo "APK sha mismatch"; exit 2; }
	[ "$(sha "$SW_APK")" = "$SW_APK_SHA" ] || { echo "switch APK sha mismatch"; exit 2; }
	[ "$(mounted)" = 0 ] || { echo "mount active, abort"; exit 2; }
	[ "$(sha /sbin/uci)" = "$ORIG_UCI_SHA" ] || { echo "original /sbin/uci sha mismatch"; exit 2; }
	apk --no-network add --allow-untrusted "$APK" "$SW_APK"; echo "apk_rc=$?"
	rm -f "$APK" "$SW_APK"
	echo "cand=$(sha /usr/sbin/uci-rs) switch=$(sha "$SWITCH") init=$(sha /etc/init.d/owrt-uci)"
	if [ "$(sha /usr/sbin/uci-rs)" = "$CAND_SHA" ] && [ "$(sha "$SWITCH")" = "$SWITCH_SHA" ] &&
		[ "$(sha /etc/init.d/owrt-uci)" = "$INIT_SHA" ]; then echo FILES_OK; else echo FILES_MISMATCH; fi
	state
	;;
gate)
	state
	"$SWITCH" gate; echo "gate_rc=$?"
	;;
enable)
	state
	"$SWITCH" enable; echo "enable_rc=$?"
	"$SWITCH" boot-enable on; echo "boot_enable_rc=$?"
	owrt-switch status
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
	apk del owrt-uci; echo "apk_del_rc=$?"
	state
	;;
*)
	echo "usage: sh -s install|gate|enable|probe|disable|rollback" >&2
	exit 64
	;;
esac
