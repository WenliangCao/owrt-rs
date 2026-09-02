#!/bin/sh
# R09b go-live device steps for owrt-fw4 0.1.0-r2 (UCI parser merged onto owrt_uci) on the AX3000T.
# Run one step per SSH call:  ssh openwrt 'sh -s <step>' < tools/r09b_go_live_device.sh
# Steps: install (APK must already be at /tmp) | gate | enable | probe | disable | rollback
set -u
APK=/tmp/owrt-fw4-0.1.0-r2.apk
APK_SHA=eaafb0b342b8bc726050dedaa79aad15a4db43ce3c912065629aa639c1a6f489
CAND_SHA=4474f87dfbd847272aa1fe9f12257ab3bcb796f73c3bca2696659d3cdb4efef1
SWITCH_SHA=b593079900c0c95d05b62cf7ebd4bc3591264028cd4d87e212847d4cd0bf22b5
INIT_SHA=26fcba28ee4a8bb69413e9e2b7fa20ecf00b37dcc72be6b3c6c17b8ee0393c4a
ORIG_SHA=c240b413a4cf80617ac1a71f601d2e0edae46b0493e3c00fbe883b2446e4a1a6
SWITCH=/usr/sbin/owrt-fw4-switch

sha() { sha256sum "$1" 2>/dev/null | cut -c1-64; }
mounts() { awk '$5=="/sbin/fw4"' /proc/self/mountinfo | wc -l; }
# kernel ruleset without volatile counters
ruleset() { nft list ruleset | sed -E 's/ packets [0-9]+ bytes [0-9]+//g'; }
state() {
	echo "== state $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "fw4=$(sha /sbin/fw4) mounts=$(mounts)"
	echo "ruleset=$(ruleset | sha256sum | cut -c1-64) lines=$(nft list ruleset | wc -l)"
	echo "print=$(QUIET=1 /sbin/fw4 print 2>/dev/null | sha256sum | cut -c1-64) print_lines=$(QUIET=1 /sbin/fw4 print 2>/dev/null | wc -l)"
	echo "switch=$("$SWITCH" status 2>&1 | tr '\n' ' '; echo rc=$?)"
	echo "boot_enable=$("$SWITCH" boot-enable status 2>&1; echo rc=$?)"
	echo "package=$(apk query --from installed --fields version owrt-fw4 2>/dev/null | awk '/^Version:/ { print $2 }')"
	echo "rc_links=$(ls /etc/rc.d/ 2>/dev/null | grep owrt-fw4 | tr '\n' ' ')"
	echo "state_file=$(sha /var/run/fw4.state || echo none)"
	echo "lookups: zone_lan=[$(/sbin/fw4 zone lan 2>&1 | tr '\n' ' ')] network_wan=[$(/sbin/fw4 network wan 2>&1)] device_brlan=[$(/sbin/fw4 device br-lan 2>&1)] rc=$?"
	echo "wan_up=$(ubus call network.interface.wan status 2>/dev/null | grep -c '"up": true') conntrack=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)"
}

case "${1:-}" in
install)
	state
	[ "$(sha "$APK")" = "$APK_SHA" ] || { echo "APK sha mismatch"; exit 2; }
	# r1 is live (bind mount): switch it off first so the upgrade replaces /usr/sbin/fw4-rs
	# with the original generator in charge; the kernel ruleset is untouched by this
	"$SWITCH" disable; echo "r1_disable_rc=$?"
	[ "$(mounts)" = 0 ] || { echo "mount still active, abort"; exit 2; }
	[ "$(sha /sbin/fw4)" = "$ORIG_SHA" ] || { echo "original fw4 sha mismatch"; exit 2; }
	apk --no-network add --allow-untrusted "$APK"; echo "apk_rc=$?"
	rm -f "$APK"
	echo "cand=$(sha /usr/sbin/fw4-rs) switch=$(sha "$SWITCH") init=$(sha /etc/init.d/owrt-fw4)"
	if [ "$(sha /usr/sbin/fw4-rs)" = "$CAND_SHA" ] && [ "$(sha "$SWITCH")" = "$SWITCH_SHA" ] &&
		[ "$(sha /etc/init.d/owrt-fw4)" = "$INIT_SHA" ]; then echo FILES_OK; else echo FILES_MISMATCH; fi
	state
	;;
gate)
	state
	"$SWITCH" gate; echo "gate_rc=$?"
	echo "cand_check=$(QUIET=1 /usr/sbin/fw4-rs check >/dev/null 2>&1; echo $?)"
	;;
enable)
	state
	before=$(ruleset | sha256sum | cut -c1-64)
	"$SWITCH" enable; echo "enable_rc=$?"; echo "mounts=$(mounts) live=$(sha /sbin/fw4)"
	echo "ruleset_same_after_enable=$([ "$(ruleset | sha256sum | cut -c1-64)" = "$before" ] && echo yes || echo no)"
	echo "check_via_mount=$(/sbin/fw4 -q check >/dev/null 2>&1; echo $?)"
	/sbin/fw4 -q reload; echo "reload_rc=$?"
	echo "ruleset_same_after_reload=$([ "$(ruleset | sha256sum | cut -c1-64)" = "$before" ] && echo yes || echo no)"
	echo "state_file_rewritten=$([ -s /var/run/fw4.state ] && grep -c '"zones"' /var/run/fw4.state)"
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
	apk del owrt-fw4; echo "apk_del_rc=$?"
	/sbin/fw4 -q reload; echo "orig_reload_rc=$?"
	state
	;;
*)
	echo "usage: sh -s install|gate|enable|probe|disable|rollback"; exit 64
	;;
esac
