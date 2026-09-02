#!/bin/sh
# Stage 2 device steps for owrt-logd 0.1.0-r1 on the AX3000T.
# Run one step per SSH call:  ssh openwrt 'sh -s <step>' < tools/r15_go_live_device.sh
# Steps: install (APK at /tmp) | canary | go-live | probe | rollback
set -u
APK=/tmp/owrt-logd-0.1.0-r1.apk
APK_SHA=719fa135f39131ce0667310338f395a9a958e0dfccc6e7dfb9afeeab8a800544
CAND_SHA=235a78a267f46df06359a6df5e1c42d13c94fc527c04817b3bb40f640d8f1a28
SWITCH_SHA=e068d9166d5653ec6d560a2e7366cf92aa695edab120c05574690aea793d4d07
INIT_SHA=12101ff68e5a96526e7ba45f298d8582de7cabc7b9f131bb61554b74a17e540e
SWITCH=/usr/sbin/owrt-logd-switch

sha() { sha256sum "$1" | cut -c1-64; }
state() {
	echo "== state $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "stock_logd_pid=$(pidof logd || echo none) logd_rs_pid=$(pidof logd-rs || echo none)"
	echo "log_service=$(ubus call service list '{"name":"log"}' 2>/dev/null | grep -c '"running": true') owrt_logd_service=$(ubus call service list '{"name":"owrt-logd"}' 2>/dev/null | grep -c '"running": true')"
	echo "log_object=$(ubus -v list log 2>/dev/null | head -1)"
	echo "switch=$("$SWITCH" status 2>&1 | tr '\n' ' '; echo rc=$?)"
	echo "boot_enable=$("$SWITCH" boot-enable status 2>&1 | tr '\n' ' '; echo rc=$?)"
	echo "rc_links=$(ls /etc/rc.d/ | grep -E 'log|owrt-logd' | tr '\n' ' ')"
	echo "package=$(apk query --from installed --fields version owrt-logd 2>/dev/null | awk '/^Version:/ { print $2 }')"
	echo "logread_lines=$(logread 2>/dev/null | wc -l)"
	echo "reload_config_mounts=$(awk '$5=="/sbin/reload_config"' /proc/self/mountinfo | wc -l)"
}
roundtrip() {
	tag=$1
	logger -t "$tag" -p daemon.info "rust logd $tag via /dev/log"
	ubus call log write "{\"event\":\"<14>$tag via ubus write\"}"; echo "write_rc=$?"
	echo "-- logread -l 2"; logread -l 2
	echo "-- ubus read lines 2"; ubus call log read '{"lines":2,"stream":false}' | grep -E '"msg"|"priority"|"source"'
	logread -f -l 0 >/tmp/owrt-logd-follow.txt 2>&1 &
	fp=$!
	sleep 1
	logger -t "$tag" "follow line"
	sleep 1
	kill $fp 2>/dev/null
	echo "-- follow"; cat /tmp/owrt-logd-follow.txt; rm -f /tmp/owrt-logd-follow.txt
	echo "-- kernel lines present: $(logread | grep -c 'kernel:')"
}

case "${1:-}" in
install)
	state
	[ "$(sha "$APK")" = "$APK_SHA" ] || { echo "APK sha mismatch"; exit 2; }
	apk --no-network add --allow-untrusted "$APK"; echo "apk_rc=$?"
	rm -f "$APK"
	echo "cand=$(sha /usr/sbin/logd-rs) switch=$(sha "$SWITCH") init=$(sha /etc/init.d/owrt-logd)"
	if [ "$(sha /usr/sbin/logd-rs)" = "$CAND_SHA" ] && [ "$(sha "$SWITCH")" = "$SWITCH_SHA" ] &&
		[ "$(sha /etc/init.d/owrt-logd)" = "$INIT_SHA" ]; then echo FILES_OK; else echo FILES_MISMATCH; fi
	/usr/sbin/logd-rs --help
	state
	;;
canary)
	state
	before=$(logread | wc -l)
	"$SWITCH" enable; echo "enable_rc=$?"
	state
	roundtrip canary
	"$SWITCH" disable; echo "disable_rc=$?"
	state
	echo "-- stock logd after switch back"; logger -t canary "back on stock logd"; logread -l 1
	echo "lines_before=$before"
	;;
go-live)
	state
	"$SWITCH" boot-enable on; echo "boot_enable_rc=$?"
	"$SWITCH" enable; echo "enable_rc=$?"
	state
	roundtrip golive
	;;
probe)
	state
	logger -t probe "probe $(date -u +%H:%M:%SZ)"; logread -l 1
	echo "logd_rs_rss_kb=$(awk '/VmRSS/ {print $2}' /proc/$(pidof logd-rs)/status 2>/dev/null)"
	;;
rollback)
	"$SWITCH" boot-enable off; "$SWITCH" disable; state
	;;
*)
	echo "usage: install|canary|go-live|probe|rollback" >&2; exit 64
	;;
esac
