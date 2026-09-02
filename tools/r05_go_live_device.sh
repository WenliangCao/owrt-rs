#!/bin/sh
# R05 go-live device steps for owrt-reload-config 0.2.0-r1 on the AX3000T.
# Run one step per SSH call:  ssh openwrt 'sh -s <step>' < tools/r05_go_live_device.sh
# Steps: install (APK must already be at /tmp) | canary | go-live | probe | rollback
set -u
APK=/tmp/owrt-reload-config-0.2.0-r1.apk
APK_SHA=ae525f6c7db7756b987d32e375f490023c85ec5cfdc904df407fd9e0284f70d6
CAND_SHA=a209dedb57d96a5fa5085c670402a0ca42f71e1aa774ab3d412dc57f6ae19ec6
SWITCH_SHA=6a9be25c735ea554a63acd396e4b54e4db03c71f0b7fa58e220697d723ab9061
INIT_SHA=d84c4caffa1537726f635b48979718d7f8748c2c279398b50a09a325bcbd51af
SWITCH=/usr/sbin/owrt-reload-config-switch
PROBE=/etc/config/r05_canary_probe

sha() { sha256sum "$1" | cut -c1-64; }
mounts() { awk '$5=="/sbin/reload_config"' /proc/self/mountinfo | wc -l; }
run() { /sbin/reload_config; echo "run_rc=$?"; }
traces() { logread -e 'reload_config\[' 2>/dev/null; }
state() {
	echo "== state $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "dispatcher=$(sha /sbin/reload_config)"
	echo "baseline=$(sha /var/run/config.md5) entries=$(grep -c . /var/run/config.md5)"
	echo "config_tree=$(cd /etc/config && find . -type f -exec sha256sum {} \; | sort | sha256sum | cut -c1-64)"
	echo "mounts=$(mounts)"
	echo "switch=$("$SWITCH" status 2>&1; echo rc=$?)"
	echo "boot_enable=$("$SWITCH" boot-enable status 2>&1; echo rc=$?)"
	echo "package=$(apk query --from installed --fields version owrt-reload-config 2>/dev/null | awk '/^Version:/ { print $2 }')"
	echo "rc_link=$(ls /etc/rc.d/S11owrt-reload-config 2>/dev/null || echo none)"
	echo "trace_lines=$(traces | wc -l)"
}
drift() {
	n=0
	for p in $(cut -c35- /var/run/config.md5 | sed 's#.*/##'); do
		b=$(grep " /var/run/config.check/$p\$" /var/run/config.md5 | cut -c1-32)
		c=$(uci show "$p" 2>/dev/null | md5sum | cut -c1-32)
		[ "$b" = "$c" ] || n=$((n + 1))
	done
	echo "drift=$n"
}

case "${1:-}" in
install)
	state; drift
	[ "$(sha "$APK")" = "$APK_SHA" ] || { echo "APK sha mismatch"; exit 2; }
	[ "$(mounts)" = 0 ] || { echo "mount active, abort"; exit 2; }
	apk --no-network add --allow-untrusted "$APK"; echo "apk_rc=$?"
	rm -f "$APK"
	echo "cand=$(sha /usr/sbin/reload_config_rs) switch=$(sha "$SWITCH") init=$(sha /etc/init.d/owrt-reload-config)"
	if [ "$(sha /usr/sbin/reload_config_rs)" = "$CAND_SHA" ] && [ "$(sha "$SWITCH")" = "$SWITCH_SHA" ] &&
		[ "$(sha /etc/init.d/owrt-reload-config)" = "$INIT_SHA" ]; then echo FILES_OK; else echo FILES_MISMATCH; fi
	state; drift
	;;
canary)
	state
	"$SWITCH" enable; echo "enable_rc=$?"; echo "mounts=$(mounts) live=$(sha /sbin/reload_config)"
	before=$(sha /var/run/config.md5)
	run; run; run
	echo "baseline_same_after_steady=$([ "$(sha /var/run/config.md5)" = "$before" ] && echo yes || echo no)"
	printf "config probe 'p'\n\toption v '1'\n" >"$PROBE"; run
	printf "config probe 'p'\n\toption v '2'\n" >"$PROBE"; run
	rm -f "$PROBE"; run
	echo "baseline_restored=$([ "$(sha /var/run/config.md5)" = "$before" ] && echo yes || echo no)"
	echo "== trace"; traces | tail -14
	"$SWITCH" disable; echo "disable_rc=$?"; run
	echo "baseline_same_after_original=$([ "$(sha /var/run/config.md5)" = "$before" ] && echo yes || echo no)"
	state
	;;
go-live)
	state
	"$SWITCH" boot-enable on; /etc/init.d/owrt-reload-config start; echo "start_rc=$?"
	echo "mounts=$(mounts) live=$(sha /sbin/reload_config)"; run
	state; drift
	;;
probe)
	state; drift
	echo "== trace tail"; traces | tail -4
	echo "delivery_failures_nonzero=$(traces | grep -c '"delivery_failures":[1-9]')"
	echo "fatal=$(traces | grep -c '"kind":"fatal"')"
	;;
rollback)
	"$SWITCH" boot-enable off; "$SWITCH" disable; state
	;;
*)
	echo "usage: install|canary|go-live|probe|rollback" >&2; exit 64
	;;
esac
