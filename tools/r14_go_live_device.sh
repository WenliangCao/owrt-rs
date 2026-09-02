#!/bin/sh
# Stage 3 device steps for owrt-httpd 0.1.0-r1 on the AX3000T.
# Run one step per SSH call:  ssh openwrt 'sh -s <step>' < tools/r14_go_live_device.sh
# Steps: install (APK at /tmp) | side-start | side-stop | canary-enable | canary-disable | go-live | probe | rollback
set -u
APK=/tmp/owrt-httpd-0.1.0-r1.apk
APK_SHA=9582799bcf5a6f75350cc3e9d8d44880504e2c612c2060eee10f864c691685e5
CAND_SHA=d00505a215a05700deeff358985079a7b2b6e6f9f70f15bfb79232d7e344f85d
SWITCH_SHA=fc5b5839c3307d8bb987c48c7c2e297c8420528e4bb649d375fd9232caab4c70
INIT_SHA=12d18c52809c3bd6c9a16b63f946518b47ff7215e7f3065ac27f3104daade093
SWITCH=/usr/sbin/owrt-httpd-switch
SIDE_PID=/tmp/owrt-httpd-side.pid

sha() { sha256sum "$1" | cut -c1-64; }
state() {
	echo "== state $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "uhttpd_pid=$(pidof uhttpd || echo none) httpd_rs_pid=$(pidof httpd-rs || echo none)"
	echo "uhttpd_service=$(ubus call service list '{"name":"uhttpd"}' 2>/dev/null | grep -c '"running": true') owrt_httpd_service=$(ubus call service list '{"name":"owrt-httpd"}' 2>/dev/null | grep -c '"running": true')"
	echo "listening=$(netstat -ltn 2>/dev/null | awk '{print $4}' | grep -E ':(80|443|8080|8443)$' | sort -u | tr '\n' ' ')"
	echo "switch=$("$SWITCH" status 2>&1 | tr '\n' ' '; echo rc=$?)"
	echo "boot_enable=$("$SWITCH" boot-enable status 2>&1 | tr '\n' ' '; echo rc=$?)"
	echo "rc_links=$(ls /etc/rc.d/ | grep -E 'uhttpd|owrt-httpd' | tr '\n' ' ')"
	echo "package=$(apk query --from installed --fields version owrt-httpd 2>/dev/null | awk '/^Version:/ { print $2 }')"
	echo "local_index_http=$(wget -q -O - -T 3 http://127.0.0.1/index.html 2>/dev/null | wc -c)"
	echo "reload_config_mounts=$(awk '$5=="/sbin/reload_config"' /proc/self/mountinfo | wc -l) logd_rs=$(pidof logd-rs || echo none)"
}

case "${1:-}" in
install)
	state
	[ "$(sha "$APK")" = "$APK_SHA" ] || { echo "APK sha mismatch"; exit 2; }
	apk --no-network add --allow-untrusted "$APK"; echo "apk_rc=$?"
	rm -f "$APK"
	echo "cand=$(sha /usr/sbin/httpd-rs) switch=$(sha "$SWITCH") init=$(sha /etc/init.d/owrt-httpd)"
	if [ "$(sha /usr/sbin/httpd-rs)" = "$CAND_SHA" ] && [ "$(sha "$SWITCH")" = "$SWITCH_SHA" ] &&
		[ "$(sha /etc/init.d/owrt-httpd)" = "$INIT_SHA" ]; then echo FILES_OK; else echo FILES_MISMATCH; fi
	/usr/sbin/httpd-rs --help | head -2
	state
	;;
side-start)
	# candidate on 8080/8443 next to the stock server; same options otherwise
	state
	/usr/sbin/httpd-rs -f -h /www -r OpenWrt -x /cgi-bin -u /ubus -t 60 -T 30 -k 20 -A 1 -n 3 -N 100 -R \
		-p 0.0.0.0:8080 -p '[::]:8080' -C /etc/uhttpd.crt -K /etc/uhttpd.key -s 0.0.0.0:8443 -s '[::]:8443' \
		--call-log /tmp/owrt-httpd-side-calls.txt >/tmp/owrt-httpd-side.log 2>&1 &
	echo $! >"$SIDE_PID"
	sleep 1
	echo "side_pid=$(cat "$SIDE_PID") alive=$(kill -0 "$(cat "$SIDE_PID")" 2>/dev/null && echo yes || echo no)"
	echo "-- log"; cat /tmp/owrt-httpd-side.log
	echo "-- local 8080 index bytes: $(wget -q -O - -T 3 http://127.0.0.1:8080/index.html 2>/dev/null | wc -c)"
	state
	;;
side-stop)
	[ -f "$SIDE_PID" ] && kill "$(cat "$SIDE_PID")" 2>/dev/null; sleep 1
	echo "-- calls seen by side instance"; cat /tmp/owrt-httpd-side-calls.txt 2>/dev/null
	echo "-- log tail"; tail -5 /tmp/owrt-httpd-side.log 2>/dev/null
	rm -f "$SIDE_PID" /tmp/owrt-httpd-side.log /tmp/owrt-httpd-side-calls.txt
	state
	;;
canary-enable)
	state
	"$SWITCH" enable; echo "enable_rc=$?"
	state
	;;
canary-disable)
	echo "-- calls seen"; cat /tmp/owrt-httpd-calls.txt 2>/dev/null
	"$SWITCH" disable; echo "disable_rc=$?"
	state
	;;
go-live)
	state
	"$SWITCH" boot-enable on; echo "boot_enable_rc=$?"
	"$SWITCH" enable; echo "enable_rc=$?"
	state
	;;
probe)
	state
	echo "httpd_rs_rss_kb=$(awk '/VmRSS/ {print $2}' /proc/$(pidof httpd-rs | cut -d' ' -f1)/status 2>/dev/null) threads=$(ls /proc/$(pidof httpd-rs | cut -d' ' -f1)/task 2>/dev/null | wc -l)"
	echo "-- calls"; cat /tmp/owrt-httpd-calls.txt 2>/dev/null | head -40
	;;
rollback)
	"$SWITCH" boot-enable off; "$SWITCH" disable; state
	;;
*)
	echo "usage: install|side-start|side-stop|canary-enable|canary-disable|go-live|probe|rollback" >&2; exit 64
	;;
esac
