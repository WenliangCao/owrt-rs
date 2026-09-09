#!/bin/sh
# P5: stage ubusd-rs as the next boot's bus daemon, or undo it. DEVICE-SIDE,
# run over ssh in an explicitly authorized device window.
#
# This is a COLD switch: /sbin/ubusd is replaced on disk and picked up by
# procd's early ubus service at the NEXT boot, so no running client ever
# experiences an ubusd restart -- which is exactly the fallout decision 0015
# recorded for the live swap (odhcpd, idle dnsmasq and network.wireless do
# not recover from one). The running ubusd keeps its old inode after the
# rename; nothing changes until the reboot. Overlay-only: failsafe boots the
# pristine /rom/sbin/ubusd.
#
# Usage: p5_switch.sh stage <ubusd-rs-binary>   # stage for next boot
#        p5_switch.sh undo                      # restore the original
#        p5_switch.sh status
set -eu

ORIG=/sbin/ubusd.c-orig

status() {
	echo "/sbin/ubusd: $(md5sum /sbin/ubusd 2>/dev/null)"
	echo "running: $(ls -l /proc/$(pgrep ubusd | head -1)/exe 2>/dev/null || echo '?')"
	[ -e "$ORIG" ] && echo "staged: yes (original kept at $ORIG)" || echo "staged: no"
}

case "${1:-status}" in
stage)
	bin=${2:?usage: p5_switch.sh stage <ubusd-rs-binary>}
	[ -x "$bin" ] || { echo "not executable: $bin" >&2; exit 1; }
	[ -e "$ORIG" ] && { echo "already staged; undo first" >&2; exit 1; }
	# Identify the binary: ubusd has no benign flag, so probe by marker
	# string and by it actually serving a throwaway socket.
	grep -q ubusd "$bin" || { echo "$bin has no ubusd marker string" >&2; exit 1; }
	"$bin" -s /tmp/p5-probe.sock & p=$!
	sleep 1
	kill -0 "$p" 2>/dev/null || { echo "$bin did not stay up on a probe socket" >&2; exit 1; }
	out=$(ubus -s /tmp/p5-probe.sock list 2>&1) || { kill -9 "$p"; echo "$bin did not answer ubus list: $out" >&2; exit 1; }
	kill -9 "$p" 2>/dev/null; rm -f /tmp/p5-probe.sock
	cp "$bin" /sbin/ubusd.rs-new
	sync
	# Copy the original aside, then one atomic rename: /sbin/ubusd exists
	# at every instant.
	cp -a /sbin/ubusd "$ORIG"
	sync
	mv /sbin/ubusd.rs-new /sbin/ubusd
	sync
	echo "staged. Next boot's bus is this binary. Undo: $0 undo"
	echo "rescue if unbootable: failsafe (mesh button + lan4) uses /rom."
	status
	;;
undo)
	[ -e "$ORIG" ] || { echo "nothing staged" >&2; exit 1; }
	mv "$ORIG" /sbin/ubusd
	sync
	echo "restored the original ubusd for the next boot."
	status
	;;
status)
	status
	;;
*)
	echo "usage: $0 stage <binary> | undo | status" >&2
	exit 1
	;;
esac
