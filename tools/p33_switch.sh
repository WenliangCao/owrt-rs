#!/bin/sh
# P3.3: stage procd-rs as the next boot's PID 1, or undo it. DEVICE-SIDE,
# run over ssh in an explicitly authorized device window -- never from CI.
#
# Why replacing /sbin/procd is the only switch point, and why it is safe to
# stage on a running system, is R67 + R72: the shipping /sbin/init execvp()s
# the literal path "/sbin/procd" (initd/preinit.c:114) and consults no
# environment; the running procd keeps its old inode after a rename; and the
# change lives in the overlay only, so failsafe mode (mesh button + lan4),
# which does not mount the overlay, boots the pristine /rom/sbin/procd.
#
# The replacement must serve every mode the boot chain uses:
#   PID 1 (no args), `-h /etc/hotplug-preinit.json` (preinit's hotplug
#   daemon), the WDTFD watchdog-fd handover, and the supervisor mode.
#
# Usage: p33_switch.sh stage <procd-rs-binary>   # stage for next boot
#        p33_switch.sh undo                      # restore the original
#        p33_switch.sh status
set -eu

ORIG=/sbin/procd.c-orig

status() {
	echo "pid1: $(readlink /proc/1/exe 2>/dev/null || echo '?')"
	echo "/sbin/procd: $(md5sum /sbin/procd 2>/dev/null)"
	[ -e "$ORIG" ] && echo "staged: yes (original kept at $ORIG)" || echo "staged: no"
}

case "${1:-status}" in
stage)
	bin=${2:?usage: p33_switch.sh stage <procd-rs-binary>}
	[ -x "$bin" ] || { echo "not executable: $bin" >&2; exit 1; }
	# Refuse to double-stage: the original must survive exactly once.
	[ -e "$ORIG" ] && { echo "already staged; undo first" >&2; exit 1; }
	# The new binary must behave like procd: -h with unreadable rules exits
	# EXACTLY 1 (both C and Rust do), and the binary carries the "procd"
	# marker string. Exit-0 imposters (/bin/true) fail the first check,
	# exit-1 imposters (/bin/false) fail the second.
	rc=0; "$bin" -h /nonexistent-rules 2>/dev/null || rc=$?
	[ "$rc" -eq 1 ] || { echo "$bin does not behave like procd (-h exited $rc, want 1)" >&2; exit 1; }
	grep -q procd "$bin" || { echo "$bin has no procd marker string" >&2; exit 1; }
	cp "$bin" /sbin/procd.rs-new
	sync
	# Keep a window-free path to PID 1: copy the original aside, then one
	# atomic rename. /sbin/procd exists at every instant.
	cp -a /sbin/procd "$ORIG"
	sync
	mv /sbin/procd.rs-new /sbin/procd
	sync
	echo "staged. Next boot's PID 1 is this binary. Undo: $0 undo"
	echo "rescue if unbootable: failsafe (mesh button + lan4) uses /rom."
	status
	;;
undo)
	[ -e "$ORIG" ] || { echo "nothing staged" >&2; exit 1; }
	mv "$ORIG" /sbin/procd
	sync
	echo "restored the original procd for the next boot."
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
