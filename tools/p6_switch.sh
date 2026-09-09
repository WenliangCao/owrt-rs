#!/bin/sh
# P6: stage netifd-rs as the next boot's network manager, or undo it.
# DEVICE-SIDE, run over ssh in an explicitly authorized device window.
#
# netifd is the one daemon whose failure makes the box unreachable over the
# network, so staging also arms a CANARY: an rc script that, 480 s after a
# boot on the staged binary, restores the C netifd and reboots -- unless
# `confirm` has been run. A healthy boot reaches ssh in ~3 min (R74-R76), so
# there is time to confirm; a dead network heals itself in ~11 min without
# touching the button. Overlay-only: failsafe boots the pristine /rom copy.
#
# Usage: p6_switch.sh stage <netifd-rs-binary>  # stage + arm canary
#        p6_switch.sh confirm                   # keep: disarm the canary
#        p6_switch.sh undo                      # restore C netifd, disarm
#        p6_switch.sh status
set -eu

ORIG=/sbin/netifd.c-orig
CONFIRM=/etc/p6-confirm
CANARY=/etc/init.d/p6-canary
CANARY_LINK=/etc/rc.d/S99p6-canary

status() {
	echo "/sbin/netifd: $(md5sum /sbin/netifd 2>/dev/null)"
	echo "running: $(ls -l /proc/$(pgrep netifd | head -1)/exe 2>/dev/null || echo '?')"
	[ -e "$ORIG" ] && echo "staged: yes (original kept at $ORIG)" || echo "staged: no"
	[ -e "$CANARY_LINK" ] && echo "canary: armed (480s)" || echo "canary: not armed"
	[ -e "$CONFIRM" ] && echo "confirmed: yes" || echo "confirmed: no"
}

case "${1:-status}" in
stage)
	bin=${2:?usage: p6_switch.sh stage <netifd-rs-binary>}
	[ -x "$bin" ] || { echo "not executable: $bin" >&2; exit 1; }
	[ -e "$ORIG" ] && { echo "already staged; undo first" >&2; exit 1; }
	# Inert identity probe: -V prints the build id and exits before any
	# netlink/ubus/config work. Never start the candidate for real here --
	# a second live netifd would fight the running one.
	"$bin" -V 2>&1 | grep -q netifd-rs || { echo "$bin -V did not identify as netifd-rs" >&2; exit 1; }
	rm -f "$CONFIRM"
	cat > "$CANARY" <<'EOF'
#!/bin/sh /etc/rc.common
# P6 canary: if this boot runs the staged netifd-rs and nobody confirms
# within 480 s, restore the C netifd and reboot. Self-disarms once the
# original is gone (i.e. after its own revert or after `confirm`).
START=99
start() {
	[ -e /sbin/netifd.c-orig ] || return 0
	[ -e /etc/p6-confirm ] && return 0
	(
		sleep 480
		[ -e /etc/p6-confirm ] && exit 0
		[ -e /sbin/netifd.c-orig ] || exit 0
		mv /sbin/netifd.c-orig /sbin/netifd
		rm -f /etc/rc.d/S99p6-canary
		sync
		reboot
	) &
}
EOF
	chmod 755 "$CANARY"
	ln -sf ../init.d/p6-canary "$CANARY_LINK"
	cp "$bin" /sbin/netifd.rs-new
	sync
	cp -a /sbin/netifd "$ORIG"
	sync
	mv /sbin/netifd.rs-new /sbin/netifd
	sync
	echo "staged, canary armed. After reboot: verify, then '$0 confirm' WITHIN 480s."
	echo "rescue: canary auto-reverts in ~8 min; failsafe (mesh button + lan4) uses /rom."
	status
	;;
confirm)
	[ -e "$ORIG" ] || { echo "nothing staged" >&2; exit 1; }
	touch "$CONFIRM"
	rm -f "$CANARY_LINK" "$CANARY"
	sync
	echo "confirmed: canary disarmed, netifd-rs stays. Rollback: mv $ORIG /sbin/netifd + reboot."
	status
	;;
undo)
	[ -e "$ORIG" ] || { echo "nothing staged" >&2; exit 1; }
	mv "$ORIG" /sbin/netifd
	rm -f "$CANARY_LINK" "$CANARY" "$CONFIRM"
	sync
	echo "restored the original netifd for the next boot."
	status
	;;
status)
	status
	;;
*)
	echo "usage: $0 stage <binary> | confirm | undo | status" >&2
	exit 1
	;;
esac
