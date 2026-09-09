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
PENDING=/etc/p6-pending
REVERTING=/etc/p6-reverting
CANARY=/etc/init.d/p6-canary
CANARY_LINK=/etc/rc.d/S99p6-canary

status() {
	echo "/sbin/netifd: $(md5sum /sbin/netifd 2>/dev/null)"
	echo "running: $(ls -l /proc/$(pidof netifd | cut -d' ' -f1)/exe 2>/dev/null || echo '?')"
	[ -e "$ORIG" ] && echo "staged: yes (original kept at $ORIG)" || echo "staged: no"
	[ -e "$CANARY_LINK" ] && echo "canary: armed (rollback T+900s unless explicitly confirmed)" || echo "canary: not armed"
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
	rm -f "$CONFIRM" "$REVERTING"
	cat > "$CANARY" <<'EOF'
#!/bin/sh /etc/rc.common
# The rollback timer never calls ubus or waits for a diagnostic command.
# Only an explicit confirm can keep the candidate. Radio up alone does not
# prove a client can get a lease, resolve DNS, or forward traffic.
START=99
snapshot() {
	umask 077
	{
		date
		md5sum /sbin/netifd
		echo '--- addresses'; ip addr
		echo '--- routes'; ip route; ip -6 route
		echo '--- interface dump'; ubus -t 3 call network.interface dump
		echo '--- wireless'; ubus -t 3 call network.wireless status
		echo '--- bridge ports'; ls -l /sys/class/net/br-lan/brif
		echo '--- processes'; ps w
		echo '--- logs'; logread 2>/dev/null | tail -80
		echo '--- kernel'; dmesg | tail -60
	} >> "$1" 2>&1
	sync
}
start() {
	[ -e /sbin/netifd.c-orig ] && [ -e /etc/p6-pending ] || return 0
	umask 077
	D=/root/p6-evidence-$(cat /proc/sys/kernel/random/boot_id).txt
	(
		sleep 300
		[ -e /etc/p6-pending ] && snapshot "$D"
	) </dev/null >/dev/null 2>&1 &
	(
		sleep 900
		# Atomic rename elects either confirm or rollback. A confirmation
		# cannot race past the deadline and claim a reverted binary is kept.
		mv /etc/p6-pending /etc/p6-reverting 2>/dev/null || exit 0
		echo "UNCONFIRMED: restoring C at $(date)" >> "$D"
		if ! mv /sbin/netifd.c-orig /sbin/netifd; then
			echo 'RESTORE FAILED; retry on next boot' >> "$D"
			mv /etc/p6-reverting /etc/p6-pending
			sync
			exit 1
		fi
		rm -f /etc/rc.d/S99p6-canary /etc/p6-reverting
		sync
		reboot
	) </dev/null >/dev/null 2>&1 &
}
EOF
	chmod 755 "$CANARY"
	ln -sf ../init.d/p6-canary "$CANARY_LINK"
	(umask 077; md5sum "$bin" | cut -d' ' -f1 > "$PENDING")
	cp "$bin" /sbin/netifd.rs-new
	sync
	cp -a /sbin/netifd "$ORIG"
	sync
	mv /sbin/netifd.rs-new /sbin/netifd
	sync
	echo "staged: C is restored and the router reboots at T+900s unless confirmed."
	echo "Evidence: /root/p6-evidence-*.txt; failsafe uses /rom."
	echo "Confirm only after client DHCP, DNS and Internet traffic are verified."
	status
	;;
confirm)
	[ -e "$ORIG" ] || { echo "nothing staged" >&2; exit 1; }
	[ -e "$PENDING" ] || { echo "not pending (already confirmed or rollback started)" >&2; exit 1; }
	expected=$(cat "$PENDING")
	actual=$(md5sum /sbin/netifd | cut -d' ' -f1)
	[ "$actual" = "$expected" ] || { echo "staged binary changed; refusing confirmation" >&2; exit 1; }
	mv "$PENDING" "$CONFIRM" || { echo "rollback already started" >&2; exit 1; }
	rm -f "$CANARY_LINK" "$CANARY"
	sync
	echo "confirmed: canary disarmed, netifd-rs stays. Rollback: mv $ORIG /sbin/netifd + reboot."
	status
	;;
undo)
	[ -e "$ORIG" ] || { echo "nothing staged" >&2; exit 1; }
	if [ -e "$PENDING" ]; then
		mv "$PENDING" "$REVERTING" || { echo "rollback already started" >&2; exit 1; }
	fi
	mv "$ORIG" /sbin/netifd
	rm -f "$CANARY_LINK" "$CANARY" "$CONFIRM" "$PENDING" "$REVERTING"
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
