#!/bin/sh
# Boot OpenWrt 25.12.5 armsr/armv8 under qemu so procd runs as real PID 1 and
# starts the bus itself at STATE_UBUS. No sandbox can do this: procd has to be
# PID 1, so until now everything about it was source reading.
#
# NOT the device's target (mediatek/filogic): same OpenWrt release and
# userspace, different kernel and virtual hardware. It can show procd's own
# behaviour and the boot-time bus selection. It cannot show anything about the
# device's radios, switch or flash.
#
# Usage: r43_vm.sh <inner-script> [candidate-ubusd] [outfile]
#   REPLACE_BUS=1 additionally installs the candidate as /sbin/ubusd, which is
#   what procd starts at STATE_UBUS.
#   The inner script is installed as /etc/rc.local and runs at the end of boot;
#   whatever it prints goes to the serial console, which is this output. The
#   candidate, when given, is installed at /usr/sbin/ubusd-rs.
set -eu
VM=${VM:-$HOME/vm}
KERNEL=$VM/openwrt-25.12.5-armsr-armv8-generic-kernel.bin
BASE=$VM/openwrt-25.12.5-armsr-armv8-generic-ext4-rootfs.img
inner=${1:?inner script}; cand=${2:-}; outfile=${3:-/tmp/r43.log}
BOOT_TIMEOUT=${BOOT_TIMEOUT:-240}

[ -f "$KERNEL" ] && [ -f "$BASE" ] || { echo "r43: images missing under $VM" >&2; exit 1; }

# Always work on a copy: the pristine image stays untouched between runs.
work=$VM/run.img
cp "$BASE" "$work"
mnt=$(mktemp -d)
sudo -n mount -o loop "$work" "$mnt"
cleanup() { sudo -n umount "$mnt" 2>/dev/null || true; rmdir "$mnt" 2>/dev/null || true; }
trap cleanup EXIT

sudo -n cp "$inner" "$mnt/etc/rc.local"
sudo -n chmod 755 "$mnt/etc/rc.local"
if [ -n "$cand" ]; then
	sudo -n cp "$cand" "$mnt/usr/sbin/ubusd-rs"
	sudo -n chmod 755 "$mnt/usr/sbin/ubusd-rs"
	# REPLACE_BUS=1 puts the candidate where procd's STATE_UBUS early service
	# looks, which is the boot-time selection the switch analysis describes.
	# The original is kept next to it so a recovery path can be exercised.
	if [ "${REPLACE_BUS:-0}" = 1 ]; then
		sudo -n cp "$mnt/sbin/ubusd" "$mnt/sbin/ubusd.orig"
		sudo -n cp "$cand" "$mnt/sbin/ubusd"
		sudo -n chmod 755 "$mnt/sbin/ubusd"
	fi
fi
# anything else the caller staged
[ -d "$VM/stage" ] && sudo -n cp -a "$VM/stage/." "$mnt/" || true
sync
cleanup
trap - EXIT

timeout "$BOOT_TIMEOUT" qemu-system-aarch64 \
	-M virt -cpu cortex-a53 -smp 2 -m 512 -nographic -no-reboot \
	-kernel "$KERNEL" \
	-drive file="$work",format=raw,if=virtio \
	-append "root=/dev/vda rootwait console=ttyAMA0" \
	< /dev/null > "$outfile" 2>&1 || true

# Only the section the inner script marks is of interest; the rest is kernel noise.
sed -n '/=====R43 BEGIN/,/=====R43 END/p' "$outfile"
grep -q '=====R43 END' "$outfile" || { echo "r43: the inner script did not finish (see $outfile)"; exit 1; }
