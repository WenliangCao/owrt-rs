#!/bin/sh
# The device's root is squashfs with a writable overlay on top. The switch
# analysis rests on an overlay file at /sbin/ubusd shadowing the read-only one,
# so that procd's STATE_UBUS early service starts the candidate. r43's ext4 VM
# could not show that; this uses OpenWrt's squashfs-combined image, which boots
# through the real mount_root/overlay path.
#
# Three boots against one disk, so the overlay persists between them:
#   1. install the candidate at /sbin/ubusd (an overlay write) and halt
#   2. report which binary the bus is actually running
#   3. remove the overlay file and confirm the original is back
#
# Commands are typed at the serial console, which is how a person would do it.
#
# Usage: r44_overlay_switch.sh <candidate-ubusd> [outdir]
set -eu
VM=${VM:-$HOME/vm}
IMG=$VM/openwrt-25.12.5-armsr-armv8-generic-squashfs-combined-efi.img
CODE=/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd
cand=${1:?candidate ubusd}; out=${2:-/tmp/r44-out}
mkdir -p "$out"
[ -f "$IMG" ] || { echo "r44: $IMG missing" >&2; exit 1; }

work=$VM/r44.img
payload=$VM/r44payload.img
vars=$VM/r44vars.fd

if [ "${R44_KEEP:-0}" != 1 ]; then
	cp "$IMG" "$work"
	cp /usr/share/AAVMF/AAVMF_VARS.fd "$vars" 2>/dev/null || cp /usr/share/AAVMF/AAVMF_VARS.ms.fd "$vars"
	rm -f "$payload"
	dd if=/dev/zero of="$payload" bs=1M count=8 status=none
	mkfs.ext4 -q -F "$payload"
	m=$(mktemp -d)
	sudo -n mount -o loop "$payload" "$m"
	sudo -n cp "$cand" "$m/ubusd-rs"; sudo -n chmod 755 "$m/ubusd-rs"
	sudo -n umount "$m"; rmdir "$m"
fi

# Feed the console: wait for the boot to settle, press Enter for a shell, then
# type the phase's commands. Repeated Enters make it robust to boot timing.
boot() { # $1 = commands, $2 = logfile
	{
		sleep "${SETTLE:-75}"
		printf '\n\n'
		sleep 5
		printf '%s\n' "$1"
		sleep 20
		printf 'poweroff -f\n'
		sleep 10
	} | timeout "${BOOT_TIMEOUT:-220}" qemu-system-aarch64 \
		-M virt -cpu cortex-a53 -smp 2 -m 512 -nographic -no-reboot \
		-drive if=pflash,format=raw,unit=0,file="$CODE",readonly=on \
		-drive if=pflash,format=raw,unit=1,file="$vars" \
		-drive file="$work",format=raw,if=virtio \
		-drive file="$payload",format=raw,if=virtio \
		> "$2" 2>&1 || true
	sed -n '/=====R44/,$p' "$2" | grep -E '^(r44|=====)' || true
}

# Each phase writes its verdict to the payload disk; the host reads it back.
# The serial console wraps long lines, so nothing important is printed there.
say_to_payload='mkdir -p /mnt/p && mount /dev/vdb /mnt/p'

report() { sudo -n mount -o loop "$payload" /mnt 2>/dev/null || true; }

phase() { # $1 = label, $2 = script, $3 = logfile
	echo "== $1"
	boot "$say_to_payload && { $2 ; } > /mnt/p/verdict.txt 2>&1 && sync" "$3"
	m=$(mktemp -d)
	sudo -n mount -o loop "$payload" "$m"
	sudo -n cat "$m/verdict.txt" 2>/dev/null | sed 's/^/   /' || echo "   (no verdict written)"
	sudo -n rm -f "$m/verdict.txt"
	sudo -n umount "$m"; rmdir "$m"
}

phase "boot 1: write the candidate into the overlay" \
	'cp /mnt/p/ubusd-rs /sbin/ubusd; sync; echo "installed_size=$(wc -c < /sbin/ubusd)"; echo "in_overlay_upper=$(ls /overlay/upper/sbin/ubusd >/dev/null 2>&1 && echo yes || echo no)"; echo "rom_original_size=$(wc -c < /rom/sbin/ubusd)"' \
	"$out/boot1.log"

phase "boot 2: which binary did procd start?" \
	'b=$(pgrep -f "^/sbin/ubusd" | head -1); echo "bus_size=$(wc -c < /proc/$b/exe)"; echo "is_candidate=$(grep -qa ubusd-rs /proc/$b/exe && echo yes || echo no)"; echo "bus_uid=$(awk "/^Uid:/{print \$2}" /proc/$b/status)"; echo "objects=$(ubus list | wc -l)"; echo "service_rc=$(ubus -S call service list "{}" >/dev/null 2>&1; echo $?)"; echo "network_rc=$(ubus -S call network.interface dump >/dev/null 2>&1; echo $?)"; echo "pid1=$(cat /proc/1/comm)"' \
	"$out/boot2.log"

phase "boot 3: revert by copying the rom original back over the overlay file" \
	'cp /rom/sbin/ubusd /sbin/ubusd; sync; echo "reverted_size=$(wc -c < /sbin/ubusd)"; echo "still_in_overlay=$(ls /overlay/upper/sbin/ubusd >/dev/null 2>&1 && echo yes || echo no)"' \
	"$out/boot3.log"

phase "boot 4: confirm the original is serving again" \
	'b=$(pgrep -f "^/sbin/ubusd" | head -1); echo "bus_size=$(wc -c < /proc/$b/exe)"; echo "is_candidate=$(grep -qa ubusd-rs /proc/$b/exe && echo yes || echo no)"; echo "objects=$(ubus list | wc -l)"; echo "service_rc=$(ubus -S call service list "{}" >/dev/null 2>&1; echo $?)"' \
	"$out/boot4.log"
