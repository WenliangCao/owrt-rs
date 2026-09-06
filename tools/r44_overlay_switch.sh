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

echo "== boot 1: write the candidate into the overlay"
boot 'mkdir -p /mnt/p && mount /dev/vdb /mnt/p && cp /mnt/p/ubusd-rs /sbin/ubusd && sync && echo "=====R44 install" && echo "r44 installed_size=$(wc -c < /sbin/ubusd)" && echo "r44 overlay_has_it=$(ls /overlay/upper/sbin/ubusd >/dev/null 2>&1 && echo yes || echo no)"' "$out/boot1.log"

echo "== boot 2: which binary did procd start?"
boot 'echo "=====R44 check" && bp=$(pgrep -f "^/sbin/ubusd" | head -1) && echo "r44 bus_size=$(wc -c < /proc/$bp/exe)" && echo "r44 bus_is_candidate=$(grep -qa ubusd-rs /proc/$bp/exe && echo yes || echo no)" && echo "r44 bus_uid=$(awk "/^Uid:/{print \$2}" /proc/$bp/status)" && echo "r44 objects=$(ubus list | wc -l)" && echo "r44 service_rc=$(ubus -S call service list "{}" >/dev/null 2>&1; echo $?)" && echo "r44 network_rc=$(ubus -S call network.interface dump >/dev/null 2>&1; echo $?)" && echo "r44 pid1=$(cat /proc/1/comm)"' "$out/boot2.log"

echo "== boot 3: remove the overlay file, the read-only original comes back"
boot 'echo "=====R44 revert" && rm -f /sbin/ubusd && sync && echo "r44 removed_rc=$?" && echo "r44 now_size=$(wc -c < /sbin/ubusd)"' "$out/boot3.log"

echo "== boot 4: confirm the original is serving again"
boot 'echo "=====R44 confirm" && bp=$(pgrep -f "^/sbin/ubusd" | head -1) && echo "r44 bus_size=$(wc -c < /proc/$bp/exe)" && echo "r44 bus_is_candidate=$(grep -qa ubusd-rs /proc/$bp/exe && echo yes || echo no)" && echo "r44 objects=$(ubus list | wc -l)" && echo "r44 service_rc=$(ubus -S call service list "{}" >/dev/null 2>&1; echo $?)"' "$out/boot4.log"
