#!/bin/sh
# r23: boot-path gate for the Rust layers on the AX3000T.
#   r23_reboot_gate.sh pre  <dir>   capture the reference state before the reboot
#   r23_reboot_gate.sh post <dir>   capture again after the reboot and diff against pre/
# Read-only on the device (ssh alias `openwrt`). Volatile values (counters, uptime,
# WAN lease, signal levels) are masked so the diff only shows structural drift.
set -eu

mode=${1:?pre|post}; out=${2:?output dir}
HOST=${OWRT_HOST:-openwrt}
d="$out/$mode"; mkdir -p "$d"
r() { ssh -o ConnectTimeout=10 "$HOST" "$@"; }

r 'ubus list' | sort > "$d/ubus-list.txt"
r 'for s in /etc/init.d/*; do n=${s##*/}; if $s enabled 2>/dev/null; then echo "$n enabled"; else echo "$n disabled"; fi; done' > "$d/init-enabled.txt"
r 'grep -E " /sbin/(uci|reload_config|fw4) " /proc/mounts | cut -d" " -f2 | sort' > "$d/bind-mounts.txt"
r 'owrt-switch status 2>&1' > "$d/owrt-switch-status.txt"
r 'ps w | awk "NR>1 {print \$5}" | grep -E "^/?(usr/)?(sbin|bin)/(rpcd-rs|httpd-rs|logd-rs|rpcd|uhttpd|logd|dropbear|netifd|hostapd|wpa_supplicant|dnsmasq|odhcpd|ubusd|procd|urngd|ntpd|crond)$" | sort | uniq -c | awk "{print \$2, \$1}"' > "$d/processes.txt"
r 'nft list ruleset' | sed -E 's/packets [0-9]+ bytes [0-9]+/packets N bytes N/g; s/(expires|timeout) [0-9smhd]+/\1 T/g' > "$d/nft-ruleset.txt"
r 'for p in /etc/config/*; do printf "%s %s\n" "$(sha256sum $p | cut -c1-16)" "${p##*/}"; done' > "$d/config-hashes.txt"
r 'sha256sum /usr/sbin/rpcd-rs /usr/sbin/httpd-rs /usr/sbin/logd-rs /usr/sbin/fw4-rs /usr/sbin/uci-rs /usr/sbin/reload_config_rs /usr/sbin/owrt-*-switch /etc/init.d/owrt-* /etc/owrt-*.boot-enable' > "$d/binary-hashes.txt"
r 'ip link | grep -E "^[0-9]+:" | awk "{print \$2, \$3}"; echo; ip -4 addr show dev br-lan | grep inet; ip -4 addr show dev wan | grep -q inet && echo "wan inet ADDR" || echo "wan inet NONE"' > "$d/links.txt"
r 'ubus call network.wireless status' | sed -E '/"(pending|autostart|retry_setup_failed)"/d' > "$d/wireless-status.txt"
r 'iwinfo' | grep -E "ESSID|Mode|Channel|Type|Encryption|Hardware" | sed -E 's/\(([0-9.]+) MHz\)/(F MHz)/' > "$d/iwinfo.txt"
r 'uci -S -n export | sha256sum; /rom/sbin/uci -S -n export | sha256sum' > "$d/uci-export-hash.txt"
r 'wget -qO- --post-data="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"call\",\"params\":[\"00000000000000000000000000000000\",\"luci\",\"getVersion\",{}]}" http://127.0.0.1/ubus; echo; wget -qO- --post-data="{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"call\",\"params\":[\"00000000000000000000000000000000\",\"luci-rpc\",\"getBoardJSON\",{}]}" http://127.0.0.1/ubus | head -c 200; echo' > "$d/jsonrpc.txt"
r 'ubus call system board; ubus call session list "{\"ubus_rpc_session\":\"00000000000000000000000000000000\"}" | head -c 300; echo; ubus call iwinfo devices; ubus call rc list | head -c 200; echo' | sed -E '/"(uptime|localtime)"/d' > "$d/ubus-probes.txt"
r 'fw_printenv flag_boot_rootfs flag_boot_success flag_last_success flag_try_sys1_failed flag_try_sys2_failed flag_ota_reboot' > "$d/boot-flags.txt"
r 'uptime; cat /proc/cmdline' > "$d/uptime-cmdline.txt"
r 'logread 2>/dev/null | grep -iE "owrt|rpcd-rs|httpd-rs|logd-rs|fw4|uci-rs|reload_config|segfault|respawn|exited|failsafe|bootcount" | tail -80' > "$d/logread-ours.txt" || true

echo "captured $mode -> $d"
[ "$mode" = post ] || exit 0

echo
echo "=== diff pre -> post (structural files)"
fail=0
for f in ubus-list init-enabled bind-mounts owrt-switch-status processes nft-ruleset config-hashes binary-hashes links wireless-status iwinfo uci-export-hash jsonrpc ubus-probes; do
	if diff -u "$out/pre/$f.txt" "$out/post/$f.txt" > "$out/$f.diff"; then
		rm -f "$out/$f.diff"; echo "same  $f"
	else
		echo "DIFF  $f  (see $out/$f.diff)"; fail=$((fail + 1))
	fi
done
echo
echo "=== boot flags"; paste "$out/pre/boot-flags.txt" "$out/post/boot-flags.txt" | awk -F'\t' '{printf "%-32s -> %s\n", $1, $2}'
echo "=== uptime/cmdline"; cat "$out/post/uptime-cmdline.txt"
echo
echo "structural diffs: $fail"
[ "$fail" -eq 0 ]
