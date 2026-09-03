#!/bin/sh
# Runs ON the router. Times the original (/rom) and the Rust implementation of
# the one-shot programs back to back, N iterations each, same inputs.
# Output: one line per case: name impl real_s user_s sys_s per_op_ms
# Requires the Rust layer enabled (/sbin/uci, /sbin/fw4, /sbin/reload_config are
# the bind-mounted candidates; /rom/sbin/* are the originals).
N=${N:-100}
NFW=${NFW:-20}

# busybox time: "real\t0m 0.12s" etc.
bench() { # name impl iterations command...
	name=$1; impl=$2; n=$3; shift 3
	out=$( { time sh -c 'i=0; while [ $i -lt '"$n"' ]; do '"$*"' >/dev/null 2>&1; i=$((i+1)); done'; } 2>&1 )
	echo "$out" | awk -v name="$name" -v impl="$impl" -v n="$n" '
		function sec(m, s) { sub("m","",m); sub("s","",s); return m*60 + s }
		/^real/ { r = sec($2,$3) } /^user/ { u = sec($2,$3) } /^sys/ { s = sec($2,$3) }
		END { printf "%-22s %-4s real=%.3fs user=%.3fs sys=%.3fs per_op=%.2fms\n", name, impl, r, u, s, r*1000/n }'
}

echo "# N=$N NFW=$NFW host=$(cat /proc/sys/kernel/hostname) $(date -Iseconds)"
echo "# sizes: $(ls -l /rom/sbin/uci /usr/sbin/uci-rs /rom/sbin/fw4 /usr/sbin/fw4-rs /rom/sbin/reload_config /usr/sbin/reload_config_rs | awk '{printf "%s=%s ", $9, $5}')"

# uci: read paths used by init scripts and LuCI
bench uci_export_network   rom $N /rom/sbin/uci -S -n export network
bench uci_export_network   rs  $N /sbin/uci -S -n export network
bench uci_export_all       rom $N /rom/sbin/uci -S -n export
bench uci_export_all       rs  $N /sbin/uci -S -n export
bench uci_show_firewall    rom $N /rom/sbin/uci -q show firewall
bench uci_show_firewall    rs  $N /sbin/uci -q show firewall
bench uci_get_lan_ipaddr   rom $N /rom/sbin/uci -q get network.lan.ipaddr
bench uci_get_lan_ipaddr   rs  $N /sbin/uci -q get network.lan.ipaddr

# uci write path on a scratch copy (set + commit), never /etc/config
rm -rf /tmp/bench-uci; mkdir -p /tmp/bench-uci; cp /etc/config/network /tmp/bench-uci/
bench uci_set_commit       rom $N "/rom/sbin/uci -c /tmp/bench-uci set network.lan.bench=1 && /rom/sbin/uci -c /tmp/bench-uci commit network"
bench uci_set_commit       rs  $N "/sbin/uci -c /tmp/bench-uci set network.lan.bench=1 && /sbin/uci -c /tmp/bench-uci commit network"
rm -rf /tmp/bench-uci

# fw4 ruleset generation (ucode script vs native)
bench fw4_print            rom $NFW /rom/sbin/fw4 print
bench fw4_print            rs  $NFW /sbin/fw4 print
bench fw4_check            rom $NFW /rom/sbin/fw4 check
bench fw4_check            rs  $NFW /sbin/fw4 check

# reload_config with an unchanged config (md5 walk only, emits no event)
bench reload_config_noop   rom $N /rom/sbin/reload_config
bench reload_config_noop   rs  $N /sbin/reload_config

# resident memory of the running Rust daemons (C counterparts measured in the swap windows)
for p in rpcd-rs httpd-rs logd-rs; do
	pid=$(pidof $p); [ -n "$pid" ] && echo "rss $p $(grep VmRSS /proc/$pid/status | awk '{print $2 " kB"}')"
done
