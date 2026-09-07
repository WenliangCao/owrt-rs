#!/bin/sh
# R60: the wireless handler protocol, C against netifd-rs, with no radios.
#
# `/lib/netifd/wireless/mac80211.sh` is replaced by a stub that answers `dump`
# and otherwise only records how it was called. Both daemons then drive the
# same stub, and what they hand it is compared: the sequence of setup and
# teardown calls, and the JSON of the first setup.
#
# That covers the part of the orchestration a sandbox can reach. A stub that
# never reports its interfaces up makes netifd retry, so the retry budget and
# the ordering are exercised too -- four setups, then the radio gives up.
# Bringing a real radio up is the handler's job and needs hardware.
#
# The JSON is compared as parsed JSON: the C pretty-prints and this build does
# not, and the whitespace is not part of the contract. Key order is.
#
# Usage: r60_wireless_handler_diff.sh <rootfs-files> <netifd-rs musl binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r60-out}
mkdir -p "$out"

run() {
	tag=$1
	w=$(mktemp -d /tmp/r60.XXXXXX); sudo -n cp -a "$rootfs"/. "$w"/ 2>/dev/null || true
	sudo -n mkdir -p "$w/etc/config" "$w/var/run" "$w/tmp/out"
	sudo -n chown -R root:root "$w/usr/share/acl.d" 2>/dev/null || true
	sudo -n tee "$w/lib/netifd/wireless/mac80211.sh" >/dev/null <<'STUB'
#!/bin/sh
echo "ARGV: $*" >> /tmp/out/handler.log
if [ "${2:-}" = "dump" ] || [ "${1:-}" = "dump" ]; then
	echo '{ "name": "mac80211", "device": [ [ "channel", 3 ], [ "band", 3 ], [ "path", 3 ] ], "iface": [ [ "ssid", 3 ], [ "encryption", 3 ] ] }'
	exit 0
fi
exit 0
STUB
	sudo -n chmod 755 "$w/lib/netifd/wireless/mac80211.sh"
	[ "$tag" = rs ] && { sudo -n cp "$cand" "$w/sbin/netifd-rs"; sudo -n chmod 755 "$w/sbin/netifd-rs"; }
	sudo -n tee "$w/etc/config/network" >/dev/null <<'X'
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1/8'
X
	sudo -n tee "$w/etc/config/wireless" >/dev/null <<'X'
config wifi-device 'radio0'
	option type 'mac80211'
	option path 'platform/soc/18000000.wifi'
	option band '2g'
	option channel '1'

config wifi-iface 'default_radio0'
	option device 'radio0'
	option network 'lan'
	option mode 'ap'
	option ssid 'probe'
	option encryption 'none'
X
	sudo -n unshare --mount --net --pid --fork --mount-proc=/proc sh -c '
	  m=$1; t=$2; o=$3
	  mount --bind "$m" "$m"; mount --make-private "$m"
	  mount -t proc proc "$m/proc" 2>/dev/null || true
	  mount --rbind /sys "$m/sys" 2>/dev/null || true
	  mount -t tmpfs tmp "$m/tmp"; mkdir -p "$m/var/run" "$m/tmp/out"
	  ip link set lo up
	  chroot "$m" /sbin/ubusd >/dev/null 2>&1 & sleep 1
	  if [ "$t" = c ]; then chroot "$m" /sbin/netifd >"$m/tmp/out/n.log" 2>&1 &
	  else chroot "$m" /sbin/netifd-rs >"$m/tmp/out/n.log" 2>&1 & fi
	  sleep 7
	  sed -E "s/ \\{.*//" "$m/tmp/out/handler.log" > "$o/$t-calls.txt" 2>/dev/null || true
	  grep -m1 " setup " "$m/tmp/out/handler.log" 2>/dev/null \
		| sed -E "s/^ARGV: [a-z0-9]+ setup [a-z0-9]+ //" > "$o/$t-json.txt" || true
	  pkill -9 -f "netifd|ubusd" 2>/dev/null || true
	' sh "$w" "$tag" "$out"
	sudo -n rm -rf "$w"
}

run c
run rs

rc=0
echo "=== handler call sequence"
if diff -u "$out/c-calls.txt" "$out/rs-calls.txt" > "$out/calls.diff"; then
	echo "RESULT(calls): identical -- $(grep -c setup "$out/c-calls.txt") setups, $(grep -c teardown "$out/c-calls.txt") teardowns"
else
	echo "calls: DIFFERS"; cat "$out/calls.diff"; rc=1
fi

echo "=== first setup payload"
python3 - "$out/c-json.txt" "$out/rs-json.txt" <<'PY' || rc=1
import json, sys
def load(p):
	t = open(p).read().strip()
	return json.loads(t) if t else None
a, b = load(sys.argv[1]), load(sys.argv[2])
if a is None or b is None:
	print(f"payload: MISSING (c={a is not None}, rs={b is not None})"); sys.exit(1)
# key order is part of the contract, so compare the re-serialised form too
if a == b and json.dumps(a) == json.dumps(b):
	print("RESULT(payload): identical, key order included")
	sys.exit(0)
print("payload: DIFFERS")
print("  C:  " + json.dumps(a)[:600])
print("  rs: " + json.dumps(b)[:600])
sys.exit(1)
PY

[ $rc -eq 0 ] && echo "R60: identical" || echo "R60: DIFFERENCES"
exit $rc
