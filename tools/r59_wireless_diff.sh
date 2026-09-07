#!/bin/sh
# R59: network.wireless's two read methods, C against netifd-rs.
#
# netifd-rs does not register `network.wireless` -- it cannot bring a radio up,
# and an object that reports radios down while they are up would be worse than
# no object at all. What it does have is the half that decides what those
# replies look like: the handler schema and the config projection. This
# compares that half directly, through `netifd-rs --dump-wireless`, against the
# C daemon's own `status` and `get_validate`.
#
# Both sides run inside a copy of the exact device rootfs, so both read the
# same /lib/netifd/wireless/mac80211.sh and the same /etc/config/wireless.
#
# The four state booleans in `status` (up, pending, autostart,
# retry_setup_failed) are reported here at their no-hardware values. They agree
# in this sandbox because the C's setup also fails here with no radio present.
# That agreement is NOT evidence for a box that has radios.
#
# Usage: r59_wireless_diff.sh <rootfs-files> <netifd-rs binary> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r59-out}
mkdir -p "$out"

NET='config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1/8"
'

# case A: no wireless config at all -- both read methods answer {}
# case B: one radio, one iface
# case C: two radios, disabled spellings UCI accepts but parse_bool does not,
#         a list where a scalar is declared, and an int-typed option
WL_B='config wifi-device "radio0"
	option type "mac80211"
	option path "platform/soc/18000000.wifi"
	option band "5g"
	option channel "36"
	option htmode "HE160"
	option disabled "0"

config wifi-iface "default_radio0"
	option device "radio0"
	option network "lan"
	option mode "ap"
	option ssid "probe"
	option encryption "none"
'

WL_C='config wifi-device "radio0"
	option type "mac80211"
	option band "2g"
	option channel "auto"
	option disabled "on"
	option beacon_int "150"
	option distance "0"
	list basic_rate "6000"
	list basic_rate "9000"

config wifi-device "radio1"
	option type "mac80211"
	option band "5g"
	option channel "36"
	option disabled "true"

config wifi-iface "ap0"
	option device "radio0"
	list network "lan"
	list network "guest"
	option mode "ap"
	option ssid "one"
	option isolate "1"
	option encryption "psk2"

config wifi-iface "ap1"
	option device "radio1"
	option network "lan wan"
	option mode "ap"
	option ssid "two"

config wifi-iface "orphan"
	option device "radio9"
	option mode "ap"
	option ssid "nowhere"

config wifi-device "unknown_type"
	option type "nosuchhandler"
	option channel "1"
'

norm() { sed -e 's/[[:space:]]\{1,\}/ /g' -e 's/^ //' -e 's/ $//' | tr -d '\n'; }

run_c() {
	w=$(mktemp -d /tmp/r59c.XXXXXX); cp -a "$rootfs"/. "$w"/
	mkdir -p "$w/etc/config" "$w/var/run" "$w/tmp"
	chown -R root:root "$w/usr/share/acl.d" 2>/dev/null || true
	printf '%s' "$NET" > "$w/etc/config/network"
	[ -n "$2" ] && printf '%s' "$2" > "$w/etc/config/wireless" || rm -f "$w/etc/config/wireless"
	unshare --mount --net --pid --fork --mount-proc=/proc sh -c '
	  m=$1; o=$2
	  mount --bind "$m" "$m"; mount --make-private "$m"
	  mount -t proc proc "$m/proc" 2>/dev/null || true
	  mount --rbind /sys "$m/sys" 2>/dev/null || true
	  mount -t tmpfs t "$m/tmp"; mkdir -p "$m/var/run"
	  ip link set lo up
	  chroot "$m" /sbin/ubusd & u=$!
	  sleep 1
	  chroot "$m" /sbin/netifd >/dev/null 2>&1 & n=$!
	  sleep 4
	  chroot "$m" ubus call network.wireless status       > "$o.status" 2>&1 || echo FAILED > "$o.status"
	  chroot "$m" ubus call network.wireless get_validate > "$o.validate" 2>&1 || echo FAILED > "$o.validate"
	  chroot "$m" ubus -v list network.wireless           > "$o.sig" 2>&1 || echo FAILED > "$o.sig"
	  kill -9 $n $u 2>/dev/null || true
	' sh "$w" "$1"
	rm -rf "$w"
}

run_rs() {
	w=$(mktemp -d /tmp/r59r.XXXXXX); cp -a "$rootfs"/. "$w"/
	mkdir -p "$w/etc/config"; cp "$cand" "$w/sbin/netifd-rs"; chmod 755 "$w/sbin/netifd-rs"
	printf '%s' "$NET" > "$w/etc/config/network"
	[ -n "$2" ] && printf '%s' "$2" > "$w/etc/config/wireless" || rm -f "$w/etc/config/wireless"
	unshare --mount --net --pid --fork --mount-proc=/proc sh -c '
	  m=$1; o=$2
	  mount --bind "$m" "$m"; mount --make-private "$m"
	  mount -t proc proc "$m/proc" 2>/dev/null || true
	  mount -t tmpfs t "$m/tmp"
	  chroot "$m" /sbin/netifd-rs --dump-wireless > "$o.raw" 2>&1 || echo '"'"'{}'"'"' > "$o.raw"
	' sh "$w" "$1"
	rm -rf "$w"
}

fail=0
for case in A B C; do
	case $case in
		A) wl='' ;;
		B) wl=$WL_B ;;
		C) wl=$WL_C ;;
	esac
	run_c  "$out/c-$case"  "$wl"
	run_rs "$out/rs-$case" "$wl"

	# the C pretty-prints; both sides are compared as normalised compact JSON
	python3 - "$out/c-$case" "$out/rs-$case" "$case" <<'PY' || fail=1
import json, sys
c, rs, case = sys.argv[1], sys.argv[2], sys.argv[3]
def load(p):
	t = open(p).read().strip()
	if not t or t == 'FAILED':
		return None
	try:
		return json.loads(t)
	except Exception:
		return {'__unparsed__': t}
want = {'status': load(c + '.status'), 'get_validate': load(c + '.validate')}
try:
	got = json.loads(open(rs + '.raw').read().strip())
except Exception as e:
	print(f'case {case}: candidate produced no JSON: {e}')
	print(open(rs + '.raw').read()[:400])
	sys.exit(1)
bad = 0
for k in ('status', 'get_validate'):
	a, b = want[k], got.get(k)
	if a == b:
		print(f'case {case} {k}: identical')
		continue
	bad = 1
	print(f'case {case} {k}: DIFFERENT')
	if isinstance(a, dict) and isinstance(b, dict):
		for radio in sorted(set(a) | set(b)):
			x, y = a.get(radio), b.get(radio)
			if x == y:
				continue
			print(f'  radio {radio}:')
			if not isinstance(x, dict) or not isinstance(y, dict):
				print(f'    C  = {json.dumps(x)[:300]}')
				print(f'    rs = {json.dumps(y)[:300]}')
				continue
			for f in sorted(set(x) | set(y)):
				if x.get(f) != y.get(f):
					print(f'    {f}:')
					print(f'      C  = {json.dumps(x.get(f))[:400]}')
					print(f'      rs = {json.dumps(y.get(f))[:400]}')
	else:
		print(f'  C  = {json.dumps(a)[:400]}')
		print(f'  rs = {json.dumps(b)[:400]}')
sys.exit(bad)
PY
done

echo
echo "--- C signature (netifd-rs does not register this object) ---"
cat "$out/c-B.sig"
echo "--- not covered: up/down/retry/reconf/notify need real radios ---"
echo "--- status's up/pending/autostart/retry_setup_failed are the"
echo "    no-hardware values on both sides and prove nothing about a"
echo "    box that has radios ---"

[ $fail -eq 0 ] && echo "R59: identical" || echo "R59: DIFFERENCES"
exit $fail
