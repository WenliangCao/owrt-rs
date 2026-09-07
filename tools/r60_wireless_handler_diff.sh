#!/bin/sh
# R60: the wireless handler protocol and the radio state machine, C against
# netifd-rs, with no radios and no device involved.
#
# `/lib/netifd/wireless/mac80211.sh` is replaced by a stub. Both daemons drive
# the same stub and are compared on: the sequence of setup/teardown calls, the
# JSON of the first setup, the registered ubus signature, and `status`.
#
# MODE=fail (default) -- the stub answers `dump` and otherwise does nothing.
#   netifd sees a handler that never reported its interfaces up, so the retry
#   budget and the setup/teardown ordering are exercised: four setups, then the
#   radio gives up.
# MODE=flood -- two radios; radio0's handler writes far more than a pipe holds
#   on both streams, including a long run with no newline, before reporting up.
#   A handler read only at exit deadlocks there and radio1 never starts, because
#   handlers are serialised. Both radios reaching up is the assertion.
# MODE=up -- the stub calls back the way netifd-wireless.sh does, first
#   `_wireless_add_vif` (command 1, with an ifname) and then `_wireless_set_up`
#   (command 0). That drives the radio to `up` and puts `ifname` in `status`,
#   which is the part a stub can reach without hardware.
#
# The setup JSON is compared parsed AND re-serialised, so key order counts.
#
# Usage: [MODE=up] r60_wireless_handler_diff.sh <rootfs> <netifd-rs musl> [outdir]
set -eu
rootfs=$1; cand=$2; out=${3:-/tmp/r60-out}
MODE=${MODE:-fail}
# CMDS=yes also walks up/down/retry/reconf and reads the state after each
CMDS=${CMDS:-no}
mkdir -p "$out"

run() {
	tag=$1
	w=$(mktemp -d /tmp/r60.XXXXXX); sudo -n cp -a "$rootfs"/. "$w"/ 2>/dev/null || true
	sudo -n mkdir -p "$w/etc/config" "$w/var/run" "$w/tmp/out"
	sudo -n chown -R root:root "$w/usr/share/acl.d" 2>/dev/null || true
	sudo -n cp /tmp/r60-stub.sh "$w/lib/netifd/wireless/mac80211.sh"
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

config wifi-device 'radio1'
	option type 'mac80211'
	option path 'platform/soc/18000000.wifi+1'
	option band '5g'
	option channel '36'

config wifi-iface 'default_radio1'
	option device 'radio1'
	option network 'lan'
	option mode 'ap'
	option ssid 'probe5'
	option encryption 'none'

config wifi-iface 'default_radio0'
	option device 'radio0'
	option network 'lan'
	option mode 'ap'
	option ssid 'probe'
	option encryption 'none'

config wifi-vlan 'v1'
	option iface 'default_radio0'
	option name 'guest'
	option vid '10'
	list network 'guest'

config wifi-vlan 'v_all'
	option vid '20'
	option name 'everywhere'

config wifi-vlan 'v_off'
	option iface 'default_radio0'
	option vid '30'
	option disabled '1'

config wifi-station 's1'
	option iface 'default_radio0'
	option mac '02:00:00:00:00:aa'
	option key 'k1'

config wifi-station 's_other'
	option iface 'nosuchiface'
	option mac '02:00:00:00:00:bb'
X
	sudo -n CMDS="$CMDS" unshare --mount --net --pid --fork --mount-proc=/proc sh -c '
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
	  sed -E "s/ \{.*//" "$m/tmp/out/handler.log" > "$o/$t-calls.txt" 2>/dev/null || true
	  grep -m1 " setup " "$m/tmp/out/handler.log" 2>/dev/null \
		| sed -E "s/^ARGV: [a-z0-9]+ setup [a-z0-9]+ //" > "$o/$t-json.txt" || true
	  if [ "$CMDS" = yes ]; then
	    # Each command, with the state after it. The state machine is what is
	    # being compared, so the radio is walked through down -> retry -> up
	    # -> reconf and read back at every step.
	    for c in down retry up reconf down up; do
	      echo "--- after $c" >> "$o/$t-cmds.txt"
	      chroot "$m" ubus call network.wireless $c "{\"device\":\"radio0\"}" >> "$o/$t-cmds.txt" 2>&1
	      sleep 2
	      chroot "$m" ubus call network.wireless status 2>/dev/null \
		| tr -d " \t\n" \
		| grep -oE "\"(up|pending|autostart|retry_setup_failed)\":(true|false)" \
		| tr "\n" " " >> "$o/$t-cmds.txt"
	      echo "" >> "$o/$t-cmds.txt"
	    done
	    echo "--- bad device" >> "$o/$t-cmds.txt"
	    chroot "$m" ubus call network.wireless up "{\"device\":\"nosuch\"}" >> "$o/$t-cmds.txt" 2>&1
	    echo "" >> "$o/$t-cmds.txt"
	  fi
	  # calls again, AFTER the commands: the first capture only covers
	  # startup, so a setup a command triggers is invisible there
	  sed -E "s/ \{.*//" "$m/tmp/out/handler.log" > "$o/$t-calls-after.txt" 2>/dev/null || true
	  chroot "$m" ubus call network.wireless status > "$o/$t-status.json" 2>&1 || true
	  chroot "$m" ubus -v list network.wireless > "$o/$t-sig.txt" 2>&1 || true
	  cp "$m/tmp/out/n.log" "$o/$t-daemon.log" 2>/dev/null || true
	  pkill -9 -f "netifd|ubusd" 2>/dev/null || true
	' sh "$w" "$tag" "$out"
	sudo -n rm -rf "$w"
}

# the stub, written once so both runs get exactly the same bytes
cat > /tmp/r60-stub.sh <<STUB
#!/bin/sh
echo "ARGV: \$*" >> /tmp/out/handler.log
if [ "\${2:-}" = "dump" ] || [ "\${1:-}" = "dump" ]; then
	echo '{ "name": "mac80211", "device": [ [ "channel", 3 ], [ "band", 3 ], [ "path", 3 ] ], "iface": [ [ "ssid", 3 ], [ "encryption", 3 ] ], "vlan": [ [ "name", 3 ], [ "vid", 3 ] ], "station": [ [ "mac", 3 ], [ "key", 3 ] ] }'
	exit 0
fi
if [ "\$2" = setup ] && [ "$MODE" = flood ] && [ "\$3" = radio0 ]; then
	# more than a pipe holds, on both streams, plus a long line with no
	# newline at all -- a handler that is only read at exit deadlocks here
	# 2000 lines of ~90 bytes is ~180 KiB per stream, comfortably past the
	# 64 KiB a Linux pipe holds. 400 lines was ~36 KiB and would not have
	# blocked at all -- the case has to exceed the buffer to test anything.
	i=0
	while [ \$i -lt 2000 ]; do
		echo "stdout flood line \$i 0123456789012345678901234567890123456789012345678901234567890123456789"
		echo "stderr flood line \$i 0123456789012345678901234567890123456789012345678901234567890123456789" >&2
		i=\$((i+1))
	done
	j=0
	while [ \$j -lt 4000 ]; do printf "no-newline-chunk-%s" "\$j"; j=\$((j+1)); done
fi
if [ "\$2" = setup ] && { [ "$MODE" = up ] || [ "$MODE" = flood ]; }; then
	ubus call network.wireless notify "{\"command\":1,\"device\":\"\$3\",\"interface\":\"01\",\"data\":{\"ifname\":\"stub-ap0\"}}" >> /tmp/out/handler.log 2>&1
	ubus call network.wireless notify "{\"command\":0,\"device\":\"\$3\",\"data\":{}}" >> /tmp/out/handler.log 2>&1
fi
exit 0
STUB

run c
run rs

rc=0
echo "=== handler call sequence (MODE=$MODE)"
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
if a == b and json.dumps(a) == json.dumps(b):
	print("RESULT(payload): identical, key order included"); sys.exit(0)
print("payload: DIFFERS")
print("  C:  " + json.dumps(a)[:600])
print("  rs: " + json.dumps(b)[:600])
sys.exit(1)
PY

echo "=== registered signature"
# the @id is assigned per registration and is not part of the contract
sed -i -E "s/@[0-9a-f]+/@ID/" "$out/c-sig.txt" "$out/rs-sig.txt" 2>/dev/null || true
if diff -u "$out/c-sig.txt" "$out/rs-sig.txt" > "$out/sig.diff" 2>/dev/null; then
	echo "RESULT(signature): identical"
else
	echo "signature: DIFFERS"; sed -n '1,24p' "$out/sig.diff"; rc=1
fi

if [ "$CMDS" = yes ]; then
	echo "=== handler calls after the commands"
	if diff -u "$out/c-calls-after.txt" "$out/rs-calls-after.txt" > "$out/calls-after.diff" 2>/dev/null; then
		echo "RESULT(calls after): identical -- $(grep -c setup "$out/c-calls-after.txt") setups total"
	else
		echo "calls after: DIFFERS"; sed -n '1,30p' "$out/calls-after.diff"; rc=1
	fi
	echo "=== command state machine"
	if diff -u "$out/c-cmds.txt" "$out/rs-cmds.txt" > "$out/cmds.diff" 2>/dev/null; then
		echo "RESULT(commands): identical"
		sed -n '1,40p' "$out/c-cmds.txt" | sed 's/^/  /'
	else
		echo "commands: DIFFERS"; sed -n '1,40p' "$out/cmds.diff"; rc=1
	fi
fi

echo "=== status"
python3 - "$out/c-status.json" "$out/rs-status.json" <<'PY' || rc=1
import json, sys
def load(p):
	try:
		return json.load(open(p))
	except Exception:
		return {"__raw__": open(p).read().strip()[:200]}
a, b = load(sys.argv[1]), load(sys.argv[2])
def show(tag, o):
	if not isinstance(o, dict): return
	for radio, body in o.items():
		if isinstance(body, dict):
			ifn = [i.get("ifname") for i in body.get("interfaces", [])]
			print(f"  {tag} {radio}: up={body.get('up')} pending={body.get('pending')} "
			      f"retry_setup_failed={body.get('retry_setup_failed')} ifname={ifn}")
if a == b and json.dumps(a) == json.dumps(b):
	print("RESULT(status): identical, key order included"); show("  ", a); sys.exit(0)
print("status: DIFFERS"); show("C ", a); show("rs", b)
print("  C:  " + json.dumps(a)[:700])
print("  rs: " + json.dumps(b)[:700])
sys.exit(1)
PY

[ $rc -eq 0 ] && echo "R60: identical" || echo "R60: DIFFERENCES"
exit $rc
