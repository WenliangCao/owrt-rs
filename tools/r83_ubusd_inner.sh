#!/bin/sh
# Runs inside the chroot (r83). $1 is the ubusd binary under test. Every line
# printed is compared byte for byte between the C run and the Rust run, so
# nothing that varies by construction (pids, random ids) is printed raw.
set -u
daemon=$1
mkdir -p /var/run/ubus /var/lock /tmp/out
chmod 1777 /var/run/ubus
S=/var/run/ubus/ubus.sock
ACL=/usr/share/acl.d

# A test-only ACL file next to the device's real ones: a private `acl` table
# for root's r83.priv object, which `acl query` echoes back typed the way the
# loader stored it. Created here as root:root 0644, which is what the loader
# demands. The device's own wpad_acl.json grants user `network` send on bss.*.
cat > $ACL/r83_probe.json <<'EOF'
{ "user": "root",
  "access": { "r83.priv": { "acl": { "n": 1, "neg": -5, "big": 3000000000, "s": "x",
                                     "b": true, "f": 1.5, "z": null, "arr": [ 1, "a" ], "t": { "k": 2 } } } } }
EOF
chmod 644 $ACL/r83_probe.json

"$daemon" >/tmp/out/ubusd.log 2>&1 &
bus=$!
i=0; while [ $i -lt 10 ]; do ubus list >/dev/null 2>&1 && break; i=$((i+1)); sleep 1; done

say() { printf '%s\n' "$*"; }
as() { /tmp/asuser "$@"; }
rc() { "$@" >/dev/null 2>&1; echo $?; }

say "--- 1. non-root callers of the pathless system objects (F02)"
# hostapd runs as `network`; its ubus_send_event("bss.add") is an INVOKE of
# the event object, which has no path, followed by the SEND check on the id
say "network_send_bss: rc=$(rc as network /bin/ubus -S send bss.add '{"k":1}')"
say "network_send_wps: rc=$(rc as network /bin/ubus -S send wps_credentials '{}')"
say "network_send_unlisted: rc=$(rc as network /bin/ubus -S send other.evt '{}')"
say "nobody_send_bss: rc=$(rc as nobody /bin/ubus -S send bss.add '{}')"
say "root_send_bss: rc=$(rc ubus -S send bss.add '{}')"
# `ubus call acl query` is a path LOOKUP first and the acl object has none:
# NOT_FOUND on both sides, which is why r36 saw nothing. The probe INVOKEs id 2.
say "cli_call_acl_query: rc=$(rc as nobody /bin/ubus -S call acl query '{}')"
say "nobody_pathless: $(as nobody /tmp/wireprobe $S pathless 2>&1 | tr '\n' ' ')"
say "network_pathless: $(as network /tmp/wireprobe $S pathless 2>&1 | tr '\n' ' ')"
say "root_pathless: $(/tmp/wireprobe $S pathless 2>&1 | tr '\n' ' ')"
# listen as network (LISTEN acl is not granted to network: register denied),
# and as root; wpad_acl.json has no "listen" key at all
say "network_listen_bss: rc=$(rc as network /bin/ubus -t 1 listen 'bss.*')"
( ubus listen 'bss.*' > /tmp/out/listen-root.txt 2>&1 ) & lp=$!
sleep 1
say "network_send_while_root_listens: rc=$(rc as network /bin/ubus -S send bss.add '{"k":1}')"
sleep 1; kill $lp 2>/dev/null; wait $lp 2>/dev/null
say "root_listen_got: [$(tr -d '\n\t ' < /tmp/out/listen-root.txt)]"
say "network_monitor: rc=$(rc as network /bin/ubus -t 1 monitor)"

say "--- 2. SIGHUP against an empty, missing or dotfile-only acl.d (F27)"
( ubus listen ubus.acl.sequence > /tmp/out/aclseq.txt 2>&1 ) & ap=$!
sleep 1
mv $ACL $ACL.off; mkdir -m 755 $ACL
kill -HUP $bus; sleep 1
say "empty_dir_hup_network_send_bss: rc=$(rc as network /bin/ubus -S send bss.add '{}')"
say "empty_dir_hup_seq_events: $(grep -c . /tmp/out/aclseq.txt || true)"
echo 'not json' > $ACL/README; kill -HUP $bus; sleep 1
say "no_json_hup_network_send_bss: rc=$(rc as network /bin/ubus -S send bss.add '{}')"
rm -rf $ACL; kill -HUP $bus; sleep 1
say "missing_dir_hup_network_send_bss: rc=$(rc as network /bin/ubus -S send bss.add '{}')"
say "missing_dir_hup_seq_events: $(grep -c . /tmp/out/aclseq.txt || true)"
mv $ACL.off $ACL; kill -HUP $bus; sleep 1
say "restored_hup_network_send_bss: rc=$(rc as network /bin/ubus -S send bss.add '{}')"
say "restored_hup_seq_events: $(grep -c . /tmp/out/aclseq.txt || true)"
printf '{"user":"nobody","send":["r83dot.*"]}\n' > $ACL/.r83dot.json; chmod 644 $ACL/.r83dot.json
kill -HUP $bus; sleep 1
say "dotfile_hup_nobody_send: rc=$(rc as nobody /bin/ubus -S send r83dot.x '{}')"
say "dotfile_hup_seq_events: $(grep -c . /tmp/out/aclseq.txt || true)"
rm -f $ACL/.r83dot.json
kill $ap 2>/dev/null; wait $ap 2>/dev/null
say "acl_seq_events_seen: [$(sed -n 's/.*"sequence": *\([0-9]*\).*/\1/p' /tmp/out/aclseq.txt | tr '\n' ' ')]"

say "--- 3. wire level: sequence numbers, attribute order, types (F27/F24)"
for sc in events monitor release aclquery utf8; do
	say "$sc: $(/tmp/wireprobe $S $sc 2>&1 | tr '\n' ' ')"
done
# what the C library's blobmsg_format_json prints for a non-UTF-8 STRING:
# the bytes themselves (0xe9), not an escape and not an empty string
( ubus listen r83.utf > /tmp/out/utf.txt 2>&1 ) & up=$!
sleep 1
/tmp/wireprobe $S utf8 >/dev/null 2>&1
sleep 1; kill $up 2>/dev/null; wait $up 2>/dev/null
# (this busybox has hexdump but no od)
say "cli_listen_utf8_hex: [$(hexdump -C /tmp/out/utf.txt | tr -s ' ' | tr '\n' '|')]"

say "--- 4. still healthy at the end"
say "final_objects: [$(ubus list | sort | tr '\n' ' ')]"
say "daemon_alive: $(kill -0 $bus 2>/dev/null && echo yes || echo no)"
{ echo "=== ubusd.log"; cat /tmp/out/ubusd.log; } > /tmp/out/diagnostics.txt 2>&1
kill $bus 2>/dev/null
exit 0
