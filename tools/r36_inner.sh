#!/bin/sh
# Runs inside the chroot. $1 is the ubusd binary to test. Every line printed
# here is compared byte for byte between the two runs, so nothing that varies
# by construction (pids, random ids, timings) may be printed raw.
set -u
daemon=$1
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out
chmod 1777 /var/run/ubus
ip link set lo up 2>/dev/null || true

"$daemon" >/tmp/out/ubusd.log 2>&1 &
bus=$!
i=0; while [ $i -lt 10 ]; do ubus list >/dev/null 2>&1 && break; i=$((i+1)); sleep 1; done

say() { printf '%s\n' "$*"; }
# ubus prints ids as hex; mask them so only structure is compared.
mask() { sed -e 's/@[0-9a-f]\{8\}/@ID/g' -e 's/"id": *[0-9]*/"id":ID/g'; }

say "--- 1. empty bus"
say "list: [$(ubus list | tr '\n' ' ')]"
say "list_rc: $?"

say "--- 2. ping and an unknown method on a system object"
ubus -S call event nosuchmethod '{}' >/dev/null 2>&1; say "event.nosuchmethod rc=$?"
ubus -S call acl query '{}' >/dev/null 2>&1; say "acl.query rc=$?"
ubus -S call monitor add '{}' >/dev/null 2>&1; say "monitor.add(root) rc=$?"
ubus -S call monitor remove '{}' >/dev/null 2>&1; say "monitor.remove(root) rc=$?"
ubus -S call monitor bogus '{}' >/dev/null 2>&1; say "monitor.bogus rc=$?"

say "--- 3. lookup of an absent object"
ubus -S list nosuch >/dev/null 2>&1; say "list nosuch rc=$?"
ubus -S call nosuch method '{}' >/dev/null 2>&1; say "call nosuch rc=$?"
ubus -S list 'nosuch*' >/dev/null 2>&1; say "list wildcard-nosuch rc=$?"

say "--- 4. a real provider: rpcd"
/sbin/rpcd >/tmp/out/rpcd.log 2>&1 &
i=0; while [ $i -lt 15 ]; do ubus list | grep -q '^uci$' && break; i=$((i+1)); sleep 1; done
say "objects: [$(ubus list | sort | tr '\n' ' ')]"
say "session_signature: [$(ubus -v list session | grep -o '"[a-z_]*":' | sort -u | tr '\n' ' ')]"
say "uci_methods: [$(ubus -v list uci | sed -n 's/^\t"\([a-z_]*\)".*/\1/p' | sort | tr '\n' ' ')]"

say "--- 5. invoke with data, and the reply path"
say "session_create: $(ubus -S call session create '{"timeout":30}' | mask | sed 's/"ubus_rpc_session":"[0-9a-f]*"/"sid":MASKED/')"
ubus -S call session list '{}' >/dev/null 2>&1; say "session.list rc=$?"
ubus -S call uci get '{"config":"system","section":"@system[0]","option":"hostname"}' >/dev/null 2>&1
say "uci.get rc=$?"
ubus -S call uci get '{"config":"nosuchconfig"}' >/dev/null 2>&1; say "uci.get(missing) rc=$?"
ubus -S call session nosuchmethod '{}' >/dev/null 2>&1; say "session.nosuchmethod rc=$?"

say "--- 6. wildcard lookup"
say "list network*: [$(ubus list 'n*' | sort | tr '\n' ' ')]"
say "list u*: [$(ubus list 'u*' | sort | tr '\n' ' ')]"

say "--- 7. events: register a listener, then send"
( ubus listen test.event > /tmp/out/listen.txt 2>&1 ) &
lp=$!
sleep 1
ubus -S send test.event '{"k":"v"}'; say "send rc=$?"
ubus -S send ubus.reserved '{"k":"v"}' 2>/dev/null; say "send reserved rc=$?"
sleep 1
kill $lp 2>/dev/null
say "listen_got: [$(cat /tmp/out/listen.txt | tr -d '\n\t ' )]"

say "--- 8. object add/remove seen as events"
( ubus listen 'ubus.object.*' > /tmp/out/objev.txt 2>&1 ) &
op=$!
sleep 1
/sbin/rpcd -s /var/run/ubus/ubus.sock >/dev/null 2>&1 &
extra=$!
sleep 1
kill $extra 2>/dev/null
sleep 1
kill $op 2>/dev/null
say "object_events_seen: $(grep -c 'ubus.object' /tmp/out/objev.txt || true)"

say "--- 9. non-root access (luci-base.json grants nobody only system.board/info)"
if [ -x /tmp/asuser ]; then
	say "nobody_uci_rc: $(/tmp/asuser nobody /bin/ubus -S call uci changes '{}' >/dev/null 2>&1; echo $?)"
	say "nobody_list: [$(/tmp/asuser nobody /bin/ubus list 2>/dev/null | sort | tr '\n' ' ')]"
	say "nobody_session_login_rc: $(/tmp/asuser nobody /bin/ubus -S call session login '{}' >/dev/null 2>&1; echo $?)"
else
	say "nobody: helper missing, skipped"
fi

say "--- 10. malformed input"
# a length field far beyond the cap must get the connection dropped, not crash
printf '\x00\x04\x00\x01\x00\x00\x00\x00\xff\xff\xff\xff' | timeout 2 nc -U /var/run/ubus/ubus.sock >/dev/null 2>&1
say "oversize_len_survived: $(ubus list >/dev/null 2>&1 && echo yes || echo no)"
printf '\x00\x04\x00\x01' | timeout 2 nc -U /var/run/ubus/ubus.sock >/dev/null 2>&1
say "short_header_survived: $(ubus list >/dev/null 2>&1 && echo yes || echo no)"

# Diagnostics, not part of the compared transcript.
{
  echo "=== ubusd.log"; cat /tmp/out/ubusd.log
  echo "=== rpcd.log"; cat /tmp/out/rpcd.log 2>/dev/null
  echo "=== listen.txt"; cat /tmp/out/listen.txt 2>/dev/null
  echo "=== objev.txt"; cat /tmp/out/objev.txt 2>/dev/null
} > /tmp/out/diagnostics.txt 2>&1
cp /tmp/out/diagnostics.txt /diagnostics.txt 2>/dev/null || true

say "--- 11. still healthy at the end"
say "final_objects: [$(ubus list | sort | tr '\n' ' ')]"
say "daemon_alive: $(kill -0 $bus 2>/dev/null && echo yes || echo no)"
kill $bus 2>/dev/null
exit 0
