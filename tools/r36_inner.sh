#!/bin/sh
# Runs inside the chroot. $1 is the ubusd binary to test. Every line printed
# here is compared byte for byte between the two runs, so nothing that varies
# by construction (pids, random ids, timings) may be printed raw.
set -u
daemon=$1
# On the device procd starts the bus with service_start_early("ubus",
# "/sbin/ubusd", "ubus", "ubus"), i.e. as uid/gid 81, not as root. Set
# DAEMON_USER=ubus to reproduce that; the directory is pre-created and owned
# the way procd leaves it.
DAEMON_USER=${DAEMON_USER:-root}
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out
chmod 1777 /var/run/ubus
ip link set lo up 2>/dev/null || true

if [ "$DAEMON_USER" = root ]; then
	"$daemon" >/tmp/out/ubusd.log 2>&1 &
else
	chown "$DAEMON_USER" /var/run/ubus 2>/dev/null || true
	/tmp/asuser "$DAEMON_USER" "$daemon" >/tmp/out/ubusd.log 2>&1 &
fi
bus=$!
i=0; while [ $i -lt 10 ]; do ubus list >/dev/null 2>&1 && break; i=$((i+1)); sleep 1; done

say() { printf '%s\n' "$*"; }
# No `timeout` applet in this rootfs: run in the background, kill after N secs.
run_for() {
	secs=$1; shift
	"$@" &
	rp=$!
	( sleep "$secs"; kill "$rp" 2>/dev/null ) &
	kp=$!
	wait "$rp" 2>/dev/null
	kill "$kp" 2>/dev/null
	wait "$kp" 2>/dev/null
	return 0
}
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

say "--- 8. object add/remove events (kill the provider, then bring it back)"
( ubus listen 'ubus.object.*' > /tmp/out/objev.txt 2>&1 ) &
op=$!
sleep 1
killall rpcd 2>/dev/null
sleep 2
say "removes_seen: $(grep -c 'ubus.object.remove' /tmp/out/objev.txt || true)"
say "objects_after_kill: [$(ubus list | sort | tr '\n' ' ')]"
/sbin/rpcd >/tmp/out/rpcd2.log 2>&1 &
i=0; while [ $i -lt 15 ]; do ubus list | grep -q '^uci$' && break; i=$((i+1)); sleep 1; done
sleep 1
kill $op 2>/dev/null
say "adds_seen: $(grep -c 'ubus.object.add' /tmp/out/objev.txt || true)"

say "--- 9. non-root access (luci-base.json grants nobody only system.board/info)"
if [ -x /tmp/asuser ]; then
	say "nobody_uci_rc: $(/tmp/asuser nobody /bin/ubus -S call uci changes '{}' >/dev/null 2>&1; echo $?)"
	say "nobody_list: [$(/tmp/asuser nobody /bin/ubus list 2>/dev/null | sort | tr '\n' ' ')]"
	say "nobody_session_login_rc: $(/tmp/asuser nobody /bin/ubus -S call session login '{}' >/dev/null 2>&1; echo $?)"
else
	say "nobody: helper missing, skipped"
fi

# Absolute counts differ legitimately between the two daemons; only the change
# across the churn below is comparable.
fdcount() { ls /proc/$bus/fd 2>/dev/null | wc -l; }
fd_base=$(fdcount)

say "--- 10. malformed input and antisocial clients"
if [ -x /tmp/busprobe ]; then
	S=/var/run/ubus/ubus.sock
	# length field past the cap: the connection must be dropped, not the daemon
	/tmp/busprobe raw $S 000400010000000000ffffff >/dev/null 2>&1; say "oversize_len probe_rc=$?"
	say "oversize_len_survived: $(ubus list >/dev/null 2>&1 && echo yes || echo no)"
	# a blob header shorter than a blob_attr
	/tmp/busprobe raw $S 000400010000000000000002 >/dev/null 2>&1; say "undersize_len probe_rc=$?"
	say "undersize_len_survived: $(ubus list >/dev/null 2>&1 && echo yes || echo no)"
	# truncated header, then EOF
	/tmp/busprobe raw $S 00040001 >/dev/null 2>&1; say "short_header probe_rc=$?"
	say "short_header_survived: $(ubus list >/dev/null 2>&1 && echo yes || echo no)"
	# a body that never arrives
	/tmp/busprobe half $S >/dev/null 2>&1; say "half_message probe_rc=$?"
	say "half_message_survived: $(ubus list >/dev/null 2>&1 && echo yes || echo no)"
	# a client that asks for everything and never reads the answer
	/tmp/busprobe slow $S 3 >/dev/null 2>&1 & sp=$!
	sleep 1
	say "during_slow_client_list: [$(ubus list | sort | tr '\n' ' ')]"
	say "during_slow_client_call_rc: $(ubus -S call session list '{}' >/dev/null 2>&1; echo $?)"
	wait $sp 2>/dev/null
	say "after_slow_client_survived: $(ubus list >/dev/null 2>&1 && echo yes || echo no)"
	# a caller that vanishes without reading its reply
	/tmp/busprobe drop $S >/dev/null 2>&1; say "drop probe_rc=$?"
	say "drop_survived: $(ubus list >/dev/null 2>&1 && echo yes || echo no)"
else
	say "probe: helper missing, skipped"
fi

say "--- 12. subscribe and notify"
ubus -S subscribe nosuchobject >/dev/null 2>&1; say "subscribe_missing_rc=$?"
ubus subscribe uci > /tmp/out/sub.txt 2>&1 &
sb=$!
sleep 1
say "subscribe_alive: $(kill -0 $sb 2>/dev/null && echo yes || echo no)"
say "during_subscribe_list_rc: $(ubus list >/dev/null 2>&1; echo $?)"
say "during_subscribe_call_rc: $(ubus -S call session list '{}' >/dev/null 2>&1; echo $?)"
say "subscribe_stderr: [$(tr -d '\n\t ' < /tmp/out/sub.txt)]"
kill $sb 2>/dev/null; wait $sb 2>/dev/null
say "after_subscribe_list_rc: $(ubus list >/dev/null 2>&1; echo $?)"

say "--- 13. wait_for: present returns at once, absent blocks on the add event"
ubus wait_for luci > /tmp/out/wait.txt 2>&1 &
wf=$!
sleep 2
say "wait_for_present_finished: $(kill -0 $wf 2>/dev/null && echo no || echo yes)"
kill $wf 2>/dev/null; wait $wf 2>/dev/null
ubus wait_for never.appears > /tmp/out/wait2.txt 2>&1 &
wf2=$!
sleep 2
say "wait_for_absent_still_waiting: $(kill -0 $wf2 2>/dev/null && echo yes || echo no)"
kill $wf2 2>/dev/null; wait $wf2 2>/dev/null

say "--- 14. an fd rides on the reply (logd stream)"
/sbin/logd -S 16 >/tmp/out/logd.log 2>&1 &
i=0; while [ $i -lt 10 ]; do ubus list | grep -q '^log$' && break; i=$((i+1)); sleep 1; done
say "log_object: [$(ubus list | grep '^log$')]"
ubus -S call log write '{"event":"r36-probe"}' >/dev/null 2>&1; say "log_write_rc=$?"
# plain read: an ordinary invoke whose reply carries no descriptor
/usr/libexec/logread-ubox > /tmp/out/logread.txt 2>&1
say "logread_rc=$?"
say "logread_saw_probe: $(grep -c 'r36-probe' /tmp/out/logread.txt || true)"

# `-f` is the real SCM_RIGHTS path: logd.c creates a pipe and attaches the read
# end with ubus_request_set_fd, which libubus sends on the STATUS reply -- the
# one message type ubusd must not close the descriptor on. The follower only
# sees messages written after it connects, so it has to start first.
/usr/libexec/logread-ubox -f > /tmp/out/logfollow.txt 2>&1 &
f1=$!
sleep 2
ubus -S call log write '{"event":"r36-stream-one"}' >/dev/null 2>&1
sleep 2
say "follow_saw_stream_one: $(grep -c 'r36-stream-one' /tmp/out/logfollow.txt || true)"

# two followers at once: two descriptors alive through the daemon
/usr/libexec/logread-ubox -f > /tmp/out/logfollow2.txt 2>&1 &
f2=$!
sleep 2
ubus -S call log write '{"event":"r36-stream-two"}' >/dev/null 2>&1
sleep 2
say "follow1_saw_stream_two: $(grep -c 'r36-stream-two' /tmp/out/logfollow.txt || true)"
say "follow2_saw_stream_two: $(grep -c 'r36-stream-two' /tmp/out/logfollow2.txt || true)"
kill $f1 $f2 2>/dev/null; wait $f1 2>/dev/null; wait $f2 2>/dev/null

# the bus is still healthy after descriptors have travelled through it
say "after_streams_list_rc: $(ubus list >/dev/null 2>&1; echo $?)"
say "after_streams_call_rc: $(ubus -S call log read '{"lines":1,"stream":false}' >/dev/null 2>&1; echo $?)"
killall logd 2>/dev/null

# Diagnostics, not part of the compared transcript.
{
  echo "=== ubusd.log"; cat /tmp/out/ubusd.log
  echo "=== rpcd.log"; cat /tmp/out/rpcd.log 2>/dev/null
  echo "=== listen.txt"; cat /tmp/out/listen.txt 2>/dev/null
  echo "=== objev.txt"; cat /tmp/out/objev.txt 2>/dev/null
} > /tmp/out/diagnostics.txt 2>&1
cp /tmp/out/diagnostics.txt /diagnostics.txt 2>/dev/null || true

say "--- 16. monitor mirrors the traffic of one call, message for message"
# `ubus monitor` prints: direction, client id, peer id, type name, data.
# The two ids are random per run, so only the direction/type sequence and the
# message count can be compared; the data is masked the same way on both sides.
ubus monitor > /tmp/out/monitor.txt 2>&1 &
mp=$!
sleep 2
ubus -S call session list '{}' >/dev/null 2>&1
sleep 2
kill $mp 2>/dev/null; wait $mp 2>/dev/null
say "monitor_lines: $(grep -c . /tmp/out/monitor.txt || true)"
say "monitor_sequence: [$(sed -n 's/^\(->\|<-\) [0-9a-f]* #[0-9a-f]* *\([A-Za-z]*\):.*/\1\2/p' /tmp/out/monitor.txt | tr '\n' ' ')]"
say "monitor_saw_invoke: $(grep -c 'INVOKE' /tmp/out/monitor.txt || true)"
say "monitor_saw_lookup: $(grep -c 'LOOKUP' /tmp/out/monitor.txt || true)"
say "monitor_nonroot_denied: $([ -x /tmp/asuser ] && { /tmp/asuser nobody /bin/ubus monitor >/dev/null 2>&1; echo $?; } || echo skipped)"

say "--- 15. no descriptor or client leak across all of the above"
fd_now=$(fdcount)
say "fd_delta_since_probe_start: $((fd_now - fd_base))"
# churn: 20 connect/disconnect cycles must leave nothing behind
i=0; while [ $i -lt 20 ]; do ubus list >/dev/null 2>&1; i=$((i+1)); done
say "fd_delta_after_20_clients: $(( $(fdcount) - fd_base ))"
say "still_serving: $(ubus -S call session list '{}' >/dev/null 2>&1; echo $?)"

say "--- 11. still healthy at the end"
say "final_objects: [$(ubus list | sort | tr '\n' ' ')]"
say "daemon_alive: $(kill -0 $bus 2>/dev/null && echo yes || echo no)"
kill $bus 2>/dev/null
exit 0
