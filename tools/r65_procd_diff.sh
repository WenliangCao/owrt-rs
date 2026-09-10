#!/bin/sh
# Differential: the shipping rootfs's own /sbin/procd against procd-rs, both
# as ordinary ubus daemons.
#
# procd.c's main() is `if (getpid() != 1) procd_connect_ubus(); else
# procd_state_next();` -- so run outside PID 1 it is exactly a service
# supervisor on the bus, which is what P3.1 implements. No PID 1, no
# inittab, no watchdog: those are P3.2 and this harness deliberately does
# not pretend to cover them.
#
# Usage: r65_procd_diff.sh <rootfs> <candidate> <outdir> [examples dir]
#
# The examples dir supplies `notifier`, which r65 needs because the `ubus`
# CLI cannot register an object and notify from it -- and procd's `watch` is
# a subscription to another object's notifications.
set -eu
root=$1
cand=$2
out=$3
examples=${4:-}
mkdir -p "$out"

# A build flag that quietly stops rebuilding the candidate (--examples
# without --bins does exactly that) produces a green run against an old
# binary. Record what was actually tested so that is visible afterwards.
{
	echo "candidate: $cand"
	ls -la --time-style=+%Y-%m-%dT%H:%M:%S "$cand" 2>/dev/null || true
	md5sum "$cand" 2>/dev/null || true
	echo "now: $(date +%Y-%m-%dT%H:%M:%S)"
} > "$out/candidate.txt"

work=$(mktemp -d /tmp/owrt-r65-XXXXXX)
trap 'rm -rf "$work"' EXIT
# One rootfs per side. Sharing a copy and clearing /tmp/out between runs was
# not enough once cases started writing outside it -- the late-exec case
# creates /tmp/late-exec, so the C run would have handed the Rust run a
# command that already existed and the case would have tested nothing.
cp -a "$root" "$work/root"
cp "$cand" "$work/root/sbin/procd-rs"
chmod 0755 "$work/root/sbin/procd-rs"
if [ -n "$examples" ] && [ -x "$examples/notifier" ]; then
	cp "$examples/notifier" "$work/root/sbin/notifier"
	chmod 0755 "$work/root/sbin/notifier"
fi
# ubusd refuses acl.d files it does not own; every rootfs copy needs this.
chown -R 0:0 "$work/root/usr/share/acl.d" 2>/dev/null || true

# F12 needs an account whose UID differs from its primary GID, plus a
# supplementary group. Without one the bug is invisible: C takes the primary
# GID from passwd, the old Rust code passed the UID in its place, and if
# UID == GID the two are indistinguishable. Added to the disposable copy
# only -- the shipping rootfs is never modified.
printf 'p31user:x:1234:2345:p31:/tmp:/bin/sh\n' >> "$work/root/etc/passwd"
printf 'p31group:x:2345:\np31extra:x:3456:p31user\n' >> "$work/root/etc/group"

mkdir -p "$work/root/tmp/out" "$work/root/tmp/initd" "$work/root/tmp/rcd"
# The F12 case drops to uid 1234, so the effect directory has to be writable
# by a non-root child. Sticky, like a real /tmp.
chmod 1777 "$work/root/tmp/out"

# rc(name, "running") globs <init.d>/<name>, so a service whose name matches
# a script here must run it -- and one whose name does not must run nothing.
cat > "$work/root/tmp/initd/hasinit" <<'X'
#!/bin/sh
echo "hasinit ran with: $*" >> /tmp/out/initd.txt
X
chmod 0755 "$work/root/tmp/initd/hasinit"

cat > "$work/root/tmp/bus.sh" <<'X'
#!/bin/sh
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out
# The rootfs copy is shared by both runs, so the previous run's socket file
# is still sitting there. Waiting for the path to EXIST would then return
# instantly and the daemon would connect to a dead socket -- which is exactly
# what happened once the build host got busy. Remove it, and wait for a real
# round trip rather than for the inode.
rm -f /var/run/ubus/ubus.sock /dev/log
/sbin/ubusd -s /var/run/ubus/ubus.sock &
echo $! > /tmp/out/ubusd.pid
i=0
while ! ubus list >/dev/null 2>&1 && [ $i -lt 20 ]; do
	sleep 1
	i=$((i+1))
done
ubus list >/dev/null 2>&1 || echo "bus.sh: ubusd never answered" >> /tmp/out/bus.err
# An instance declaring stdout/stderr sends its output to syslog, so the
# differential needs a real log daemon to read it back from.
/sbin/logd -S 32 &
echo $! > /tmp/out/logd.pid
i=0
while [ ! -S /dev/log ] && [ $i -lt 10 ]; do
	sleep 1
	i=$((i+1))
done
X

# The supervisor readiness gate. Astra's review proved the old harness
# passed with BOTH supervisors replaced by /bin/false: it only ever checked
# that ubusd answered. This checks the thing under test is present, is the
# binary we meant, owns the `service` object with its methods, and answers a
# real round trip. Anything missing is written to ready.err, which fails the
# run outright rather than becoming comparable text.
cat > "$work/root/tmp/ready.sh" <<'X'
#!/bin/sh
err() { echo "$1" >> /tmp/out/ready.err; }
pid=$(cat /tmp/out/procd.pid 2>/dev/null || true)
[ -n "$pid" ] || err "no supervisor pid recorded"
i=0
while [ $i -lt 20 ]; do
	kill -0 "$pid" 2>/dev/null || break
	ubus list 2>/dev/null | grep -qx service && break
	sleep 1
	i=$((i+1))
done
kill -0 "$pid" 2>/dev/null || err "supervisor pid $pid is not alive"
exe=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
echo "supervisor exe: $exe" >> /tmp/out/ready.txt
case "$exe" in
	*/procd|*/procd-rs) ;;
	*) err "supervisor exe is not a procd: $exe" ;;
esac
ubus list 2>/dev/null | grep -qx service || err "no service object on the bus"
for m in set add list delete signal update_start update_complete event 	 validate get_data set_data state watchdog; do
	ubus -v list service 2>/dev/null | grep -q "\"$m\":" || err "service has no method $m"
done
# A real round trip through the supervisor, not just through ubusd.
ubus call service list >/tmp/out/ready-list.txt 2>&1 || err "service list round trip failed"
grep -q "^{" /tmp/out/ready-list.txt 2>/dev/null || err "service list did not return an object"
X

cat > "$work/root/tmp/cproc.sh" <<'X'
#!/bin/sh
DBGLVL=0 /sbin/procd -S -I /tmp/initd -R /tmp/rcd > /tmp/out/procd.log 2>&1 &
echo $! > /tmp/out/procd.pid
X

cat > "$work/root/tmp/rsproc.sh" <<'X'
#!/bin/sh
/sbin/procd-rs -I /tmp/initd > /tmp/out/procd.log 2>&1 &
echo $! > /tmp/out/procd.pid
X

# The drive script: every case is a ubus call whose reply is compared. Long
# waits are explicit so a timing difference shows up as a diff, not a flake.
cat > "$work/root/tmp/drive.sh" <<'X'
#!/bin/sh
# `call` used to pass "${3:-}", which turns a no-argument call into an
# explicit empty-string JSON and makes the shipping CLI fail to parse it --
# so case 2 was two mutual failures compared equal. Now a missing third
# argument is genuinely absent.
#
# Every `call` must SUCCEED. Recording rc= into the compared text is not an
# assertion: if a bug in this script breaks a call, it breaks it identically
# on both sides, the diff stays empty and the run passes -- which is exactly
# how case 2 hid two mutual parse failures. So `call` now fails the run on a
# non-zero status, and the deliberate bad-argument cases say so with `callx`.
#
# call  <obj> <method> [json]   -- must succeed; a failure fails the run
# callx <obj> <method> [json]   -- must fail; a success fails the run
#
# Both print exactly what the old `call` printed, so the comparable text --
# and therefore the baseline -- is unchanged.
call() {
	printf -- '--- %s %s\n' "$1" "$2"
	rc=0
	if [ $# -ge 3 ]; then
		ubus call "$1" "$2" "$3" 2>&1 || rc=$?
	else
		ubus call "$1" "$2" 2>&1 || rc=$?
	fi
	if [ "$rc" != 0 ]; then
		printf 'rc=%s\n' "$rc"
		echo "EXPECT-FAIL: $1 $2 should have succeeded, rc=$rc" >> /tmp/out/expect.err
	fi
	return 0
}

callx() {
	printf -- '--- %s %s\n' "$1" "$2"
	rc=0
	if [ $# -ge 3 ]; then
		ubus call "$1" "$2" "$3" 2>&1 || rc=$?
	else
		ubus call "$1" "$2" 2>&1 || rc=$?
	fi
	if [ "$rc" = 0 ]; then
		echo "EXPECT-FAIL: $1 $2 should have failed but succeeded" >> /tmp/out/expect.err
	else
		printf 'rc=%s\n' "$rc"
	fi
	return 0
}

# For a positive result whose exact text must NOT enter the diff -- it holds
# a pid, a count, or a timestamp. `gate yes|no <text> <why>` prints the same
# constant the case printed before, and fails the run when the positive
# result did not happen, so "both sides produced nothing" stops being
# agreement in the five places that still allowed it.
gate() {
	if [ "$1" = yes ]; then
		echo "$2"
	else
		echo "$3"
		echo "EXPECT-FAIL: $4" >> /tmp/out/expect.err
	fi
}

# A positive effect file must exist and be non-empty. Its CONTENT still goes
# into the diff; this only stops "neither side produced anything" passing.
#
# `must_have <file> [lines]` -- with an expected line count, it also asserts
# the file is that long. Six trigger sub-cases appended to one shared
# fired.txt with no rm between them, so from the second one on `must_have`
# was satisfied by the PREVIOUS step's content: the three "must not fire"
# steps could not fail, and the later "must fire" steps did not have to fire.
# The count is what distinguishes "grew" from "unchanged".
must_have() {
	if [ -s "$1" ]; then
		cat "$1"
		if [ -n "${2:-}" ]; then
			n=$(wc -l < "$1")
			if [ "$n" -ne "$2" ]; then
				echo "EXPECT-FAIL: $1 has $n line(s), expected $2" >> /tmp/out/expect.err
			fi
		fi
	else
		echo "(no file)"
		echo "EXPECT-FAIL: $1 should exist and be non-empty" >> /tmp/out/expect.err
	fi
}

# Everything the `service` object notifies -- instance.start/stop/respawn/
# fail, service.start/stop -- as a subscriber sees it. Until now no side
# recorded these at all, so a missing, extra or differently-shaped
# notification was invisible to the diff. The subscriber dies with ubusd in
# F06, which is the last case, so this covers every case before it.
ubus subscribe service > /tmp/out/notify.txt 2>&1 &
echo $! > /tmp/out/sub.pid
sleep 1

# 1. signature: what `ubus -v list` prints is part of the interface
printf -- '--- signature\n'
ubus -v list service 2>&1
ubus -v list container 2>&1
ubus -v list system 2>&1

# 2. empty list -- with no third argument at all, so the CLI does not choke
#    on an empty-string JSON. This is the case Astra found was two mutual
#    parse failures compared equal.
call service list

# 3. one instance that exits immediately -- exit_code, running=false
call service set '{"name":"t1","instances":{"one":{"command":["/bin/true"]}}}'
sleep 1
call service list '{"name":"t1"}'

# 4. a non-zero exit
call service set '{"name":"t2","instances":{"one":{"command":["/bin/sh","-c","exit 7"]}}}'
sleep 1
call service list '{"name":"t2"}'

# 5. a long-lived instance -- running=true, and the pid must be hidden from
#    the diff since it is never going to match
call service set '{"name":"t3","instances":{"one":{"command":["/bin/sleep","300"]}}}'
sleep 1
call service list '{"name":"t3"}'

# 6. an invalid instance: no command at all. instance_dump skips it, so t4
#    must list with no instances table.
call service set '{"name":"t4","instances":{"bad":{"env":{"A":"b"}}}}'
sleep 1
call service list '{"name":"t4"}'

# 7. respawn shape in the dump, and term_timeout default
call service set '{"name":"t5","instances":{"one":{"command":["/bin/sleep","300"],"respawn":["3600","5","5"],"term_timeout":11}}}'
sleep 1
call service list '{"name":"t5"}'

# 8. env, data and limits projection
call service set '{"name":"t6","instances":{"one":{"command":["/bin/sleep","300"],"env":{"Z":"26","A":"1"},"data":{"k":"v"},"limits":{"nofile":"64 128"}}}}'
sleep 1
call service list '{"name":"t6"}'

# 9. `set` replaces the instance set; `add` merges into it
call service set '{"name":"t7","instances":{"a":{"command":["/bin/sleep","300"]},"b":{"command":["/bin/sleep","300"]}}}'
sleep 1
call service add '{"name":"t7","instances":{"c":{"command":["/bin/sleep","300"]}}}'
sleep 1
printf -- '--- after add, t7 should have a b c\n'
call service list '{"name":"t7"}'
call service set '{"name":"t7","instances":{"b":{"command":["/bin/sleep","300"]}}}'
sleep 2
printf -- '--- after set, t7 should have only b\n'
call service list '{"name":"t7"}'

# 10. a config change restarts; an identical set does not
call service set '{"name":"t8","instances":{"one":{"command":["/bin/sleep","300"]}}}'
sleep 1
ubus call service list '{"name":"t8"}' | sed -n 's/.*"pid": \([0-9]*\).*/pid1=\1/p'
call service set '{"name":"t8","instances":{"one":{"command":["/bin/sleep","300"]}}}'
sleep 1
ubus call service list '{"name":"t8"}' | sed -n 's/.*"pid": \([0-9]*\).*/pid2=\1/p'
printf -- '--- identical set must keep the same pid (compared as same/differs below)\n'

# 11. delete one instance, then the whole service
call service delete '{"name":"t7","instance":"b"}'
sleep 2
call service list '{"name":"t7"}'
call service delete '{"name":"t3"}'
sleep 2
call service list '{"name":"t3"}'

# 12. signal
call service signal '{"name":"t5","instance":"one","signal":15}'
sleep 2
call service list '{"name":"t5"}'

# 13. state: spawn=false stops without deleting, spawn=true brings back
call service set '{"name":"t9","instances":{"one":{"command":["/bin/sleep","300"]}}}'
sleep 1
call service state '{"name":"t9","spawn":false}'
sleep 2
printf -- '--- t9 stopped by state, must still be listed\n'
call service list '{"name":"t9"}'
call service state '{"name":"t9","spawn":true}'
sleep 1
call service list '{"name":"t9"}'
printf -- '--- state argument errors\n'
callx service state '{"name":"t9"}'
callx service state '{"spawn":true}'
callx service state '{"name":"nope","spawn":true}'

# 14. update_start / add / update_complete: only the re-added survive
call service set '{"name":"ta","instances":{"x":{"command":["/bin/sleep","300"]},"y":{"command":["/bin/sleep","300"]}}}'
sleep 1
call service update_start '{"name":"ta"}'
call service add '{"name":"ta","instances":{"y":{"command":["/bin/sleep","300"]}}}'
call service update_complete '{"name":"ta"}'
sleep 2
printf -- '--- after update window, ta should have only y\n'
call service list '{"name":"ta"}'
callx service update_start '{"name":"nope"}'

# 15. get_data: service data under "*", instance data under its own name
call service set '{"name":"tb","data":{"sv":"1","other":"2"},"instances":{"one":{"command":["/bin/sleep","300"],"data":{"iv":"3"}}}}'
sleep 1
call service get_data '{"name":"tb"}'
call service get_data '{"name":"tb","type":"sv"}'
call service get_data '{"name":"tb","instance":"one"}'
printf -- '--- get_data across every service\n'
call service get_data '{"type":"iv"}'

# 16. set_data at both levels
call service set_data '{"name":"tb","data":{"sv":"changed"}}'
sleep 1
call service get_data '{"name":"tb"}'
call service set_data '{"name":"tb","instance":"one","data":{"iv":"changed"}}'
sleep 1
call service get_data '{"name":"tb","instance":"one"}'
callx service set_data '{"name":"tb","instance":"nope","data":{"a":"b"}}'
callx service set_data '{"name":"tb"}'

# 17. autostart=false is the only case where the flag is printed
call service set '{"name":"tc","autostart":false,"instances":{"one":{"command":["/bin/sleep","300"]}}}'
sleep 1
printf -- '--- autostart false: flag printed, instance must NOT be running\n'
call service list '{"name":"tc"}'

# 18. triggers: a rule that fires run_script on a matching event.
#     The command writes a file, so what actually ran is observable rather
#     than inferred from a log line.
call service set '{"name":"td","triggers":[["mytrig.*",[["if",["eq","ACT","go"],[["run_script","/bin/sh","-c","echo %WHO% >> /tmp/out/fired.txt"]]]]]],"instances":{"one":{"command":["/bin/sleep","300"]}}}'
sleep 1
call service event '{"type":"mytrig.now","data":{"ACT":"go","WHO":"first"}}'
sleep 2
printf -- '--- fired after a matching event\n'
must_have /tmp/out/fired.txt 1

printf -- '--- an event whose expression is false must not fire\n'
call service event '{"type":"mytrig.now","data":{"ACT":"stop","WHO":"second"}}'
sleep 2
must_have /tmp/out/fired.txt 1

printf -- '--- a non-matching event type must not fire\n'
call service event '{"type":"other.now","data":{"ACT":"go","WHO":"third"}}'
sleep 2
must_have /tmp/out/fired.txt 1

printf -- '--- .* truncates before the dot: "mytrigX" matches too\n'
call service event '{"type":"mytrigX","data":{"ACT":"go","WHO":"fourth"}}'
sleep 2
must_have /tmp/out/fired.txt 2

printf -- '--- an unset variable expands to nothing\n'
call service event '{"type":"mytrig.now","data":{"ACT":"go"}}'
sleep 2
# %WHO% unset -> `echo` with no argument -> an EMPTY line is appended.
must_have /tmp/out/fired.txt 3

printf -- '--- event argument errors\n'
callx service event '{"type":"mytrig.now"}'
callx service event '{"data":{"ACT":"go"}}'

printf -- '--- a case arm, and a command other than run_script (must be dropped)\n'
call service set '{"name":"te","triggers":[["ev2",[["case","K",{"a":[["run_script","/bin/sh","-c","echo caseA >> /tmp/out/fired.txt"]],"b":[["exec","/bin/sh","-c","echo SHOULD-NOT-RUN >> /tmp/out/fired.txt"]]}]]]]}'
sleep 1
call service event '{"type":"ev2","data":{"K":"a"}}'
sleep 2
call service event '{"type":"ev2","data":{"K":"b"}}'
sleep 2
# The `a` arm appended one line; the `b` arm's `exec` is not run_script and
# must be dropped, so this is 4 and not 5.
must_have /tmp/out/fired.txt 4

# 19. validate: grouped package -> type -> option -> rule across services
call service set '{"name":"tf","validate":[{"package":"network","type":"interface","data":{"proto":"string","ifname":"string"}},{"package":"network","type":"device","data":{"name":"string"}}]}'
call service set '{"name":"tg","validate":[{"package":"dhcp","type":"host","data":{"mac":"string"}},{"package":"bogus","data":{"x":"y"}}]}'
sleep 1
printf -- '--- all validators (the entry missing `type` must be dropped)\n'
call service validate '{}'
printf -- '--- filtered by package\n'
call service validate '{"package":"network"}'
printf -- '--- filtered by package and type\n'
call service validate '{"package":"network","type":"device"}'
printf -- '--- a `service` argument short-circuits to an empty reply\n'
call service validate '{"service":"tf"}'
printf -- '--- verbose list shows the validators inline\n'
call service list '{"name":"tf","verbose":true}'

# 20. rc(name, "running"): a service whose name matches an init.d script
printf -- '--- a service with a matching init script\n'
call service set '{"name":"hasinit","instances":{"one":{"command":["/bin/true"]}}}'
sleep 2
must_have /tmp/out/initd.txt
printf -- '--- a second set with instances runs it again\n'
call service set '{"name":"hasinit","instances":{"one":{"command":["/bin/true"]}}}'
sleep 2
must_have /tmp/out/initd.txt
printf -- '--- a service with no matching script runs nothing\n'
call service set '{"name":"noinit","instances":{"one":{"command":["/bin/true"]}}}'
sleep 2
must_have /tmp/out/initd.txt

# 21. the per-instance watchdog method
call service set '{"name":"twd","instances":{"one":{"command":["/bin/sleep","300"],"watchdog":["1","20"]}}}'
sleep 1
printf -- '--- reads back the configured mode/timeout\n'
call service watchdog '{"name":"twd","instance":"one"}'
printf -- '--- setting mode marks it self-managed (timeout is long on\n'
printf -- '    purpose: this case is about arming and the self-managed bit,\n'
printf -- '    not about the timer firing -- F16 covers that separately)\n'
call service watchdog '{"name":"twd","instance":"one","mode":2,"timeout":3600}'
call service watchdog '{"name":"twd","instance":"one"}'
printf -- '--- a set carrying the ORIGINAL watchdog must not restart it now\n'
ubus call service list '{"name":"twd"}' | sed -n "s/.*\"pid\": \([0-9]*\).*/wdpid1=\1/p"
call service set '{"name":"twd","instances":{"one":{"command":["/bin/sleep","300"],"watchdog":["1","20"]}}}'
sleep 2
ubus call service list '{"name":"twd"}' | sed -n "s/.*\"pid\": \([0-9]*\).*/wdpid2=\1/p"
printf -- '--- out-of-range mode falls back to 0, zero timeout to 30\n'
call service set '{"name":"twd2","instances":{"one":{"command":["/bin/sleep","300"],"watchdog":["99","0"]}}}'
sleep 1
call service watchdog '{"name":"twd2","instance":"one"}'
printf -- '--- watchdog argument errors are NOT_FOUND, not INVALID_ARGUMENT\n'
callx service watchdog '{"name":"twd"}'
callx service watchdog '{"instance":"one"}'
callx service watchdog '{"name":"twd","instance":"nope"}'

# 22. watch: an instance names a ubus path; that object's notifications must
#     become trigger events. This is the netifd -> procd line
#     (/etc/init.d/network:21 does exactly this with network.interface), so
#     it is driven with a real second object rather than asserted.
#
#     The watched object is registered AFTER the watch is declared, which is
#     the real ordering: netifd comes up after procd. If ubus.object.add is
#     not handled, nothing fires.
call service set '{"name":"tw","triggers":[["iface.up",[["run_script","/bin/sh","-c","echo watched:%ifname% >> /tmp/out/watched.txt"]]]],"instances":{"one":{"command":["/bin/sleep","300"],"watch":["fake.iface"]}}}'
sleep 1
printf -- '--- publish the watched object, then notify from it\n'
/sbin/notifier fake.iface iface.up ifname=eth9 >/dev/null 2>&1 &
sleep 5
must_have /tmp/out/watched.txt

# F04b: a watch must not outlive the thing that asked for it.
#
#     Delete only the INSTANCE. The service and its iface.up rule stay --
#     can_be_freed() needs `deleted`, which an instance delete does not set
#     -- so the rule is still armed and able to fire. Only the `watch` went
#     away with the instance.
#
#     C: instance_free() -> watch_del(), the subscription is dropped, the
#     notification never reaches procd, nothing fires.
#     Rust before the fix: refresh_watches() had ONE call site (the `set`
#     path), so nothing freed the subscription or the watches[] mapping when
#     the instance was freed -- the notification still arrived and the rule
#     still ran.
#
#     Deleting the whole SERVICE does not test this: that also deletes the
#     rules, so nothing fires either way and the case proves nothing. The
#     first version of this case did exactly that and passed on both
#     binaries -- a non-assertion.
printf -- '--- delete only the watching instance; the rule stays armed\n'
call service delete '{"name":"tw","instance":"one"}'
sleep 2
rm -f /tmp/out/watched.txt
printf -- '--- publish the object again and notify from it\n'
/sbin/notifier fake.iface iface.up ifname=eth9 >/dev/null 2>&1 &
sleep 5
printf -- '--- the watch died with its instance: nothing may appear here\n'
cat /tmp/out/watched.txt 2>&1 || echo "(correctly absent)"

# F19: the TERM grace window. C tests `in->proc.pending` -- the child still
#     exists -- where this used Run::Running, which excludes the window
#     between SIGTERM and reap. Three consequences, all reproduced on
#     845b7b43 before the fix:
#
#     (A) delete the whole service while an instance is restarting. C stops
#         and deletes it. instance_stop returned early for a Halting
#         instance and never cleared `restart`, so the instance came back
#         with a NEW pid -- a deleted service revived itself.
printf -- '--- F19a: delete a service whose instance is mid-restart\n'
call service set '{"name":"fw1","instances":{"one":{"command":["/bin/sh","-c","trap \"\" TERM; while :; do sleep 1; done"],"term_timeout":6}}}'
sleep 2
call service set '{"name":"fw1","instances":{"one":{"command":["/bin/sh","-c","trap \"\" TERM; echo v2 > /tmp/out/fw1-v2; while :; do sleep 1; done"],"term_timeout":6}}}'
sleep 1
call service delete '{"name":"fw1"}'
sleep 8
printf -- '--- deleted mid-restart: it must be gone, not back with a new pid\n'
call service list '{"name":"fw1"}'

#     (B) delete, then state(spawn=true) inside the grace window. C leaves it
#         deleted. The Halting instance took instance_start and revived.
printf -- '--- F19b: state spawn=true inside the TERM window of a delete\n'
call service set '{"name":"fw2","instances":{"one":{"command":["/bin/sh","-c","trap \"\" TERM; while :; do sleep 1; done"],"term_timeout":6}}}'
sleep 2
call service delete '{"name":"fw2"}'
sleep 1
# Succeeds on both: during the TERM window the service is still in the map
# with its deleted flag set, so this is a normal call, not an error case.
call service state '{"name":"fw2","spawn":true}'
sleep 8
printf -- '--- must stay deleted\n'
call service list '{"name":"fw2"}'

#     (C) state(spawn=false), then a config change inside the window. C
#         restarts into the new config. `stopping` read the STATE instead of
#         the halt FLAG -- a stopped-by-state instance has halt set but is
#         not Halting -- so the running branch killed it dead (exit 137).
printf -- '--- F19c: config change while stopped by state(spawn=false)\n'
call service set '{"name":"fw3","instances":{"one":{"command":["/bin/sleep","300"]}}}'
sleep 2
call service state '{"name":"fw3","spawn":false}'
sleep 1
call service set '{"name":"fw3","instances":{"one":{"command":["/bin/sleep","301"]}}}'
sleep 3
printf -- '--- must be running the new config, not dead\n'
call service list '{"name":"fw3"}'

# F20: `service signal`. Read out of service.c rather than assumed:
#     `int sig = SIGHUP` (not SIGKILL); a missing `name` returns NOT_FOUND
#     (not INVALID_ARGUMENT, unlike its sibling handlers); and
#     service_handle_kill() does NOT test proc.pending -- it calls kill() and
#     maps errno, so an instance whose child is gone gives ESRCH -> NOT_FOUND
#     where filtering on state silently returned OK.
printf -- '--- F20a: the default signal is SIGHUP, so a plain signal is not a kill\n'
call service set '{"name":"fs1","instances":{"one":{"command":["/bin/sh","-c","trap \"echo got-hup >> /tmp/out/fs1.txt\" HUP; while :; do sleep 1; done"]}}}'
sleep 2
call service signal '{"name":"fs1"}'
sleep 2
# No assertion on the trap's output file: it never appeared on EITHER side,
# so it asserted nothing about the implementation. Whether busybox ash runs a
# HUP trap while blocked in `sleep` is not this suite's business. The
# property under test is survival, and the list below shows it -- pre-fix
# this instance is running:false with exit_code 137, because the default was
# SIGKILL.
printf -- '--- and it must still be running: SIGHUP was handled, not fatal\n'
call service list '{"name":"fs1"}'

printf -- '--- F20b: signalling an instance whose child is gone is NOT_FOUND\n'
call service set '{"name":"fs2","instances":{"one":{"command":["/bin/true"]}}}'
sleep 2
callx service signal '{"name":"fs2","instance":"one","signal":15}'

printf -- '--- F20c: a missing name is NOT_FOUND here, not INVALID_ARGUMENT\n'
callx service signal '{"signal":15}'

# 23. instance stdout/stderr -> syslog, with the C's ident format
call service set '{"name":"tlog","instances":{"one":{"command":["/bin/sh","-c","echo hello-stdout; echo hello-stderr >&2; sleep 300"],"stdout":true,"stderr":true}}}'
sleep 3
printf -- '--- the instance lines must reach the log, ident basename[pid]\n'
logread >/tmp/out/instance-log.txt 2>&1
logged=$(grep -E "hello-stdout|hello-stderr" /tmp/out/instance-log.txt | sed -E "s/^[A-Z][a-z]{2} [A-Z][a-z]{2} +[0-9]+ [0-9:]+ [0-9]{4} //; s/\[[0-9]+\]/[PID]/")
if [ -n "$logged" ]; then printf '%s\n' "$logged"; else
	echo "(nothing logged)"
	echo "EXPECT-FAIL: instance stdout/stderr never reached the log" >> /tmp/out/expect.err
fi
printf -- '--- an instance NOT asking for stdout must log nothing\n'
call service set '{"name":"tquiet","instances":{"one":{"command":["/bin/sh","-c","echo should-not-be-logged; sleep 300"]}}}'
sleep 3
logread 2>&1 | grep -c "should-not-be-logged" | sed "s/^/quiet_matches=/"

# 24. structured data must keep its type. A flattening implementation drops
#     the integer and the boolean entirely, which `list` and `get_data` show.
call service set '{"name":"tdata","data":{"s":"str","n":42,"b":true},"instances":{"one":{"command":["/bin/sleep","300"],"data":{"in":7,"is":"x"}}}}'
sleep 1
printf -- '--- typed data survives list\n'
call service list '{"name":"tdata"}'
printf -- '--- and get_data\n'
call service get_data '{"name":"tdata"}'

# 25. a jailed instance must exec ujail, not the bare command. ujail is not
#     runnable in this namespace, so what is compared is the OBSERVABLE
#     consequence: both sides must fail to start it the same way, and
#     neither may end up running the raw command as root.
cat > /tmp/initd/showargv <<'Y'
#!/bin/sh
Y
chmod 0755 /tmp/initd/showargv
# Counting ujail processes was a racy proxy for the thing that matters. The
# property F01 is about is whether the instance's OWN command can run
# unconfined, so the command writes a marker: ujail here fails in this
# namespace (both sides report exit_code 1), which means the inner command
# must never have been reached.
rm -f /tmp/out/unconfined.txt
call service set '{"name":"tjail","instances":{"one":{"command":["/bin/sh","-c","echo ran-unconfined >> /tmp/out/unconfined.txt; sleep 300"],"jail":{"name":"tj","procfs":true,"ubus":true,"setns":[{"pid":1,"namespaces":["net","ipc"]},{"namespaces":["uts"]}]},"user":"nobody","no_new_privs":true}}}'
sleep 3
printf -- '--- a jailed instance: running state and exit code, and every setns\n'
printf -- '    entry echoed raw -- including the one without a pid that ujail never sees\n'
call service list '{"name":"tjail"}'
printf -- '--- its command must NOT have run outside the jail\n'
if [ -s /tmp/out/unconfined.txt ]; then
	echo "RAN UNCONFINED"
	echo "EXPECT-FAIL: a jailed command ran outside the jail" >> /tmp/out/expect.err
else
	echo "never ran unconfined"
fi

# 25b. array-valued fields come back in the C's avl order. blobmsg_list_fill()
#      keys an ARRAY element by blobmsg_data() as a C string under avl_strcmp
#      with duplicates refused: netdev sorted by name with the repeat dropped;
#      env/limits by name; and setns -- tables -- by the raw payload bytes up
#      to the first NUL, so the three entries whose payload starts with a
#      `pid` attr collapse to the first (pid 3) and the pid-less one sorts in
#      front of it. Measured on the shipping procd before being asserted.
printf -- '--- 25b: netdev/env/limits echo back in avl order, duplicates dropped\n'
call service set '{"name":"tord","instances":{"one":{"command":["/bin/sleep","300"],"netdev":["zeth","aeth","meth","aeth"],"env":{"ZZ":"1","A":"22","MM":"333"},"limits":{"nofile":"1024","core":"0"}}}}'
sleep 2
call service list '{"name":"tord"}'
printf -- '--- and an identical set with the lists in another order is NOT a config change\n'
ubus call service list '{"name":"tord"}' | sed -n "s/.*\"pid\": \([0-9]*\).*/ordpid1=\1/p" | head -1
call service set '{"name":"tord","instances":{"one":{"command":["/bin/sleep","300"],"netdev":["aeth","meth","zeth"],"env":{"A":"22","MM":"333","ZZ":"1"},"limits":{"core":"0","nofile":"1024"}}}}'
sleep 2
ubus call service list '{"name":"tord"}' | sed -n "s/.*\"pid\": \([0-9]*\).*/ordpid2=\1/p" | head -1
printf -- '--- setns: tables keyed by their leading bytes, so three pid-first entries collapse to the first\n'
call service set '{"name":"tord2","instances":{"one":{"command":["/bin/sleep","300"],"jail":{"name":"jo","setns":[{"pid":3,"namespaces":["c"]},{"pid":1,"namespaces":["a"]},{"pid":2,"namespaces":["b"]},{"namespaces":["zz"]}]}}}}'
sleep 2
call service list '{"name":"tord2"}'

# 26. R68's counter-examples. Each of these was red on the candidate that
#     passed the old gate, which is the point: they test behaviour the
#     previous cases could not see.

printf -- '--- F03: a service.data.update trigger must actually run\n'
call service set '{"name":"fd","triggers":[["service.data.update",[["run_script","/bin/sh","-c","echo dataev:%name% >> /tmp/out/dataev.txt"]]]],"data":{"old":"one"}}'
sleep 1
call service set_data '{"name":"fd","data":{"new":"two"}}'
sleep 3
must_have /tmp/out/dataev.txt

printf -- '--- F05: a changed file with the SAME path must restart it\n'
echo old > /tmp/out/watched.conf
call service set '{"name":"ff","instances":{"one":{"command":["/bin/sleep","300"],"file":["/tmp/out/watched.conf"]}}}'
sleep 1
ubus call service list '{"name":"ff"}' | sed -n "s/.*\"pid\": \([0-9]*\).*/filepid1=\1/p"
echo new > /tmp/out/watched.conf
call service set '{"name":"ff","instances":{"one":{"command":["/bin/sleep","300"],"file":["/tmp/out/watched.conf"]}}}'
sleep 2
ubus call service list '{"name":"ff"}' | sed -n "s/.*\"pid\": \([0-9]*\).*/filepid2=\1/p"

printf -- '--- F07: an update adding reload_signal uses the OLD config\n'
call service set '{"name":"fr","instances":{"one":{"command":["/bin/sleep","300"]}}}'
sleep 1
call service set '{"name":"fr","instances":{"one":{"command":["/bin/sleep","300"],"reload_signal":10}}}'
sleep 2
call service list '{"name":"fr"}'

printf -- '--- F08: a command that appears late must still be retried\n'
# Publish between the initial exec failure and the 3-second retry. Publishing
# exactly when a 1-second retry fires races chmod against exec, changing the
# notification count even when both supervisors behave correctly.
rm -f /tmp/out/late-ran.txt /tmp/late-exec
call service set '{"name":"fl","instances":{"one":{"command":["/tmp/late-exec"],"respawn":["3600","3","5"]}}}'
sleep 1
printf '#!/bin/sh\necho ran >> /tmp/out/late-ran.txt\nsleep 300\n' > /tmp/late-exec
chmod 0755 /tmp/late-exec
sleep 4
must_have /tmp/out/late-ran.txt

printf -- '--- F09: a crash-looped instance stays listed with its exit code\n'
call service set '{"name":"fc","instances":{"one":{"command":["/bin/sh","-c","exit 7"],"respawn":["3600","0","1"]}}}'
sleep 4
call service list '{"name":"fc"}'

printf -- '--- F09b: a crash-looped instance must still be deletable\n'
call service delete '{"name":"fc","instance":"one"}'
sleep 2
call service list '{"name":"fc"}'

printf -- '--- F10: a deleted service must stop firing its rules\n'
call service set '{"name":"fg","triggers":[["gone.ev",[["run_script","/bin/sh","-c","echo gone >> /tmp/out/gone.txt"]]]]}'
sleep 1
call service event '{"type":"gone.ev","data":{"k":"v"}}'
sleep 2
must_have /tmp/out/gone.txt
call service delete '{"name":"fg"}'
rm -f /tmp/out/gone.txt
call service event '{"type":"gone.ev","data":{"k":"v"}}'
sleep 2
printf -- '--- after delete, nothing may fire\n'
cat /tmp/out/gone.txt 2>&1 || echo "(correctly absent)"

printf -- '--- F10b: an instance-level trigger must fire\n'
call service set '{"name":"fi","instances":{"one":{"command":["/bin/sleep","300"],"triggers":[["inst.ev",[["run_script","/bin/sh","-c","echo instfired >> /tmp/out/instfired.txt"]]]]}}}'
sleep 1
call service event '{"type":"inst.ev","data":{"k":"v"}}'
sleep 2
must_have /tmp/out/instfired.txt
printf -- '--- verbose list shows the instance-level triggers (instance_dump: verbose && in->trigger)\n'
call service list '{"name":"fi","verbose":true}'

# F12: with `user` set and no `group`, C takes the primary GID from passwd.
# The old code passed the UID in its place. p31user is UID 1234 / GID 2345
# with supplementary group 3456, so uid, gid and groups are all distinct and
# a wrong primary GID cannot hide behind a matching UID.
printf -- '--- F12: primary gid comes from passwd, not from the uid\n'
call service set '{"name":"fu","instances":{"one":{"command":["/bin/sh","-c","id > /tmp/out/identity.txt"],"user":"p31user"}}}'
sleep 2
must_have /tmp/out/identity.txt

printf -- '--- F13: pidfile must be written\n'
call service set '{"name":"fp","instances":{"one":{"command":["/bin/sleep","300"],"pidfile":"/tmp/out/managed.pid"}}}'
sleep 2
[ -s /tmp/out/managed.pid ] && w=yes || w=no
gate "$w" "pidfile written" "PIDFILE MISSING" "pidfile was never written"

printf -- '--- F14: during the TERM grace period it is still running\n'
call service set '{"name":"fh","instances":{"one":{"command":["/bin/sh","-c","trap \"\" TERM; while :; do sleep 1; done"],"term_timeout":5}}}'
sleep 2
call service delete '{"name":"fh","instance":"one"}'
sleep 1
ubus call service list '{"name":"fh"}' 2>&1 | grep -E '"running"' | head -1

printf -- '--- F15: validity rules\n'
call service set '{"name":"fv1","instances":{"one":{"command":["/bin/true"],"env":{"A":"ok","B":7}}}}'
call service set '{"name":"fv2","instances":{"one":{"command":"/bin/true"}}}'
call service set '{"name":"fv3","instances":{"one":{"command":["/bin/true"],"nice":21}}}'
sleep 2
call service list '{"name":"fv1"}'
call service list '{"name":"fv2"}'
call service list '{"name":"fv3"}'

printf -- '--- F15b: integer-typed fields (R73 findings 2 and 3)\n'
# nice is (int8_t)blobmsg_get_u32: 236 truncates to -20, which is VALID --
# the instance must run. The string cases above never exercised the cast.
call service set '{"name":"fv4","instances":{"one":{"command":["/bin/sleep","300"],"nice":236}}}'
# respawn/watchdog array elements go through blobmsg_get_string + atoi even
# when the element is an integer: the payload's first byte is 0, so the
# value read is 0, whatever the integer was.
call service set '{"name":"fv5","instances":{"one":{"command":["/bin/sleep","300"],"respawn":[3600,5,5]}}}'
call service set '{"name":"fv6","instances":{"one":{"command":["/bin/sleep","300"],"watchdog":[1,10]}}}'
sleep 2
call service list '{"name":"fv4"}'
call service list '{"name":"fv5"}'
call service list '{"name":"fv6"}'

printf -- '--- F21: validate_firmware_image and the safe sysupgrade error paths (P4)\n'
# The rootfs ships /usr/libexec/validate_firmware_image; on a garbage file it
# deterministically answers valid:false forceable:true allow_backup:true.
# sysupgrade with that image and no force stops at "Firmware image is
# invalid" -- an error reply plus NOT_SUPPORTED, safely BEFORE the exec.
echo garbage-not-firmware > /tmp/fake-fw.bin
call system validate_firmware_image '{"path":"/tmp/fake-fw.bin"}'
callx system validate_firmware_image '{}'
callx system sysupgrade '{"path":"/tmp/fake-fw.bin"}'
callx system sysupgrade '{"path":"/tmp/fake-fw.bin","prefix":"/"}'

printf -- '--- F16: the watchdog timer must actually act\n'
call service set '{"name":"fw","instances":{"one":{"command":["/bin/sleep","300"]}}}'
sleep 1
call service watchdog '{"name":"fw","instance":"one","mode":2,"timeout":1}'
sleep 3
call service list '{"name":"fw"}'

printf -- '--- F17: rc running must also run after a respawn\n'
# The instance exits instantly and respawns once a second, so sampling
# mid-loop compares two crash counters that were never going to agree. Give
# it a retry budget of 1 and wait past the point where BOTH sides have
# certainly given up, then look only at whether the hook ran again.
rm -f /tmp/out/initd.txt
call service set '{"name":"hasinit","instances":{"one":{"command":["/bin/sh","-c","exit 0"],"respawn":["3600","1","1"]}}}'
sleep 8
printf -- '--- the hook must have run more than once\n'
c=$(grep -c "hasinit ran" /tmp/out/initd.txt 2>/dev/null || true); [ -n "$c" ] || c=0
[ "$c" -gt 1 ] && w=yes || w=no
gate "$w" "hook ran repeatedly" "HOOK RAN ONLY $c TIME(S)" "rc running hook ran $c time(s), expected more than one"

printf -- '--- F18: merged validators keep insertion order, not global sort\n'
call service set '{"name":"fz","validate":[{"package":"same","type":"same","data":{"z":"string"}}]}'
call service set '{"name":"fa","validate":[{"package":"same","type":"same","data":{"a":"string"}}]}'
sleep 1
call service validate '{"package":"same"}'

printf -- '--- F05b: a recreated interface with the SAME name must restart it\n'
ip link add p31dummy type dummy 2>/dev/null || true
call service set '{"name":"fn","instances":{"one":{"command":["/bin/sleep","300"],"netdev":["p31dummy"]}}}'
sleep 1
ubus call service list '{"name":"fn"}' | sed -n "s/.*\"pid\": \([0-9]*\).*/netpid1=\1/p"
ip link del p31dummy 2>/dev/null || true
ip link add p31dummy type dummy 2>/dev/null || true
call service set '{"name":"fn","instances":{"one":{"command":["/bin/sleep","300"],"netdev":["p31dummy"]}}}'
sleep 2
ubus call service list '{"name":"fn"}' | sed -n "s/.*\"pid\": \([0-9]*\).*/netpid2=\1/p"

printf -- '--- F11: an identical command triggered while one is queued must run twice\n'
rm -f /tmp/out/q.txt
call service set '{"name":"fq","triggers":[["slow.ev",[["run_script","/bin/sh","-c","sleep 2; echo slow >> /tmp/out/q.txt"]]],["fast.ev",[["run_script","/bin/sh","-c","echo fast >> /tmp/out/q.txt"]]]]}'
sleep 1
call service event '{"type":"slow.ev","data":{"k":"v"}}'
call service event '{"type":"fast.ev","data":{"k":"v"}}'
sleep 1
call service event '{"type":"fast.ev","data":{"k":"v"}}'
sleep 6
printf -- '--- fast must appear twice: once queued behind slow, once requeued\n'
c=$(grep -c "^fast$" /tmp/out/q.txt 2>/dev/null || true); [ -n "$c" ] || c=0
[ "$c" -ge 2 ] && w=yes || w=no
gate "$w" "fast_runs=$c" "fast_runs=$c" "queued trigger ran $c time(s), expected the requeue to make it two"

printf -- '--- F06: the supervisor must survive ubusd going away\n'
call service set '{"name":"fb","instances":{"one":{"command":["/bin/sleep","300"]}}}'
sleep 1
sup=$(cat /tmp/out/procd.pid)
old=$(kill -0 "$sup" 2>/dev/null && echo alive || echo gone)
printf 'supervisor before: %s\n' "$old"
kill -9 "$(cat /tmp/out/ubusd.pid)" 2>/dev/null || true
sleep 2
printf 'supervisor after ubusd died: %s\n' "$(kill -0 "$sup" 2>/dev/null && echo alive || echo gone)"
rm -f /var/run/ubus/ubus.sock
/sbin/ubusd -s /var/run/ubus/ubus.sock &
echo $! > /tmp/out/ubusd.pid
i=0
while ! ubus list >/dev/null 2>&1 && [ $i -lt 15 ]; do sleep 1; i=$((i+1)); done
sleep 4
printf 'supervisor after a new ubusd: %s\n' "$(kill -0 "$sup" 2>/dev/null && echo alive || echo gone)"
printf -- '--- and it must be back on the bus with its instance\n'
# `"running"` alone also matches `"running": false` -- the supervisor coming
# back with a DEAD instance would have passed.
back=$(ubus call service list '{"name":"fb"}' 2>&1 | grep -E '"running": true' | head -1)
if [ -n "$back" ]; then printf '%s\n' "$back"; else
	echo "NOT BACK"
	echo "EXPECT-FAIL: supervisor did not come back on the bus after a new ubusd" >> /tmp/out/expect.err
fi

# 26b. the system object's readable methods. All four answer OUTSIDE PID 1
#      on the shipping procd, so they are directly comparable. `info`'s
#      values move between runs; only its SHAPE is compared (numbers
#      scrubbed). `board` is deterministic inside one rootfs: same kernel,
#      hostname, cpuinfo and os-release on both sides.
printf -- '--- system board\n'
call system board
printf -- '--- system info, numbers scrubbed to N\n'
ubus call system info 2>&1 | sed -E 's/[0-9]+/N/g'
printf -- '--- system watchdog: read, reconfigure, clamp, read back\n'
call system watchdog
call system watchdog '{"timeout":60,"frequency":10}'
printf -- '--- frequency above timeout/2 is clamped to timeout/2\n'
call system watchdog '{"frequency":40}'
printf -- '--- magicclose is echoed\n'
call system watchdog '{"magicclose":true}'
call system watchdog '{"magicclose":false,"timeout":30,"frequency":5}'
printf -- '--- system signal: missing fields are INVALID_ARGUMENT, a bad pid is fine\n'
callx system signal '{"pid":99999}'
callx system signal '{"signum":15}'
call system signal '{"pid":99999,"signum":15}'

# 26c. the hotplug.<subsystem> objects (hotplug-dispatch.c). One per
#      /etc/hotplug.d directory plus `button`, present in the SUPERVISOR
#      mode too; `call` sources the directory's scripts with the given env
#      merged under procd's own; inotify tracks directory creation live.
printf -- '--- the hotplug objects on the bus, and one signature\n'
ubus list "hotplug.*" 2>&1
ubus -v list hotplug.button 2>&1
mkdir -p /etc/hotplug.d/p31sub
cat > /etc/hotplug.d/p31sub/10-mark <<'Y'
echo "ran with FOO=$FOO INTERFACE=$INTERFACE" >> /tmp/out/hpcall.txt
Y
cat > /etc/hotplug.d/p31sub/20-mark <<'Y'
echo "second script" >> /tmp/out/hpcall.txt
Y
printf -- '--- a created directory appears as an object (inotify)\n'
sleep 2
ubus list "hotplug.p31sub" 2>&1
printf -- '--- call runs every script, in order, with the merged env\n'
call hotplug.p31sub call '{"env":["FOO=bar","INTERFACE=lan","LD_PRELOAD=/evil","9BAD=x"]}'
sleep 2
must_have /tmp/out/hpcall.txt 2
printf -- '--- env is required, and ASYNC=0 is refused\n'
callx hotplug.p31sub call
callx hotplug.p31sub call '{"env":["ASYNC=0"]}'
printf -- '--- an empty directory is a successful no-op\n'
mkdir -p /etc/hotplug.d/p31empty
sleep 2
call hotplug.p31empty call '{"env":["X=1"]}'

# 27. the whole table, so ordering is compared too
printf -- '--- full list\n'
ubus call service list 2>&1

# 28. what the subscriber saw. Notifications carry no pids on this procd
#     (service_event is two strings). They are compared SORTED: two
#     independent timers -- a respawn coming due and the next `set` in this
#     script -- race across sides, and their relative order flipped between
#     two otherwise identical runs. What is asserted is the multiset: which
#     notifications, with which payload, how many times.
printf -- '--- notifications seen by a subscriber of service (sorted)\n'
kill "$(cat /tmp/out/sub.pid)" 2>/dev/null
sleep 1
if [ -s /tmp/out/notify.txt ]; then
	sort /tmp/out/notify.txt
	printf 'notifications=%s\n' "$(wc -l < /tmp/out/notify.txt)"
else
	echo "(no notifications)"
	echo "EXPECT-FAIL: the service object notified nothing in the whole run" >> /tmp/out/expect.err
fi

# Last line: proves the drive script ran to the end.
echo done > /tmp/out/drive.done
X

run() {
	tag=$1
	rootdir=$2
	starter=$3
	sudo -n unshare --mount --net --pid --fork /bin/sh -c '
		root=$1; tag=$2; out=$3; starter=$4
		mount --make-rprivate /
		mount -t proc proc "$root/proc"
		mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		# Host kernel traffic must not evict fixture syslog lines from logd.
		mount --bind "$root/dev/null" "$root/proc/kmsg"
		trap "umount $root/proc/kmsg 2>/dev/null; umount $root/dev 2>/dev/null; umount $root/proc 2>/dev/null" EXIT
		ip link set lo up
		chroot "$root" /bin/sh /tmp/bus.sh
		chroot "$root" /bin/sh "$starter"
		# Prove the supervisor is there BEFORE driving it. A run whose
		# supervisor never started must fail, not produce comparable text.
		chroot "$root" /bin/sh /tmp/ready.sh
		chroot "$root" /bin/sh /tmp/drive.sh > "$out/$tag-calls.txt" 2>&1 || true
		# `|| true` keeps a failing call from aborting the run, but it would
		# also hide a drive script that died halfway. The last line of the
		# script writes this marker; its absence fails the run.
		cp "$root/tmp/out/drive.done" "$out/$tag-drive.done" 2>/dev/null || true
		cp "$root/tmp/out/procd.log" "$out/$tag-daemon.log" 2>/dev/null || true
		cp "$root/tmp/out/bus.err" "$out/$tag-bus.err" 2>/dev/null || true
		cp "$root/tmp/out/ready.err" "$out/$tag-ready.err" 2>/dev/null || true
		cp "$root/tmp/out/ready.txt" "$out/$tag-ready.txt" 2>/dev/null || true
		cp "$root/tmp/out/expect.err" "$out/$tag-expect.err" 2>/dev/null || true
		cp "$root/tmp/out/instance-log.txt" "$out/$tag-instance-log.txt" 2>/dev/null || true
		for f in procd ubusd logd; do
			p=$(cat "$root/tmp/out/$f.pid" 2>/dev/null || true)
			[ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
		done
	' sh "$rootdir" "$tag" "$out" "$starter"
}

# A pristine second copy, taken before either side runs.
cp -a "$work/root" "$work/root-rs"

run c "$work/root" /tmp/cproc.sh
run rs "$work/root-rs" /tmp/rsproc.sh

# pids never match between two runs; compare their identity, not their value.
scrub() {
	# ubusd hands out object ids at random, and they differ even between two
	# runs of the same binary -- checked, the C's own ids changed run to run.
	# The signature text after the id is the part that carries meaning.
	#
	# The "pid" rule below is anchored to an indented JSON field, so
	# `"pidfile": ...` is safe. It would still catch a business `"pid": N`
	# inside `data` -- no case has one today; a case that adds one must scrub
	# differently rather than lose the comparison silently.
	sed -E \
		-e "s/^'([a-z.0-9]+)' @[0-9a-f]+$/'\\1' @ID/" \
		-e 's/^(\t+)"pid": [0-9]+/\1"pid": PID/' \
		-e 's/^pid1=[0-9]+$/pid1=P1/' \
		-e 's/^pid2=[0-9]+$/pid2=P2/' \
		-e 's/^wdpid1=[0-9]+$/wdpid1=W1/' \
		-e 's/^wdpid2=[0-9]+$/wdpid2=W2/' \
		-e 's/^filepid1=[0-9]+$/filepid1=F1/' \
		-e 's/^filepid2=[0-9]+$/filepid2=F2/' \
		-e 's/^netpid1=[0-9]+$/netpid1=N1/' \
		-e 's/^netpid2=[0-9]+$/netpid2=N2/' \
		-e 's/^ordpid1=[0-9]+$/ordpid1=O1/' \
		-e 's/^ordpid2=[0-9]+$/ordpid2=O2/' \
		-e 's/^supervisor before: .*/supervisor before: STATE/' \
		"$1"
}
scrub "$out/c-calls.txt" > "$out/c-calls.scrubbed"
scrub "$out/rs-calls.txt" > "$out/rs-calls.scrubbed"

# ... but whether pid1 and pid2 are equal IS the assertion for case 10.
# "differs" used to cover both "the pid really changed" and "there was no
# pid at all". Report those separately so a missing pid can never satisfy an
# assertion that two pids matched.
same_pid() {
	a=$(sed -n 's/^pid1=\([0-9][0-9]*\)$/\1/p' "$1")
	b=$(sed -n 's/^pid2=\([0-9][0-9]*\)$/\1/p' "$1")
	if [ -z "$a" ] || [ -z "$b" ]; then
		echo missing
	elif [ "$a" = "$b" ]; then
		echo same
	else
		echo differs
	fi
}
same_netpid() {
	a=$(sed -n 's/^netpid1=\([0-9][0-9]*\)$/\1/p' "$1")
	b=$(sed -n 's/^netpid2=\([0-9][0-9]*\)$/\1/p' "$1")
	if [ -z "$a" ] || [ -z "$b" ]; then
		echo missing
	elif [ "$a" = "$b" ]; then
		echo same
	else
		echo differs
	fi
}
same_filepid() {
	a=$(sed -n 's/^filepid1=\([0-9][0-9]*\)$/\1/p' "$1")
	b=$(sed -n 's/^filepid2=\([0-9][0-9]*\)$/\1/p' "$1")
	if [ -z "$a" ] || [ -z "$b" ]; then
		echo missing
	elif [ "$a" = "$b" ]; then
		echo same
	else
		echo differs
	fi
}
same_ordpid() {
	a=$(sed -n 's/^ordpid1=\([0-9][0-9]*\)$/\1/p' "$1")
	b=$(sed -n 's/^ordpid2=\([0-9][0-9]*\)$/\1/p' "$1")
	if [ -z "$a" ] || [ -z "$b" ]; then
		echo missing
	elif [ "$a" = "$b" ]; then
		echo same
	else
		echo differs
	fi
}
same_wdpid() {
	a=$(sed -n 's/^wdpid1=\([0-9][0-9]*\)$/\1/p' "$1")
	b=$(sed -n 's/^wdpid2=\([0-9][0-9]*\)$/\1/p' "$1")
	if [ -z "$a" ] || [ -z "$b" ]; then
		echo missing
	elif [ "$a" = "$b" ]; then
		echo same
	else
		echo differs
	fi
}
{
	echo "identical-set-keeps-pid c=$(same_pid "$out/c-calls.txt") rs=$(same_pid "$out/rs-calls.txt")"
	echo "self-managed-watchdog-keeps-pid c=$(same_wdpid "$out/c-calls.txt") rs=$(same_wdpid "$out/rs-calls.txt")"
	echo "changed-file-restarts c=$(same_filepid "$out/c-calls.txt") rs=$(same_filepid "$out/rs-calls.txt")"
	echo "recreated-netdev-restarts c=$(same_netpid "$out/c-calls.txt") rs=$(same_netpid "$out/rs-calls.txt")"
	echo "reordered-lists-keep-pid c=$(same_ordpid "$out/c-calls.txt") rs=$(same_ordpid "$out/rs-calls.txt")"
} > "$out/pid-identity.txt"

rc=0
# The pid scrub maps every "pid": N to a constant, which would also hide a
# nonsense pid. Check the raw output separately: a running instance must
# have a positive pid on both sides.
for t in c rs; do
	if grep -qE '"pid": (0|-[0-9]+)' "$out/$t-calls.txt"; then
		echo "r65: $t reported a running instance with a non-positive pid" >&2
		rc=1
	fi
	# An absent calls file makes grep print nothing, and `[ "" -lt 1 ]` is an
	# error rather than true -- which would skip this check instead of firing it.
	n=$(grep -c '"pid":' "$out/$t-calls.txt" 2>/dev/null || true); [ -n "$n" ] || n=0
	if [ "$n" -lt 1 ]; then
		echo "r65: $t never reported a pid at all -- nothing was running" >&2
		rc=1
	fi
	echo "$t: $n pid lines" >> "$out/coverage.txt"
done
for t in c rs; do
	if [ -s "$out/$t-bus.err" ]; then
		echo "r65: $t run never got a working bus: $(cat "$out/$t-bus.err")" >&2
		rc=1
	fi
	# THE gate. Astra proved the old harness passed with both supervisors
	# replaced by /bin/false; this is what makes that impossible.
	if [ -s "$out/$t-ready.err" ]; then
		echo "r65: $t supervisor was not ready:" >&2
		sed "s/^/  $t: /" "$out/$t-ready.err" >&2
		rc=1
	fi
	if [ ! -s "$out/$t-drive.done" ]; then
		echo "r65: $t drive script did not run to completion" >&2
		rc=1
	fi
	if [ ! -s "$out/$t-ready.txt" ]; then
		echo "r65: $t produced no readiness evidence at all" >&2
		rc=1
	fi
	if [ -s "$out/$t-expect.err" ]; then
		echo "r65: $t had calls that did not do what the case expected:" >&2
		sed "s/^/  $t: /" "$out/$t-expect.err" >&2
		rc=1
	fi
done
# A drive script that stops early truncates BOTH sides identically, so the
# diff is clean and every other check still passes -- drive.done can even
# have been written if the truncation is after it. The only thing that
# notices is how much was actually compared, so require a floor on the number
# of case markers. Measured, not guessed -- and re-measured when cases are
# added, because the floor must sit ABOVE the self-test's truncation point or
# the injection goes red for an unrelated reason instead of this one: a full
# run currently emits 272 markers (v15, F21 added) and the F13-truncated
# run 199, so 225.
for t in c rs; do
	m=$(grep -c '^--- ' "$out/$t-calls.txt" 2>/dev/null || true); [ -n "$m" ] || m=0
	echo "$t: $m case markers" >> "$out/coverage.txt"
	if [ "$m" -lt 225 ]; then
		echo "r65: $t only reached $m case markers -- the drive stopped early" >&2
		rc=1
	fi
done
# A run where almost everything failed would still diff clean. Count the
# failures and refuse a run that is mostly errors.
for t in c rs; do
	f=$(grep -c "Command failed" "$out/$t-calls.txt" 2>/dev/null || true); [ -n "$f" ] || f=0
	echo "$t: $f failed calls" >> "$out/coverage.txt"
	# Every unexpected failure now also lands in expect.err, so this is
	# belt-and-braces against a run that is mostly errors. It has to move
	# when `callx` cases are added -- 13 are deliberate as of F20.
	if [ "$f" -gt 25 ]; then
		echo "r65: $t had $f failed calls -- the run is mostly errors" >&2
		rc=1
	fi
done
if ! diff -u "$out/c-calls.scrubbed" "$out/rs-calls.scrubbed" > "$out/calls.diff"; then
	echo "r65: ubus replies differ" >&2
	rc=1
fi
# Each line must agree between the two sides; the VALUES never match across
# runs, so only the same/differs verdict is compared.
while read -r line; do
	c=${line#*c=}; c=${c%% *}
	r=${line#*rs=}
	if [ "$c" != "$r" ]; then
		echo "r65: pid behaviour differs: $line" >&2
		rc=1
	fi
	# Both sides agreeing on "missing" is not agreement about behaviour --
	# it means neither run produced a pid the case needed.
	if [ "$c" = missing ]; then
		echo "r65: pid assertion had no pid to compare: $line" >&2
		rc=1
	fi
done < "$out/pid-identity.txt"
[ $rc -eq 0 ] && echo "r65: ok"
exit $rc
