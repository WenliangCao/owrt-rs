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

mkdir -p "$work/root/tmp/out" "$work/root/tmp/initd" "$work/root/tmp/rcd"

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
# ok  <obj> <method> [json]   -- must succeed; a failure fails the run
# err <obj> <method> [json]   -- must fail; a success fails the run
call() {
	printf -- '--- %s %s\n' "$1" "$2"
	if [ $# -ge 3 ]; then
		ubus call "$1" "$2" "$3" 2>&1 || printf 'rc=%s\n' "$?"
	else
		ubus call "$1" "$2" 2>&1 || printf 'rc=%s\n' "$?"
	fi
}

# Record what each call was SUPPOSED to do, so "both sides failed" stops
# counting as agreement.
expect() {
	want=$1; shift
	printf -- '--- %s %s\n' "$1" "$2"
	rc=0
	if [ $# -ge 3 ]; then
		out=$(ubus call "$1" "$2" "$3" 2>&1) || rc=$?
	else
		out=$(ubus call "$1" "$2" 2>&1) || rc=$?
	fi
	printf '%s\n' "$out"
	if [ "$want" = ok ] && [ "$rc" != 0 ]; then
		echo "EXPECT-FAIL: $1 $2 should have succeeded, rc=$rc" >> /tmp/out/expect.err
	fi
	if [ "$want" = err ] && [ "$rc" = 0 ]; then
		echo "EXPECT-FAIL: $1 $2 should have failed" >> /tmp/out/expect.err
	fi
	[ "$want" = err ] && printf 'rc=%s\n' "$rc"
	return 0
}

# A positive effect file must exist and be non-empty. Its CONTENT still goes
# into the diff; this only stops "neither side produced anything" passing.
must_have() {
	if [ -s "$1" ]; then
		cat "$1"
	else
		echo "(no file)"
		echo "EXPECT-FAIL: $1 should exist and be non-empty" >> /tmp/out/expect.err
	fi
}

# 1. signature: what `ubus -v list` prints is part of the interface
printf -- '--- signature\n'
ubus -v list service 2>&1
ubus -v list container 2>&1
ubus -v list system 2>&1

# 2. empty list -- with no third argument at all, so the CLI does not choke
#    on an empty-string JSON. This is the case Astra found was two mutual
#    parse failures compared equal.
expect ok service list

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
call service state '{"name":"t9"}'
call service state '{"spawn":true}'
call service state '{"name":"nope","spawn":true}'

# 14. update_start / add / update_complete: only the re-added survive
call service set '{"name":"ta","instances":{"x":{"command":["/bin/sleep","300"]},"y":{"command":["/bin/sleep","300"]}}}'
sleep 1
call service update_start '{"name":"ta"}'
call service add '{"name":"ta","instances":{"y":{"command":["/bin/sleep","300"]}}}'
call service update_complete '{"name":"ta"}'
sleep 2
printf -- '--- after update window, ta should have only y\n'
call service list '{"name":"ta"}'
call service update_start '{"name":"nope"}'

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
call service set_data '{"name":"tb","instance":"nope","data":{"a":"b"}}'
call service set_data '{"name":"tb"}'

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
must_have /tmp/out/fired.txt

printf -- '--- an event whose expression is false must not fire\n'
call service event '{"type":"mytrig.now","data":{"ACT":"stop","WHO":"second"}}'
sleep 2
must_have /tmp/out/fired.txt

printf -- '--- a non-matching event type must not fire\n'
call service event '{"type":"other.now","data":{"ACT":"go","WHO":"third"}}'
sleep 2
must_have /tmp/out/fired.txt

printf -- '--- .* truncates before the dot: "mytrigX" matches too\n'
call service event '{"type":"mytrigX","data":{"ACT":"go","WHO":"fourth"}}'
sleep 2
must_have /tmp/out/fired.txt

printf -- '--- an unset variable expands to nothing\n'
call service event '{"type":"mytrig.now","data":{"ACT":"go"}}'
sleep 2
must_have /tmp/out/fired.txt

printf -- '--- event argument errors\n'
call service event '{"type":"mytrig.now"}'
call service event '{"data":{"ACT":"go"}}'

printf -- '--- a case arm, and a command other than run_script (must be dropped)\n'
call service set '{"name":"te","triggers":[["ev2",[["case","K",{"a":[["run_script","/bin/sh","-c","echo caseA >> /tmp/out/fired.txt"]],"b":[["exec","/bin/sh","-c","echo SHOULD-NOT-RUN >> /tmp/out/fired.txt"]]}]]]]}'
sleep 1
call service event '{"type":"ev2","data":{"K":"a"}}'
sleep 2
call service event '{"type":"ev2","data":{"K":"b"}}'
sleep 2
must_have /tmp/out/fired.txt

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
printf -- '--- setting mode marks it self-managed\n'
call service watchdog '{"name":"twd","instance":"one","mode":2,"timeout":45}'
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
call service watchdog '{"name":"twd"}'
call service watchdog '{"instance":"one"}'
call service watchdog '{"name":"twd","instance":"nope"}'

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

# 23. instance stdout/stderr -> syslog, with the C's ident format
call service set '{"name":"tlog","instances":{"one":{"command":["/bin/sh","-c","echo hello-stdout; echo hello-stderr >&2; sleep 300"],"stdout":true,"stderr":true}}}'
sleep 3
printf -- '--- the instance lines must reach the log, ident basename[pid]\n'
logread 2>&1 | grep -E "hello-stdout|hello-stderr" | sed -E "s/^[A-Z][a-z]{2} [A-Z][a-z]{2} +[0-9]+ [0-9:]+ [0-9]{4} //; s/\[[0-9]+\]/[PID]/" || echo "(nothing logged)"
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
call service set '{"name":"tjail","instances":{"one":{"command":["/bin/sleep","300"],"jail":{"name":"tj","procfs":true,"ubus":true},"user":"nobody","no_new_privs":true}}}'
sleep 2
printf -- '--- a jailed instance: running state and exit code\n'
call service list '{"name":"tjail"}'
printf -- '--- nothing named /bin/sleep may be running unconfined for it\n'
ps 2>/dev/null | grep "[u]jail" | sed -E "s/^ *[0-9]+ +//; s/^[a-z]+ +[0-9:]+ +//" | sort
ps 2>/dev/null | grep -c "[u]jail" | sed "s/^/ujail_procs=/"

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
rm -f /tmp/out/late-ran.txt /tmp/late-exec
call service set '{"name":"fl","instances":{"one":{"command":["/tmp/late-exec"],"respawn":["3600","1","5"]}}}'
sleep 1
printf '#!/bin/sh\necho ran >> /tmp/out/late-ran.txt\nsleep 300\n' > /tmp/late-exec
chmod 0755 /tmp/late-exec
sleep 4
must_have /tmp/out/late-ran.txt

printf -- '--- F09: a crash-looped instance stays listed with its exit code\n'
call service set '{"name":"fc","instances":{"one":{"command":["/bin/sh","-c","exit 7"],"respawn":["3600","0","1"]}}}'
sleep 4
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

printf -- '--- F13: pidfile must be written\n'
call service set '{"name":"fp","instances":{"one":{"command":["/bin/sleep","300"],"pidfile":"/tmp/out/managed.pid"}}}'
sleep 2
[ -s /tmp/out/managed.pid ] && echo "pidfile written" || echo "PIDFILE MISSING"

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

printf -- '--- F16: the watchdog timer must actually act\n'
call service set '{"name":"fw","instances":{"one":{"command":["/bin/sleep","300"]}}}'
sleep 1
call service watchdog '{"name":"fw","instance":"one","mode":2,"timeout":1}'
sleep 3
call service list '{"name":"fw"}'

printf -- '--- F17: rc running must also run after a respawn\n'
rm -f /tmp/out/initd.txt
call service set '{"name":"hasinit","instances":{"one":{"command":["/bin/sh","-c","exit 0"],"respawn":["3600","1","5"]}}}'
sleep 4
must_have /tmp/out/initd.txt

printf -- '--- F18: merged validators keep insertion order, not global sort\n'
call service set '{"name":"fz","validate":[{"package":"same","type":"same","data":{"z":"string"}}]}'
call service set '{"name":"fa","validate":[{"package":"same","type":"same","data":{"a":"string"}}]}'
sleep 1
call service validate '{"package":"same"}'

# 27. the whole table, so ordering is compared too
printf -- '--- full list\n'
ubus call service list 2>&1

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
		trap "umount $root/dev 2>/dev/null; umount $root/proc 2>/dev/null" EXIT
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
	sed -E \
		-e "s/^'([a-z]+)' @[0-9a-f]+$/'\\1' @ID/" \
		-e 's/^(\t+)"pid": [0-9]+/\1"pid": PID/' \
		-e 's/^pid1=[0-9]+$/pid1=P1/' \
		-e 's/^pid2=[0-9]+$/pid2=P2/' \
		-e 's/^wdpid1=[0-9]+$/wdpid1=W1/' \
		-e 's/^wdpid2=[0-9]+$/wdpid2=W2/' \
		-e 's/^filepid1=[0-9]+$/filepid1=F1/' \
		-e 's/^filepid2=[0-9]+$/filepid2=F2/' \
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
	n=$(grep -c '"pid":' "$out/$t-calls.txt" || true)
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
# A run where almost everything failed would still diff clean. Count the
# failures and refuse a run that is mostly errors.
for t in c rs; do
	f=$(grep -c "Command failed" "$out/$t-calls.txt" || true)
	echo "$t: $f failed calls" >> "$out/coverage.txt"
	if [ "$f" -gt 12 ]; then
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
