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
# Usage: r65_procd_diff.sh <rootfs> <candidate> <outdir>
set -eu
root=$1
cand=$2
out=$3
mkdir -p "$out"

work=$(mktemp -d /tmp/owrt-r65-XXXXXX)
trap 'rm -rf "$work"' EXIT
cp -a "$root" "$work/root"
cp "$cand" "$work/root/sbin/procd-rs"
chmod 0755 "$work/root/sbin/procd-rs"
# ubusd refuses acl.d files it does not own; every rootfs copy needs this.
chown -R 0:0 "$work/root/usr/share/acl.d" 2>/dev/null || true

mkdir -p "$work/root/tmp/out" "$work/root/tmp/initd" "$work/root/tmp/rcd"

cat > "$work/root/tmp/bus.sh" <<'X'
#!/bin/sh
mkdir -p /var/run /var/lock /var/state /tmp/out
/sbin/ubusd -s /var/run/ubus/ubus.sock &
echo $! > /tmp/out/ubusd.pid
i=0
while [ ! -S /var/run/ubus/ubus.sock ] && [ $i -lt 10 ]; do
	sleep 1
	i=$((i+1))
done
X

cat > "$work/root/tmp/cproc.sh" <<'X'
#!/bin/sh
DBGLVL=0 /sbin/procd -S -I /tmp/initd -R /tmp/rcd > /tmp/out/procd.log 2>&1 &
echo $! > /tmp/out/procd.pid
X

cat > "$work/root/tmp/rsproc.sh" <<'X'
#!/bin/sh
/sbin/procd-rs > /tmp/out/procd.log 2>&1 &
echo $! > /tmp/out/procd.pid
X

# The drive script: every case is a ubus call whose reply is compared. Long
# waits are explicit so a timing difference shows up as a diff, not a flake.
cat > "$work/root/tmp/drive.sh" <<'X'
#!/bin/sh
call() {
	printf -- '--- %s %s\n' "$1" "$2"
	ubus call "$1" "$2" "${3:-}" 2>&1 || printf 'rc=%s\n' "$?"
}

# 1. signature: what `ubus -v list` prints is part of the interface
printf -- '--- signature\n'
ubus -v list service 2>&1
ubus -v list container 2>&1
ubus -v list system 2>&1

# 2. empty list
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

# 13. the whole table, so ordering is compared too
printf -- '--- full list\n'
ubus call service list 2>&1
X

run() {
	tag=$1
	starter=$2
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
		sleep 2
		chroot "$root" /bin/sh /tmp/drive.sh > "$out/$tag-calls.txt" 2>&1 || true
		cp "$root/tmp/out/procd.log" "$out/$tag-daemon.log" 2>/dev/null || true
		for f in procd ubusd; do
			p=$(cat "$root/tmp/out/$f.pid" 2>/dev/null || true)
			[ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
		done
	' sh "$work/root" "$tag" "$out" "$starter"
}

run c /tmp/cproc.sh
# The second run needs a clean rootfs state: the first left pidfiles and
# whatever the instances wrote.
rm -rf "$work/root/tmp/out"; mkdir -p "$work/root/tmp/out"
run rs /tmp/rsproc.sh

# pids never match between two runs; compare their identity, not their value.
scrub() {
	# ubusd hands out object ids at random, and they differ even between two
	# runs of the same binary -- checked, the C's own ids changed run to run.
	# The signature text after the id is the part that carries meaning.
	sed -E \
		-e "s/^'([a-z]+)' @[0-9a-f]+$/'\\1' @ID/" \
		-e 's/"pid": [0-9]+/"pid": PID/' \
		-e 's/pid1=[0-9]+/pid1=P1/' \
		-e 's/pid2=[0-9]+/pid2=P2/' \
		"$1"
}
scrub "$out/c-calls.txt" > "$out/c-calls.scrubbed"
scrub "$out/rs-calls.txt" > "$out/rs-calls.scrubbed"

# ... but whether pid1 and pid2 are equal IS the assertion for case 10.
same_pid() {
	a=$(sed -n 's/^pid1=//p' "$1"); b=$(sed -n 's/^pid2=//p' "$1")
	[ -n "$a" ] && [ "$a" = "$b" ] && echo same || echo differs
}
{
	echo "identical-set-keeps-pid c=$(same_pid "$out/c-calls.txt") rs=$(same_pid "$out/rs-calls.txt")"
} > "$out/pid-identity.txt"

rc=0
if ! diff -u "$out/c-calls.scrubbed" "$out/rs-calls.scrubbed" > "$out/calls.diff"; then
	echo "r65: ubus replies differ" >&2
	rc=1
fi
if ! grep -q 'c=same rs=same' "$out/pid-identity.txt" \
	&& ! grep -q 'c=differs rs=differs' "$out/pid-identity.txt"; then
	echo "r65: identical-set pid behaviour differs: $(cat "$out/pid-identity.txt")" >&2
	rc=1
fi
[ $rc -eq 0 ] && echo "r65: ok"
exit $rc
