#!/bin/sh
# Reviewer probe: `service signal` without a `signal` field, and a signal
# aimed at an instance that has already exited. C defaults to SIGHUP and
# kill()s whatever pid it has; the candidate defaults to SIGKILL and skips
# anything not Running.
# Usage: signal_probe.sh <rootfs> <candidate> <outdir>
set -eu
root=$1; cand=$2; out=$3
mkdir -p "$out"
work=$(mktemp -d /tmp/rv-signal-XXXXXX)
trap 'rm -rf "$work"' EXIT
{ echo "candidate: $cand"; md5sum "$cand"; echo "rootfs: $root"; date +%Y-%m-%dT%H:%M:%S; } > "$out/inputs.txt"

cat > "$work/go.sh" <<'X'
#!/bin/sh
tag=$1
out=/tmp/out
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out /tmp/initd /tmp/rcd
log() { echo "$(date +%T) [$tag] $*"; }
lst() { ubus call service list "{\"name\":\"$1\"}" 2>&1 | tr -d '\n\t ' ; }
rm -f /var/run/ubus/ubus.sock
/sbin/ubusd -s /var/run/ubus/ubus.sock &
i=0; while ! ubus list >/dev/null 2>&1 && [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done
if [ "$tag" = c ]; then
	DBGLVL=0 /sbin/procd -S -I /tmp/initd -R /tmp/rcd > $out/procd.log 2>&1 &
else
	/sbin/procd-rs -I /tmp/initd > $out/procd.log 2>&1 &
fi
echo $! > $out/procd.pid
i=0; while ! ubus list 2>/dev/null | grep -qx service && [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done
log "supervisor exe: $(readlink /proc/$(cat $out/procd.pid)/exe)"

# A: no `signal` field -> which signal reaches the child?
ubus call service set '{"name":"sa","instances":{"one":{"command":["/bin/sleep","300"]}}}'
sleep 1
log "A0: $(lst sa)"
ubus call service signal '{"name":"sa","instance":"one"}' 2>&1 | tr -d '\n'; echo " <- signal rc=$?"
sleep 2
log "A1 after signal with no field (129 = HUP, 137 = KILL): $(lst sa)"

# B: a signal aimed at an instance that already exited
ubus call service set '{"name":"sb","instances":{"one":{"command":["/bin/true"]}}}'
sleep 1
log "B0: $(lst sb)"
r=$(ubus call service signal '{"name":"sb","instance":"one","signal":15}' 2>&1 | tr -d '\n'); echo "B1 signal to exited instance -> [$r]"
log "B1 done"

# C: signal to a HALTING instance (child ignoring TERM)
ubus call service set '{"name":"sc","instances":{"one":{"command":["/bin/sh","-c","trap \"\" TERM; sleep 300"]}}}'
sleep 1
ubus call service delete '{"name":"sc","instance":"one"}'
sleep 1
log "C0 halting: $(lst sc)"
r=$(ubus call service signal '{"name":"sc","instance":"one","signal":9}' 2>&1 | tr -d '\n'); echo "C1 SIGKILL to halting instance -> [$r]"
sleep 2
log "C2 2s later (C: killed now and gone; candidate: still waiting for term_timeout?): $(lst sc)"

log "full list: $(ubus call service list | tr -d '\n\t ')"
log "procd.log:"; cat $out/procd.log
kill -9 "$(cat $out/procd.pid)" 2>/dev/null || true
X

for tag in c rs; do
	r="$work/$tag-root"
	cp -a "$root" "$r"
	cp "$cand" "$r/sbin/procd-rs"; chmod 0755 "$r/sbin/procd-rs"
	cp "$work/go.sh" "$r/tmp/go.sh"
	chown -R 0:0 "$r/usr/share/acl.d" 2>/dev/null || true
	unshare --mount --net --pid --fork /bin/sh -c '
		root=$1; tag=$2
		mount --make-rprivate /
		mount -t proc proc "$root/proc"
		mount -t tmpfs -o mode=1777 tmpfs "$root/dev"
		mknod -m 666 "$root/dev/null" c 1 3
		mknod -m 666 "$root/dev/urandom" c 1 9
		mknod -m 666 "$root/dev/zero" c 1 5
		trap "umount $root/dev 2>/dev/null; umount $root/proc 2>/dev/null" EXIT
		ip link set lo up
		chroot "$root" /bin/sh /tmp/go.sh "$tag"
	' sh "$r" "$tag" > "$out/$tag.log" 2>&1 || echo "[$tag] inner exit $?" >> "$out/$tag.log"
done
echo "signal_probe: done -> $out"
