#!/bin/sh
# Reviewer probe: what happens to an instance that is HALTING (SIGTERM sent,
# child ignoring it) when a delete / state call arrives inside the
# term_timeout window? C re-applies instance_stop() to a live child; the
# candidate returns early for anything that is not Running.
# Usage: halting_probe.sh <rootfs> <candidate> <outdir>
set -eu
root=$1; cand=$2; out=$3
mkdir -p "$out"
work=$(mktemp -d /tmp/rv-halting-XXXXXX)
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

# A: delete the whole service while its instance is halting for a restart
ubus call service set '{"name":"ta","instances":{"one":{"command":["/bin/sh","-c","trap \"\" TERM; sleep 300"]}}}'
sleep 1
log "A0 started: $(lst ta)"
ubus call service set '{"name":"ta","instances":{"one":{"command":["/bin/sh","-c","trap \"\" TERM; sleep 301"]}}}'
sleep 1
log "A1 after changed set (restart pending, TERM ignored): $(lst ta)"
ubus call service delete '{"name":"ta"}'
log "A2 delete issued inside the term window: rc=$?"
sleep 9
log "A3 9s later (term_timeout 5 elapsed): $(lst ta)"

# B: delete the whole service, then `state spawn=true` inside the term window
ubus call service set '{"name":"tb","instances":{"one":{"command":["/bin/sh","-c","trap \"\" TERM; sleep 300"]}}}'
sleep 1
log "B0 started: $(lst tb)"
ubus call service delete '{"name":"tb"}'
sleep 1
log "B1 after delete (halting, TERM ignored): $(lst tb)"
ubus call service state '{"name":"tb","spawn":true}' 2>&1 | tr -d '\n' ; echo
log "B2 state spawn=true issued inside the term window"
sleep 9
log "B3 9s later: $(lst tb)"

# C: `state spawn=false` (stop without halt), then a changed set inside the window
ubus call service set '{"name":"tc","instances":{"one":{"command":["/bin/sh","-c","trap \"\" TERM; sleep 300"]}}}'
sleep 1
log "C0 started: $(lst tc)"
ubus call service state '{"name":"tc","spawn":false}'
sleep 1
log "C1 after state spawn=false (halting, halt=false): $(lst tc)"
ubus call service set '{"name":"tc","instances":{"one":{"command":["/bin/sh","-c","trap \"\" TERM; sleep 301"]}}}'
log "C2 changed set issued inside the term window"
sleep 9
log "C3 9s later: $(lst tc)"

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
echo "halting_probe: done -> $out"
