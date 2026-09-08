#!/bin/sh
# Reviewer probe: does a supervisor's `watch` survive a ubusd restart?
# Runs the shipping C procd and the candidate in separate rootfs copies,
# same script, same waits. Never touches the router.
# Usage: reconnect_probe.sh <rootfs> <candidate> <examples dir> <outdir>
set -eu
root=$1; cand=$2; ex=$3; out=$4
mkdir -p "$out"
work=$(mktemp -d /tmp/rv-reconnect-XXXXXX)
trap 'sudo -n rm -rf "$work"' EXIT
{ echo "candidate: $cand"; md5sum "$cand"; echo "notifier: $ex/notifier"; md5sum "$ex/notifier"; echo "rootfs: $root"; date +%Y-%m-%dT%H:%M:%S; } > "$out/inputs.txt"

cat > "$work/go.sh" <<'X'
#!/bin/sh
tag=$1
out=/tmp/out
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out /tmp/initd /tmp/rcd
chmod 1777 /tmp/out
log() { echo "$(date +%T) [$tag] $*"; }
wtxt() { tr '\n' ' ' < /tmp/out/w.txt 2>/dev/null || echo "(none)"; }
startbus() {
	rm -f /var/run/ubus/ubus.sock
	/sbin/ubusd -s /var/run/ubus/ubus.sock &
	echo $! > $out/ubusd.pid
	i=0; while ! ubus list >/dev/null 2>&1 && [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done
}
startbus
if [ "$tag" = c ]; then
	DBGLVL=0 /sbin/procd -S -I /tmp/initd -R /tmp/rcd > $out/procd.log 2>&1 &
else
	/sbin/procd-rs -I /tmp/initd > $out/procd.log 2>&1 &
fi
echo $! > $out/procd.pid
i=0; while ! ubus list 2>/dev/null | grep -qx service && [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done
log "supervisor exe: $(readlink /proc/$(cat $out/procd.pid)/exe)"

ubus call service set '{"name":"tw","triggers":[["iface.up",[["run_script","/bin/sh","-c","echo %tag% >> /tmp/out/w.txt"]]]],"instances":{"one":{"command":["/bin/sleep","300"],"watch":["fake.iface"]}}}'
sleep 1
/sbin/notifier fake.iface iface.up tag=before >/dev/null 2>&1 &
sleep 5
log "step1 watch before restart: w=[$(wtxt)]"

kill -9 "$(cat $out/ubusd.pid)"
sleep 1
startbus
ubus monitor > $out/monitor.txt 2>&1 &
echo $! > $out/mon.pid
t0=$(date +%s)
i=0; while ! ubus list 2>/dev/null | grep -qx service && [ $i -lt 60 ]; do sleep 1; i=$((i+1)); done
log "step2 supervisor back on new bus after $(( $(date +%s) - t0 ))s alive=$(kill -0 $(cat $out/procd.pid) 2>/dev/null && echo yes || echo no) objects=[$(ubus list 2>/dev/null | tr '\n' ' ')]"

j=0; while ! ubus list 2>/dev/null | grep -qx service && [ $j -lt 60 ]; do sleep 1; j=$((j+1)); done
log "service object present again after extra ${j}s wait: $(ubus list 2>/dev/null | grep -cx service)"
ubus call service event '{"type":"iface.up","data":{"tag":"direct-after"}}'
sleep 3
log "step3 CONTROL direct event after restart: w=[$(wtxt)]"

/sbin/notifier fake.iface iface.up tag=republished >/dev/null 2>&1 &
sleep 30
log "step4 same path republished, 30s: w=[$(wtxt)]"

ubus call service set '{"name":"tw2","triggers":[["fresh.up",[["run_script","/bin/sh","-c","echo %tag% >> /tmp/out/w.txt"]]]],"instances":{"one":{"command":["/bin/sleep","300"],"watch":["fresh.obj"]}}}'
sleep 1
/sbin/notifier fresh.obj fresh.up tag=fresh >/dev/null 2>&1 &
sleep 30
log "step5 NEW watch declared after restart, new object, 30s: w=[$(wtxt)]"

kill "$(cat $out/mon.pid)" 2>/dev/null || true
log "monitor: $(wc -l < $out/monitor.txt) lines; lines mentioning register/subscribe/object.add:"
grep -n 'register\|subscribe\|lookup\|ubus.object.add\|add_object' $out/monitor.txt | head -40 || true
log "final service list: $(ubus call service list | tr -d '\n\t ')"
log "procd.log:"; cat $out/procd.log
kill -9 "$(cat $out/procd.pid)" "$(cat $out/ubusd.pid)" 2>/dev/null || true
X

for tag in c rs; do
	r="$work/$tag-root"
	cp -a "$root" "$r"
	cp "$cand" "$r/sbin/procd-rs"; chmod 0755 "$r/sbin/procd-rs"
	cp "$ex/notifier" "$r/sbin/notifier"; chmod 0755 "$r/sbin/notifier"
	cp "$work/go.sh" "$r/tmp/go.sh"
	sudo -n chown -R 0:0 "$r/usr/share/acl.d" 2>/dev/null || true
	sudo -n unshare --mount --net --pid --fork /bin/sh -c '
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
	sudo -n cp "$r/tmp/out/monitor.txt" "$out/$tag-monitor.txt" 2>/dev/null || true
	sudo -n cp "$r/tmp/out/w.txt" "$out/$tag-w.txt" 2>/dev/null || true
done
echo "reconnect_probe: done -> $out"
