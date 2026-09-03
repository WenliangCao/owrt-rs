#!/bin/sh
# r25: why does `logread` (the stock C client) spend more CPU on logd-rs' stream
# than on C logd's? Runs both servers in the exact rootfs sandbox (qemu-user),
# fills the ring with N lines, then straces the host-side syscalls of the
# client (read sizes/counts) and of the server (the raw frames it writes).
# Usage: r25_logd_stream_probe.sh <rootfs-files> <logd-rs-musl-binary> [lines]
set -eu
rootfs=$1; bin=$2; n=${3:-400}
command -v strace >/dev/null || { echo "strace missing on the build host" >&2; exit 2; }
tmp=$(mktemp -d /tmp/owrt-r25-XXXXXX); root=$tmp/root
sudo -n cp -a "$rootfs" "$root"
sudo -n chown -R root:root "$root/usr/share/acl.d"
sudo -n cp "$bin" "$root/tmp/logd-rs"; sudo -n chmod 755 "$root/tmp/logd-rs"
cat > "$tmp/steps.sh" <<'STEPS'
set -u
impl=$1; n=$2
mkdir -p /var/run/ubus /tmp/out; rm -rf /dev/log
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 & u=$!
sleep 1
if [ "$impl" = c ]; then /sbin/logd -S 64 >/tmp/out/logd.log 2>&1 & else /tmp/logd-rs -S 64 --kmsg none >/tmp/out/logd.log 2>&1 & fi
l=$!
for i in 1 2 3 4 5; do ubus list log >/dev/null 2>&1 && break; sleep 1; done
i=0; while [ $i -lt $n ]; do logger -t r25 "line $i of the probe payload xxxxxxxxxxxxxxxxxxxxxxxx"; i=$((i+1)); done
sleep 1
echo "server_pid=$l" > /tmp/out/pids
# client run 1: plain, timed by the sandbox clock
s=$(cut -d' ' -f1 /proc/uptime); /sbin/logread > /tmp/out/logread.txt; e=$(cut -d' ' -f1 /proc/uptime)
echo "lines=$(wc -l < /tmp/out/logread.txt) wall=$(echo "$e $s" | awk '{print ($1-$2)*1000 " ms"}')" > /tmp/out/client.txt
sleep 30   # window for the host-side strace of a second client run
kill $l $u 2>/dev/null
STEPS
sudo -n cp "$tmp/steps.sh" "$root/tmp/steps.sh"
run() { # impl
	impl=$1
	sudo -n rm -rf "$root/tmp/out"; sudo -n mkdir -p "$root/tmp/out"
	sudo -n setsid unshare --mount --fork /bin/sh -c '
		root=$1; impl=$2; n=$3
		mount -t tmpfs none $root/dev && mknod $root/dev/null c 1 3 && chmod 666 $root/dev/null && mknod $root/dev/urandom c 1 9 && chmod 666 $root/dev/urandom
		mkdir -p $root/dev/log
		chroot $root /bin/sh /tmp/steps.sh $impl $n' sh "$root" "$impl" "$n" &
	# wait for the first client run to finish
	for i in $(seq 1 60); do sudo -n test -f "$root/tmp/out/client.txt" && break; sleep 1; done
	echo "== $impl: $(sudo -n cat "$root/tmp/out/client.txt")"
	spid=$(sudo -n cat "$root/tmp/out/pids" | cut -d= -f2)
	# host pid of the server: the qemu process whose command line carries the guest binary
	hpid=$(pgrep -f "$([ "$impl" = c ] && echo '/sbin/logd -S 64' || echo '/tmp/logd-rs -S 64')" | head -1)
	echo "   server host pid=$hpid (guest $spid)"
	# strace the server's writes (raw frames, hex) while a second client runs
	sudo -n strace -p "$hpid" -f -e trace=write,sendmsg,sendto -xx -s 200000 -o "$tmp/server-$impl.st" &
	st=$!
	sleep 1
	sudo -n strace -f -e trace=read,recvmsg,recvfrom,write -s 0 -o "$tmp/client-$impl.st" \
		chroot "$root" /sbin/logread > "$tmp/logread-$impl.txt" 2>/dev/null || true
	sleep 1
	sudo -n kill $st 2>/dev/null || true
	echo "   client syscalls: read=$(grep -c 'read(' "$tmp/client-$impl.st") write=$(grep -c 'write(' "$tmp/client-$impl.st") recvmsg=$(grep -c 'recvmsg(' "$tmp/client-$impl.st")"
	echo "   client read sizes (top): $(grep -oE 'read\([0-9]+, [^,]*, [0-9]+\) = [0-9]+' "$tmp/client-$impl.st" | awk '{print $NF}' | sort -n | uniq -c | sort -rn | head -4 | tr '\n' ';')"
	echo "   server writes: $(grep -c 'write(' "$tmp/server-$impl.st") sizes: $(grep -oE '\) = [0-9]+$' "$tmp/server-$impl.st" | awk '{print $3}' | sort -n | uniq -c | sort -rn | head -4 | tr '\n' ';')"
	# first frame bytes (hex) for a byte-level comparison
	grep -oE '"(\\x[0-9a-f]{2})+"' "$tmp/server-$impl.st" | head -1 | cut -c1-400 > "$tmp/frame-$impl.hex"
	sleep 32
}
run rs
run c
echo "== first frame, rs vs c:"; cat "$tmp/frame-rs.hex"; echo; cat "$tmp/frame-c.hex"; echo
echo "== logread output identical: $(cmp -s "$tmp/logread-rs.txt" "$tmp/logread-c.txt" && echo yes || echo no)"
echo "raw traces in $tmp"
