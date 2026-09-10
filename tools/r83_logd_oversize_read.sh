#!/bin/sh
# R83 F15: a LOCAL error while serving `log read` must cost one request, not the
# `log` object.
#
# With `option log_size 1024` (a 1 MiB ring) a full `ubus call log read
# {"stream":false}` reply exceeds UBUS_MAX_MSGLEN. logd-rs' Connection refuses
# such a reply locally (INVALID_ARGUMENT); before R83 that error unwound
# run_connected() into reconnect(), which connected a second time WITHOUT
# closing the old socket, so ubusd -- still holding the old client and its
# `log` path -- refused every add_object("log") and logd looped at 1 Hz with no
# log object at all. C ubus_reconnect() closes the old fd first
# (libubus-io.c:421-426) and C logd only reconnects when the socket really died.
#
# The gate fills the ring past 1 MiB, issues the oversize read, and then checks
# that BOTH implementations still serve the object: `ubus list log`, a fresh
# `log write` and a bounded `log read` must all keep working, and the daemon
# must still be alive.
# Red proof: with the pre-R83 main.rs the candidate's `log` object never comes
# back (list/write/read all fail).
#
# Usage: r83_logd_oversize_read.sh <rootfs-files> <logd-rs-musl-binary>
set -eu
rootfs=$1; bin=$2; size=${3:-1100}; lines=${4:-1250}
command -v sudo >/dev/null || { echo "sudo required" >&2; exit 2; }
tmp=$(mktemp -d /tmp/owrt-r83o-XXXXXX)
trap 'sudo -n rm -rf -- "$tmp"' EXIT

cat > "$tmp/steps.sh" <<'STEPS'
set -u
impl=$1; size=$2; lines=$3
mkdir -p /var/run/ubus /tmp/out
rm -rf /dev/log
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 & u=$!
sleep 1
if [ "$impl" = c ]; then
  /sbin/logd -S "$size" >/tmp/out/logd.log 2>&1 & l=$!
else
  /tmp/logd-rs -S "$size" --kmsg none >/tmp/out/logd.log 2>&1 & l=$!
fi
i=0
while [ $i -lt 8 ]; do ubus list log >/dev/null 2>&1 && break; sleep 1; i=$((i+1)); done
pad=$(awk 'BEGIN{s="";while(length(s)<980)s=s "F";print substr(s,1,980)}')
i=0
while [ $i -lt "$lines" ]; do
  ubus call log write "{\"event\":\"fill${i}_$pad\"}" >/dev/null 2>&1
  i=$((i+1))
done
{
  echo "filled=$(ubus -t 10 -S call log read '{"lines":3,"stream":false}' 2>&1 | grep -o 'fill[0-9]*_' | wc -l)"
  ubus -t 20 -S call log read '{"stream":false}' >/tmp/out/oversize.json 2>/tmp/out/oversize.err
  echo "oversize_rc=$?"
  echo "oversize_bytes=$(wc -c </tmp/out/oversize.json)"
  echo "oversize_err=$(head -c 120 /tmp/out/oversize.err | tr -d '\n')"
  sleep 3
  echo "still_listed=$(ubus -t 10 list 2>/dev/null | grep -c '^log$')"
  ubus -t 10 call log write '{"event":"after_oversize_marker"}' >/dev/null 2>&1
  echo "write_rc=$?"
  sleep 1
  echo "marker_read=$(ubus -t 10 -S call log read '{"lines":2,"stream":false}' 2>/dev/null | grep -c after_oversize_marker)"
  # `logread` against a `log` object nobody serves any more blocks forever, and
  # the image has no timeout(1) (not even as a busybox applet), so bound it by
  # hand; -l 5 keeps a 1 MiB backlog from being streamed for nothing
  logread -l 5 >/tmp/out/logread.txt 2>/dev/null &
  lr=$!
  i=0
  while [ $i -lt 15 ] && kill -0 $lr 2>/dev/null; do sleep 1; i=$((i+1)); done
  kill $lr 2>/dev/null
  echo "logread_marker=$(grep -c after_oversize_marker /tmp/out/logread.txt 2>/dev/null)"
  echo "logread_blocked=$i"
  echo "daemon_alive=$(kill -0 $l 2>/dev/null && echo 1 || echo 0)"
} >/tmp/out/verdict.txt 2>&1
kill $l $u 2>/dev/null || true
STEPS

cat > "$tmp/enter.sh" <<'ENTER'
set -eu
root=$1; impl=$2; size=$3; lines=$4
mount --make-rprivate /
mount -t tmpfs tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/zero" c 1 5
mknod -m 666 "$root/dev/urandom" c 1 9
trap 'umount "$root/dev" 2>/dev/null || true' EXIT
timeout 900 chroot "$root" /bin/sh /tmp/steps.sh "$impl" "$size" "$lines"
ENTER

run_impl() {
  impl=$1
  root=$tmp/root-$impl
  sudo -n cp -a "$rootfs" "$root"
  sudo -n chown -R root:root "$root/usr/share/acl.d"
  sudo -n mkdir -p "$root/tmp"
  sudo -n cp "$bin" "$root/tmp/logd-rs"
  sudo -n chmod 755 "$root/tmp/logd-rs"
  sudo -n cp "$tmp/steps.sh" "$root/tmp/steps.sh"
  sudo -n setsid -w unshare --mount --fork /bin/sh "$tmp/enter.sh" "$root" "$impl" "$size" "$lines" \
    >"$tmp/$impl.out" 2>&1 || { echo "scenario failed for $impl"; sed -n '1,40p' "$tmp/$impl.out"; }
  sudo -n cp -a "$root/tmp/out" "$tmp/out-$impl"
  sudo -n chown -R "$(id -u):$(id -g)" "$tmp/out-$impl"
  echo "--- $impl ---"
  cat "$tmp/out-$impl/verdict.txt"
  echo "--- $impl logd stderr (tail) ---"
  tail -3 "$tmp/out-$impl/logd.log" 2>/dev/null || true
}

field() { sed -n "s/^$2=//p" "$tmp/out-$1/verdict.txt" | head -1; }

run_impl c
run_impl rs
status=0
for impl in c rs; do
  [ "$(field "$impl" filled)" = 3 ] || { echo "FAIL $impl: the ring was not filled, the oversize read proved nothing"; status=1; }
  # a reply that fits is not the case under test
  [ "$(field "$impl" oversize_rc)" != 0 ] || { echo "FAIL $impl: the full read succeeded -- raise -S/lines, nothing was proved"; status=1; }
  [ "$(field "$impl" still_listed)" = 1 ] || { echo "FAIL $impl: the log object is gone after the oversize read"; status=1; }
  [ "$(field "$impl" write_rc)" = 0 ] || { echo "FAIL $impl: log write fails after the oversize read"; status=1; }
  [ "$(field "$impl" marker_read)" = 1 ] || { echo "FAIL $impl: log read does not return records written after the oversize read"; status=1; }
  [ "$(field "$impl" logread_marker)" -ge 1 ] || { echo "FAIL $impl: logread cannot see records written after the oversize read"; status=1; }
  [ "$(field "$impl" daemon_alive)" = 1 ] || { echo "FAIL $impl: the daemon died"; status=1; }
done
[ "$status" = 0 ] && echo 'OK   both implementations still serve the log object after the oversize read'
exit $status
