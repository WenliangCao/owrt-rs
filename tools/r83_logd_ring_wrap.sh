#!/bin/sh
# R83 F16: ring retention under MIXED-LENGTH records.
#
# r15/r28 feed same-length lines, so every lap wraps at the same offset and the
# wrap branch is never asked to evict a record that is not at the head of the
# retained list. This gate feeds an identical mixed-length sequence (a ~900 B
# line every 17th record, otherwise 20-120 B) to the exact image's /sbin/logd
# and to the candidate, both in a disposable copy of the exact rootfs with the
# image's own ubusd/ubus/logread, and compares what each retains:
#   * `ubus call log read {"stream":false}` -> per record "id|source|msg"
#     (kernel records dropped, timestamps never compared)
#   * `logread` with timestamps and pids masked
# Red proof: with the pre-R83 ring.rs (front-only eviction in the wrap branch)
# the candidate keeps overwritten records, so both comparisons differ.
#
# Usage: r83_logd_ring_wrap.sh <rootfs-files> <logd-rs-musl-binary> [size-KiB]
set -eu
rootfs=$1; bin=$2; size=${3:-4}
command -v sudo >/dev/null || { echo "sudo required" >&2; exit 2; }
tmp=$(mktemp -d /tmp/owrt-r83w-XXXXXX)
trap 'sudo -n rm -rf -- "$tmp"' EXIT

cat > "$tmp/steps.sh" <<'STEPS'
set -u
impl=$1; size=$2
mkdir -p /var/run/ubus /tmp/out
rm -rf /dev/log
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 & u=$!
sleep 1
# no /proc in this sandbox, so C logd finds no /proc/kmsg and stays kmsg-free,
# exactly like the candidate's --kmsg none: the rings see the same input only
if [ "$impl" = c ]; then
  /sbin/logd -S "$size" >/tmp/out/logd.log 2>&1 & l=$!
else
  /tmp/logd-rs -S "$size" --kmsg none >/tmp/out/logd.log 2>&1 & l=$!
fi
i=0
while [ $i -lt 8 ]; do ubus list log >/dev/null 2>&1 && break; sleep 1; i=$((i+1)); done
long=$(awk 'BEGIN{s="";while(length(s)<900)s=s "L";print substr(s,1,900)}')
i=0
while [ $i -lt 320 ]; do
  case $((i % 17)) in
    0) body="r${i}_$long" ;;
    3) body=$(awk -v i=$i 'BEGIN{s="";while(length(s)<300)s=s "M";printf "r%d_%s",i,substr(s,1,300)}') ;;
    *) body=$(awk -v i=$i 'BEGIN{n=20+(i*7)%100;s="";while(length(s)<n)s=s "s";printf "r%d_%s",i,substr(s,1,n)}') ;;
  esac
  # `ubus call log write` (no spaces in the body) keeps log_add's priority and
  # timestamp stripping out of the picture: only the ring arithmetic differs
  ubus call log write "{\"event\":\"$body\"}" || echo "write $i failed" >>/tmp/out/errors.txt
  i=$((i+1))
done
sleep 1
ubus call log read '{"stream":false}' >/tmp/out/read-all.json 2>&1
ubus call log read '{"lines":5,"stream":false}' >/tmp/out/read-5.json 2>&1
logread >/tmp/out/logread.txt 2>&1
kill $l $u 2>/dev/null || true
STEPS

# /dev is empty in the extracted rootfs and /proc is deliberately left out: with
# no /proc/kmsg the image's own logd runs kmsg-free, like the candidate's
# --kmsg none, so both rings see exactly the same input
cat > "$tmp/enter.sh" <<'ENTER'
set -eu
root=$1; impl=$2; size=$3
mount --make-rprivate /
mount -t tmpfs tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/zero" c 1 5
mknod -m 666 "$root/dev/urandom" c 1 9
trap 'umount "$root/dev" 2>/dev/null || true' EXIT
timeout 600 chroot "$root" /bin/sh /tmp/steps.sh "$impl" "$size"
ENTER

run_impl() {
  impl=$1
  root=$tmp/root-$impl
  sudo -n cp -a "$rootfs" "$root"
  # ubusd ignores acl.d files that are not root-owned ("wrong owner")
  sudo -n chown -R root:root "$root/usr/share/acl.d"
  sudo -n mkdir -p "$root/tmp"
  sudo -n cp "$bin" "$root/tmp/logd-rs"
  sudo -n chmod 755 "$root/tmp/logd-rs"
  sudo -n cp "$tmp/steps.sh" "$root/tmp/steps.sh"
  sudo -n cp "$tmp/enter.sh" "$tmp/enter-$impl.sh"
  sudo -n setsid -w unshare --mount --fork /bin/sh "$tmp/enter-$impl.sh" "$root" "$impl" "$size" \
    >"$tmp/$impl.out" 2>&1 || { echo "scenario failed for $impl"; sed -n '1,40p' "$tmp/$impl.out"; exit 1; }
  sudo -n cp -a "$root/tmp/out" "$tmp/out-$impl"
  sudo -n chown -R "$(id -u):$(id -g)" "$tmp/out-$impl"
}

# "id|source|msg" per retained record, kernel records dropped
records() {
  awk '
    /"msg":/    { msg = $0; sub(/^[ \t]*"msg": "/, "", msg); sub(/",?$/, "", msg) }
    /"id":/     { id = $2; sub(/,$/, "", id) }
    /"source":/ { src = $2; sub(/,$/, "", src);
                  if (src == 1) printf "%s|%s|%s\n", id, src, msg }
  ' "$1"
}
# logread lines with the timestamp and pids masked, kernel lines dropped
readable() {
  sed -E 's/^[A-Z][a-z]{2} [A-Z][a-z]{2} [ 0-9][0-9] [0-9:]{8} [0-9]{4} //; s/\[[0-9]+\]/[PID]/g' "$1" \
    | grep -v 'kernel:' || true
}

run_impl c
run_impl rs
status=0
for name in read-all read-5; do
  records "$tmp/out-c/$name.json" >"$tmp/$name.c"
  records "$tmp/out-rs/$name.json" >"$tmp/$name.rs"
  if cmp -s "$tmp/$name.c" "$tmp/$name.rs"; then
    echo "OK   $name: $(wc -l <"$tmp/$name.c") records identical (ids and text)"
  else
    echo "FAIL $name differs (C $(wc -l <"$tmp/$name.c") records, candidate $(wc -l <"$tmp/$name.rs")):"
    diff "$tmp/$name.c" "$tmp/$name.rs" | head -12
    status=1
  fi
done
readable "$tmp/out-c/logread.txt" >"$tmp/logread.c"
readable "$tmp/out-rs/logread.txt" >"$tmp/logread.rs"
if cmp -s "$tmp/logread.c" "$tmp/logread.rs"; then
  echo "OK   logread: $(wc -l <"$tmp/logread.c") lines identical"
else
  echo "FAIL logread differs (C $(wc -l <"$tmp/logread.c") lines, candidate $(wc -l <"$tmp/logread.rs")):"
  diff "$tmp/logread.c" "$tmp/logread.rs" | head -12
  status=1
fi
for impl in c rs; do
  [ -s "$tmp/out-$impl/errors.txt" ] && { echo "FAIL $impl reported write errors:"; head -5 "$tmp/out-$impl/errors.txt"; status=1; }
done
[ "$(wc -l <"$tmp/read-all.c")" -ge 5 ] || { echo "FAIL nothing retained -- the comparison proved nothing"; status=1; }
exit $status
