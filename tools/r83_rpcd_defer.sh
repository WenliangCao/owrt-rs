#!/bin/sh
# R83 gate for R81 F23/F24: rpcd-rs must keep answering while `file exec` runs,
# and its delayed rpc-sys actions must be real child processes.
#
#   tools/r83_rpcd_defer.sh <rootfs-files> <rpcd-rs-musl-binary>
#
# Runs inside a disposable copy of the exact device rootfs (its own ubusd, no C
# rpcd), so the candidate owns every object. Three assertions, each with a
# known red injection:
#
#   defer     `file exec /bin/sh -c "sleep 5"` in flight, `session list` from a
#             second client must answer at once. C defers the request
#             (file.c:1064 ubus_defer_request + uloop); measured 0 s for C
#             rpcd, 4 s for a rpcd-rs that runs the child on the loop.
#   parallel  two 4 s execs at once must finish in well under 8 s -- C forks
#             one child per request, they do not queue.
#   respawn   `rpc-sys upgrade_start` followed immediately by SIGHUP: sys.c
#             forks a child that sleeps 2 s and then execs, so the upgrade
#             still happens across an rpcd respawn. A thread inside rpcd does
#             not survive the re-exec.
set -eu
[ $# -eq 2 ] || { echo "usage: $0 <rootfs-files> <rpcd-rs-binary>" >&2; exit 2; }
ROOTFS=$1
BIN=$2
TMP=$(mktemp -d /tmp/r83-rpcd.XXXXXX)
trap 'sudo -n rm -rf -- "$TMP"' EXIT
sudo -n cp -a "$ROOTFS" "$TMP/rootfs"
sudo -n mkdir -p "$TMP/rootfs/tmp/out"
sudo -n chmod 1777 "$TMP/rootfs/tmp" "$TMP/rootfs/tmp/out"
sudo -n cp "$BIN" "$TMP/rootfs/tmp/rpcd-rs"
sudo -n chmod 755 "$TMP/rootfs/tmp/rpcd-rs"
# stand-in for the real sysupgrade: it only has to leave a mark
sudo -n sh -c "printf '#!/bin/sh\ntouch /tmp/out/upgraded\n' > '$TMP/rootfs/sbin/sysupgrade'"
sudo -n chmod 755 "$TMP/rootfs/sbin/sysupgrade"

SCENARIO='
set -eu
root=$1
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount -t tmpfs tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/zero" c 1 5
mknod -m 666 "$root/dev/urandom" c 1 9
trap "umount \"$root/dev\" 2>/dev/null || true; umount \"$root/proc\" 2>/dev/null || true" EXIT
chroot "$root" /bin/sh -s <<"IN"
set -u
mkdir -p /var/run/ubus /tmp/out /var/lock /var/state /var/lib
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 &
sleep 1
/tmp/rpcd-rs -s /var/run/ubus/ubus.sock -t 30 >/tmp/out/rpcd-rs.log 2>&1 &
rs=$!
for i in 1 2 3 4 5 6 7 8 9 10; do ubus list file >/dev/null 2>&1 && break; sleep 1; done
ubus list file >/dev/null 2>&1 || { echo "FAIL rpcd-rs never registered"; exit 1; }

# --- defer: a slow exec must not stall the request loop -------------------
ubus -t 20 call file exec "{\"command\":\"/bin/sh\",\"params\":[\"-c\",\"sleep 5\"]}" >/tmp/out/exec.json 2>&1 &
slow=$!
sleep 1
s=$(date +%s)
ubus -t 20 call session list "{}" >/tmp/out/sess.json 2>&1
e=$(date +%s)
echo "defer_session_list_s=$((e - s))"
wait $slow
echo "defer_exec_reply=$(tr -d " \t\n" < /tmp/out/exec.json)"

# --- parallel: one child per request, not a queue -------------------------
s=$(date +%s)
ubus -t 20 call file exec "{\"command\":\"/bin/sh\",\"params\":[\"-c\",\"sleep 4\"]}" >/dev/null 2>&1 &
a=$!
ubus -t 20 call file exec "{\"command\":\"/bin/sh\",\"params\":[\"-c\",\"sleep 4\"]}" >/dev/null 2>&1 &
b=$!
wait $a; wait $b
e=$(date +%s)
echo "parallel_two_execs_s=$((e - s))"

# --- respawn: the delayed action is a child, not a thread -----------------
rm -f /tmp/out/upgraded
ubus -t 20 call rpc-sys upgrade_start "{}" >/dev/null 2>&1
kill -HUP $rs
sleep 4
[ -f /tmp/out/upgraded ] && echo "respawn_upgrade_ran=1" || echo "respawn_upgrade_ran=0"
echo DONE
IN
'
sudo -n setsid -w unshare --mount --fork sh -c "$SCENARIO" scenario "$TMP/rootfs" 2>&1 | tee "$TMP/log"

fail=0
grep -q "^DONE$" "$TMP/log" || { echo "FAIL scenario did not finish"; fail=1; }
d=$(sed -n 's/^defer_session_list_s=//p' "$TMP/log")
p=$(sed -n 's/^parallel_two_execs_s=//p' "$TMP/log")
u=$(sed -n 's/^respawn_upgrade_ran=//p' "$TMP/log")
r=$(sed -n 's/^defer_exec_reply=//p' "$TMP/log")
[ -n "$d" ] && [ "$d" -le 1 ] || { echo "FAIL session list waited ${d:-?} s behind file exec (C: 0)"; fail=1; }
[ "$r" = '{"code":0}' ] || { echo "FAIL deferred exec reply was '$r', expected {\"code\":0}"; fail=1; }
[ -n "$p" ] && [ "$p" -le 6 ] || { echo "FAIL two 4 s execs took ${p:-?} s, they must overlap"; fail=1; }
[ "$u" = 1 ] || { echo "FAIL upgrade_start did not survive the SIGHUP respawn"; fail=1; }
[ "$fail" = 0 ] && echo "r83 rpcd defer gate: PASS" || echo "r83 rpcd defer gate: FAIL"
exit $fail
