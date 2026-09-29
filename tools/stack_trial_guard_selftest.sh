#!/bin/sh
# Linux-host-only chroot test of the trial lease, with a mock switch/reboot.
set -eu
[ ! -f /etc/openwrt_release ] && [ "$(id -u)" -eq 0 ]
root=$1; bundle=$2; out=$3
[ ! -e "$out" ]; mkdir -p "$out"
work=$(mktemp -d /tmp/stack-guard-test.XXXXXX)
trap 'rm -rf "$work"' EXIT
cp -a "$root" "$work/root"
mkdir -p "$work/root/root/r84/tools"
cp "$bundle/tools/stack_trial_guard.sh" "$work/root/root/r84/tools/"
cat > "$work/root/tmp/test.sh" <<'EOF'
#!/bin/sh
set -eu
mkdir -p /tmp/bin
export PATH=/tmp/bin:/usr/sbin:/usr/bin:/sbin:/bin
cat > /tmp/bin/reboot <<'X'
#!/bin/sh
echo reboot >> /tmp/reboots
X
cat > /root/r84/stack-switch.sh <<'X'
#!/bin/sh
case "$1:$2" in
  verify:stock) [ ! -e /tmp/rust ] ;;
  rescue:) [ ! -e /tmp/restore-fails ] || exit 1; echo restore >> /tmp/restores ;;
  *) exit 2 ;;
esac
X
chmod 755 /tmp/bin/reboot
guard=/root/r84/tools/stack_trial_guard.sh
token=$(sh "$guard" arm 1)
if sh "$guard" arm 1; then exit 1; fi
sh "$guard" restore stale
[ "$(head -n 1 /root/r84/trial.pending)" = "$token" ]
[ ! -e /tmp/reboots ]
touch /tmp/rust
if sh "$guard" disarm; then exit 1; fi
[ -f /root/r84/trial.pending ]
rm /tmp/rust
touch /tmp/restore-fails
if sh "$guard" restore "$token"; then exit 1; fi
[ -f /root/r84/trial.pending ] && [ ! -e /tmp/reboots ]
rm /tmp/restore-fails
sh "$guard" run
[ "$(cat /tmp/restores)" = restore ] && [ "$(cat /tmp/reboots)" = reboot ]
[ ! -e /root/r84/trial.pending ] && [ ! -e /root/r84/trial.reverting ]
[ ! -e /etc/init.d/owrt-stack-trial ] && [ ! -e /etc/rc.d/S98owrt-stack-trial ]
echo 'PASS: lease expiry restores; failures stay armed; Rust disarm and stale token rejected'
old=$(sh "$guard" arm 60)
sh "$guard" disarm
new=$(sh "$guard" arm 60)
sh "$guard" restore "$old"
[ "$(head -n 1 /root/r84/trial.pending)" = "$new" ]
[ "$(wc -l < /tmp/reboots)" -eq 1 ]
sh "$guard" disarm
[ ! -e /root/r84/trial.pending ] && [ ! -e /etc/init.d/owrt-stack-trial ]
echo 'PASS: old lease cannot restore a new window; stock disarm clears all lease files'
EOF
"$bundle/bins/ns-exec" /bin/sh -c '
  set -eu
  root=$1
  mount --bind /proc "$root/proc"
  mount -t tmpfs tmpfs "$root/dev"
  mknod -m 666 "$root/dev/null" c 1 3
  chroot "$root" /bin/sh /tmp/test.sh
' sh "$work/root" > "$out/test.log" 2>&1
cat "$out/test.log"
touch "$out/COMPLETE"
