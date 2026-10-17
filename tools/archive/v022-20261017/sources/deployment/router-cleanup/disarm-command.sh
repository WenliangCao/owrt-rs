set -eu
base=${TRIAL_ROOT:?set the reviewed trial directory}
test "$(cat /proc/sys/kernel/random/boot_id)" = "${EXPECTED_BOOT_ID:?set the accepted boot identity}"
test "$(sha256sum "$base/native_trial_guard.sh" | cut -d' ' -f1)" = "${EXPECTED_GUARD_SHA256:?set the verified guard digest}"
test ! -e "$base/rollback-requested"
test ! -e "$base/c-bridge-used"
test ! -e "${ROLLBACK_MARKER:?set the rollback marker path}"
test "$(cat "$base/healthy-boot")" = "${EXPECTED_BOOT_ID:?set the accepted boot identity}"
test "$(cat "$base/accepted")" = "$(cat "$base/armed") ${EXPECTED_BOOT_ID:?set the accepted boot identity}"
pid=$(cat "${GUARD_LOCK:?set the guard lock directory}/pid")
case "$pid" in ''|*[!0-9]*) exit 2;; esac
start=$(awk '{print $22}' /proc/$pid/stat)
tr '\000' ' ' < /proc/$pid/cmdline | grep -F "$base/native_trial_guard.sh run" >/dev/null
printf 'owned_guard_pid=%s start=%s\n' "$pid" "$start"
rm "$base/armed"
i=0
while [ -d /proc/$pid ] && [ "$(awk '{print $22}' /proc/$pid/stat 2>/dev/null || :)" = "$start" ]; do
 i=$((i+1)); [ "$i" -le 40 ]; sleep 1
done
test ! -e "${GUARD_LOCK:?set the guard lock directory}"
 tail -n 1 "$base/guard.log" | grep -F 'explicitly disarmed'
printf 'normal_disarm_complete\n'
