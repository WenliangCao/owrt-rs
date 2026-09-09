#!/bin/bash
# P6 device window orchestrator. Runs DETACHED on the control Mac so that a
# dead chat session can never lose the confirm again: window #2 (2026-09-09
# 19:27) booted a healthy candidate -- br-lan addressed, WAN routed, both APs
# bridged, dnsmasq/odhcpd serving -- and was reverted at T+480 simply because
# nobody was there to run `confirm`.
#
# Flow: pre-flight the acceptance probe on the CURRENT boot -> upload the
# candidate + switch script to persistent /root -> stage -> reboot -> wait for
# ssh -> require CONFIRM_OBS seconds of consecutive client-side health (DHCP
# lease on this boot, DNS via the router, HTTPS out through the router's Wi-Fi,
# both APs in br-lan, running netifd == candidate) -> confirm -> post-check.
# Never confirms on a failing probe: the device's own canary reverts to C at
# T+900 and this script then just collects the evidence file.
#
# Usage: p6_window.sh <candidate-binary> <expected-md5> [--ipv4-only]
#   nohup setsid tools/p6_window.sh /tmp/netifd-rs <md5> > /dev/null 2>&1 &
#   tail -f /tmp/p6-window-*.log
set -u
set -o pipefail  # `ssh ... | tee` must fail when ssh fails (window #5 rebooted on a refused stage)
BIN=$1; MD5=$2; V4=${3:-}
LOG=${P6_LOG:-/tmp/p6-window-$(date +%Y%m%d-%H%M%S).log}
HERE=$(cd "$(dirname "$0")" && pwd)
DEV_SCRIPT=/root/p6-switch.sh
CONFIRM_OBS=180     # consecutive seconds of client-side health before confirm
PROBE_GAP=15
DEADLINE_MARGIN=870 # canary fires ~T0+930 (900 s after rc S99 ~ boot+20 s); never confirm past this
REACH_CAP=800       # stop waiting for ssh after this; the canary decides alone

log() { echo "$(date +%T) $*" | tee -a "$LOG"; }
ssh_dev() { ssh -o BatchMode=yes -o ConnectTimeout=5 -o ConnectionAttempts=1 -o ServerAliveInterval=5 openwrt "$@"; }
probe() { python3 "$HERE/p6_client_probe.py" --expected-md5 "$MD5" $V4 2>>"$LOG"; }

log "== P6 window: candidate=$BIN md5=$MD5 mode=${V4:-dual-stack} log=$LOG"

# 0. pre-flight: the acceptance tool must pass on the current (C) boot from
#    this Mac, or a later failure says nothing about the candidate
if pre=$(python3 "$HERE/p6_client_probe.py" $V4 2>&1); then
	log "pre-flight on current boot ok: $pre"
else
	log "PRE-FLIGHT FAILED on current boot -- not staging: $pre"; exit 2
fi
[ "$(md5 -q "$BIN")" = "$MD5" ] || { log "local candidate md5 != $MD5"; exit 2; }

# 1. upload to PERSISTENT /root (tmpfs /tmp is wiped by the reboot)
bn=$(basename "$BIN")
COPYFILE_DISABLE=1 tar cf - -C "$(dirname "$BIN")" "$bn" -C "$HERE" p6_switch.sh \
	| ssh_dev "cd /root && tar xf - && mv -f p6_switch.sh $DEV_SCRIPT && chmod 755 $bn $DEV_SCRIPT && md5sum $bn" | tee -a "$LOG"
ssh_dev "md5sum /root/$bn" | grep -q "^$MD5" || { log "device-side md5 mismatch"; exit 2; }

# 2. read-only baseline, then stage + reboot. A previous Rust candidate that
#    is already resident (c-orig kept + confirmed) is undone first so that
#    stage sees the C original at /sbin/netifd and keeps THAT as .c-orig --
#    rs-to-rs upgrades must never make an old Rust build the rollback target.
ssh_dev "if [ -e /sbin/netifd.c-orig ] && [ -e /etc/p6-confirm ]; then sh $DEV_SCRIPT undo; fi" | tee -a "$LOG"
ssh_dev 'echo "baseline objs=$(ubus list | wc -l) running=$(ubus call service list "{}" | grep -c "\"running\": true") aps=$(iwinfo | grep -c ESSID) p6files=$(ls /etc/p6-* 2>/dev/null | tr "\n" " ")"' | tee -a "$LOG"
if ! ssh_dev "sh $DEV_SCRIPT stage /root/$bn" | tee -a "$LOG"; then log "STAGE FAILED"; exit 2; fi
T0=$(date +%s)
log "rebooting (T0=$T0; canary deadline ~T0+930)"
ssh_dev 'reboot' 2>>"$LOG" || true
sleep 60

# 3. wait for ssh (nc first: cheap, no ssh handshakes hammering the box)
while :; do
	el=$(( $(date +%s) - T0 ))
	if [ $el -gt $REACH_CAP ]; then log "not reachable after ${el}s; leaving it to the canary"; break; fi
	if nc -z -w3 192.168.1.1 22 2>/dev/null && ssh_dev true 2>/dev/null; then log "reachable at T0+${el}s"; break; fi
	sleep 5
done

# 4. client-side acceptance: CONFIRM_OBS seconds of consecutive passes
first=0; confirmed=0
while :; do
	el=$(( $(date +%s) - T0 ))
	if [ $el -gt $DEADLINE_MARGIN ]; then log "T0+${el}s: past the confirm margin without a hold; the canary decides"; break; fi
	if out=$(probe); then
		if [ $first -eq 0 ]; then first=$(date +%s); log "first pass at T0+${el}s: $out"; fi
		held=$(( $(date +%s) - first ))
		log "pass (held ${held}s)"
		if [ $held -ge $CONFIRM_OBS ]; then
			if ssh_dev "sh $DEV_SCRIPT confirm" | tee -a "$LOG"; then confirmed=1; log "CONFIRMED at T0+${el}s"; else log "confirm refused by the device"; fi
			break
		fi
	else
		first=0
		# the probe prints {"error": ...} on stdout; keep the reason (window #3
		# failed for a full run on "router DNS has no A response" and the log
		# only said "probe fail")
		log "probe fail at T0+${el}s (hold reset): $out"
	fi
	sleep $PROBE_GAP
done

# 5. outcome
if [ $confirmed -eq 1 ]; then
	sleep 30
	if out=$(probe); then log "post-confirm probe ok: $out"; else log "POST-CONFIRM PROBE FAILED"; fi
	ssh_dev "sh $DEV_SCRIPT status; ls -la /root/p6-evidence-*.txt 2>/dev/null" | tee -a "$LOG"
	log "== RESULT: netifd-rs confirmed and resident"
else
	log "waiting for the canary revert (fires ~T0+930, box back ~T0+1100) ..."
	while [ $(( $(date +%s) - T0 )) -lt 1600 ]; do
		if ssh_dev 'md5sum /sbin/netifd' 2>/dev/null | grep -q 031a542b; then log "device back on C netifd"; break; fi
		sleep 15
	done
	ssh_dev 'f=$(ls -t /root/p6-evidence-*.txt 2>/dev/null | head -1); echo "== $f"; grep -nE "UNCONFIRMED|RESTORE|SELF|^---" "$f" | head -20' | tee -a "$LOG"
	log "== RESULT: not confirmed; candidate reverted or never reachable -- read the evidence"
fi
