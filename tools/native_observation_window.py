#!/usr/bin/env python3
"""One fixed, passive 3600s post-reboot observation; requires confirmed native deployment."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import threading
import time
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parent / 'dnsmasq'))
import daily_usage

SECONDS = 3600
INTERVAL = 5
HEALTH_PERIOD = 30
HEALTH_GROUPS = 120
HEALTH_NAME = 'www.cloudflare.com'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stamp():
    now = datetime.datetime.now(datetime.timezone.utc)
    return {'utc': now.isoformat(), 'local': now.astimezone(ZoneInfo('Europe/Berlin')).isoformat()}


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n'); path.chmod(0o600)


def pairing_summary(value):
    p = value['same_source_name_pairing']
    assert p['window_seconds'] == 10 and p['capacity'] == 2048
    assert p['groups'] == p['a_only_groups'] + p['aaaa_only_groups'] + p['dual_groups']
    assert p['eligible_queries'] == p['tracked_queries'] + p['overflow_queries']
    assert p['tracked_queries'] == p['tracked_a'] + p['tracked_aaaa']
    return {'dual_group_fraction': p['dual_groups'] / p['groups'] if p['groups'] else None,
            'dual_group_query_fraction': p['dual_group_queries'] / p['tracked_queries'] if p['tracked_queries'] else None,
            'raw_counts': p,
            'scope': 'Fixed non-overlapping10s windows; same source IP/family and case-normalized question name, source port ignored. Repeat queries remain in query denominator. Cross-window pairs are not combined. Keys stay only in memory.',
            'limitations': 'UDP53 to initial br-lan local addresses only; TCP is counted as segments, not decoded queries. DoH/DoT, bypass resolvers, and unobserved clients are invisible. Overflow, dropped/truncated/fragment packets and malformed queries remain explicit; this is not the fraction of all household DNS or proven cache-hit coverage.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, help='Existing native deployment directory containing result-normal.json and recovery-gate.json')
    parser.add_argument('--dhcp-evidence', type=Path, required=True)
    parser.add_argument('--daily-probe', type=Path, required=True)
    parser.add_argument('--daily-sha256', required=True)
    parser.add_argument('--pairing-probe', type=Path, required=True)
    parser.add_argument('--pairing-sha256', required=True)
    parser.add_argument('--host', default='openwrt')
    parser.add_argument('--interface', default='en0')
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    assert re.fullmatch(r'en[0-9]+', args.interface)
    for path, digest in ((args.daily_probe, args.daily_sha256), (args.pairing_probe, args.pairing_sha256)):
        assert re.fullmatch(r'[0-9a-f]{64}', digest) and sha(path) == digest
    if not args.execute:
        print(json.dumps({'execute': False, 'seconds': SECONDS, 'resource_samples': 721,
              'health_groups': HEALTH_GROUPS, 'health_checks_per_group': 5,
              'earliest_local_start': '09:00 Europe/Berlin', 'normal_reboot_and_guard_confirmation_required': True,
              'fresh_DHCP_ACK_required': True, 'guard_removed_by_this_tool': False}))
        return
    assert datetime.datetime.now(ZoneInfo('Europe/Berlin')).hour >= 9, 'Wait for local daytime; this tool does not wait or poll for09:00'
    base = args.directory.resolve()
    normal = json.loads((base / 'result-normal.json').read_text())
    dhcp = json.loads(args.dhcp_evidence.read_text())
    assert normal['status'] == 'native_image_healthy_and_client_confirmed'
    assert normal['observation_label'] == 'normal' and normal['automatic_guard_remains_armed']
    assert normal['continuous_client_health_s'] >= 180
    assert dhcp['passed'] and dhcp['current_packet_is_ACK'] and dhcp['expected_router_server']
    reboot = json.loads((base / 'normal-reboot-request.json').read_text())
    assert normal['boot_id'] != reboot['previous_boot_id']
    assert dhcp['not_before_unix'] == reboot['requested_unix']
    gate = json.loads((base / 'recovery-gate.json').read_text())
    manifest = json.loads(Path(gate['manifest_path']).read_text())
    assert normal['source_commit'] == manifest['source_commit']
    assert normal['image_sha256'] == manifest['image']['sha256']
    out = base / 'observation-3600'; out.mkdir(mode=0o700, exist_ok=False)
    ssh = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
           '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2', args.host]

    def remote(command, timeout=30, check=True):
        result = subprocess.run(ssh + [command], capture_output=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError('remote observation operation failed; no service mutation requested')
        return result

    boot = normal['boot_id']
    expected = manifest['components']['dnsmasq']['rust_sha256']
    identity_script = '''set -eu
[ "$(cat /proc/sys/kernel/random/boot_id)" = BOOT ]
[ "$(cat /root/owrt-native-trial/accepted)" = "$(cat /root/owrt-native-trial/armed) BOOT" ]
kill -0 "$(cat /tmp/owrt-native-guard-lock/pid)"
test ! -f /root/owrt-native-trial/rollback-requested
for p in $(pidof dnsmasq); do
 if [ "$(sha256sum /proc/$p/exe | cut -d' ' -f1)" = HASH ]; then
  printf '%s %s\n' "$p" "$(awk '{print $22}' /proc/$p/stat)"
 fi
done
'''.replace('BOOT', shlex.quote(boot)).replace('HASH', expected)
    identity = remote(identity_script).stdout.decode().splitlines()
    assert len(identity) == 1
    pid, start = map(int, identity[0].split())
    address_command = "ip -o addr show dev br-lan | awk '{print $3,$4}' | sort | sha256sum"
    addresses_before = remote(address_command).stdout.decode().split()[0]
    css_hash = remote('sha256sum /www/luci-static/bootstrap/cascade.css').stdout.decode().split()[0]
    address = subprocess.check_output(['ipconfig', 'getifaddr', args.interface], text=True).strip()
    remote_dir = '/tmp/owrt-v021-observation-' + str(time.time_ns())
    remote('umask 077; mkdir ' + remote_dir)
    for path, name, digest in ((args.daily_probe, 'daily_usage_probe', args.daily_sha256),
                               (args.pairing_probe, 'query-pairing-stats', args.pairing_sha256)):
        command = 'set -eu\numask 077\ncat > '+remote_dir+'/'+name+'\ntest "$(sha256sum '+remote_dir+'/'+name+' | cut -d " " -f 1)" = '+digest+'\nchmod 700 '+remote_dir+'/'+name
        subprocess.run(ssh + [command], input=path.read_bytes(), capture_output=True, check=True, timeout=30)
    group = '''#!/bin/sh
set -eu
root=$1
pid=$2
start=$3
[ "$(awk '{print $22}' /proc/$pid/stat)" = "$start" ]
printf '%s %s\n' "$$" "$(awk '{print $22}' /proc/$$/stat)" > "$root/owner"
nice -n 10 "$root/query-pairing-stats" br-lan 3600 > "$root/pairing.json" 2> "$root/pairing.stderr" &
pair=$!
pair_start=$(awk '{print $22}' /proc/$pair/stat)
set +e
nice -n 10 "$root/daily_usage_probe" "$pid" "$start" 3600 5 /tmp/dhcp.leases
daily_status=$?
if [ "$daily_status" -ne 0 ] && [ "$(awk '{print $22}' /proc/$pair/stat 2>/dev/null)" = "$pair_start" ]; then kill -TERM "$pair"; fi
wait "$pair"
pair_status=$?
printf '%s %s\n' "$daily_status" "$pair_status" > "$root/exits"
[ "$daily_status" -eq 0 ] && [ "$pair_status" -eq 0 ]
'''
    (out / 'group.sh').write_text(group)
    subprocess.run(ssh + ['cat > ' + remote_dir + '/group.sh'], input=group.encode(), capture_output=True, check=True, timeout=20)
    finished = threading.Event(); failed = threading.Event(); health_rows = []
    started = time.monotonic()

    def stop_observers():
        # Signals only our exact recorded session, never the daemon or native rollback guard.
        command = '''set -eu
read owner expected < ROOT/owner
case "$owner:$expected" in *[!0-9:]*|:*) exit 2;; esac
[ "$owner" -gt 1 ]
[ "$(awk '{print $22}' /proc/$owner/stat 2>/dev/null)" = "$expected" ] || exit 0
[ "$(awk '{print $5}' /proc/$owner/stat)" = "$owner" ]
tr '\\000' '\\n' < /proc/$owner/cmdline | grep -F 'ROOT/group.sh' >/dev/null
kill -TERM -- -"$owner"
'''.replace('ROOT', remote_dir)
        try:
            result = remote(command, check=False)
            (out / 'stop-observers.stderr').write_bytes(result.stderr)
        except Exception as caught:
            write(out / 'stop-observers-error.json', {'error': repr(caught)})

    def health_loop():
        try:
            with (out / 'health.jsonl').open('x') as log:
                for index in range(HEALTH_GROUPS):
                    if finished.wait(max(0, started + index * HEALTH_PERIOD - time.monotonic())):
                        return
                    group_started = time.monotonic() - started
                    checks = []
                    commands = [
                        ('dns_udp', ['dig', '-b', address, '@192.168.1.1', HEALTH_NAME, 'A', '+time=3', '+tries=1']),
                        ('dns_tcp', ['dig', '-b', address, '@192.168.1.1', HEALTH_NAME, 'A', '+tcp', '+time=3', '+tries=1']),
                        ('luci', ['curl', '--interface', address, '--noproxy', '*', '-4', '-sS', '--connect-timeout', '4', '--max-time', '8', 'http://192.168.1.1/luci-static/bootstrap/cascade.css']),
                        ('ipv4_https', ['curl', '--interface', address, '--noproxy', '*', '-4', '-sS', '--connect-timeout', '4', '--max-time', '8', '-o', '/dev/null', '-w', '%{http_code} %{time_total}', 'https://' + HEALTH_NAME + '/']),
                        ('ipv6_https', ['curl', '--interface', args.interface, '--noproxy', '*', '-6', '-sS', '--connect-timeout', '4', '--max-time', '8', '-o', '/dev/null', '-w', '%{http_code} %{time_total}', 'https://' + HEALTH_NAME + '/'])]
                    for name, command in commands:
                        began = time.monotonic()
                        try:
                            p = subprocess.run(command, capture_output=True, timeout=10)
                            okay = p.returncode == 0
                            if name.startswith('dns_'):
                                text = p.stdout.decode(errors='replace')
                                okay = okay and 'status: NOERROR' in text and re.search(r'\bANSWER: [1-9][0-9]*\b', text) is not None
                            elif name == 'luci':
                                okay = okay and hashlib.sha256(p.stdout).hexdigest() == css_hash
                            else:
                                okay = okay and p.stdout.startswith(b'200 ')
                            row = {'name': name, 'exit': p.returncode, 'passed': okay,
                                   'seconds': time.monotonic()-began, 'stdout_sha256': hashlib.sha256(p.stdout).hexdigest()}
                            if not okay:
                                (out / f'health-{index}-{name}.stdout').write_bytes(p.stdout)
                                (out / f'health-{index}-{name}.stderr').write_bytes(p.stderr)
                        except Exception as error:
                            row = {'name': name, 'passed': False, 'seconds': time.monotonic()-began, 'error': type(error).__name__}
                        checks.append(row)
                    row = {'index': index, 'time': stamp(), 'scheduled_offset_s': index*HEALTH_PERIOD,
                           'started_offset_s': group_started, 'completed_offset_s': time.monotonic()-started, 'checks': checks}
                    health_rows.append(row); log.write(json.dumps(row)+'\n'); log.flush()
                    print(json.dumps({'health_group': index+1, 'passed': sum(c['passed'] for c in checks), 'checks': len(checks), 'time': row['time']}), flush=True)
                    if not all(check['passed'] for check in checks):
                        failed.set(); stop_observers(); return
        except Exception as error:
            failed.set(); write(out / 'health-failure.json', {'error': repr(error), 'time': stamp()})
            stop_observers()

    monitor = threading.Thread(target=health_loop, daemon=True)
    launch = {'start': stamp(), 'seconds': SECONDS, 'resource_interval_s': INTERVAL,
              'expected_resource_samples': 721, 'planned_health_groups': HEALTH_GROUPS,
              'source_commit': manifest['source_commit'], 'boot_id': boot, 'pid_start': [pid,start],
              'daily_sha256': args.daily_sha256, 'pairing_sha256': args.pairing_sha256,
              'remote_directory': remote_dir, 'addresses_before_sha256': addresses_before,
              'native_guard_remains_armed': True}
    write(out / 'launch.json', launch)
    error = None
    try:
        with (out / 'usage.jsonl').open('xb') as stdout, (out / 'collection.stderr').open('xb') as stderr:
            process = subprocess.Popen(ssh + ['setsid /bin/sh ' + remote_dir + '/group.sh ' + remote_dir + ' ' + str(pid) + ' ' + str(start)], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            monitor.start()
            status = process.wait(timeout=3660)
        if status or failed.is_set():
            raise RuntimeError('observation helper or client health failed')
    except BaseException as caught:
        error = repr(caught); failed.set(); stop_observers()
    finally:
        finished.set()
        if monitor.is_alive(): monitor.join(timeout=55)
        for name in ('pairing.json','pairing.stderr','owner','exits'):
            try:
                result = remote('cat '+remote_dir+'/'+name, check=False)
                (out / name).write_bytes(result.stdout)
            except Exception as caught:
                write(out / (name+'.retrieval-error.json'), {'error': repr(caught)})
        write(out / 'collection.json', {'start': launch['start'], 'end': stamp(), 'error': error,
              'health_failed': failed.is_set(), 'health_groups_executed': len(health_rows),
              'usage_sha256': sha(out/'usage.jsonl'), 'pairing_sha256': sha(out/'pairing.json') if (out/'pairing.json').exists() else None})
    if error:
        raise RuntimeError(error)
    assert not monitor.is_alive() and len(health_rows) == HEALTH_GROUPS and not failed.is_set()
    assert remote(identity_script).stdout.decode().splitlines() == identity
    assert remote(address_command).stdout.decode().split()[0] == addresses_before
    rows = [json.loads(line) for line in (out/'usage.jsonl').read_text().splitlines()]
    resources = daily_usage.summarize(rows, SECONDS, INTERVAL)
    aggregate = json.loads((out/'pairing.json').read_text())
    assert aggregate['schema'] == 2 and aggregate['duration_seconds'] == SECONDS
    assert 3599.9 <= aggregate['elapsed_seconds'] <= 3601 and not aggregate['interrupted']
    assert not aggregate['receive_errors'] and aggregate['socket_stats_available']
    assert resources['valid_observation_window'] and not (out/'pairing.stderr').read_bytes()
    resources['service_age_at_start_seconds'] = rows[0]['monotonic_ns']/1e9 - start/resources['clock_ticks_per_second']
    resources['one_tick_window_percentage_points'] = 100/(resources['clock_ticks_per_second']*SECONDS)
    summary = {'complete': True, 'start': launch['start'], 'end': stamp(), 'resources': resources,
               'health_groups_executed': len(health_rows), 'health_checks_passed': sum(c['passed'] for row in health_rows for c in row['checks']),
               'pairing': pairing_summary(aggregate), 'aggregate': aggregate,
               'sampling_socket_drops': aggregate['socket_drops'],
               'captured_packet_coverage_qualified': not any(aggregate[key] for key in ('socket_drops','fragment_packets_skipped','truncated','receive_errors')) and not aggregate['same_source_name_pairing']['overflow_queries'],
               'native_guard_still_armed': True,
               'observation_is_performance_comparison': False}
    write(out / 'result.json', summary)
    print(json.dumps({'complete': True, 'samples': len(rows), 'health_groups': len(health_rows), 'end': summary['end']}))


if __name__ == '__main__':
    main()
