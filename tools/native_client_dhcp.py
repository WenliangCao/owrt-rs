#!/usr/bin/env python3
"""Record a fresh Mac DHCP ACK without disconnecting or renewing any client."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
from zoneinfo import ZoneInfo


def inspect(summary, packet, not_before, captured_at, timezone='Europe/Berlin'):
    ipv4 = summary.split('IPv4 :', 1)[1].split('IPv6 :', 1)[0] if 'IPv4 :' in summary else ''
    match = re.search(r'LeaseStartTime\s*:\s*(\d+/\d+/\d+ \d+:\d+:\d+)', ipv4)
    start = None
    if match:
        start = datetime.datetime.strptime(match.group(1), '%m/%d/%Y %H:%M:%S').replace(
            tzinfo=ZoneInfo(timezone)).timestamp()
    ack = 'op = BOOTREPLY' in packet and re.search(r'dhcp_message_type\s*\(uint8\):\s*ACK\s+0x5\b', packet) is not None
    server = re.search(r'server_identifier\s*\(ip\):\s*192\.168\.1\.1\b', packet) is not None
    errors = []
    if start is None:
        errors.append('IPv4 lease start time missing')
    elif not not_before <= start <= captured_at:
        errors.append('IPv4 lease start is not after this reboot/request boundary')
    if not ack:
        errors.append('current client packet is not a DHCP ACK')
    if not server:
        errors.append('current DHCP ACK server is not the expected router')
    return {'passed': not errors, 'errors': errors, 'lease_start_unix': start,
            'not_before_unix': not_before, 'captured_at_unix': captured_at,
            'current_packet_is_ACK': ack, 'expected_router_server': server,
            'scope': 'Mac DHCP lease start plus current ACK snapshot; no forced renew/disconnect and no inference from the router lease file alone.'}


def capture(interface, output, not_before):
    assert re.fullmatch(r'en[0-9]+', interface)
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    values = {}
    for name, arguments in (('summary', ['getsummary', interface]), ('packet', ['getpacket', interface])):
        result = subprocess.run(['ipconfig', *arguments], capture_output=True, timeout=10)
        for suffix, data in (('txt', result.stdout), ('stderr', result.stderr)):
            path = output / (name + '.' + suffix); path.write_bytes(data); path.chmod(0o600)
        if result.returncode:
            raise RuntimeError('ipconfig ' + name + ' failed; private output retained')
        values[name] = result.stdout.decode()
    result = inspect(values['summary'], values['packet'], not_before, time.time())
    result['private_sha256'] = {name: hashlib.sha256(text.encode()).hexdigest() for name, text in values.items()}
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', default='en0')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--not-before-unix', required=True, type=float,
                        help='Actual reboot command or client reconnect boundary, never inferred from boot ID')
    args = parser.parse_args()
    result = capture(args.interface, args.output, args.not_before_unix)
    print(json.dumps(result))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
