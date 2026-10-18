#!/usr/bin/env python3
"""Frozen one-batch odhcpd A/B gate. Raw samples are retained in the result.

No device access, sampling, outlier removal, floor subtraction or reruns.
Exit 0: all formal pairs pass; 1: a regression; 2: incomplete/invalid evidence.
"""
import argparse
from fractions import Fraction
import hashlib
import ipaddress
import json
from pathlib import Path
import re


ELFS = {
    'A': '53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82',
    'B': 'c7c5f1f9e79ea80febe696d6c758db8d3463d1e4b94c7a002f1aa597b9c3ea30',
}
SCHEDULE = {'calibration': 'ABBAAB', 'formal': 'ABBABAAB'}
CONTRACT = {
    'schema_version': 1, 'elf_sha256': ELFS, 'schedule': SCHEDULE,
    'settle_ns': 2_000_000_000, 'idle_requested_ns': 3_000_000_000,
    'counts': {'rs': 16, 'solicit': 16, 'request': 16, 'renew': 16,
               'update': 8},
    'population': {'bound_na': 3, 'bound_pd': 0},
    'update_drain_ns': 1_000_000,
    'aggregation': {
        'rs_latency_ns': 'median of all 16 elapsed_ns',
        'solicit_latency_ns': 'median of all 16 elapsed_ns',
        'request_latency_ns': 'median of all 16 elapsed_ns',
        'renew_latency_ns': 'median of all 16 elapsed_ns',
        'update_cpu_ns': 'median of all 8 process CPU deltas through matched RA + 1 ms',
        'idle_cpu_ns_per_s': 'whole-process CPU delta * 1e9 / actual idle elapsed_ns',
        'empty_rss_kib': 'one empty VmRSS observation',
        'empty_rss_anon_kib': 'one empty RssAnon observation',
        'populated_rss_kib': 'one 3-bound-NA, no-PD VmRSS observation',
        'populated_rss_anon_kib': 'one 3-bound-NA, no-PD RssAnon observation',
    },
    'noise': 'max(A calibration range, B calibration range, 2 * actual quantum)',
    'gate': 'each adjacent formal AB/BA pair: any B-A > noise => stop_and_report',
    'idle_periodic_ra': 'included and counted; no solicited traffic; no subtraction',
    'floor': '16 clock and 16 echo records retained, not subtracted or used to exclude samples',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def contract_for(profile='full', candidate_sha=None):
    if profile == 'full':
        require(candidate_sha in (None, ELFS['B']), 'full profile is bound to the original candidate')
        return CONTRACT
    require(profile == 'idle-renew', 'unknown measurement profile')
    require(isinstance(candidate_sha, str) and re.fullmatch(r'[0-9a-f]{64}', candidate_sha),
            'idle-renew requires an explicit candidate SHA256')
    result = {**CONTRACT, 'profile': profile, 'elf_sha256': {**ELFS, 'B': candidate_sha},
              'counts': {'solicit': 16, 'request': 16, 'renew': 16},
              'idle_population': {'bound_na': 0, 'bound_pd': 0},
              'aggregation': {key: CONTRACT['aggregation'][key]
                              for key in ('idle_cpu_ns_per_s', 'renew_latency_ns')},
              'setup': 'Solicit and Request remain raw records; neither is a performance gate'}
    del result['update_drain_ns']
    return result


def integer(record, key, minimum=0):
    value = record.get(key)
    require(type(value) is int and value >= minimum, f'invalid {key}: {value!r}')
    return value


def span(record, start='start_ns', end='end_ns'):
    value = integer(record, end) - integer(record, start)
    require(value >= 0, f'negative {start}/{end} span')
    return value


def packet(record, key='hex'):
    try:
        return bytes.fromhex(record[key])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f'invalid {key}') from error


def options(data):
    result = []
    while data:
        require(len(data) >= 4, 'truncated DHCP option')
        code, length = int.from_bytes(data[:2], 'big'), int.from_bytes(data[2:4], 'big')
        require(len(data) >= 4 + length, 'truncated DHCP option body')
        result.append((code, data[4:4 + length]))
        data = data[4 + length:]
    return result


def dhcp(record):
    kind = record['kind']
    request, reply = packet(record, 'request_hex'), packet(record)
    sent_type = {'solicit': 1, 'request': 3, 'renew': 5}[kind]
    require(len(request) >= 4 and len(reply) >= 4, 'short DHCP packet')
    require(request[0] == sent_type and reply[0] == (2 if sent_type == 1 else 7),
            f'{kind}: wrong DHCP message type')
    require(request[1:4] == reply[1:4], 'DHCP transaction mismatch')
    offered = [body for code, body in options(request[4:]) if code == 3]
    returned = [body for code, body in options(reply[4:]) if code == 3]
    require(len(offered) == len(returned) == 1, 'missing/duplicate requested IA')
    require(len(offered[0]) >= 12 and len(returned[0]) >= 12, 'short IA')
    require(offered[0][:4] == returned[0][:4], 'IAID mismatch')
    suboptions = options(returned[0][12:])
    for code, body in options(reply[4:]) + suboptions:
        if code == 13:
            require(len(body) >= 2 and body[:2] == b'\0\0', 'DHCP failure status')
    addresses = [body for code, body in suboptions if code == 5]
    require(bool(addresses), 'successful reply has no IA address')
    for body in addresses:
        require(len(body) >= 24, 'short IA address')
        preferred = int.from_bytes(body[16:20], 'big')
        valid = int.from_bytes(body[20:24], 'big')
        require(0 < valid and preferred <= valid, 'invalid address lifetime')


def ra_dns(record):
    data = packet(record)
    require(len(data) >= 16 and data[:2] == b'\x86\0', 'invalid RA header')
    result = []
    data = data[16:]
    while data:
        require(len(data) >= 2 and data[1] > 0, 'invalid RA option length')
        size = data[1] * 8
        require(size <= len(data), 'truncated RA option')
        if data[0] == 25:
            require(size >= 24 and (size - 8) % 16 == 0, 'invalid RDNSS option')
            result.extend(str(ipaddress.IPv6Address(data[i:i + 16]))
                          for i in range(8, size, 16))
        data = data[size:]
    return result


def median(values):
    ordered = sorted(Fraction(value) for value in values)
    middle = len(ordered) // 2
    return ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2


def aggregate(identity, records, contract=CONTRACT):
    require(identity.get('schema_version') == 1, 'identity schema must be 1')
    side = identity.get('side')
    elfs = contract['elf_sha256']
    profile = contract.get('profile', 'full')
    require(side in elfs and identity.get('elf_sha256') == elfs[side], 'ELF identity mismatch')
    require(identity.get('profile', 'full') == profile, 'identity profile mismatch')
    require(records and records[0].get('kind') == 'instrument'
            and records[-1].get('kind') == 'complete', 'missing instrument/complete boundaries')
    instrument, complete = records[0], records[-1]
    require(instrument.get('profile', 'full') == complete.get('profile', 'full') == profile,
            'measurement profile mismatch')
    require(instrument.get('schema_version') == complete.get('schema_version') == 1,
            'measurement schema must be 1')
    for key in ('pid', 'start_ticks', 'exe_dev', 'exe_ino'):
        require(integer(instrument, key) == integer(complete, key), f'process changed: {key}')
    require(instrument.get('cpu_clock_kind') == 'process', 'CPU clock must include all threads')
    wall_quantum = integer(instrument, 'clock_quantum_ns', 1)
    cpu_quantum = integer(instrument, 'cpu_clock_quantum_ns', 1)
    page_size = integer(instrument, 'page_size_bytes', 1024)
    require(page_size % 1024 == 0, 'page size is not whole KiB')
    by_kind = {}
    for record in records:
        by_kind.setdefault(record.get('kind'), []).append(record)
    allowed = set(contract['counts']) | {'instrument', 'complete', 'idle'}
    if profile == 'full':
        allowed.add('memory')
    require(set(by_kind) == allowed, 'missing or unexpected record kind')
    for kind in ('instrument', 'complete', 'idle'):
        require(len(by_kind[kind]) == 1, f'duplicate {kind}')
    for kind, count in contract['counts'].items():
        events = by_kind[kind]
        require(len(events) == count, f'{kind}: expected {count} raw events')
        require([integer(event, 'index') for event in events] == list(range(count)),
                f'{kind}: event indices are missing/reordered')
        for event in events:
            require(integer(event, 'elapsed_ns', 1) == span(event), f'{kind}: elapsed disagrees')
            if kind == 'rs':
                ra_dns(event)
            elif kind != 'update':
                dhcp(event)
    require([record['kind'] for record in records if record['kind'] in ('solicit', 'request', 'renew')]
            == ['solicit', 'request', 'renew'] * 16, 'DHCP exchange order differs')
    for kind in ('solicit', 'request', 'renew'):
        require([integer(event, 'client') for event in by_kind[kind]] == [i % 3 for i in range(16)],
                f'{kind}: expected three rotating NA clients')
    for key, count in {'rs_count': contract['counts'].get('rs', 0), 'dhcp_count_each': 16,
                       'updates': contract['counts'].get('update', 0),
                       'na_count': 3, 'pd_count': 0}.items():
        require(integer(complete, key) == count, f'completion count differs: {key}')
    memory = {}
    if profile == 'full':
        memory = {record.get('stage'): record for record in by_kind['memory']}
        require(len(by_kind['memory']) == 2 and set(memory) == {'empty', 'populated'},
                'expected one empty and one populated memory sample')
        require(records.index(memory['empty']) < records.index(by_kind['solicit'][0])
                and records.index(memory['populated']) > records.index(by_kind['renew'][-1]),
                'memory observation has the wrong population phase')
    else:
        require([record['kind'] for record in records]
                == ['instrument', 'idle'] + ['solicit', 'request', 'renew'] * 16 + ['complete'],
                'idle-renew must observe empty idle before three-client setup')
    idle = by_kind['idle'][0]
    elapsed = span(idle)
    require(elapsed >= contract['idle_requested_ns'], 'idle window shorter than 3 seconds')
    require(integer(idle, 'solicited_count') == 0, 'solicited traffic in idle window')
    integer(idle, 'periodic_ra_count')  # Natural periodic work stays in the measurement.
    idle_cpu = span(idle, 'cpu_before_ns', 'cpu_after_ns')
    first_request = by_kind['rs'][0] if 'rs' in by_kind else by_kind['solicit'][0]
    require(integer(first_request, 'start_ns') >= idle['end_ns'], 'request overlaps idle window')
    # Rate values and their CPU-clock quantum use the same actual wall span.
    # The aggregation and quantum formula are fixed before device sampling.
    values = {'idle_cpu_ns_per_s': (Fraction(idle_cpu * 10**9, elapsed),
                                    Fraction(cpu_quantum * 10**9, elapsed))}
    for kind in ('rs', 'solicit', 'request', 'renew'):
        metric = f'{kind}_latency_ns'
        if metric in contract['aggregation']:
            values[metric] = (median(event['elapsed_ns'] for event in by_kind[kind]), wall_quantum)
    previous_dns = None
    for event in by_kind.get('update', []):
        dns = str(ipaddress.IPv6Address(event.get('dns')))
        require(dns != previous_dns and dns in ra_dns(event), 'update did not observe fresh RDNSS')
        previous_dns = dns
        require(integer(event, 'drain_ns') == contract['update_drain_ns'], 'update drain differs')
        require(event['start_ns'] <= integer(event, 'ra_received_ns')
                and event['end_ns'] >= event['ra_received_ns'] + event['drain_ns'],
                'update CPU does not cover RA completion and drain')
        require(integer(event, 'cpu_ns') == span(event, 'cpu_before_ns', 'cpu_after_ns'),
                'update CPU delta disagrees')
    if 'update' in by_kind:
        values['update_cpu_ns'] = (median(event['cpu_ns'] for event in by_kind['update']), cpu_quantum)
    for stage, record in memory.items():
        rss, anon = integer(record, 'rss_kib'), integer(record, 'rss_anon_kib')
        require(0 <= anon <= rss and rss > 0, 'invalid memory counters')
        for key in ('rss_kib', 'rss_anon_kib'):
            values[f'{stage}_{key}'] = (record[key], Fraction(page_size, 1024))
    return values


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def completed(directory, parent_netns=None):
    require((directory / 'COMPLETE').read_text().strip() == 'complete', f'{directory}: not complete')
    require(not (directory / 'TIMEOUT').exists(), f'{directory}: timed out')
    if parent_netns is not None:
        child = (directory / 'netns.txt').read_text().strip()
        require(re.fullmatch(r'net:\[[0-9]+\]', child) and child != parent_netns,
                f'{directory}: child network namespace is not isolated')


def check_floor(records):
    require(records and records[-1] == {'kind': 'floor_complete', 'clock_count': 16, 'echo_count': 16},
            'floor did not complete')
    require([record.get('kind') for record in records]
            == ['floor_clock'] * 16 + ['floor_echo'] * 16 + ['floor_complete'],
            'expected 16 clock and 16 echo floor records')
    for kind in ('floor_clock', 'floor_echo'):
        group = [record for record in records if record['kind'] == kind]
        require([integer(record, 'index') for record in group] == list(range(16)), 'floor indices differ')
        for record in group:
            require(integer(record, 'elapsed_ns') == span(record), 'floor elapsed disagrees')
            if kind == 'floor_clock':
                integer(record, 'clock_quantum_ns', 1)
            else:
                require(record['elapsed_ns'] > 0, 'nonpositive echo elapsed')
                require(integer(record, 'bytes') == 64 and record.get('payload_matches') is True,
                        'echo failed')
                sent, received = packet(record, 'request_hex'), packet(record)
                require(len(sent) == 64 and sent == received, 'echo payload mismatch')


def check_population(directory):
    leases = json.loads((directory / 'leases-final.json').read_text())['device']['br-lan']['leases']
    require(isinstance(leases, list) and len(leases) == 3, 'expected three final NA bindings')
    require(all(lease.get('ipv6-addr') and 'ipv6-prefix' not in lease
                and 'bound' in lease.get('flags', []) for lease in leases),
            'final population is not three bound NA leases without PD')
    require(len({(lease['duid'], lease['iaid']) for lease in leases}) == 3,
            'final lease identities are duplicated')
    counts = json.loads((directory / 'lease-counts.json').read_text())
    require(counts == {'na': 3, 'pd': 0, 'bound': 3}, 'driver lease counts differ')
    return leases


def analyze(root, profile='full', candidate_sha=None):
    contract = contract_for(profile, candidate_sha)
    completed(root)
    require((root / 'mode.txt').read_text().strip() == 'device', 'smoke data is not a device gate')
    profile_path = root / 'profile.txt'
    recorded_profile = profile_path.read_text().strip() if profile_path.exists() else 'full'
    require(recorded_profile == profile, 'batch profile mismatch')
    if profile == 'idle-renew':
        require((root / 'candidate.sha256').read_text().strip() == candidate_sha, 'batch candidate mismatch')
    boot = (root / 'boot-before.txt').read_text().strip()
    require(boot and boot == (root / 'boot-after.txt').read_text().strip(), 'boot identity changed')
    parent_netns = (root / 'parent-netns.txt').read_text().strip()
    require(re.fullmatch(r'net:\[[0-9]+\]', parent_netns), 'missing parent namespace identity')
    samples = []
    for path in sorted(root.glob('*/identity.json')):
        completed(path.parent, parent_netns)
        identity = json.loads(path.read_text())
        raw_path = path.with_name('measurements.jsonl')
        records = read_jsonl(raw_path)
        provider = json.loads(path.with_name('provider-final.json').read_text())
        require(integer(provider, 'sequence') == integer(provider, 'notifications') == contract['counts'].get('update', 0)
                and provider.get('subscribed') is True, 'provider updates did not complete')
        leases = check_population(path.parent)
        samples.append({'identity': identity, 'source': str(raw_path),
                        'sha256': hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                        'records': records, 'provider_final': provider,
                        'leases_final': leases,
                        'metrics': aggregate(identity, records, contract)})
    ordered = []
    for phase, sides in SCHEDULE.items():
        group = sorted((sample for sample in samples if sample['identity'].get('phase') == phase),
                       key=lambda sample: sample['identity'].get('ordinal', -1))
        require([sample['identity'].get('ordinal') for sample in group] == list(range(len(sides)))
                and ''.join(sample['identity']['side'] for sample in group) == sides,
                f'incomplete/reordered {phase} schedule; no replacements permitted')
        ordered.extend(group)
    require(len(ordered) == len(samples) == 14, 'unexpected samples')
    for key in ('clock_quantum_ns', 'cpu_clock_quantum_ns', 'page_size_bytes'):
        require(len({sample['records'][0][key] for sample in ordered}) == 1,
                f'instrument quantization changed: {key}')
    calibration, formal = ordered[:6], ordered[6:]
    metrics = {}
    failures = []
    for name in contract['aggregation']:
        a = [sample['metrics'][name][0] for sample in calibration if sample['identity']['side'] == 'A']
        b = [sample['metrics'][name][0] for sample in calibration if sample['identity']['side'] == 'B']
        quantum = max(sample['metrics'][name][1] for sample in ordered)
        noise = max(max(a) - min(a), max(b) - min(b), 2 * quantum)
        pairs = []
        for index in range(0, 8, 2):
            pair = {sample['identity']['side']: sample for sample in formal[index:index + 2]}
            c, rust = pair['A']['metrics'][name][0], pair['B']['metrics'][name][0]
            delta = rust - c
            classification = 'regression' if delta > noise else 'improvement' if delta < -noise else 'within_noise'
            pairs.append({'pair': index // 2, 'order': ''.join(sample['identity']['side'] for sample in formal[index:index + 2]),
                          'C': c, 'Rust': rust, 'Rust_minus_C': delta, 'classification': classification})
            if classification == 'regression':
                failures.append({'metric': name, **pairs[-1], 'noise': noise})
        metrics[name] = {'calibration_C': a, 'calibration_Rust': b, 'quantum': quantum,
                         'noise': noise, 'pairs': pairs,
                         'formal_C_median': median(pair['C'] for pair in pairs),
                         'formal_Rust_median': median(pair['Rust'] for pair in pairs),
                         'maximum_regression': max(pair['Rust_minus_C'] for pair in pairs)}
    floor_path = root / 'floor' / 'measurements.jsonl'
    completed(floor_path.parent, parent_netns)
    floor = read_jsonl(floor_path)
    check_floor(floor)
    return {'schema_version': 1, 'decision': 'stop_and_report' if failures else 'pass',
            'contract': contract, 'metrics': metrics, 'failures': failures,
            'samples': ordered, 'floor': floor, 'boot_id': boot, 'parent_netns': parent_netns}


def json_number(value):
    if isinstance(value, Fraction):
        return value.numerator if value.denominator == 1 else float(value)
    raise TypeError(type(value).__name__)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, nargs='?')
    parser.add_argument('--output', type=Path, help='new JSON file; never overwrite evidence')
    parser.add_argument('--contract', action='store_true')
    parser.add_argument('--profile', choices=('full', 'idle-renew'), default='full')
    parser.add_argument('--candidate-sha', help='required candidate identity for idle-renew')
    args = parser.parse_args()
    try:
        contract = contract_for(args.profile, args.candidate_sha)
    except ValueError as error:
        parser.error(str(error))
    if args.contract:
        result, status = contract, 0
    else:
        if args.directory is None:
            parser.error('directory is required')
        try:
            result = analyze(args.directory, args.profile, args.candidate_sha)
            status = int(result['decision'] != 'pass')
        except (OSError, ValueError, KeyError, TypeError) as error:
            result = {'schema_version': 1, 'decision': 'invalid_stop', 'error': str(error),
                      'directory': str(args.directory), 'contract': contract}
            status = 2
    output = json.dumps(result, indent=2, default=json_number) + '\n'
    if args.output:
        with args.output.open('x') as destination:
            destination.write(output)
    else:
        print(output, end='')
    return status


if __name__ == '__main__':
    raise SystemExit(main())
