#!/usr/bin/env python3
"""Recheck downloaded final DHCP case evidence locally; never contact Oracle."""
import argparse
from collections import Counter
import hashlib
import itertools
import json
import math
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[6]
sys.path.insert(0, str(ROOT / 'tools/dnsmasq'))
from dns_service_probe import read_name, semantics

C_SHA = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
REMOTE = '/home/ubuntu/dnsmasq-fix4-repair-20261013/private/'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def need(value, label):
    if not value:
        raise ValueError(label)


def differences(left, right, path=()):
    if type(left) != type(right):
        return [path]
    if isinstance(left, dict):
        if set(left) != set(right):
            return [path]
        return [item for key in left for item in differences(left[key], right[key], (*path, key))]
    if isinstance(left, list):
        if len(left) != len(right):
            return [path]
        return [item for index, (a, b) in enumerate(zip(left, right)) for item in differences(a, b, (*path, index))]
    return [] if left == right else [path]


def wire_check(event):
    packet = bytes.fromhex(event['packet'])
    need(semantics(packet) == event['reply'], 'retained decoded fields disagree with packet')
    _, _, qd, an, ns, ar = struct.unpack_from('!6H', packet)
    position = 12
    for _ in range(qd):
        _, position = read_name(packet, position)
        position += 4
    for _ in range(an + ns + ar):
        _, position = read_name(packet, position)
        size = struct.unpack_from('!H', packet, position + 8)[0]
        position += 10 + size
    need(position == len(packet), 'full response wire framing')
    request = semantics(bytes.fromhex(event['request']))
    need(request['questions'] == event['reply']['questions'] and request['id'] == event['reply']['id'],
         'response matches its original query')


def check(args, report):
    directory, raw = args.directory, args.raw
    sdk = read(directory / 'dhcp-sdk.json')
    index = read(directory / 'dhcp-sdk-raw-index.json')['files']
    build = read(directory.parent / 'build/final-summary.json')
    expected_rust = build['sdk'][0]['elf']['sha256']
    need(sdk['passed'] and sdk['source_commit'] == build['source_commit']
         and sdk['SDK_elf']['sha256'] == expected_rust, 'final SDK/source identity')
    indexed = {row['path'].removeprefix(REMOTE): row for row in index}
    need(len(indexed) == len(index), 'unique raw evidence inventory')
    checked = {}
    for path in sorted(raw.rglob('*.json')):
        relative = str(path.relative_to(raw))
        expected = sdk['invocation'] if relative == 'dhcp-final-invocations.json' else indexed[relative]
        need(sha(path) == expected['sha256'] and path.stat().st_size == expected['bytes'], 'downloaded raw hash: ' + relative)
        checked[relative] = sha(path)
    need(len(checked) == 204, 'all 200 side results, 3 summaries and invocation downloaded')
    invocation = read(raw / 'dhcp-final-invocations.json')
    need(invocation['passed'] and invocation['rust_sha256'] == expected_rust, 'three final probe invocations')
    stats, aged = {}, []
    for suite, expected_cases, driver in (
        ('negative', 24, 'dhcp_negative_cache_diff.py'), ('soa', 64, 'dhcp_negative_soa_boundaries.py'),
        ('cursor', 12, 'dhcp_negative_cursor_diff.py')):
        folder = raw / ('dhcp-final-' + suite)
        summary = read(folder / 'summary.json')
        exported = sdk['probes'][suite]
        need(sha(folder / 'summary.json') == exported['summary']['sha256'], 'exported summary identity')
        need(summary['status'] == 'passed' and len(summary['runs']) == expected_cases == exported['cases'], 'complete suite')
        need(len(exported['runs']) == expected_cases, 'all cases exported')
        for original, derived in zip(summary['runs'], exported['runs']):
            need({k: v for k, v in original.items() if k != 'boundary'}
                 == {k: v for k, v in derived.items() if k != 'boundary'}, 'exported case fields equal raw summary')
            if 'boundary' in original:
                boundary = {side: {'reply': event['reply'], 'packet_bytes': len(bytes.fromhex(event['packet'])),
                    'packet_sha256': hashlib.sha256(bytes.fromhex(event['packet'])).hexdigest(),
                    'upstream_requests': len(event['upstream']), 'alive': event['alive']}
                    for side, event in original['boundary'].items()}
                need(boundary == derived['boundary'], 'exported boundary packet identity and fields')
        need(summary['identities']['c'] == C_SHA and summary['identities']['rust'] == expected_rust,
             'exact C and SDK used for each probe')
        need(summary['identities']['driver'] == sha(ROOT / 'tools/dnsmasq' / driver), 'probe driver hash')
        command = exported['command']
        need(command['passed'] and command['returncode'] == 0 and command in invocation['commands'], 'successful recorded invocation')
        names = [row['name'] for row in summary['runs']]
        need(len(set(names)) == expected_cases, 'unique cases')
        if suite == 'negative':
            actual = {(r['rcode'], r['soa'], r['debug'], r['warm_type'], r['warm_transport']) for r in summary['runs']}
            need(actual == set(itertools.product((3,), (False, True), (False, True), (1, 28, 16), ('udp', 'tcp'))), 'NX24 matrix')
        elif suite == 'soa':
            actual = {(r['large'], r['debug'], r['host'], r['transport'], r['rd'], r['do']) for r in summary['runs']}
            need(actual == set(itertools.product((False, True), (False, True), ('client1.leases.test', 'alias.leases.test'),
                 ('udp', 'tcp'), (False, True), (False, True))), 'SOA64 matrix')
        else:
            labels = ('raw-pointer', 'raw-target-nx', 'raw-owner-nx', 'configured-cname-stop', 'reverse-synth', 'reverse-explicit')
            need(set(names) == {f'{label}-debug{debug}' for label in labels for debug in (0, 1)}, 'cursor12 matrix')
        totals = Counter(cases=expected_cases, responses=0, exact=0, bounded_soa=0, upstream_pairs=0)
        for case in summary['runs']:
            need(not case.get('differences') and case['status'] == {'c': 'passed', 'rust': 'passed'}, 'case declared complete')
            sides = [read(folder / case['name'] / side / 'result.json') for side in ('c', 'rust')]
            for side in sides:
                need(side['status'] == 'passed' and not side.get('error'), 'healthy case result')
                need(all(item['pass'] and item['actual'] == item['expected'] for item in side['dhcp_checks']), 'DHCP and exit/resource checks')
                need(any(item['case'].endswith('-exit') and item['actual'] == 0 for item in side['dhcp_checks']), 'clean daemon exit')
                need(all(event['alive'] and event['ended'] >= event['started'] for event in side['events']), 'all queries observed live daemon')
                need(all(a['ended'] <= b['started'] for a, b in zip(side['events'], side['events'][1:])), 'ordered query times')
                for event in side['events']:
                    wire_check(event)
            need(len(sides[0]['events']) == len(sides[1]['events']), 'same query count')
            exact = bounded = 0
            for a, b in zip(sides[0]['events'], sides[1]['events']):
                need(a['label'] == b['label'] and a['request'] == b['request'], 'paired identical queries')
                fields = differences(a['reply'], b['reply'])
                if not fields:
                    exact += 1
                else:
                    for path in fields:
                        need(len(path) == 3 and path[0] == 'records' and isinstance(path[1], int) and path[2] == 'ttl',
                             'difference outside SOA TTL: ' + repr(path))
                        records = [event['reply']['records'][path[1]] for event in (a, b)]
                        need(all(rr['section'] == 'authority' and rr['type'] == 6 for rr in records), 'only authority SOA TTL may age')
                        need(abs(records[0]['ttl'] - records[1]['ttl']) <= 1, 'SOA TTL delta exceeds one second')
                        bounds = []
                        for event, rr, side in zip((a, b), records, sides):
                            elapsed = event['ended'] - side['events'][0]['started']
                            lower = 3600 - math.floor(elapsed) - 1
                            need(0 <= elapsed and lower <= rr['ttl'] <= 3600, 'SOA TTL exceeds per-instance elapsed bound')
                            bounds.append({'ttl': rr['ttl'], 'elapsed_seconds': elapsed, 'minimum_ttl': lower})
                        aged.append({'suite': suite, 'case': case['name'], 'event': a['label'], 'bounds': bounds})
                    bounded += 1
                upstream = lambda event: [(u['transport'], u['host'], u['type'], u['class'], u['enabled']) for u in event['upstream']]
                need(upstream(a) == upstream(b), 'upstream transactions differ')
                totals['upstream_pairs'] += 1
            need(exact == case['exact_responses'] and bounded == case['clock_bounded_soa_responses'], 'independent response counts')
            totals.update(responses=exact + bounded, exact=exact, bounded_soa=bounded)
        need(totals['exact'] == exported['exact_responses'] and totals['bounded_soa'] == exported['clock_bounded_soa_responses'], 'suite totals')
        stats[suite] = dict(totals)
    contract = read(directory.parent / 'dhcp/before.json')['source_contract']
    for name in ('cache.c', 'rfc1035.c'):
        need(sha(ROOT / 'private/dnsmasq-rewrite/reference/dnsmasq-2.93/src' / name) == contract[name], 'matching exact C source hash')
    report.update(status='passed', source_commit=sdk['source_commit'], SDK_elf_sha256=expected_rust, C_elf_sha256=C_SHA,
                  downloaded_json_files_rehashed=len(checked), raw_index_files=len(index),
                  downloaded_inventory_sha256=hashlib.sha256(json.dumps(checked, sort_keys=True).encode()).hexdigest(),
                  probes=stats, total_response_pairs=sum(row['responses'] for row in stats.values()),
                  clock_bounded_soa_details=aged, exact_C_source_hashes={name: contract[name] for name in ('cache.c', 'rfc1035.c')})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--raw', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    need(not args.output.exists(), 'fresh output required')
    report = {'schema': 1, 'status': 'failed', 'script_sha256': sha(Path(__file__)),
              'input_sha256': {name: sha(args.directory / name) for name in ('dhcp-sdk.json', 'dhcp-sdk-raw-index.json')},
              'scope': 'Local rehash of downloaded case/summary/invocation files and independent all-field/upstream/health/TTL comparison; shared DNS wire decoder used only to recheck stored packets. No Oracle access or experiment rerun.'}
    try:
        check(args, report)
    except Exception as error:
        report['error'] = repr(error)
        raise
    finally:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'output': str(args.output), 'status': report['status'], 'sha256': sha(args.output)}))
