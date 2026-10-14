#!/usr/bin/env python3
"""Fresh FIX5 release NX24/SOA64/cursor12 plus an independent strict wire check.

Only the compact checked receipt enters Git; all 200 side-results and packets
remain under the caller's private/ directory. This run does not measure performance.
"""
import argparse
import copy
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import struct
import subprocess
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def decode(packet):
    """Parse complete DNS frames independently of dns_service_probe.semantics."""
    def name(start):
        labels, pos, end, seen = [], start, None, set()
        while True:
            assert pos < len(packet) and pos not in seen, 'name bounds/cycle'
            seen.add(pos)
            size = packet[pos]
            pos += 1
            if size == 0:
                return labels, end if end is not None else pos
            if size & 0xc0 == 0xc0:
                assert pos < len(packet)
                if end is None:
                    end = pos + 1
                pos = ((size & 63) << 8) | packet[pos]
            else:
                assert 0 < size <= 63 and pos + size <= len(packet)
                labels.append(packet[pos:pos + size].hex())
                pos += size

    assert len(packet) >= 12
    header = struct.unpack_from('!6H', packet)
    pos, questions, records = 12, [], []
    for _ in range(header[2]):
        owner, pos = name(pos)
        kind, cls = struct.unpack_from('!HH', packet, pos)
        pos += 4
        questions.append([owner, kind, cls])
    for section, count in zip(['answer', 'authority', 'additional'], header[3:]):
        for _ in range(count):
            owner, pos = name(pos)
            kind, cls, ttl, size = struct.unpack_from('!HHIH', packet, pos)
            pos += 10
            end = pos + size
            assert end <= len(packet)
            if kind in (2, 5, 12):
                data, consumed = name(pos)
                assert consumed == end, 'name RDATA framing'
            elif kind == 6:
                mname, consumed = name(pos)
                rname, consumed = name(consumed)
                assert consumed + 20 == end, 'SOA RDATA framing'
                data = [mname, rname, *struct.unpack_from('!5I', packet, consumed)]
            elif kind in (15, 33):
                prefix = 2 if kind == 15 else 6
                target, consumed = name(pos + prefix)
                assert consumed == end
                data = [packet[pos:pos + prefix].hex(), target]
            else:
                if kind == 1:
                    assert size == 4
                if kind == 28:
                    assert size == 16
                data = packet[pos:end].hex()
            records.append(dict(section=section, owner=owner, type=kind, cls=cls, ttl=ttl, data=data))
            pos = end
    assert pos == len(packet), 'trailing bytes outside DNS sections'
    return dict(header=list(header), questions=questions, records=records)


def strict_pair(c, rust):
    assert len(c['events']) == len(rust['events'])
    exact, aged, ttl_bounds = 0, 0, []
    for result in (c, rust):
        assert result['status'] == 'passed' and not result.get('error')
        assert all(item['pass'] and item['actual'] == item['expected'] for item in result['dhcp_checks'])
        assert all(event['alive'] and event['ended'] >= event['started'] for event in result['events'])
    for left, right in zip(c['events'], rust['events']):
        assert left['label'] == right['label'] and left['request'] == right['request']
        answers = [decode(bytes.fromhex(event['packet'])) for event in (left, right)]
        for event, response in zip((left, right), answers):
            request = decode(bytes.fromhex(event['request']))
            assert request['questions'] == response['questions'] and request['header'][0] == response['header'][0]
        if answers[0] == answers[1]:
            exact += 1
        else:
            assert len(answers[0]['records']) == len(answers[1]['records'])
            for lrr, rrr in zip(answers[0]['records'], answers[1]['records']):
                if lrr['ttl'] != rrr['ttl']:
                    assert lrr['type'] == rrr['type'] == 6 and lrr['section'] == rrr['section'] == 'authority'
                    assert abs(lrr['ttl'] - rrr['ttl']) <= 1
                    bound = dict(label=left['label'], c_ttl=lrr['ttl'], rust_ttl=rrr['ttl'], sides=[])
                    for side, event, rr, result in [('c', left, lrr, c), ('rust', right, rrr, rust)]:
                        elapsed = event['ended'] - result['events'][0]['started']
                        lower = 3600 - math.floor(elapsed) - 1
                        assert lower <= rr['ttl'] <= 3600
                        bound['sides'].append(dict(side=side, elapsed=elapsed, allowed_lower=lower, allowed_upper=3600))
                    ttl_bounds.append(bound)
                    rrr['ttl'] = lrr['ttl']
            assert answers[0] == answers[1], 'DNS field difference other than bounded SOA TTL'
            aged += 1
        upstream = lambda event: [(u['transport'], u['host'], u['type'], u['class'], u['enabled']) for u in event['upstream']]
        assert upstream(left) == upstream(right), 'upstream behavior differs'
    dhcp = []
    for result in (c, rust):
        replies = copy.deepcopy(result['dhcp_replies'])
        for reply in replies:
            reply.pop('sent')
            reply.pop('received')
        dhcp.append(replies)
    assert dhcp[0] == dhcp[1], 'DHCP decoded header/options/timer difference'
    return dict(responses=exact + aged, exact=exact, bounded_soa=aged, ttl_bounds=ttl_bounds, dhcp_replies=len(dhcp[0]))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('source', 'image', 'fix', 'out'):
        p.add_argument('--' + key, type=Path, required=True)
    p.add_argument('--fix-sha256', required=True)
    p.add_argument('--collect-only', action='store_true')
    a = p.parse_args()
    assert 'private' in a.out.resolve().parts
    if not a.collect_only:
        assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1' and os.geteuid() == 0
        a.out.mkdir(parents=True, exist_ok=False)
    report = dict(status='failed', script_sha256=sha(__file__), fix_sha256=sha(a.fix), suites=[])
    assert report['fix_sha256'] == a.fix_sha256
    tools = a.source / 'tools/dnsmasq'
    for label, script, count in [('negative', 'dhcp_negative_cache_diff.py', 24),
            ('soa', 'dhcp_negative_soa_boundaries.py', 64), ('cursor', 'dhcp_negative_cursor_diff.py', 12)]:
        folder = a.out / label
        argv = ['python3', str(tools / script), '--image-root', str(a.image), '--rust', str(a.fix), '--out', str(folder)]
        if label != 'negative':
            argv += ['--config-evidence', str(a.out / 'negative/summary.json')]
        invocation_path = a.out / (label + '-invocation.json')
        if not a.collect_only:
            start = time.time()
            with (a.out / (label + '.log')).open('wb') as log:
                proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, timeout=180)
            invocation_path.write_text(json.dumps(dict(argv=argv, exit=proc.returncode, started=start,
                finished=time.time(), tool_sha256=sha(tools / script)), indent=2) + '\n')
        invocation = json.loads(invocation_path.read_text())
        assert invocation['exit'] == 0
        summary = json.loads((folder / 'summary.json').read_text())
        assert summary['status'] == 'passed' and len(summary['runs']) == count
        assert summary['identities']['rust'] == report['fix_sha256']
        assert summary['identities']['c'] == '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
        assert summary['identities']['driver'] == sha(tools / script)
        checked = []
        for case in summary['runs']:
            paths = [folder / case['name'] / side / 'result.json' for side in ['c', 'rust']]
            results = [json.loads(path.read_text()) for path in paths]
            counts = strict_pair(*results)
            assert counts['exact'] == case['exact_responses'] and counts['bounded_soa'] == case['clock_bounded_soa_responses']
            checked.append(dict(name=case['name'], **counts, result_sha256=[sha(path) for path in paths]))
        report['suites'].append(dict(name=label, cases=count, summary_sha256=sha(folder / 'summary.json'),
            invocation=invocation, identities=summary['identities'], checks=checked))
        (a.out / 'checked.json').write_text(json.dumps(report, indent=2) + '\n')
        print(label, count, 'strictly checked', flush=True)
    assert sha(a.fix) == report['fix_sha256'], 'release changed during run'
    report['status'] = 'passed'
    report['response_pairs'] = sum(case['responses'] for suite in report['suites'] for case in suite['checks'])
    report['exact'] = sum(case['exact'] for suite in report['suites'] for case in suite['checks'])
    report['bounded_soa'] = sum(case['bounded_soa'] for suite in report['suites'] for case in suite['checks'])
    (a.out / 'checked.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ['status', 'response_pairs', 'exact', 'bounded_soa']}))


if __name__ == '__main__':
    main()
