#!/usr/bin/env python3
"""Check retained raw results and emit compact, redacted regression evidence."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    source, private = a.root / 'source', a.root / 'private'
    tools = source / 'tools/dnsmasq'
    a.out.mkdir(parents=True, exist_ok=True)
    decoder = module(source / 'docs/dnsmasq/audits/20261014/fix5/dns/collect.py', 'wire')
    actual_decoder = module(source / 'docs/dnsmasq/audits/20261014/predeploy_behavior/root/check_dns.py', 'actual_wire')

    def decode_actual(packet):
        # The focused-audit decoder keeps SOA opaque; the broader corpus also
        # checks its two names and five integers with the independent RR decoder.
        result = actual_decoder.decode(packet)
        decoded = decoder.decode(dict(status='reply', hex=packet.hex()))
        assert 'parse_error' not in decoded
        records = [rr for section in decoded['sections'] for rr in section]
        assert len(result['records']) == len(records)
        for record, rr in zip(result['records'], records):
            if record['type'] == 6:
                labels = lambda value: '.'.join(bytes.fromhex(part).decode('ascii') for part in value).lower()
                record['data'] = [labels(rr[4][0]), labels(rr[4][1]),
                                  *struct.unpack('!5I', bytes.fromhex(rr[4][2]))]
        return result

    summary = dict(checker_sha256=sha(__file__), actual={}, history={})
    for label in ('focused', 'public-cache', 'regular'):
        folders = {side: private / 'actual' / (side + '-' + label) for side in ('c', 'rust')}
        argv = ['python3', str(tools / 'predeploy_audit_dns.py'), '--mode', 'compare',
                '--reference', str(folders['c'] / 'result.json'), '--candidate', str(folders['rust'] / 'result.json'),
                '--out', str(a.out / label)]
        run = subprocess.run(argv, check=True, capture_output=True, text=True)
        compared = read(a.out / label / 'comparison.json')
        assert compared['process_exits'] == {'c': [0, 0], 'rust': [0, 0]}
        assert all(row['daemon_alive_both'] for row in compared['cases'])
        raw = {side: read(folder / 'result.json') for side, folder in folders.items()}
        decoded = 0
        for side, folder in folders.items():
            for case in raw[side]['cases']:
                for index, client in enumerate(case['clients']):
                    request = decode_actual((folder / case['label'] / f'{index}.request').read_bytes())
                    assert request['questions'] == [[client['host'], client['type'], 1]]
                    if 'response' in client:
                        reply = decode_actual((folder / case['label'] / f'{index}.reply').read_bytes())
                        assert reply == client['response']
                        assert (reply['id'], reply['questions']) == (request['id'], request['questions'])
                        decoded += 1
        if label == 'focused':
            outage = {side: next(c for c in trace['cases'] if c['label'] == 'local-chain-outage')
                      for side, trace in raw.items()}
            assert all(x['clients'][1]['response']['records'] == [] and
                       x['clients'][1]['response']['flags'] & 15 == 0 for x in outage.values())
            upstream = {side: [r['type'] for r in trace['upstream'] if r['stage'] == 'local-chain-outage']
                        for side, trace in raw.items()}
            assert upstream == {'c': [1], 'rust': [1]}
        summary['actual'][label] = dict(**compared['totals'], independently_decoded_responses=decoded,
            upstream_requests={side: compared['upstream'][side]['requests'] for side in ('c', 'rust')},
            upstream_stage_counts_equal=compared['upstream']['c']['by_stage'] == compared['upstream']['rust']['by_stage'],
            endpoint_query_counts_equal=compared['upstream']['endpoint_query_counts_equal'],
            result_sha256=compared['source_result_sha256'], comparison_sha256=sha(a.out / label / 'comparison.json'))

    subprocess.run(['python3', str(tools / 'predeploy_audit_reload.py'), '--mode', 'compare',
        '--c-out', str(private / 'actual/c-reload'), '--rust-out', str(private / 'actual/rust-reload'),
        '--out', str(a.out / 'reload')], check=True, capture_output=True, text=True)
    summary['actual']['reload'] = read(a.out / 'reload/summary.json')
    summary['actual']['reload']['result_sha256'] = {side: sha(private / 'actual' / (side + '-reload/result.json')) for side in ('c', 'rust')}

    robust = {side: read(private / 'actual' / (side + '-robustness/result.json')) for side in ('c', 'rust')}
    counts, differences = {}, []
    for side, trace in robust.items():
        assert trace['daemon_alive_after_corpus'] and trace['daemon_exit'] == 0 and not trace['errors']
        assert not trace['quick'] and not trace['client']['errors']
        assert len(trace['client']['dns']) == 316 and len(trace['client']['dhcp']) == 31
        assert len(trace['client']['health']) == 20
        assert [(h['dhcp_type'], h['reply_type']) for h in trace['client']['health'] if 'dhcp_type' in h] == [(1, 2), (3, 5)]
        assert all('reply_hex' in h for h in trace['client']['health'])
        counts[side] = dict(binary_sha256=trace['binary_sha256'], config_sha256=trace['config_sha256'],
            immutable_sha256=trace['immutable_sha256'], result_sha256=sha(private / 'actual' / (side + '-robustness/result.json')),
            dns_replies=sum('reply_hex' in r for r in trace['client']['dns']),
            dhcp_replies=sum(bool(r['reply_hex']) for r in trace['client']['dhcp']), health=20, daemon_exit=0)
    for c, rust in zip(robust['c']['client']['dns'], robust['rust']['client']['dns']):
        if c != rust:
            assert c['case'] == rust['case'] and c['tcp'] == rust['tcp'] is True
            assert c['case'] in ('padded-4096', 'padded-65507')
            assert c['outcome'] == 'ConnectionError' and rust['outcome'] == 'ConnectionResetError'
            differences.append(dict(case=c['case'], c=c['outcome'], rust=rust['outcome']))
    assert robust['c']['client']['dhcp'] == robust['rust']['client']['dhcp']
    summary['actual']['robustness'] = dict(sides=counts, dns_cases=316, dns_exact_matches=316-len(differences),
        retained_b03_differences=differences, dhcp_exact_matches=31, complete_image_files=True)

    def upstream(rows):
        result = []
        for row in rows:
            row = copy.deepcopy(row)
            for field in ('query', 'reply'):
                if field in row:
                    parsed = decoder.decode(dict(status='reply', hex=row[field]))
                    assert 'parse_error' not in parsed
                    parsed['header'][0] = 0
                    row[field] = parsed
            result.append(row)
        return result

    groups = [('regression', label) for label in ('f2', 'f2-anchor', 'candidate-anchor', 'extended-controls',
              'f1-query-dynamic', 'f1-query-anchor', 'f1-target-dynamic', 'f1-target-anchor',
              'full-terminal', 'chain-dynamic', 'chain-anchor', 'n1')]
    groups += [('boundary', 'alias'), ('boundary', 'direct')]
    for family, label in groups:
        path = private / family / label / 'result.json'
        raw = read(path)
        cases = raw.get('cases', raw.get('runs'))
        malformed, warm = [], 0
        for case in cases:
            c, fix = (case['sides'][side] for side in ('c', 'fix'))
            left, right = (decoder.decode(side['response']) for side in (c, fix))
            if 'parse_error' in left:
                assert c['response'] == fix['response'], case['label']
                malformed.append(case['label'])
            else:
                assert left == right, (family, label, case.get('label', case.get('name')), 'response')
            assert upstream(c['upstream']) == upstream(fix['upstream']), (label, case.get('label', case.get('name')), 'upstream')
            for side in (c, fix):
                assert side['alive'] and side['exit'] == 0
            health = 'health' if 'health' in c else 'health_after_connection_close'
            assert c[health]['status'] == fix[health]['status'] == 'reply'
            assert decoder.decode(c[health]) == decoder.decode(fix[health])
            warm_key = 'warm' if 'warm' in c else 'warm_response'
            if warm_key in c:
                assert decoder.decode(c[warm_key]) == decoder.decode(fix[warm_key])
                warm += 1
        summary['history'][family + '/' + label] = dict(cases=len(cases), current_equals_c=len(cases),
            valid_semantics=len(cases)-len(malformed), malformed_c_raw_equal=malformed, warm_equal=warm,
            all_current_c_lifecycle_health_upstream_equal=True, raw_result_sha256=sha(path))
    for label in ('negative', 'large-soa'):
        path = private / label / 'checked.json'
        report = read(path)
        assert report['status'] == 'passed'
        rows = [case for suite in report['suites'] for case in suite['checks']] if label == 'negative' else [r['comparison'] for r in report['runs']]
        summary['history'][label] = dict(cases=len(rows), responses=sum(r['responses'] for r in rows),
            exact=sum(r['exact'] for r in rows), bounded_soa=sum(r['bounded_soa'] for r in rows),
            dhcp_replies=sum(r['dhcp_replies'] for r in rows), checked_sha256=sha(path))
    (a.out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
