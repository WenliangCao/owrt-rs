#!/usr/bin/env python3
"""Collect private DNS recheck evidence, independently checking every raw packet."""
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
import sys
from collections import Counter


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--tools', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    sys.path.insert(0, str(args.tools))
    from recheck_dns_local_cache import decode
    args.out.mkdir(parents=True, exist_ok=True)
    def save(name, data):
        (args.out / name).write_text(json.dumps(data, indent=2) + '\n')
    all_manifests = {}
    for suffix in ('focused-02', 'matrix-02'):
        for side in ('c', 'rust'):
            folder = args.root / 'private' / (side + '-' + suffix)
            result = json.loads((folder / 'result.json').read_text())
            assert not result['errors'] and result['process_exits'] == [0, 0]
            assert result['config_sha256'] == '273642923b52722c6b423c22d1586972e7475d78142c2f14185a940230ad9afe'
            assert all(x['pass'] for x in result['ubus_checks'])
            files = {str(f.relative_to(folder)): sha(f) for f in sorted(folder.rglob('*')) if f.is_file()}
            manifest = json.dumps(files, sort_keys=True).encode()
            path = args.root / 'private' / (side + '-' + suffix + '-manifest.json')
            path.write_bytes(manifest)
            all_manifests[side + '-' + suffix] = dict(path=str(path), sha256=sha(path), files=len(files), result_sha256=sha(folder / 'result.json'), identity={k: result[k] for k in ('binary_sha256', 'config_sha256', 'tool_sha256', 'errors', 'process_exits', 'ubus_checks')})
    focused = {}
    for side in ('c', 'rust'):
        folder = args.root / 'private' / (side + '-focused-02')
        trace = json.loads((folder / 'result.json').read_text())
        rows = []
        for case in trace['cases']:
            assert case['daemon_alive']
            for index, client in enumerate(case['clients']):
                assert 'response' in client
                q = decode((folder / case['label'] / f'{index}.request').read_bytes())
                r = decode((folder / case['label'] / f'{index}.reply').read_bytes())
                assert q['id'] == r['id'] and q['questions'] == r['questions']
                rows.append(dict(label=case['label'], response=r))
        focused[side] = rows
    assert focused['c'] == focused['rust']
    save('focused-independent.json', dict(responses_each=len(focused['c']), strict_equal=True, observations=focused))
    rows_by_side, upstreams, observations = {}, {}, {}
    for side in ('c', 'rust'):
        folder = args.root / 'private' / (side + '-matrix-02')
        rows = json.loads((folder / 'client/result.json').read_text())
        rows_by_side[side] = rows
        upstreams[side] = [json.loads(x) for x in (folder / 'upstream/queries.jsonl').read_text().splitlines()]
        for row in rows:
            assert 'response' in row and 'error' not in row
            ident = row['response']['id']
            q = decode((folder / 'client' / f'{ident}.request').read_bytes())
            r = decode((folder / 'client' / f'{ident}.reply').read_bytes())
            assert q['id'] == r['id'] and q['questions'] == r['questions']
            assert r == row['response']
        observations[side] = [r for r in rows if r['label'].startswith(('expired-', 'hup-'))]
    def normalized(row, ttl=True):
        row = copy.deepcopy(row)
        row.pop('sent'); row.pop('received')
        if not ttl:
            for rr in row['response']['records']:
                if rr['type'] != 41:
                    rr.pop('ttl')
        return row
    def ttl_check(side, row, rr):
        folder = args.root / 'private' / (side + '-matrix-02')
        candidates = []
        for upstream in upstreams[side]:
            if upstream['time'] > row['sent']:
                continue
            reply = folder / 'upstream' / f'{upstream["seq"]:05}.reply'
            if not reply.exists():
                continue
            records = decode(reply.read_bytes())['records']
            for original in records:
                if all(original[k] == rr[k] for k in ('owner', 'type', 'cls', 'data')):
                    matching = [x for x in rows_by_side[side] if x['host'] == upstream['host'] and x['kind'] == upstream['type'] and x['sent'] <= upstream['time'] <= x['received']]
                    if matching:
                        warm = matching[0]
                        minimum = max(0, original['ttl'] + math.floor(upstream['time']) - math.floor(row['received']))
                        maximum = original['ttl'] + math.floor(warm['received']) - math.floor(row['sent'])
                        candidates.append(dict(upstream_seq=upstream['seq'], inserted_between=[upstream['time'], warm['received']], queried_between=[row['sent'], row['received']], original_ttl=original['ttl'], allowed=[minimum, maximum], observed=rr['ttl']))
        assert candidates
        bound = candidates[-1]
        assert bound['allowed'][0] <= rr['ttl'] <= bound['allowed'][1], bound
        return bound
    differences, strict = [], 0
    for c, rust in zip(rows_by_side['c'], rows_by_side['rust'], strict=True):
        assert normalized(c, False) == normalized(rust, False), (c, rust)
        if normalized(c) == normalized(rust):
            strict += 1
            continue
        entry = dict(id=c['response']['id'], label=c['label'], host=c['host'], kind=c['kind'], ttl_bounds={})
        for side, row in [('c', c), ('rust', rust)]:
            entry['ttl_bounds'][side] = [ttl_check(side, row, rr) for rr in row['response']['records'] if rr['type'] != 41]
        differences.append(entry)
    counters = {side: Counter((x['host'], x['type'], x['tcp']) for x in records) for side, records in upstreams.items()}
    save('matrix.json', dict(exchanges_each=len(rows_by_side['c']), strict_equal=strict, non_ttl_differences=0, ttl_differences=differences, upstream_requests={s:len(v) for s,v in upstreams.items()}, upstream_host_type_transport_counts_equal=counters['c'] == counters['rust'], phase_observations=observations, source_rows_sha256={s:sha(args.root / 'private' / (s + '-matrix-02/client/result.json')) for s in rows_by_side}))
    save('identity.json', dict(scope='Actual captured config; exact image C and final SDK Rust ELF; independent isolated rerun', product_freeze='807db8a15e43452414acc048874bf04a4c639bd9', raw_evidence=all_manifests, collector_sha256=sha(Path(__file__)), decoder_tool_sha256=sha(args.tools / 'recheck_dns_local_cache.py')))
    # The independently bounded TTL rule rejects an artificial +2 at every
    # retained mismatch; flags remain part of the strict semantic comparison.
    calibration = []
    for entry in differences:
        for side, bounds in entry['ttl_bounds'].items():
            for b in bounds:
                calibration.append(not (b['allowed'][0] <= b['observed'] + 2 <= b['allowed'][1]))
    assert all(calibration)
    altered = copy.deepcopy(rows_by_side['rust'][0]); altered['response']['flags'] ^= 0x10
    assert normalized(rows_by_side['c'][0], False) != normalized(altered, False)
    save('checker-calibration.json', dict(ttl_plus_2_rejected=len(calibration), flags_mutation_rejected=True, decoded_responses=2 * (len(focused['c']) + len(rows_by_side['c']))))
    print(json.dumps(dict(exchanges_each=len(rows_by_side['c']), strict_equal=strict, ttl_only=len(differences))))


if __name__ == '__main__':
    main()
