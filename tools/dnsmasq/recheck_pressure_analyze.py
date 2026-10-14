#!/usr/bin/env python3
"""Independently classify captured audit-C failures and join syscall evidence.

Publish only synthetic workload summaries and hashes. Device dumps, original
configuration, ELF files, and complete packet/trace files remain private.
"""
import argparse
import collections
import hashlib
import json
import struct
from pathlib import Path


def load(path):
    return json.loads(path.read_text())


def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def identity(path):
    return {'path': str(path.resolve()), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def question(packet):
    pos = 12
    labels = []
    while packet[pos]:
        length = packet[pos]
        assert 0 < length <= 63 and pos + 1 + length < len(packet)
        labels.append(packet[pos + 1:pos + 1 + length].decode('ascii').lower())
        pos += length + 1
    pos += 1
    qtype, qclass = struct.unpack_from('!HH', packet, pos)
    return ('.'.join(labels), qtype, qclass), pos + 4


def classify(row):
    query, reply = (bytes.fromhex(row[k]) for k in ('query_hex', 'reply_hex'))
    q, qe = question(query)
    r, re = question(reply)
    header = struct.unpack_from('!6H', reply)
    assert query[:2] == reply[:2] and q == r and query[12:qe] == reply[12:re]
    assert header[1] & 0x8000 and header[2] == 1
    assert header[3:5] == (0, 0), 'error unexpectedly contains answers/authority'
    pos = re
    edes = []
    for _ in range(header[5]):
        assert reply[pos] == 0
        rrtype, udp_size, ttl, size = struct.unpack_from('!HHIH', reply, pos + 1)
        assert rrtype == 41 and udp_size <= 1232 and ttl == 0
        pos += 11
        end = pos + size
        while pos < end:
            code, length = struct.unpack_from('!HH', reply, pos)
            pos += 4
            assert pos + length <= end <= len(reply)
            if code == 15:
                assert length >= 2
                edes.append(struct.unpack_from('!H', reply, pos)[0])
            pos += length
        assert pos == end
    assert pos == len(reply)
    return {'sequence': row['sequence'], 'phase': row['phase'],
            'name': q[0], 'qtype': q[1], 'rcode': header[1] & 15,
            'flags': header[1], 'ede': edes}


def summarize(run):
    state = load(run / 'state.json')
    assert state.get('complete') is True
    result = {'artifact_sha256': state['artifact_sha256'],
              'state': identity(run / 'state.json'), 'windows': [],
              'cleanup': load(run / 'cleanup.json')}
    health = [state['baseline'], state['final_health']]
    for entry in state['windows']:
        folder = run / entry['name']
        health.extend(entry['health'])
        window = {'name': entry['name'], 'implementation': entry['implementation'],
                  'socket_isolation': entry['socket_proof'], 'modes': {}, 'errors': [],
                  'raw_evidence': []}
        for mode in ('udp', 'tcp', 'dhcp'):
            path = folder / (mode + '.json')
            data = load(path)
            window['modes'][mode] = {
                'rate': data['rate'], 'clients': data['clients'],
                'warmup': data['warmup'], 'measurement': data['measurement'],
                'measurement_start_ns': data['measurement_start_ns']}
            window['raw_evidence'].append(identity(path))
            if mode == 'dhcp':
                continue
            wire = folder / (mode + '.wire-samples.jsonl')
            errors = [classify(row) for row in lines(wire) if not row['correct']]
            records_path = folder / (mode + '.latencies.bin')
            records = {r[0]: r for r in struct.iter_unpack('<QQQHHBBBB', records_path.read_bytes())}
            for phase, label in ((0, 'warmup'), (1, 'measurement')):
                assert sum(e['phase'] == phase for e in errors) == data[label]['wrong']
            for error in errors:
                error['mode'] = mode
                if error['phase'] == 1:
                    record = records[error['sequence']]
                    assert record[5] == 2
                    error.update(sent_ns=record[2], completed_ns=record[2] + record[1],
                                 latency_ns=record[1])
            window['errors'].extend(errors)
            window['raw_evidence'].extend([identity(wire), identity(records_path)])
        trace = folder / 'syscalls.jsonl'
        if trace.exists():
            events = lines(trace)
            assert events[0]['event'] == 'attached' and events[-1]['event'] == 'complete'
            failures = [r for r in events if r['event'] == 'failure']
            window['trace'] = {'attached': events[0], 'complete': events[-1],
                              'failure_counts': dict(collections.Counter(
                                  f"{r['syscall']}/{r['errno']}" for r in failures))}
            matched = set()
            for index, failure in enumerate(failures):
                if failure['syscall'] != 'sendto' or failure.get('destination') != '127.0.0.1:15354':
                    continue
                key, _ = question(bytes.fromhex(failure['query_hex']))
                for error in window['errors']:
                    if error.get('syscall') or 'sent_ns' not in error:
                        continue
                    if (error['name'], error['qtype']) == key[:2] and (
                            error['sent_ns'] <= failure['monotonic_ns'] <= error['completed_ns']):
                        error['syscall'] = {k: failure[k] for k in (
                            'syscall', 'errno', 'destination', 'monotonic_ns', 'monotonic_raw_ns')}
                        matched.add(index)
                        break
            window['trace']['matched_measured_failures'] = len(matched)
            window['raw_evidence'].extend([identity(trace), identity(folder / 'syscalls.log')])
        window['error_counts'] = dict(collections.Counter(
            f"{e['mode']}/phase{e['phase']}/rcode{e['rcode']}/ede{e['ede']}" for e in window['errors']))
        result['windows'].append(window)
    result['health'] = {'checks': len(health),
                        'all_ok': all(h['wan_up'] and h['wan_probe_ok'] and h['dns_ok'] for h in health),
                        'min_mem_available_kib': min(h['mem_available_kib'] for h in health),
                        'production_identity_unchanged': all(
                            h['hashes'] == health[0]['hashes'] and
                            h['production_start_ticks'] == health[0]['production_start_ticks'] for h in health)}
    counters = run.parent / 'conntrack.jsonl'
    if counters.exists():
        samples = lines(counters)
        result['conntrack'] = {
            'sample_count': len(samples), 'limit': samples[0]['maximum'],
            'count_first': samples[0]['count'], 'count_last': samples[-1]['count'],
            'count_max': max(r['count'] for r in samples),
            'delta': {k: sum(c[k] for c in samples[-1]['per_cpu']) -
                     sum(c[k] for c in samples[0]['per_cpu']) for k in ('drop', 'early_drop', 'insert_failed')},
            'raw_evidence': identity(counters)}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = summarize(args.run)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
