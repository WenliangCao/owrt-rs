#!/usr/bin/env python3
"""Source-bound TCP A internal accounting; never product CPU/PSS acceptance.

One profile per fresh image namespace. Parent names, wire responses and capacity
stay fixed after prefill; one structural warm batch precedes ten measured batches.
Actual companion rows, gauges, wires, stable FD samples and smaps remain raw.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import random
import re
import shutil
import struct
import subprocess
import time

import m5_dns_cache as driver
import m6b_tcp_pressure as pressure

CAPACITIES = [0, 1, 150, 4096, 16384]
PROFILES = ['reconnect', 'half', 'multi-rr', 'pin150', 'limit30']
LIMIT_HOLD_NS = 2_200_000_000
CONTROLS = [
    'm6b_resource_diag::m6b_controls::system_operations_and_known_live_object',
    'm6b_resource_diag::m6b_controls::failed_realloc_retains_old_object_and_balance',
    'm6b_resource_diag::m6b_controls::registry_scope_reserve_grow_and_drop_balance',
    'dns::cache::m6b_root_controls::snapshots_and_detach_track_actual_owners_without_extra_arcs',
    'dns::cache::m6b_root_controls::missing_constructor_and_detach_are_detected',
    'dns::cache::m6b_root_controls::creation_stamp_replaces_old_parent_history_at_same_address',
]
TOOLS = ['m6b_tcp_internal.py', *pressure.TOOLS]
DRAIN_FIELDS = ['clients', 'G', 'dns_work', 'views', 'tcp_pending', 'tcp_accept_pending',
                'udp_pending', 'typed_transfer_inflight', 'old_pinned_content', 'old_pinned_index',
                'private_content', 'private_index']
REGISTRY_CAPACITY_SEMANTICS = 'effective-insertion-lower-bound'
# Keep effective HashMap capacity as raw diagnostic context. Allocator-requested
# registry/total bytes and object/root counts are the actual balance contract.
BALANCE_FIELDS = ['content_versions', 'index_versions', 'registry_len',
                  'observer_registry_requested', 'live_requested_including_diagnostic',
                  'live_objects', 'poll_fd_bytes', 'ready_fd_bytes',
                  'client_vector_bytes', 'view_lru_bytes', 'cache_pending',
                  'pending_capacity', 'reverse_capacity', 'input_capacity', 'framer_capacity',
                  'writing_capacity', 'waiting_mac_capacity', 'query_event_descriptors',
                  'stale_capacity', 'mac_capacity', 'upstream_capacity', 'log_payload_capacity',
                  'log_queue_capacity']


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def binding(path):
    receipt = json.loads(path.read_text())
    if (receipt.get('status') != 'built-not-validated'
            or not re.fullmatch('[0-9a-f]{40}', receipt.get('source_commit', ''))
            or not re.fullmatch('[0-9a-f]{64}', receipt.get('product_elf_sha256', ''))
            or not re.fullmatch('[0-9a-f]{64}', receipt.get('diagnostic_elf', {}).get('sha256', ''))
            or receipt.get('cpu_or_product_pss_qualification') is not False):
        raise ValueError('same-source built companion receipt required')
    return receipt


def trace_rows(path):
    if not path.exists():
        return []
    data = path.read_bytes()
    # A live write may not yet have terminated its last row. Collection after
    # process exit rejects any incomplete trailing line instead of dropping it.
    lines = data.split(b'\n')[:-1]
    return [json.loads(line) for line in lines if line]


def product_live(row):
    return row['live_requested_including_diagnostic'] - row['observer_registry_requested']


def population(capacity, profile):
    if profile in ['half', 'multi-rr']:
        return capacity // 2
    return max(capacity, 32)


def case_name(capacity, profile):
    return f'm6b-internal-{profile}-{capacity}'


def profile_clients(profile):
    return 30 if profile == 'limit30' else 20


class InternalCaller(pressure.Caller):
    def capture(self, label, wire, reply):
        if self.spec['profile'] != 'multi-rr':
            return super().capture(label, wire, reply)
        (self.folder / (label + '.query')).write_bytes(wire)
        if reply is not None:
            (self.folder / (label + '.reply')).write_bytes(reply)
        if reply is None or reply[:2] != wire[:2]:
            raise AssertionError('missing or wrong-ID multi-RR reply: ' + label)
        parsed = driver.normalized(reply)
        question = driver.normalized(wire)['questions']
        if (parsed.get('questions') != question or parsed.get('flags', 0) & 0x820f != 0x8000
                or 'unparsed' in parsed):
            raise AssertionError('wrong question/rcode/framing in multi-RR reply: ' + label)
        answers = [row for row in parsed['records'] if row['section'] == 'answer']
        wanted = ['198.51.100.99'] if question[0][0] == 'health.cache.test' else ['198.51.100.7', '198.51.100.8']
        if sorted(row['data'] for row in answers) != wanted or any(row['type'] != 1 or not 0 < row['ttl'] <= 600 for row in answers):
            raise AssertionError('multi-RR contents/TTL differ: ' + label)
        self.event(label, query=driver.normalized(wire), reply=parsed)
        return parsed


def drain_row(row):
    return row.get('full_drained') is True and all(row.get(key) == 0 for key in DRAIN_FIELDS)


def active_owner_contract(row, capacity, clients=20):
    if not row.get('clients') == row.get('views') == row.get('dns_work') == row.get('G') == clients:
        return False
    if capacity == 0:
        return all(row.get(key) == 0 for key in
                   ['content_versions', 'old_pinned_content', 'private_content'])
    if capacity == 1:
        # One content block per cache. The fixed batch writes through all
        # twenty independent views, so every child has detached its sole old
        # root. That old allocation can legitimately have no remaining owner.
        # Require exactly twenty private roots plus the one current parent;
        # accepting arbitrary private/root totals would hide a missing view or
        # a retained historical owner. End-of-batch balances remain strict.
        return (row.get('old_pinned_content') == 0
                and row.get('private_content') == clients
                and row.get('content_versions') == clients + 1)
    return row.get('old_pinned_content', 0) > 0 and row.get('private_content', 0) > 0


def stable_trace(path, after):
    until = time.monotonic() + 5
    while True:
        rows = trace_rows(path)
        if len(rows) >= after + 2:
            pair = rows[-2:]
            if (all(drain_row(row) for row in pair)
                    and pair[1]['elapsed_ns'] - pair[0]['elapsed_ns'] >= 900_000_000
                    and product_live(pair[0]) == product_live(pair[1])
                    and pair[0]['live_objects'] == pair[1]['live_objects']):
                return len(rows) - 1, rows[-1]
        if time.monotonic() > until:
            raise AssertionError('actual internal drain/live values did not stabilize')
        time.sleep(.02)


def active_trace(path, after, capacity, clients=20):
    until = time.monotonic() + 5
    while True:
        rows = trace_rows(path)
        for index in range(after, len(rows)):
            row = rows[index]
            if active_owner_contract(row, capacity, clients):
                return index, row
        if time.monotonic() > until:
            raise AssertionError(f'{clients}-view old/private root witness was not observed')
        time.sleep(.02)


def schedule(spec, port, upstream, folder, root):
    fixture = InternalCaller(spec, port, upstream, folder, root)
    trace = root / 'm2/internal.jsonl'
    names = [f'r{n:06}.internal.test' for n in range(population(spec['capacity'], spec['profile']))]
    answers = [{'data': 'c6336407'}]
    if spec['profile'] == 'multi-rr':
        answers += [{'data': 'c6336408'}]
    for host in names:
        upstream.plan[host] = {'ttl': 600, 'answers': answers}
    markers = {'prefill_names': names, 'capacity': spec['capacity'], 'profile': spec['profile'], 'clients': 20,
               'batches': [], 'warm_batch': None, 'baseline': None, 'final': None}
    marker_path = folder / 'internal-markers.json'
    clients = profile_clients(spec['profile'])
    markers['clients'] = clients

    def checkpoint():
        marker_path.write_text(json.dumps(markers, indent=2, sort_keys=True) + '\n')

    def forced(label, host, client=None):
        fixture.wire_id += 1
        wire = driver.query(host, fixture.wire_id, do=True)
        before = len(upstream.events)
        parsed = fixture.capture(label, wire, driver.exchange(port, wire, tcp=client is not None, connection=client))
        if len(upstream.events) <= before:
            raise AssertionError('force-refresh request did not reach the frozen upstream')
        fixture.event(label + '-upstream-witness', before=before, after=len(upstream.events))
        return parsed

    def batch(label):
        start = len(trace_rows(trace))
        for _ in range(clients):
            fixture.connect()
        # Both parent and child replacements use the same existing names and
        # exact RDATA. No growing name universe can masquerade as a leak.
        for n in range(min(len(names), 32)):
            forced(label + f'-parent-{n:02}', names[n])
        order = list(range(len(names)))
        random.Random(0x6b4096).shuffle(order)
        for n, client in enumerate(fixture.clients):
            target = names[order[n % len(order)]]
            forced(label + f'-child-{n:02}', target, client)
            first = fixture.query(label + f'-hit-{n:02}', client, target)
            if spec['profile'] == 'multi-rr':
                second = fixture.query(label + f'-hit-again-{n:02}', client, target)
                a = [rr['data'] for rr in first['records'] if rr['section'] == 'answer']
                b = [rr['data'] for rr in second['records'] if rr['section'] == 'answer']
                if a == b:
                    raise AssertionError('private multi-RR order did not rotate')
                fixture.event(label + f'-rotation-{n:02}', before=a, after=b, seed=0x6b4096)
        limit = None
        if spec['profile'] == 'limit30':
            # A fixed hold makes two genuine 1Hz rows observable; admission
            # is still measured with the original sockets/gauge, not counts
            # manufactured by the controller or a diagnostic timer shortcut.
            before_hold, held_at = len(trace_rows(trace)), time.monotonic_ns()
            time.sleep(LIMIT_HOLD_NS / 1_000_000_000)
            finished_at = time.monotonic_ns()
            held_rows = [(index, row) for index, row in enumerate(trace_rows(trace))
                         if index >= before_hold and active_owner_contract(row, spec['capacity'], clients)]
            if len(held_rows) < 2 or held_rows[-1][1]['elapsed_ns'] - held_rows[0][1]['elapsed_ns'] < 900_000_000:
                raise AssertionError('configured limit30 was not observed in two actual separated rows')
            active_index, active = held_rows[0]
            limit = {'started_monotonic_ns': held_at, 'completed_monotonic_ns': finished_at,
                     'first_trace_index': held_rows[0][0], 'first': held_rows[0][1],
                     'last_trace_index': held_rows[-1][0], 'last': held_rows[-1][1]}
            with pressure.socket.socket(pressure.socket.AF_INET, pressure.socket.SOCK_STREAM) as queued:
                queued.settimeout(3); queued.bind((driver.CLIENT, 0)); queued.connect((driver.LISTEN, port))
                wire = fixture.request()
                (folder / (label + '-over-limit.query')).write_bytes(wire)
                queued.sendall(struct.pack('!H', len(wire)) + wire)
                queued.settimeout(.2)
                try:
                    unexpected = queued.recv(1)
                    (folder / (label + '-over-limit.unexpected')).write_bytes(unexpected)
                    raise AssertionError('31st request replied/closed while configured limit30 remained full')
                except pressure.socket.timeout:
                    fixture.event(label + '-over-limit-held', no_reply=True,
                                  metrics=fixture.gauge(30, label + '-over-limit-gauge'))
                fixture.query(label + '-parent-at-limit')
                fixture.query(label + '-existing-at-limit', fixture.clients[0])
                fixture.close(fixture.clients[0])
                queued.settimeout(3)
                reply = driver.exact_read(queued, struct.unpack('!H', driver.exact_read(queued, 2))[0])
                fixture.capture(label + '-over-limit-recovered', wire, reply)
        else:
            active_index, active = active_trace(trace, start, spec['capacity'], clients)
        fixture.sample(label + '-active')
        before_drain = len(trace_rows(trace))
        fixture.drain(label + '-drained')
        drain_index, drained = stable_trace(trace, before_drain)
        fixture.sample(label + '-idle')
        return {'label': label, 'active_trace_index': active_index, 'active': active, 'limit': limit,
                'drain_trace_index': drain_index, 'drained': drained,
                'upstream_events': len(upstream.events)}

    try:
        fixture.sample('initial-idle')
        for n, host in enumerate(names):
            fixture.query(f'prefill-{n:06}', host=host)
        if spec['capacity']:
            populated = fixture.metrics('prefilled')
            if populated['dns_cache_inserted'] < len(names) * len(answers):
                raise AssertionError('configured parent population witness absent')
        fixture.confirm_warm_idle('pre-batch-idle')
        markers['warm_batch'] = batch('warm')
        # Warm all persistent client vector, fd-array and map capacities before
        # claiming the baseline. Repeat exactly the same workload ten times.
        index, row = stable_trace(trace, markers['warm_batch']['drain_trace_index'] - 1)
        markers['baseline'] = {'trace_index': index, 'row': row}
        checkpoint()
        if spec['profile'] == 'pin150':
            before_pin = len(trace_rows(trace))
            client = fixture.connect()
            accepted = time.monotonic()
            for number in range(140):
                forced(f'pin-parent-{number:03}', names[number % len(names)])
                delay = accepted + number + 1 - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
            fixture.query('pin-old-view-at-140', client, names[0])
            pin_rows = trace_rows(trace)
            witnesses = [(i, row) for i, row in enumerate(pin_rows) if i >= before_pin
                         and row['clients'] == row['G'] == row['dns_work'] == row['views'] == 1
                         and row['old_pinned_content'] > 0]
            if not witnesses or witnesses[-1][1]['elapsed_ns'] - witnesses[0][1]['elapsed_ns'] < 130_000_000_000:
                raise AssertionError('long-lived old parent root pin was not actually observed')
            client.settimeout(20)
            if client.recv(1) != b'':
                raise AssertionError('150s idle view emitted unexpected data')
            elapsed = time.monotonic() - accepted
            if not 145 <= elapsed <= 160:
                raise AssertionError('query at140 altered the original 150s deadline')
            markers['pin'] = {'first_trace_index': witnesses[0][0], 'first': witnesses[0][1],
                              'last_trace_index': witnesses[-1][0], 'last': witnesses[-1][1],
                              'lifetime_seconds': elapsed, 'parent_replacements': 140}
            fixture.event('pin-150-eof', lifetime_seconds=elapsed, recent_query_seconds=140, eof=True)
            fixture.close(client)
            checkpoint()
        else:
            for number in range(10):
                markers['batches'].append(batch(f'b{number:02}'))
                checkpoint()
        fixture.drain('final-drain')
        fixture.after_drain()
        index, row = stable_trace(trace, len(trace_rows(trace)) - 2)
        markers['final'] = {'trace_index': index, 'row': row}
        checkpoint()
        return fixture.rows
    finally:
        checkpoint()
        for client in list(fixture.clients):
            fixture.close(client)


def run(args):
    receipt = binding(args.bound_receipt)
    if driver.sha256(args.rust) != receipt['diagnostic_elf']['sha256']:
        raise ValueError('this internal run requires the bound diagnostic copy')
    if (args.profile in ['half', 'multi-rr'] and args.capacity != 4096
            or args.profile in ['pin150', 'limit30'] and args.capacity != 150):
        raise ValueError('half/multi-RR freeze at4096 and pin150/limit30 freeze at150')
    spec = {'case': case_name(args.capacity, args.profile), 'mode': 'internal-reconnect',
            'capacity': args.capacity, 'profile': args.profile,
            'config': 'max-tcp-connections=30' if args.profile == 'limit30' else '', 'metrics': True,
            'samples_after_drain_seconds': [0, 1, 5, 15, 60]}
    frozen = {name: Path(__file__).with_name(name).read_bytes() for name in TOOLS}
    driver.SYNTAX.clear()
    driver.SCENARIOS[:] = [spec]
    driver.schedule = schedule
    args.side, args.only = 'rust', '^m6b-internal-'
    os.environ['DNSMASQ_M6B_RESOURCE_TRACE'] = '/m2/internal.jsonl'
    status = driver.run(args)
    raw = args.out / 'rootfs-overlay/upper/m2/internal.jsonl'
    copied = args.out / 'diagnostic.jsonl'
    if raw.is_file():
        copied.write_bytes(raw.read_bytes())
    (args.out / 'bound-receipt.json').write_bytes(args.bound_receipt.read_bytes())
    for name, data in frozen.items():
        (args.out / 'drivers' / name).write_bytes(data)
    unchanged = all(Path(__file__).with_name(name).read_bytes() == data for name, data in frozen.items())
    marker = args.out / spec['case'] / 'internal-markers.json'
    missing = [str(path.relative_to(args.out)) for path in [copied, marker] if not path.is_file()]
    save(args.out / 'internal-run-receipt.json', {
        'source_commit': receipt['source_commit'], 'product_sha256': receipt['product_elf_sha256'],
        'diagnostic_sha256': receipt['diagnostic_elf']['sha256'], 'capacity': args.capacity, 'profile': args.profile,
        'bound_receipt_sha256': driver.sha256(args.bound_receipt),
        'trace_sha256': driver.sha256(copied) if copied.is_file() else None,
        'result_sha256': driver.sha256(args.out / 'result.json'),
        'marker_sha256': driver.sha256(marker) if marker.is_file() else None, 'missing_raw': missing,
        'tools': {name: driver.sha256(args.out / 'drivers' / name) for name in TOOLS},
        'tools_unchanged': unchanged, 'completed_without_fixture_errors': status == 0,
        'product_cpu_pss_qualification': False, 'internal_balance_qualification': False})
    return status or int(not unchanged or bool(missing))


def validate(rows, markers):
    if not rows or any(row.get('diagnostic_only') is not True or row.get('product_qualification') is not False
                       or row.get('extra_trace_fd') != 1
                       or row.get('registry_capacity_semantics') != REGISTRY_CAPACITY_SEMANTICS
                       or row.get('missing_hooks') != 0
                       or row.get('balance_errors') != 0 or row.get('alloc_failed') != 0 for row in rows):
        raise ValueError('diagnostic method failed or trace inventory missing')
    if any(b['elapsed_ns'] <= a['elapsed_ns'] for a, b in zip(rows, rows[1:])):
        raise ValueError('diagnostic rows are not strictly ordered')
    profile = markers.get('profile', 'reconnect')
    if profile not in PROFILES or markers['capacity'] not in CAPACITIES:
        raise ValueError('unknown frozen internal profile/capacity')
    if profile == 'limit30' and markers['capacity'] != 150:
        raise ValueError('limit30 freezes at capacity150')
    wanted_batches = 0 if profile == 'pin150' else 10
    clients = profile_clients(profile)
    if (markers.get('clients') != clients or len(markers.get('batches', [])) != wanted_batches
            or markers.get('prefill_names') != [f'r{n:06}.internal.test'
                                               for n in range(population(markers['capacity'], profile))]):
        raise ValueError('fixed prefill or ten complete batches missing')
    base = markers['baseline']
    if rows[base['trace_index']] != base['row'] or not drain_row(base['row']):
        raise ValueError('baseline is not an actual fully drained trace row')
    baseline = base['row']
    warm = markers.get('warm_batch')
    if (not warm or warm['label'] != 'warm'
            or not warm['active_trace_index'] < warm['drain_trace_index'] <= base['trace_index']
            or rows[warm['active_trace_index']] != warm['active']
            or rows[warm['drain_trace_index']] != warm['drained']
            or not active_owner_contract(warm['active'], markers['capacity'], clients)
            or not drain_row(warm['drained']) or warm['drained']['drain_epoch'] != baseline['drain_epoch']
            or product_live(warm['drained']) != product_live(baseline)
            or any(warm['drained'][key] != baseline[key] for key in BALANCE_FIELDS)):
        raise ValueError('matching structural warm batch/baseline raw evidence missing')
    prior_index, prior_epoch = base['trace_index'], baseline['drain_epoch']
    checked = []
    for number, batch in enumerate(markers['batches']):
        if batch['label'] != f'b{number:02}':
            raise ValueError('batch order changed or a faster subset was selected')
        ai, di = batch['active_trace_index'], batch['drain_trace_index']
        if not prior_index < ai < di or rows[ai] != batch['active'] or rows[di] != batch['drained']:
            raise ValueError('active/drain witness does not match actual ordered trace')
        active, drained = rows[ai], rows[di]
        if not active_owner_contract(active, markers['capacity'], clients):
            raise ValueError(f'actual {clients}-view private/old-root owner contract differs')
        if not drain_row(drained) or drained['drain_epoch'] != prior_epoch + 1:
            raise ValueError('batch did not actually drain all owner/view/transaction state')
        if (product_live(drained) != product_live(baseline)
                or any(drained[key] != baseline[key] for key in BALANCE_FIELDS)):
            raise ValueError('fixed parent live/object/root/capacity balance grew across reconnections')
        checked.append({'batch': number, 'live_without_registry': product_live(drained),
                        'live_objects': drained['live_objects'], 'root_versions': drained['registry_len']})
        prior_index, prior_epoch = di, drained['drain_epoch']
    if profile == 'limit30':
        for batch in [warm, *markers['batches']]:
            hold = batch.get('limit')
            if (not hold or hold['completed_monotonic_ns'] - hold['started_monotonic_ns'] < LIMIT_HOLD_NS
                    or not batch['active_trace_index'] == hold['first_trace_index']
                    <= hold['last_trace_index'] < batch['drain_trace_index']
                    or rows[hold['first_trace_index']] != hold['first']
                    or rows[hold['last_trace_index']] != hold['last']
                    or hold['last']['elapsed_ns'] - hold['first']['elapsed_ns'] < 900_000_000
                    or any(not active_owner_contract(row, markers['capacity'], 30)
                           for row in [hold['first'], hold['last']])):
                raise ValueError('fixed limit30 hold/two actual independent-view rows missing')
    if profile == 'pin150':
        pin = markers['pin']
        first, last = rows[pin['first_trace_index']], rows[pin['last_trace_index']]
        if (first != pin['first'] or last != pin['last']
                or not prior_index < pin['first_trace_index'] <= pin['last_trace_index']
                or last['elapsed_ns'] - first['elapsed_ns'] < 130_000_000_000
                or pin['parent_replacements'] != 140 or not 145 <= pin['lifetime_seconds'] <= 160
                or any(not row['clients'] == row['G'] == row['views'] == row['dns_work'] == 1
                       or row['old_pinned_content'] <= 0 for row in [first, last])):
            raise ValueError('150s old root ownership/deadline witness differs')
        prior_index, prior_epoch = pin['last_trace_index'], baseline['drain_epoch'] + 1
    final = markers['final']
    if (not final or final['trace_index'] < prior_index or rows[final['trace_index']] != final['row']
            or final['row']['drain_epoch'] != prior_epoch
            or not drain_row(final['row']) or product_live(final['row']) != product_live(baseline)
            or any(final['row'][key] != baseline[key] for key in BALANCE_FIELDS)):
        raise ValueError('final initial/end live balance differs')
    points = [row for row in rows if row['drain_epoch'] == prior_epoch
              and row['nominal_drain_second'] >= 0]
    if [row['nominal_drain_second'] for row in points] != [0, 1, 5, 15, 60]:
        raise ValueError('complete final drain epoch 0/1/5/15/60 points missing')
    for row in points:
        nominal = row['nominal_drain_second'] * 1_000_000_000
        if not drain_row(row) or not nominal <= row['actual_drain_ns'] <= nominal + 1_500_000_000:
            raise ValueError('final drain timing was shortened or late')
    return checked


def limit_observations(work, row, pid, root):
    config = (work / 'config').read_text().splitlines()
    if (row.get('config') != 'max-tcp-connections=30'
            or [line for line in config if line.startswith('max-tcp-connections=')] != ['max-tcp-connections=30']
            or [line for line in config if line.startswith('cache-size=')] != ['cache-size=150']):
        raise ValueError('limit30 actual configuration differs')
    observations = row['observations']
    labels = [value['label'] for value in observations]
    for prefix in ['warm', *[f'b{number:02}' for number in range(10)]]:
        wanted = [prefix + suffix for suffix in ['-over-limit-held', '-parent-at-limit',
                                               '-existing-at-limit', '-over-limit-recovered']]
        if any(labels.count(label) != 1 for label in wanted):
            raise ValueError('limit30 complete admission/progress/recovery observations missing')
        positions = [labels.index(label) for label in wanted]
        if positions != sorted(positions):
            raise ValueError('limit30 admission/progress/recovery order differs')
        held = observations[positions[0]]
        gauges = pressure.gauge_receipt(work, prefix + '-over-limit-gauge.gauge.json', pid, root, 30)
        if held.get('no_reply') is not True or held.get('metrics') != gauges[-1]['value']:
            raise ValueError('limit30 held request lacks actual full gauge')
        if any('query' not in observations[index] or 'reply' not in observations[index]
               for index in positions[1:]):
            raise ValueError('limit30 parent/existing/recovered answers missing')
        if (work / (prefix + '-over-limit.query')).read_bytes() != (work / (wanted[-1] + '.query')).read_bytes():
            raise ValueError('limit30 recovery is not the originally queued request')


def rejection_controls(rows, markers):
    mutations = ['retained-client', 'retained-view', 'retained-transaction', 'retained-pinned-root',
                 'known-one-byte-leak', 'known-one-object-leak', 'registry-growth', 'missing-hook',
                 'missing-batch', 'shortened-drain']
    if markers.get('profile') == 'pin150':
        mutations.remove('missing-batch')
        mutations.append('shortened-pin')
    if markers['capacity'] == 1:
        mutations += ['missing-private-owner', 'extra-content-root']
    if markers.get('profile') == 'limit30':
        mutations += ['missing-limit-view', 'shortened-limit-hold']
    results = []
    for name in mutations:
        changed, altered = copy.deepcopy(rows), copy.deepcopy(markers)
        last = altered['batches'][-1] if altered['batches'] else None
        target = changed[last['drain_trace_index']] if last else changed[altered['final']['trace_index']]
        if name == 'missing-batch':
            altered['batches'].pop()
        elif name == 'shortened-drain':
            next(row for row in changed if row['nominal_drain_second'] == 60
                 and row['drain_epoch'] == target['drain_epoch'])['actual_drain_ns'] = 59_000_000_000
        elif name == 'shortened-pin':
            altered['pin']['lifetime_seconds'] = 140
        elif name == 'shortened-limit-hold':
            last['limit']['completed_monotonic_ns'] = last['limit']['started_monotonic_ns'] + LIMIT_HOLD_NS - 1
        elif name == 'missing-limit-view':
            target = changed[last['active_trace_index']]
            target['views'] -= 1
            last['active'] = copy.deepcopy(target)
            last['limit']['first'] = copy.deepcopy(target)
        elif name in ['missing-private-owner', 'extra-content-root']:
            target = changed[last['active_trace_index']]
            if name == 'missing-private-owner':
                target['private_content'] -= 1
            else:
                target['content_versions'] += 1
            last['active'] = copy.deepcopy(target)
        else:
            key = {'retained-client': 'clients', 'retained-view': 'views',
                   'retained-transaction': 'tcp_pending', 'retained-pinned-root': 'old_pinned_content',
                   'known-one-byte-leak': 'live_requested_including_diagnostic',
                   'known-one-object-leak': 'live_objects', 'registry-growth': 'observer_registry_requested',
                   'missing-hook': 'missing_hooks'}[name]
            target[key] += 1
            if name == 'registry-growth':
                # Real observer growth increases total by the same amount,
                # keeping product_live unchanged; registry bytes must reject it.
                target['live_requested_including_diagnostic'] += 1
            # Mutate both raw observation and its marker, so rejection cannot
            # merely rely on the trivial report/raw identity check.
            if last:
                last['drained'] = copy.deepcopy(target)
            else:
                altered['final']['row'] = copy.deepcopy(target)
        rejected = False
        try:
            validate(changed, altered)
        except (ValueError, KeyError):
            rejected = True
        results.append({'control': name, 'rejected': rejected})
    if not all(row['rejected'] for row in results):
        raise ValueError('internal collector negative control did not reject corrupted evidence')
    return results


def collect(args):
    folder = args.run
    receipt = json.loads((folder / 'internal-run-receipt.json').read_text())
    bound = binding(folder / 'bound-receipt.json')
    report = json.loads((folder / 'result.json').read_text())
    raw = folder / 'diagnostic.jsonl'
    case = case_name(receipt['capacity'], receipt.get('profile', 'reconnect'))
    marker_path = folder / case / 'internal-markers.json'
    if (not receipt['completed_without_fixture_errors'] or not receipt['tools_unchanged']
            or receipt.get('missing_raw', [])
            or report['failures'] or report['executed_cases'] != [case] or len(report['scenarios']) != 1
            or report['side'] != 'rust' or report['rust_sha256'] != bound['diagnostic_elf']['sha256']
            or receipt['source_commit'] != bound['source_commit']):
        raise ValueError('incomplete or differently bound internal run')
    for filename, key in [('bound-receipt.json', 'bound_receipt_sha256'),
                          ('result.json', 'result_sha256'), ('diagnostic.jsonl', 'trace_sha256')]:
        if driver.sha256(folder / filename) != receipt[key]:
            raise ValueError('saved raw identity differs: ' + filename)
    if driver.sha256(marker_path) != receipt['marker_sha256']:
        raise ValueError('saved marker identity differs')
    if raw.read_bytes() != (folder / 'rootfs-overlay/upper/m2/internal.jsonl').read_bytes() or not raw.read_bytes().endswith(b'\n'):
        raise ValueError('raw overlay trace incomplete or different from copied trace')
    for name in TOOLS:
        if (driver.sha256(folder / 'drivers' / name) != receipt['tools'][name]
                or driver.sha256(Path(__file__).with_name(name)) != receipt['tools'][name]):
            raise ValueError('frozen dependency differs: ' + name)
    row = report['scenarios'][0]
    root = json.loads((folder / 'rootfs-identity.json').read_text())
    pressure.root_provenance(root)
    if (row.get('failure') or row['exit'] != 0 or row['upstream_errors']
            or row['identity']['sha256'] != bound['diagnostic_elf']['sha256']):
        raise ValueError('actual diagnostic process/cleanup failed')
    for obs in row['observations']:
        if 'query' in obs:
            for kind in ['query', 'reply']:
                if driver.normalized((folder / case / (obs['label'] + '.' + kind)).read_bytes()) != obs[kind]:
                    raise ValueError('actual query/reply differs from its report')
    pressure.validate_profile(folder / case, row, row['identity']['pid'], root['root'])
    markers, rows = json.loads(marker_path.read_text()), trace_rows(raw)
    if markers['capacity'] != receipt['capacity'] or markers.get('profile', 'reconnect') != receipt.get('profile', 'reconnect'):
        raise ValueError('actual marker profile differs from frozen run')
    if receipt.get('profile') == 'limit30':
        limit_observations(folder / case, row, row['identity']['pid'], root['root'])
    if receipt.get('profile') == 'multi-rr':
        observed = {value['label']: value for value in row['observations']}
        for prefix in ['warm', *[f'b{number:02}' for number in range(10)]]:
            for number in range(20):
                first = observed[prefix + f'-hit-{number:02}']['reply']
                second = observed[prefix + f'-hit-again-{number:02}']['reply']
                a = [rr['data'] for rr in first['records'] if rr['section'] == 'answer']
                b = [rr['data'] for rr in second['records'] if rr['section'] == 'answer']
                if sorted(a) != ['198.51.100.7', '198.51.100.8'] or sorted(b) != sorted(a) or a == b:
                    raise ValueError('actual private multi-RR rotation differs')
    checked = validate(rows, markers)
    controls = json.loads(args.controls.read_text())
    if (controls.get('qualified') is not True or controls.get('source_commit') != bound['source_commit']
            or controls.get('bound_receipt_sha256') != receipt['bound_receipt_sha256']
            or controls.get('passed_tests') != CONTROLS or len(controls.get('tests', [])) != len(CONTROLS)):
        raise ValueError('same-source actual six method controls required before balance qualification')
    control_folder = args.controls.parent
    control_build = json.loads((control_folder / 'control-build.json').read_text())
    inputs = {name: digest for name, digest in bound['diagnostic_source_files'].items()
              if name.startswith(('components/dnsmasq/', 'components/ubus/'))}
    if (driver.sha256(control_folder / 'control-build.json') != controls['control_build_sha256']
            or driver.sha256(control_folder / 'lib-dnsmasq_rs') != controls['control_elf_sha256']
            or control_build['source_files'] != inputs or controls['layout_matches'] is not True
            or driver.sha256(control_folder / 'layout-report.json') != controls['layout_report_sha256']):
        raise ValueError('method control actual source/build/copy/layout receipts differ')
    for number, result in enumerate(controls['tests']):
        work = control_folder / f'{number:02}'
        if (result != json.loads((work / 'run.json').read_text())
                or result['test'] != CONTROLS[number] or result['returncode'] != 0
                or not result['elf_before'] == result['elf_after'] == controls['control_elf_sha256']
                or result['stdout_sha256'] != driver.sha256(work / 'stdout')
                or result['stderr_sha256'] != driver.sha256(work / 'stderr')
                or '1 passed; 0 failed; 0 ignored' not in (work / 'stdout').read_text()):
            raise ValueError('actual method control invocation/output differs')
    result = {'source_commit': bound['source_commit'], 'product_sha256': bound['product_elf_sha256'],
              'diagnostic_sha256': bound['diagnostic_elf']['sha256'], 'capacity': receipt['capacity'],
              'profile': receipt.get('profile', 'reconnect'),
              'batches': checked, 'trace_rows': len(rows), 'controls_sha256': driver.sha256(args.controls),
              'negative_controls': rejection_controls(rows, markers), 'internal_balance_qualified': True,
              'product_cpu_pss_qualification': False,
              'scope': 'selected fixed internal profile only; all other design pressure gates remain separate'}
    save(args.out, result)
    return 0


def controls(args):
    bound = binding(args.bound_receipt)
    build = json.loads(args.build_json.read_text())
    elf = args.build_json.parent / 'lib-dnsmasq_rs'
    inputs = {name: digest for name, digest in bound['diagnostic_source_files'].items()
              if name.startswith(('components/dnsmasq/', 'components/ubus/'))}
    if (build.get('kind') != 'probe-tests' or build.get('opt_level') != '3' or build.get('features') != ''
            or build.get('cargo_target_dir') != '/home/ubuntu/dnsmasq-cargo-target'
            or build.get('source') != bound['source_root']
            or build['source_files'] != inputs
            or not any(row['path'] == elf.name and row['sha256'] == driver.sha256(elf)
                       for row in build['artifacts'])):
        raise ValueError('source-bound copied diagnostic control lib-test build required')
    if args.out.exists() or 'private' not in args.out.resolve().parts:
        raise ValueError('fresh private control output required')
    args.out.mkdir(parents=True)
    shutil.copy2(elf, args.out / elf.name)
    elf = args.out / elf.name
    (args.out / 'control-build.json').write_bytes(args.build_json.read_bytes())
    (args.out / 'layout-report.json').write_bytes(args.layout_report.read_bytes())
    passed = []
    results = []
    for number, test in enumerate(CONTROLS):
        work = args.out / f'{number:02}'; work.mkdir()
        env = dict(os.environ, TMPDIR=str(work / 'tmp')); Path(env['TMPDIR']).mkdir()
        argv = [str(elf), '--exact', test, '--test-threads=1', '--nocapture']
        before = driver.sha256(elf)
        with (work / 'stdout').open('wb') as stdout, (work / 'stderr').open('wb') as stderr:
            result = subprocess.run(argv, stdout=stdout, stderr=stderr, env=env, timeout=60)
        after = driver.sha256(elf)
        ok = (result.returncode == 0 and before == after and
              '1 passed; 0 failed; 0 ignored' in (work / 'stdout').read_text())
        results.append({'test': test, 'argv': argv, 'returncode': result.returncode,
                        'elf_before': before, 'elf_after': after, 'passed': ok,
                        'stdout_sha256': driver.sha256(work / 'stdout'), 'stderr_sha256': driver.sha256(work / 'stderr')})
        save(work / 'run.json', results[-1])
        if ok:
            passed.append(test)
    layouts = re.findall(r'M6B_RESOURCE_LAYOUT slot=(\d+) entry=(\d+) record=(\d+) content=(\d+) cache=(\d+) indices=(\d+) index=(\d+)',
                         (args.out / '03/stdout').read_text())
    layout = json.loads(args.layout_report.read_text())
    sizes = layout['type_sizes']
    expected = tuple(str(sizes[key]) for key in ['Slot', 'Entry', 'Record', 'ContentBlock', 'Cache', 'SlotIndices', 'NameIndex'])
    layout_matches = layouts == [expected] and layout['source_commit'] == bound['source_commit']
    report = {'source_commit': bound['source_commit'], 'bound_receipt_sha256': driver.sha256(args.bound_receipt),
              'control_build_sha256': driver.sha256(args.build_json), 'control_elf_sha256': driver.sha256(elf),
              'layout_report_sha256': driver.sha256(args.layout_report), 'layout_matches': layout_matches,
              'passed_tests': passed, 'tests': results, 'qualified': passed == CONTROLS and layout_matches,
              'scope': 'System balance, known undropped object, observer scope, root detach/missing/reuse controls; not product performance'}
    save(args.out / 'controls.json', report)
    return int(not report['qualified'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    execute = sub.add_parser('run')
    for name in ['image-root', 'rust', 'bound-receipt', 'out']:
        execute.add_argument('--' + name, type=Path, required=True)
    execute.add_argument('--capacity', type=int, choices=CAPACITIES, required=True)
    execute.add_argument('--profile', choices=PROFILES, default='reconnect')
    compare = sub.add_parser('collect')
    for name in ['run', 'controls', 'out']:
        compare.add_argument('--' + name, type=Path, required=True)
    control = sub.add_parser('controls')
    for name in ['bound-receipt', 'build-json', 'layout-report', 'out']:
        control.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    return {'run': run, 'collect': collect, 'controls': controls}[args.action](args)


if __name__ == '__main__':
    raise SystemExit(main())
