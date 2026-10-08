#!/usr/bin/env python3
"""Exact-image/source-bound TCP A interleaving and internal lifetime gates.

One fresh namespace per profile and side. The Rust side uses the ignored
same-source diagnostic companion, never a product performance build. A fresh
image C run is required to qualify wire/order semantics. The six real method
controls remain separate. All requests, upstream replies, gauges, structural
witnesses and fixed 0/1/5/15/60-second drain observations are retained.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import signal
import socket
import struct
import threading
import time

import m5_dns_cache as driver
import m6b_tcp_internal as internal
import m6b_tcp_pressure as pressure


CASES = {
    'staggered-conflicts': {'case': 'm6b-internal-staggered-conflicts', 'mode': 'staggered-conflicts',
                           'capacity': 150, 'config': ''},
    'reload-held-import': {'case': 'm6b-internal-reload-held-import', 'mode': 'reload-held-import',
                          'capacity': 150, 'config': 'addn-hosts=/m2/caller.hosts', 'initial_hosts': ''},
    'lease-held-import': {'case': 'm6b-internal-lease-held-import', 'mode': 'lease-held-import',
                         'capacity': 150, 'config':
                         'dhcp-range=192.0.2.40,192.0.2.60,255.255.255.0,120s\n'
                         'dhcp-authoritative\nno-ping\ndhcp-leasefile=/m2/cache.leases\n'
                         'domain=cache.test\ndhcp-ttl=120'},
}
TOOLS = list(dict.fromkeys(['m6b_tcp_interleaved.py', 'm6b_tcp_internal.py', *pressure.TOOLS]))
CLIENTS = {'staggered-conflicts': 3, 'reload-held-import': 2, 'lease-held-import': 2}
HOSTS = {'staggered-conflicts': 'conflict.interleaved.test',
         'reload-held-import': 'reload.interleaved.test', 'lease-held-import': 'leaseold.cache.test'}
BATCHES = 10
DRAIN_SECONDS = [0, 1, 5, 15, 60]


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def frozen_tools():
    return {name: Path(__file__).with_name(name).read_bytes() for name in TOOLS}


def witness(path, after, wanted):
    """Wait for a new actual companion sample; no controller-made counts."""
    until = time.monotonic() + 5
    while True:
        rows = internal.trace_rows(path)
        for index in range(after, len(rows)):
            row = rows[index]
            if all(row.get(key) == value for key, value in wanted.items()):
                return {'trace_index': index, 'row': row, 'wanted': wanted}
        if time.monotonic() >= until:
            raise AssertionError(('actual interleaved structural witness missing', wanted))
        time.sleep(.02)


def active_content_contract(mode, row, parent):
    # A sole child can modify an old parent block in place. `ever_parent`
    # classifies that exclusive root as old, even after a successful commit.
    # The latest view shares the current parent; every earlier view has one
    # distinct non-parent content root, regardless of that historical label.
    exclusive = CLIENTS[mode] - 1
    old, private = row['old_pinned_content'], row['private_content']
    if (not internal.drain_row(parent) or old < 0 or private < 0
            or old + private != exclusive
            or row['content_versions'] != parent['content_versions'] + exclusive):
        raise ValueError('post-import content roots do not match actual independent views')


class Caller(pressure.Caller):
    """Public FD/UBus receipts, with profile-specific content assertions."""
    def __init__(self, *args):
        super().__init__(*args)
        self.publication = 0

    def capture_expected(self, label, wire, reply, wanted, transport, started, completed):
        (self.folder / (label + '.query')).write_bytes(wire)
        if reply is not None:
            (self.folder / (label + '.reply')).write_bytes(reply)
        parsed = driver.normalized(reply)
        question = driver.normalized(wire)['questions']
        if (reply is None or reply[:2] != wire[:2] or 'unparsed' in parsed
                or parsed.get('questions') != question or parsed.get('flags', 0) & 0x820f != 0x8000):
            raise AssertionError(('missing/malformed/wrong query reply', label, parsed))
        answers = [r for r in parsed['records'] if r['section'] == 'answer']
        ceiling = 120 if wanted == driver.LEASE_CLIENT else 600
        if (len(answers) != 1 or answers[0]['type'] != 1 or answers[0]['data'] != wanted
                or not 0 < answers[0]['ttl'] <= ceiling):
            raise AssertionError(('wrong A/TTL at interleaved phase', label, wanted, parsed))
        self.event(label, query=driver.normalized(wire), reply=parsed, expected=wanted,
                   transport=transport, sent_monotonic_ns=started, completed_monotonic_ns=completed,
                   ttl_ceiling=ceiling)
        return parsed

    def ask(self, label, wanted, client=None, host='health.cache.test', forced=False):
        self.wire_id += 1
        wire = driver.query(host, self.wire_id, do=forced)
        before_events, started = len(self.upstream.events), time.monotonic_ns()
        reply = driver.exchange(self.port, wire, tcp=client is not None, connection=client)
        parsed = self.capture_expected(label, wire, reply, wanted, 'tcp' if client else 'udp',
                                       started, time.monotonic_ns())
        reached = len(self.upstream.events) - before_events
        if forced and reached != 1:
            raise AssertionError(('forced query did not reach exactly one upstream', label, reached))
        self.rows[-1]['upstream_before'] = before_events
        self.rows[-1]['upstream_after'] = len(self.upstream.events)
        self.rows[-1]['forced'] = forced
        return parsed

    def hold(self, label, host, client):
        self.wire_id += 1
        wire = driver.query(host, self.wire_id, do=True)
        started, before = time.monotonic_ns(), len(self.upstream.events)
        (self.folder / (label + '.query')).write_bytes(wire)
        client.sendall(struct.pack('!H', len(wire)) + wire)
        until = time.monotonic() + 3
        while True:
            held = [row for row in self.upstream.held if driver.read_name(row[3], 12)[0] == host]
            if len(held) == 1:
                transport, _, _, actual = held[0]
                if transport != 'tcp' or driver.normalized(actual)['questions'] != driver.normalized(wire)['questions']:
                    raise AssertionError('held upstream transport/question differs')
                break
            if time.monotonic() >= until:
                raise AssertionError('actual held upstream query was not received')
            time.sleep(.01)
        if len(self.upstream.events) != before + 1:
            raise AssertionError('held request has extra upstream events')
        self.event(label + '-held', query=driver.normalized(wire), no_reply_yet=True,
                   sent_monotonic_ns=started, held_monotonic_ns=time.monotonic_ns(),
                   upstream_index=before, upstream_wire=actual.hex())
        return wire, started

    def release(self, label, host, client, request, wanted):
        released = time.monotonic_ns()
        count = self.upstream.release(host)
        if count != 1:
            raise AssertionError(('expected exactly one held release', count))
        self.event(label + '-release', count=count, released_monotonic_ns=released)
        wire, started = request
        reply = driver.exact_read(client, struct.unpack('!H', driver.exact_read(client, 2))[0])
        self.capture_expected(label, wire, reply, wanted, 'tcp', started, time.monotonic_ns())
        # This is an explicitly frozen service schedule, not latency sampling.
        # C exports before replying but the parent does not acknowledge import.
        before = time.monotonic_ns()
        time.sleep(.15)
        self.event(label + '-parent-import-wait', nominal_ns=150_000_000,
                   started_monotonic_ns=before, completed_monotonic_ns=time.monotonic_ns())
        self.ask(label + '-parent-progress', '198.51.100.99')

    def publish_hosts(self, label, contents):
        path = self.root / 'm2/caller.hosts'
        (self.folder / (label + '.hosts')).write_text(contents)
        path.write_text(contents)
        sent = time.monotonic_ns()
        os.kill(self.pid, signal.SIGHUP)
        time.sleep(.1)
        self.event(label, pid=self.pid, signal=signal.SIGHUP, file='/m2/caller.hosts',
                   contents_sha256=driver.sha256(self.folder / (label + '.hosts')),
                   sent_monotonic_ns=sent, completed_monotonic_ns=time.monotonic_ns())

    def publish_lease(self, label, hostname):
        proof = driver.lease_exchange(self.folder, label, hostname=hostname)
        if proof['address'] != driver.LEASE_CLIENT or proof['lease_seconds'] != 120:
            raise AssertionError('fixed lease ACK identity/lifetime differs')
        write(self.folder / (label + '.dhcp.receipt.json'), proof)
        self.event(label, lease=proof)
        return proof


def upstream_recorder(upstream, folder):
    """Preserve actual upstream response/hold/release wires, not only queries."""
    original, rows, lock = upstream.answer, [], threading.Lock()

    def answer(packet, transport, force=False):
        started = time.monotonic_ns()
        reply = original(packet, transport, force)
        value = {'monotonic_ns': started, 'completed_monotonic_ns': time.monotonic_ns(),
                 'transport': transport, 'release': force, 'query_wire': packet.hex(),
                 'query': driver.normalized(packet), 'reply_wire': None if reply is None else reply.hex(),
                 'reply': driver.normalized(reply)}
        with lock:
            rows.append(value)
            write(folder / 'upstream-wire-events.json', rows)
        return reply

    upstream.answer = answer


def schedule(spec, port, upstream, folder, root):
    upstream_recorder(upstream, folder)
    fixture = Caller(spec, port, upstream, folder, root)
    mode, host = spec['mode'], HOSTS[spec['mode']]
    diagnostic = spec['diagnostic']
    trace = root / 'm2/internal.jsonl'
    marker_path = folder / 'interleaved-markers.json'
    markers = {'profile': mode, 'capacity': spec['capacity'], 'clients': CLIENTS[mode],
               'batches': [], 'warm_batch': None, 'baseline': None, 'final': None}

    def plan(value, hold=False):
        upstream.plan[host] = {'ttl': 600, 'hold': hold, 'answers': [{'data': socket.inet_aton(value).hex()}]}

    def point(after, **wanted):
        return witness(trace, after, wanted) if diagnostic else None

    def reset(label):
        if mode == 'staggered-conflicts':
            plan('198.51.100.7')
            fixture.ask(label + '-reset-parent', '198.51.100.7', host=host, forced=True)
        elif mode == 'reload-held-import':
            fixture.publish_hosts(label + '-reset-hosts', '')
        else:
            fixture.publish_lease(label + '-reset-lease', 'seedlease')
            fixture.ask(label + '-reset-lease-visible', driver.LEASE_CLIENT, host='seedlease.cache.test')

    def batch(label):
        rows = internal.trace_rows(trace)
        trace_start, before_rows = len(rows), len(fixture.rows)
        parent = ({'trace_index': trace_start - 1,
                   'row': rows[-1]} if diagnostic else None)
        first = fixture.connect()
        accepted_first = time.monotonic_ns()
        fixture.event(label + '-accept-first', accepted_monotonic_ns=accepted_first,
                       gauge_receipt='accept-' + str(fixture.accept_sequence) + '.gauge.json', clients=1)
        if mode == 'staggered-conflicts':
            plan('198.51.100.8')
            fixture.ask(label + '-parent-between-accepts', '198.51.100.8', host=host, forced=True)
            second = fixture.connect()
            fixture.event(label + '-accept-second', accepted_monotonic_ns=time.monotonic_ns(),
                           gauge_receipt='accept-' + str(fixture.accept_sequence) + '.gauge.json', clients=2)
            fixture.ask(label + '-first-older-view', '198.51.100.7', first, host)
            plan('198.51.100.9', hold=True)
        else:
            plan('198.51.100.7', hold=True)
        request = fixture.hold(label + '-held-child', host, first)
        if mode == 'staggered-conflicts':
            plan('198.51.100.10')
            fixture.ask(label + '-parent-during-hold', '198.51.100.10', host=host, forced=True)
            fixture.ask(label + '-second-older-view', '198.51.100.8', second, host)
        elif mode == 'reload-held-import':
            fixture.publish_hosts(label + '-publish-hosts', '198.51.100.9 ' + host + '\n')
            fixture.ask(label + '-parent-during-hold', '198.51.100.9', host=host)
        else:
            fixture.publish_lease(label + '-publish-lease', 'leaseold')
            fixture.ask(label + '-parent-during-hold', driver.LEASE_CLIENT, host=host)
        held_count = 2 if mode == 'staggered-conflicts' else 1
        held = point(trace_start, clients=held_count, G=held_count, dns_work=held_count,
                     views=held_count, tcp_pending=1, udp_pending=0)
        fixture.sample(label + '-held-active')
        before_release = len(internal.trace_rows(trace))
        value = '198.51.100.9' if mode == 'staggered-conflicts' else '198.51.100.7'
        plan(value)
        fixture.release(label + '-held-child', host, first, request, value)
        parent_value = ('198.51.100.9' if mode != 'lease-held-import' else driver.LEASE_CLIENT)
        fixture.ask(label + '-parent-after-import', parent_value, host=host)
        fixture.ask(label + '-first-private-repeat', value, first, host)
        last = fixture.connect()
        fixture.event(label + '-accept-latest', accepted_monotonic_ns=time.monotonic_ns(),
                       gauge_receipt='accept-' + str(fixture.accept_sequence) + '.gauge.json', clients=CLIENTS[mode])
        fixture.ask(label + '-latest-view', parent_value, last, host)
        if mode == 'staggered-conflicts':
            fixture.ask(label + '-second-private-repeat', '198.51.100.8', second, host)
        active = point(before_release, clients=CLIENTS[mode], G=CLIENTS[mode],
                       dns_work=CLIENTS[mode], views=CLIENTS[mode], tcp_pending=0, udp_pending=0)
        if diagnostic:
            active_content_contract(mode, active['row'], parent['row'])
        fixture.sample(label + '-post-import-active')
        fixture.drain(label + '-drained')
        reset(label)
        after = len(internal.trace_rows(trace))
        if diagnostic:
            index, row = internal.stable_trace(trace, after)
            drained = {'trace_index': index, 'row': row}
        else:
            drained = None
        fixture.sample(label + '-idle')
        return {'label': label, 'parent': parent, 'held': held, 'active': active, 'drained': drained,
                'observation_range': [before_rows, len(fixture.rows)], 'upstream_events': len(upstream.events)}

    try:
        fixture.sample('initial-idle')
        reset('initial')
        fixture.confirm_warm_idle('pre-batch-idle')
        markers['warm_batch'] = batch('warm')
        markers['baseline'] = markers['warm_batch']['drained']
        write(marker_path, markers)
        for number in range(BATCHES):
            markers['batches'].append(batch(f'b{number:02}'))
            write(marker_path, markers)
        fixture.drain('final-drain')
        fixture.after_drain()
        if diagnostic:
            index, row = internal.stable_trace(trace, len(internal.trace_rows(trace)) - 2)
            markers['final'] = {'trace_index': index, 'row': row}
        write(marker_path, markers)
        return fixture.rows
    finally:
        write(marker_path, markers)
        for client in list(fixture.clients):
            fixture.close(client)


def run(args):
    bound = internal.binding(args.bound_receipt)
    if driver.sha256(args.rust) != bound['diagnostic_elf']['sha256']:
        raise ValueError('same-source bound diagnostic copy required, including the paired C namespace')
    spec = copy.deepcopy(CASES[args.profile])
    spec.update(metrics=True, diagnostic=args.side == 'rust', samples_after_drain_seconds=DRAIN_SECONDS)
    frozen = frozen_tools()
    driver.SYNTAX.clear()
    driver.SCENARIOS[:] = [spec]
    driver.schedule = schedule
    args.only = '^m6b-internal-'
    os.environ['DNSMASQ_M6B_RESOURCE_TRACE'] = '/m2/internal.jsonl'
    status = driver.run(args)
    out = args.out
    (out / 'bound-receipt.json').write_bytes(args.bound_receipt.read_bytes())
    write(out / 'profile-plan.json', spec)
    for name, data in frozen.items():
        (out / 'drivers' / name).write_bytes(data)
    raw = out / 'rootfs-overlay/upper/m2/internal.jsonl'
    if args.side == 'rust' and raw.exists():
        (out / 'diagnostic.jsonl').write_bytes(raw.read_bytes())
    names = ['bound-receipt.json', 'profile-plan.json', 'result.json',
             *[spec['case'] + '/' + name for name in
               ['interleaved-markers.json', 'upstream-wire-events.json', 'resources.json']]]
    if args.side == 'rust':
        names.append('diagnostic.jsonl')
    missing = [name for name in names if not (out / name).exists()]
    digests = {name: driver.sha256(out / name) for name in names if (out / name).exists()}
    write(out / 'interleaved-run-receipt.json', {
        'profile': args.profile, 'side': args.side, 'source_commit': bound['source_commit'],
        'product_sha256': bound['product_elf_sha256'], 'diagnostic_sha256': bound['diagnostic_elf']['sha256'],
        'files': digests, 'missing_raw': missing,
        'tools': {name: driver.sha256(out / 'drivers' / name) for name in TOOLS},
        'tools_unchanged': frozen_tools() == frozen, 'completed_without_fixture_errors': status == 0,
        'product_cpu_pss_qualification': False, 'interleaved_internal_qualified': False})
    return status or int(frozen_tools() != frozen)


def answer_semantics(observations):
    """RR order/content is strict; fixed-clock TTL has its separate S2 gate."""
    results = []
    for observation in observations:
        if 'reply' not in observation:
            continue
        value = {key: copy.deepcopy(observation[key]) for key in ['label', 'query', 'reply', 'transport']}
        for record in value['reply']['records']:
            if record['section'] == 'answer':
                if not 0 < record['ttl'] <= observation['ttl_ceiling']:
                    raise ValueError('TTL outside frozen source-specific lifetime')
                record['ttl'] = 'bounded-interleaved-TTL; strict-S2-separate'
        results.append(value)
    return results


def validate_trace(rows, markers):
    if (not rows or any(row.get('diagnostic_only') is not True or row.get('product_qualification') is not False
                       or row.get('extra_trace_fd') != 1 or row.get('missing_hooks') != 0
                       or row.get('balance_errors') != 0 or row.get('alloc_failed') != 0 for row in rows)):
        raise ValueError('diagnostic method or complete inventory failed')
    if any(b['elapsed_ns'] <= a['elapsed_ns'] for a, b in zip(rows, rows[1:])):
        raise ValueError('actual trace samples are unordered')
    mode = markers['profile']
    if (mode not in CASES or markers['capacity'] != 150 or markers['clients'] != CLIENTS[mode]
            or len(markers['batches']) != BATCHES or markers['warm_batch']['label'] != 'warm'):
        raise ValueError('fixed workload or ten complete batches missing')
    base = markers['baseline']
    if (base != markers['warm_batch']['drained'] or rows[base['trace_index']] != base['row']
            or not internal.drain_row(base['row'])):
        raise ValueError('warmed fully drained baseline is not a raw observation')
    before = base['trace_index']
    checked = []
    for number, batch in enumerate(markers['batches']):
        if batch['label'] != f'b{number:02}':
            raise ValueError('batch missing/reordered; no faster subset permitted')
        held, active, drained = (batch[name] for name in ['held', 'active', 'drained'])
        if not before < held['trace_index'] < active['trace_index'] < drained['trace_index']:
            raise ValueError('held/import/drain structural witnesses reordered')
        for point in [held, active, drained]:
            if rows[point['trace_index']] != point['row']:
                raise ValueError('marker differs from actual companion row')
        parent = batch['parent']
        if (not before <= parent['trace_index'] < held['trace_index']
                or rows[parent['trace_index']] != parent['row']):
            raise ValueError('pre-accept parent differs from the actual idle trace')
        for point in [held, active]:
            if not all(point['row'].get(key) == value for key, value in point['wanted'].items()):
                raise ValueError('actual client/view/transaction witness does not match phase')
        held_clients = 2 if mode == 'staggered-conflicts' else 1
        if held['wanted'] != {'clients': held_clients, 'G': held_clients, 'dns_work': held_clients,
                              'views': held_clients, 'tcp_pending': 1, 'udp_pending': 0}:
            raise ValueError('held upstream state was weakened')
        count = CLIENTS[mode]
        if active['wanted'] != {'clients': count, 'G': count, 'dns_work': count,
                                'views': count, 'tcp_pending': 0, 'udp_pending': 0}:
            raise ValueError('post-import independent views were weakened')
        active_content_contract(mode, active['row'], parent['row'])
        if (not internal.drain_row(drained['row'])
                or internal.product_live(drained['row']) != internal.product_live(base['row'])
                or any(drained['row'][key] != base['row'][key] for key in internal.BALANCE_FIELDS)):
            raise ValueError('fixed final parent live/object/root/capacity balance grew')
        checked.append({'batch': number, 'live_without_registry': internal.product_live(drained['row']),
                        'live_objects': drained['row']['live_objects'],
                        'held_root_counts': {key: held['row'][key] for key in
                                             ['content_versions', 'index_versions', 'old_pinned_content', 'old_pinned_index']},
                        'active_private_roots': {key: active['row'][key] for key in ['private_content', 'private_index']}})
        before = drained['trace_index']
    final = markers['final']
    if (not final or final['trace_index'] < before or rows[final['trace_index']] != final['row']
            or not internal.drain_row(final['row'])
            or internal.product_live(final['row']) != internal.product_live(base['row'])
            or any(final['row'][key] != base['row'][key] for key in internal.BALANCE_FIELDS)):
        raise ValueError('final actual drain balance changed')
    epoch = final['row']['drain_epoch']
    points = [row for row in rows if row['drain_epoch'] == epoch and row['nominal_drain_second'] >= 0]
    if [row['nominal_drain_second'] for row in points] != DRAIN_SECONDS:
        raise ValueError('complete 0/1/5/15/60-second internal drain epoch missing')
    for row in points:
        nominal = row['nominal_drain_second'] * 1_000_000_000
        if not internal.drain_row(row) or not nominal <= row['actual_drain_ns'] <= nominal + 1_500_000_000:
            raise ValueError('actual drain sample retained work or timing was shortened/late')
    return checked


def method_controls(path, bound, bound_sha):
    """Verify saved actual six controls, copied ELF and same diagnostic source."""
    value = json.loads(path.read_text())
    folder = path.parent
    build_path, elf = folder / 'control-build.json', folder / 'lib-dnsmasq_rs'
    build = json.loads(build_path.read_text())
    inputs = {name: digest for name, digest in bound['diagnostic_source_files'].items()
              if name.startswith(('components/dnsmasq/', 'components/ubus/'))}
    if (value.get('qualified') is not True or value.get('passed_tests') != internal.CONTROLS
            or value.get('source_commit') != bound['source_commit']
            or value.get('bound_receipt_sha256') != bound_sha or value.get('layout_matches') is not True
            or value.get('control_build_sha256') != driver.sha256(build_path)
            or value.get('control_elf_sha256') != driver.sha256(elf) or build['source_files'] != inputs
            or value.get('layout_report_sha256') != driver.sha256(folder / 'layout-report.json')):
        raise ValueError('same-source actual diagnostic method controls are required')
    if len(value['tests']) != len(internal.CONTROLS):
        raise ValueError('method control inventory incomplete')
    for number, test in enumerate(value['tests']):
        work = folder / f'{number:02}'
        if (test != json.loads((work / 'run.json').read_text()) or test['test'] != internal.CONTROLS[number]
                or test['returncode'] != 0 or not test['elf_before'] == test['elf_after'] == value['control_elf_sha256']
                or test['stdout_sha256'] != driver.sha256(work / 'stdout')
                or test['stderr_sha256'] != driver.sha256(work / 'stderr')
                or '1 passed; 0 failed; 0 ignored' not in (work / 'stdout').read_text()):
            raise ValueError('actual diagnostic method invocation/output differs')


def expected_answer(mode, suffix):
    if suffix == 'held-child-parent-progress':
        return '198.51.100.99'
    if mode == 'staggered-conflicts':
        return {'parent-between-accepts': '198.51.100.8', 'parent-during-hold': '198.51.100.10',
                'first-older-view': '198.51.100.7',
                'second-older-view': '198.51.100.8', 'held-child': '198.51.100.9',
                'parent-after-import': '198.51.100.9', 'first-private-repeat': '198.51.100.9',
                'latest-view': '198.51.100.9', 'second-private-repeat': '198.51.100.8',
                'reset-parent': '198.51.100.7'}[suffix]
    if suffix in ['held-child', 'first-private-repeat']:
        return '198.51.100.7'
    return driver.LEASE_CLIENT if mode == 'lease-held-import' else '198.51.100.9'


def validate_actions(mode, observations, folder, upstream_rows, ordinary_upstream):
    labels = {row['label']: row for row in observations}
    if len(labels) != len(observations):
        raise ValueError('duplicate action labels')
    for label in ['warm', *[f'b{n:02}' for n in range(BATCHES)]]:
        required = ['accept-first', 'held-child-held', 'parent-during-hold', 'held-child-release',
                    'held-child', 'held-child-parent-import-wait', 'held-child-parent-progress',
                    'parent-after-import', 'first-private-repeat', 'accept-latest', 'latest-view', 'drained']
        if mode == 'staggered-conflicts':
            required += ['parent-between-accepts', 'accept-second', 'second-older-view',
                         'first-older-view', 'second-private-repeat', 'reset-parent']
        else:
            required += ['publish-hosts', 'reset-hosts'] if mode == 'reload-held-import' else [
                'publish-lease', 'reset-lease', 'reset-lease-visible']
        if any(label + '-' + key not in labels for key in required):
            raise ValueError('complete interleaved action inventory missing')
        for observation in observations:
            if not observation['label'].startswith(label + '-') or 'reply' not in observation:
                continue
            suffix = observation['label'].removeprefix(label + '-')
            wanted = expected_answer(mode, suffix)
            ceiling = 120 if wanted == driver.LEASE_CLIENT else 600
            answers = [record for record in observation['reply']['records'] if record['section'] == 'answer']
            if (observation['expected'] != wanted or observation['ttl_ceiling'] != ceiling
                    or len(answers) != 1 or answers[0]['type'] != 1 or answers[0]['data'] != wanted
                    or not 0 < answers[0]['ttl'] <= ceiling):
                raise ValueError('frozen interleaved answer/TTL differs')
        held, released, reply = [labels[label + '-held-child' + suffix] for suffix in ['-held', '-release', '']]
        parent = labels[label + '-parent-during-hold']
        if (held['no_reply_yet'] is not True or released['count'] != 1
                or not held['sent_monotonic_ns'] < held['held_monotonic_ns'] < parent['sent_monotonic_ns']
                <= parent['completed_monotonic_ns'] < released['released_monotonic_ns'] < reply['completed_monotonic_ns']):
            raise ValueError('parent publication did not interleave an actual held child request')
        if (driver.normalized(bytes.fromhex(held['upstream_wire'])) != held['query']
                or held['query'] != driver.normalized((folder / (label + '-held-child.query')).read_bytes())):
            raise ValueError('held actual upstream wire/query differs')
        wait = labels[label + '-held-child-parent-import-wait']
        if (wait['nominal_ns'] != 150_000_000 or wait['completed_monotonic_ns'] - wait['started_monotonic_ns'] < 150_000_000
                or wait['started_monotonic_ns'] < reply['completed_monotonic_ns']):
            raise ValueError('frozen parent import observation wait was shortened')
        latest = labels[label + '-accept-latest']
        if not reply['completed_monotonic_ns'] < latest['accepted_monotonic_ns'] < labels[label + '-latest-view']['sent_monotonic_ns']:
            raise ValueError('latest snapshot not accepted after child commit')
        if mode == 'staggered-conflicts':
            first, second, middle = [labels[label + '-' + key] for key in ['accept-first', 'accept-second', 'parent-between-accepts']]
            if not first['accepted_monotonic_ns'] < middle['sent_monotonic_ns'] <= middle['completed_monotonic_ns'] < second['accepted_monotonic_ns'] < held['sent_monotonic_ns']:
                raise ValueError('accepts did not straddle actual parent mutation')
        else:
            publication = labels[label + ('-publish-hosts' if mode == 'reload-held-import' else '-publish-lease')]
            if mode == 'reload-held-import':
                if (publication['signal'] != signal.SIGHUP or publication['file'] != '/m2/caller.hosts'
                        or publication['contents_sha256'] != driver.sha256(folder / (label + '-publish-hosts.hosts'))
                        or (folder / (label + '-publish-hosts.hosts')).read_text() != '198.51.100.9 ' + HOSTS[mode] + '\n'):
                    raise ValueError('actual host publication bytes/signal differ')
                sent, done = publication['sent_monotonic_ns'], publication['completed_monotonic_ns']
            else:
                proof = publication['lease']
                if (proof != json.loads((folder / (label + '-publish-lease.dhcp.receipt.json')).read_text())
                        or proof['message'] != 5 or proof['address'] != driver.LEASE_CLIENT or proof['lease_seconds'] != 120):
                    raise ValueError('actual same-name lease ACK differs')
                query = (folder / (label + '-publish-lease.dhcp.query')).read_bytes()
                response = (folder / (label + '-publish-lease.dhcp.reply')).read_bytes()
                if (len(query) < 240 or len(response) < 240 or query[4:8] != response[4:8]
                        or socket.inet_ntoa(response[16:20]) != driver.LEASE_CLIENT):
                    raise ValueError('actual DHCP query/reply identity differs')
                sent, done = proof['sent_monotonic_ns'], proof['completed_monotonic_ns']
            if not held['held_monotonic_ns'] < sent <= done < parent['sent_monotonic_ns']:
                raise ValueError('reload/lease was not published between upstream hold and import')
    for row in upstream_rows:
        query = bytes.fromhex(row['query_wire'])
        if driver.normalized(query) != row['query']:
            raise ValueError('actual upstream query/report differs')
        reply = None if row['reply_wire'] is None else bytes.fromhex(row['reply_wire'])
        if driver.normalized(reply) != row['reply']:
            raise ValueError('actual upstream response/report differs')
        if reply is not None and (reply[:2] != query[:2] or row['reply']['questions'] != row['query']['questions']):
            raise ValueError('actual upstream reply identity differs')
    observed = [{'host': driver.read_name(bytes.fromhex(row['query_wire']), 12)[0],
                 'transport': row['transport'], 'query': row['query'], 'wire': row['query_wire']}
                for row in upstream_rows if row['release'] is False]
    if observed != ordinary_upstream:
        raise ValueError('recorded upstream wires omit or add actual daemon requests')
    count = (BATCHES + 1) * 4 + 1 if mode == 'staggered-conflicts' else BATCHES + 1
    if len(observed) != count or any(row['host'] != HOSTS[mode] for row in observed):
        raise ValueError('frozen upstream request inventory differs')
    if (sum(row['reply_wire'] is None for row in upstream_rows) != BATCHES + 1
            or sum(row['release'] is True for row in upstream_rows) != BATCHES + 1):
        raise ValueError('all eleven real held/release upstream events are required')


def read_run(folder, side):
    receipt = json.loads((folder / 'interleaved-run-receipt.json').read_text())
    bound = internal.binding(folder / 'bound-receipt.json')
    mode, case = receipt['profile'], CASES[receipt['profile']]['case']
    expected = copy.deepcopy(CASES[mode])
    expected.update(metrics=True, diagnostic=side == 'rust', samples_after_drain_seconds=DRAIN_SECONDS)
    if (receipt['side'] != side or receipt['source_commit'] != bound['source_commit']
            or receipt['product_sha256'] != bound['product_elf_sha256']
            or receipt['diagnostic_sha256'] != bound['diagnostic_elf']['sha256']
            or receipt.get('tools_unchanged') is not True or receipt.get('completed_without_fixture_errors') is not True
            or receipt.get('product_cpu_pss_qualification') is not False or receipt.get('missing_raw') != []
            or json.loads((folder / 'profile-plan.json').read_text()) != expected):
        raise ValueError('different source binding, incomplete run or changed frozen plan')
    names = {'bound-receipt.json', 'profile-plan.json', 'result.json',
             *[case + '/' + name for name in
               ['interleaved-markers.json', 'upstream-wire-events.json', 'resources.json']]}
    if side == 'rust':
        names.add('diagnostic.jsonl')
    if set(receipt['files']) != names:
        raise ValueError('complete raw hash inventory missing')
    for name, digest in receipt['files'].items():
        if driver.sha256(folder / name) != digest:
            raise ValueError('retained raw/marker identity changed: ' + name)
    for name in TOOLS:
        if (receipt['tools'].get(name) != driver.sha256(Path(__file__).with_name(name))
                or receipt['tools'][name] != driver.sha256(folder / 'drivers' / name)):
            raise ValueError('frozen dependency identity changed: ' + name)
    report = json.loads((folder / 'result.json').read_text())
    root = json.loads((folder / 'rootfs-identity.json').read_text())
    provenance = pressure.root_provenance(root)
    if (report['side'] != side or report['c_sha256'] != driver.STOCK_SHA256
            or report['rust_sha256'] != bound['diagnostic_elf']['sha256'] or report['failures']
            or report['executed_cases'] != [case] or report['syntax'] or len(report['scenarios']) != 1):
        raise ValueError('fresh exact-image scenario inventory/identity differs')
    row = report['scenarios'][0]
    elf = driver.STOCK_SHA256 if side == 'c' else bound['diagnostic_elf']['sha256']
    if (row['case'] != case or row.get('config') != expected['config']
            or row['identity']['sha256'] != elf or row.get('failure')
            or row['identity']['root'] != root['root'] or row['exit'] != 0 or row['upstream_errors']):
        raise ValueError('actual daemon or namespace cleanup failed')
    work = folder / case
    for observation in row['observations']:
        if 'reply' in observation:
            for kind in ['query', 'reply']:
                if driver.normalized((work / (observation['label'] + '.' + kind)).read_bytes()) != observation[kind]:
                    raise ValueError('actual downstream wire/report differs')
    pressure.validate_profile(work, row, row['identity']['pid'], root['root'])
    upstream = json.loads((work / 'upstream-wire-events.json').read_text())
    validate_actions(mode, row['observations'], work, upstream, row['upstream'])
    markers = json.loads((work / 'interleaved-markers.json').read_text())
    rows, checked = [], None
    if side == 'rust':
        raw = folder / 'diagnostic.jsonl'
        if raw.read_bytes() != (folder / 'rootfs-overlay/upper/m2/internal.jsonl').read_bytes() or not raw.read_bytes().endswith(b'\n'):
            raise ValueError('complete overlay trace differs from retained raw copy')
        rows = internal.trace_rows(raw)
        checked = validate_trace(rows, markers)
    return receipt, bound, provenance, row, markers, rows, checked


def rejection_controls(rows, markers):
    rejected = []
    for mode in ['retained-view', 'retained-transaction', 'one-byte-leak', 'missing-batch', 'shortened-drain', 'reordered-phases']:
        changed, altered = copy.deepcopy(rows), copy.deepcopy(markers)
        last = altered['batches'][-1]
        if mode == 'missing-batch':
            altered['batches'].pop()
        elif mode == 'reordered-phases':
            last['held'], last['active'] = last['active'], last['held']
        elif mode == 'shortened-drain':
            epoch = altered['final']['row']['drain_epoch']
            next(row for row in changed if row['drain_epoch'] == epoch and row['nominal_drain_second'] == 60)['actual_drain_ns'] = 59_000_000_000
        else:
            key = {'retained-view': 'views', 'retained-transaction': 'tcp_pending',
                   'one-byte-leak': 'live_requested_including_diagnostic'}[mode]
            changed[last['drained']['trace_index']][key] += 1
            last['drained']['row'] = copy.deepcopy(changed[last['drained']['trace_index']])
        try:
            validate_trace(changed, altered)
        except (ValueError, KeyError):
            rejected.append({'control': mode, 'rejected': True})
        else:
            raise ValueError('collector accepted corrupted interleaving/balance evidence: ' + mode)
    return rejected


def collect(args):
    if args.out.exists():
        raise ValueError('fresh collector output required')
    c = read_run(args.c_run, 'c')
    rust = read_run(args.rust_run, 'rust')
    if (c[0]['profile'] != rust[0]['profile'] or c[1] != rust[1] or c[2] != rust[2]
            or answer_semantics(c[3]['observations']) != answer_semantics(rust[3]['observations'])):
        raise ValueError('fresh exact-image C and diagnostic Rust content/order/provenance differ')
    def upstream_semantics(folder, case):
        rows = json.loads((folder / case / 'upstream-wire-events.json').read_text())
        return [{key: row[key] for key in ['transport', 'release', 'query', 'reply']} for row in rows]
    case = CASES[rust[0]['profile']]['case']
    if upstream_semantics(args.c_run, case) != upstream_semantics(args.rust_run, case):
        raise ValueError('actual upstream request/reply/hold/release sequence differs from image C')
    method_controls(args.controls, rust[1], rust[0]['files']['bound-receipt.json'])
    result = {'profile': rust[0]['profile'], 'source_commit': rust[1]['source_commit'],
              'product_sha256': rust[1]['product_elf_sha256'], 'diagnostic_sha256': rust[1]['diagnostic_elf']['sha256'],
              'c_run_receipt_sha256': driver.sha256(args.c_run / 'interleaved-run-receipt.json'),
              'rust_run_receipt_sha256': driver.sha256(args.rust_run / 'interleaved-run-receipt.json'),
              'controls_sha256': driver.sha256(args.controls), 'root_provenance': rust[2],
              'batches': rust[6], 'trace_rows': len(rust[5]),
              'negative_controls': rejection_controls(rust[5], rust[4]),
              'interleaved_internal_qualified': True, 'product_cpu_pss_qualification': False,
              'scope': 'fresh image C paired interleaved wires plus source-bound ten-batch diagnostic balance; canonical feature-off product gates remain required'}
    internal.save(args.out, result)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    execute = sub.add_parser('run')
    for name in ['image-root', 'rust', 'bound-receipt', 'out']:
        execute.add_argument('--' + name, type=Path, required=True)
    execute.add_argument('--side', choices=['c', 'rust'], required=True)
    execute.add_argument('--profile', choices=list(CASES), required=True)
    compare = sub.add_parser('collect')
    for name in ['c-run', 'rust-run', 'controls', 'out']:
        compare.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    return {'run': run, 'collect': collect}[args.action](args)


if __name__ == '__main__':
    raise SystemExit(main())
