#!/usr/bin/env python3
"""Source-bound S8 DNS-owner release while an accepted TCP log sink is full.

Rust diagnostic-only, with the M5 deliberate nonblocking FIFO difference.
Recovery runs one warm plus ten fixed-name batches and exact live balances.
TERM is separate: before exit DNS owners are gone but slot/G/log remain;
after exit only actual process/FD absence is claimed, never a fabricated heap
sample. Canonical feature-off product logging/TERM gates remain required.
"""
import argparse
import copy
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import time

import m5_dns_cache as driver
import m6b_tcp_internal as internal
import m6b_tcp_interleaved as interleaved
import m6b_tcp_pressure as pressure


TOOLS = list(dict.fromkeys(['m6b_tcp_log_lifetime.py', *interleaved.TOOLS]))
ZERO_DNS = ['dns_work', 'views', 'tcp_pending', 'tcp_accept_pending', 'udp_pending',
            'typed_transfer_inflight', 'old_pinned_content', 'old_pinned_index',
            'private_content', 'private_index', 'view_lru_bytes', 'cache_pending',
            'pending_capacity', 'reverse_capacity', 'input_capacity', 'framer_capacity',
            'writing_capacity', 'waiting_mac_capacity', 'query_event_descriptors',
            'stale_capacity', 'mac_capacity', 'upstream_capacity']
HOST = 'child.logonly.test'
PREFILL = [f'p{n:02}.logonly.test' for n in range(32)]
SINK = '/m2/tcp-log.fifo'
HOLDER = {}


def write(path, value):
    interleaved.write(path, value)


def save_bytes(path, value):
    path.write_bytes(value)
    return driver.sha256(path)


def setup_root(*args, **kwargs):
    root = HOLDER['original_prepare'](*args, **kwargs)
    fifo = root / SINK.lstrip('/')
    os.mkfifo(fifo, 0o640)
    HOLDER.update(root=root, path=fifo, reader=os.open(fifo, os.O_RDONLY | os.O_NONBLOCK))
    return root


def read_sink():
    result = bytearray()
    while True:
        try:
            data = os.read(HOLDER['reader'], 65536)
        except BlockingIOError:
            break
        if not data:
            break
        result.extend(data)
    return bytes(result)


def fill_sink(folder, label):
    writer = os.open(HOLDER['path'], os.O_WRONLY | os.O_NONBLOCK)
    size, written = fcntl.fcntl(writer, 1032), 0  # Linux F_GETPIPE_SZ.
    started = time.monotonic_ns()
    try:
        while True:
            try:
                written += os.write(writer, b'B' * 4096)
            except BlockingIOError:
                break
    finally:
        os.close(writer)
    if written != size:
        raise AssertionError(('FIFO not empty/full to actual capacity', written, size))
    value = {'path': SINK, 'capacity': size, 'filler_bytes': written, 'byte_hex': '42',
             'started_monotonic_ns': started, 'completed_monotonic_ns': time.monotonic_ns(),
             'filled_until_eagain': True}
    write(folder / (label + '.fifo-fill.json'), value)
    return value


def log_only(row):
    return (row.get('clients') == row.get('G') == 1 and row.get('full_drained') is False
            and all(row.get(key) == 0 for key in ZERO_DNS)
            and row.get('log_payload_capacity', 0) > 0 and row.get('log_queue_capacity', 0) > 0)


def log_witness(trace, after):
    until = time.monotonic() + 5
    while True:
        rows = internal.trace_rows(trace)
        for index in range(after, len(rows)):
            if log_only(rows[index]):
                return {'trace_index': index, 'row': rows[index]}
        if time.monotonic() >= until:
            raise AssertionError('real DNS-work-free log-only slot/G witness missing')
        time.sleep(.02)


def successful_dns_witness(trace):
    # Acceptance alone has no committed private content. Only a new sample
    # after the successful query can prove the child still owns its COW root.
    active = interleaved.fresh_witness(trace, {'clients': 1, 'G': 1, 'dns_work': 1,
                                'views': 1, 'tcp_pending': 0, 'udp_pending': 0})
    if active['row']['private_content'] <= 0:
        raise AssertionError('child did not have successful private DNS work before release')
    return active


def proc_exit(pid):
    path = Path('/proc') / str(pid)
    if not path.exists():
        return {'pid': pid, 'state': 'absent', 'fd_identities': {}, 'running': False}
    text = (path / 'stat').read_text()
    state = text[text.rfind(')') + 2:].split()[0]
    fds = pressure.fd_set(pid)
    return {'pid': pid, 'state': state, 'stat_raw': text, 'fd_identities': fds, 'running': state != 'Z'}


def schedule(spec, port, upstream, folder, root):
    interleaved.upstream_recorder(upstream, folder)
    fixture = interleaved.Caller(spec, port, upstream, folder, root)
    trace = root / 'm2/internal.jsonl'
    marker_path = folder / 'log-lifetime-markers.json'
    meta = HOLDER['path'].stat()
    write(folder / 'fifo-metadata.json', {'path': SINK, 'mode': stat.S_IMODE(meta.st_mode),
          'uid': meta.st_uid, 'gid': meta.st_gid, 'fifo': stat.S_ISFIFO(meta.st_mode)})
    markers = {'profile': spec['mode'], 'capacity': 150, 'prefill_names': PREFILL,
               'warm_batch': None, 'baseline': None, 'batches': [], 'final': None, 'term': None}
    for host in [*PREFILL, HOST]:
        upstream.plan[host] = {'ttl': 600, 'answers': [{'data': 'c6336407'}]}

    def checkpoint():
        write(marker_path, markers)

    def batch(label, recover=True):
        # Drain previous successful records before measuring the exact kernel
        # pipe capacity. Filling is a controller write, not a daemon log.
        before = read_sink()
        save_bytes(folder / (label + '.before-fill.raw'), before)
        filled = fill_sink(folder, label)
        client = fixture.connect()
        fixture.ask(label + '-correct-child-answer', '198.51.100.7', client, HOST, forced=True)
        active = successful_dns_witness(trace)
        fixture.sample(label + '-dns-active')
        before_close = len(internal.trace_rows(trace))
        closed = time.monotonic_ns()
        fixture.close(client)
        fixture.event(label + '-client-close', closed_monotonic_ns=closed)
        only = log_witness(trace, before_close)
        gauge = fixture.gauge(1, label + '-log-only-gauge')
        fixture.sample(label + '-log-only-active')
        fixture.event(label + '-log-only', metrics=gauge, gauge_receipt=label + '-log-only-gauge.gauge.json',
                       witness_trace_index=only['trace_index'], dns_owners_released=True)
        item = {'label': label, 'fill': filled, 'active': active, 'log_only': only,
                'closed_monotonic_ns': closed, 'drained': None, 'sink_raw_sha256': None}
        if not recover:
            return item
        recovered = time.monotonic_ns()
        collected = bytearray()
        until = time.monotonic() + 5
        while True:
            collected.extend(read_sink())
            value = fixture.metrics(label + '-recover-' + str(len(fixture.rows)))
            fixture.event(label + '-recover-' + str(len(fixture.rows)), metrics=value)
            if value['tcp_connections'] == 0:
                break
            if time.monotonic() >= until:
                raise AssertionError('reader recovery did not release actual slot/G')
            time.sleep(.02)
        collected.extend(read_sink())
        raw = bytes(collected)
        if raw[:filled['filler_bytes']] != b'B' * filled['filler_bytes']:
            raise AssertionError('actual full FIFO filler changed or was not first')
        records = raw[filled['filler_bytes']:]
        if HOST.encode() not in records:
            raise AssertionError('accepted TCP producer record was lost after reader recovery')
        item['sink_raw_sha256'] = save_bytes(folder / (label + '.sink.raw'), raw)
        fixture.event(label + '-reader-recovery', started_monotonic_ns=recovered,
                       completed_monotonic_ns=time.monotonic_ns(), filler_bytes=filled['filler_bytes'],
                       accepted_child_record_present=True, sink_raw_sha256=item['sink_raw_sha256'])
        fixture.drain(label + '-drained')
        index, row = internal.stable_trace(trace, len(internal.trace_rows(trace)))
        item['drained'] = {'trace_index': index, 'row': row}
        fixture.sample(label + '-idle')
        return item

    try:
        # This reader is present from startup. Startup itself is never held.
        startup = read_sink()
        save_bytes(folder / 'startup-sink.raw', startup)
        for number, host in enumerate(PREFILL):
            fixture.ask(f'prefill-{number:02}', '198.51.100.7', host=host)
            read = read_sink()
            save_bytes(folder / f'prefill-{number:02}.sink.raw', read)
        fixture.confirm_warm_idle('pre-batch-idle')
        markers['warm_batch'] = batch('warm')
        markers['baseline'] = markers['warm_batch']['drained']
        checkpoint()
        if spec['mode'] == 'recover':
            for number in range(10):
                markers['batches'].append(batch(f'b{number:02}'))
                checkpoint()
            fixture.drain('final-drain')
            fixture.after_drain()
            index, row = internal.stable_trace(trace, len(internal.trace_rows(trace)) - 2)
            markers['final'] = {'trace_index': index, 'row': row}
        else:
            markers['term'] = batch('term', recover=False)
            checkpoint()
            sent = time.monotonic_ns()
            os.kill(fixture.pid, signal.SIGTERM)
            exit_rows, until = [], time.monotonic() + 1
            while True:
                value = proc_exit(fixture.pid)
                value['monotonic_ns'] = time.monotonic_ns()
                exit_rows.append(value)
                write(folder / 'term-exit-observations.json', exit_rows)
                if value['running'] is False:
                    break
                if time.monotonic() >= until:
                    raise AssertionError('full log sink prevented bounded actual TERM exit')
                time.sleep(.01)
            samples, start = [], time.monotonic()
            for second in [0, 1, 5, 15, 60]:
                delay = start + second - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                value = proc_exit(fixture.pid)
                value.update(nominal_second=second, monotonic_ns=time.monotonic_ns(),
                             live_requested_after_exit='not-observed; process-exit is not a heap sample')
                samples.append(value)
                write(folder / 'term-post-exit-samples.json', samples)
            fixture.event('term-signal', pid=fixture.pid, signal=signal.SIGTERM,
                           sent_monotonic_ns=sent, exited_monotonic_ns=exit_rows[-1]['monotonic_ns'],
                           actual_fd_absence=True, never_released_sink=True)
            # Preserve remaining kernel FIFO bytes after exit without opening
            # it again. A blocking open/read of a FIFO is never used here.
            remaining = read_sink()
            save_bytes(folder / 'term.sink.raw', remaining)
            markers['term']['sink_raw_sha256'] = driver.sha256(folder / 'term.sink.raw')
        checkpoint()
        return fixture.rows
    finally:
        checkpoint()
        for client in list(fixture.clients):
            fixture.close(client)


def run(args):
    bound = internal.binding(args.bound_receipt)
    if driver.sha256(args.rust) != bound['diagnostic_elf']['sha256']:
        raise ValueError('same-source bound diagnostic ELF required')
    frozen = {name: Path(__file__).with_name(name).read_bytes() for name in TOOLS}
    spec = {'case': 'm6b-internal-log-' + args.profile, 'mode': args.profile, 'capacity': 150,
            'config': 'log-queries\nlog-facility=' + SINK, 'metrics': True,
            'samples_after_drain_seconds': [0, 1, 5, 15, 60]}
    driver.SYNTAX.clear()
    driver.SCENARIOS[:] = [spec]
    driver.schedule = schedule
    HOLDER['original_prepare'] = driver.prepare
    driver.prepare = setup_root
    args.side, args.only = 'rust', '^m6b-internal-log-'
    os.environ['DNSMASQ_M6B_RESOURCE_TRACE'] = '/m2/internal.jsonl'
    try:
        status = driver.run(args)
    finally:
        driver.prepare = HOLDER['original_prepare']
        if 'reader' in HOLDER:
            os.close(HOLDER['reader'])
            HOLDER.pop('reader')
    out = args.out
    for name, data in frozen.items():
        (out / 'drivers' / name).write_bytes(data)
    (out / 'bound-receipt.json').write_bytes(args.bound_receipt.read_bytes())
    write(out / 'profile-plan.json', spec)
    raw = out / 'rootfs-overlay/upper/m2/internal.jsonl'
    if raw.exists():
        (out / 'diagnostic.jsonl').write_bytes(raw.read_bytes())
    names = ['bound-receipt.json', 'profile-plan.json', 'result.json', 'diagnostic.jsonl',
             *[spec['case'] + '/' + name for name in ['log-lifetime-markers.json', 'upstream-wire-events.json',
               'resources.json', 'fifo-metadata.json']]]
    if args.profile == 'term':
        names += [spec['case'] + '/' + name for name in ['term-exit-observations.json', 'term-post-exit-samples.json', 'term.sink.raw']]
    missing = [name for name in names if not (out / name).exists()]
    unchanged = all(Path(__file__).with_name(name).read_bytes() == value for name, value in frozen.items())
    write(out / 'log-lifetime-run-receipt.json', {
        'profile': args.profile, 'source_commit': bound['source_commit'],
        'product_sha256': bound['product_elf_sha256'], 'diagnostic_sha256': bound['diagnostic_elf']['sha256'],
        'files': {name: driver.sha256(out / name) for name in names if (out / name).exists()},
        'missing_raw': missing, 'tools': {name: driver.sha256(out / 'drivers' / name) for name in TOOLS},
        'tools_unchanged': unchanged,
        'completed_without_fixture_errors': status == 0, 'product_cpu_pss_qualification': False,
        'internal_log_lifetime_qualified': False})
    return status or int(not unchanged)


def check_row(rows, point):
    if rows[point['trace_index']] != point['row']:
        raise ValueError('structural marker differs from actual companion row')
    return point['row']


def validate_trace(rows, markers):
    if (not rows or any(row.get('diagnostic_only') is not True or row.get('product_qualification') is not False
                       or row.get('extra_trace_fd') != 1 or row.get('missing_hooks') != 0
                       or row.get('balance_errors') != 0 or row.get('alloc_failed') != 0 for row in rows)
            or any(b['elapsed_ns'] <= a['elapsed_ns'] for a, b in zip(rows, rows[1:]))):
        raise ValueError('complete ordered diagnostic method/inventory required')
    if markers['prefill_names'] != PREFILL or markers['capacity'] != 150 or markers['profile'] not in ['recover', 'term']:
        raise ValueError('fixed names/capacity/profile changed')
    warm, baseline = markers['warm_batch'], markers['baseline']
    if warm['label'] != 'warm' or baseline != warm['drained']:
        raise ValueError('one actual warm batch required before measurement')
    base = check_row(rows, baseline)
    if not internal.drain_row(base):
        raise ValueError('warm baseline not fully drained')
    previous = -1
    expected_count = 10 if markers['profile'] == 'recover' else 0
    if len(markers['batches']) != expected_count:
        raise ValueError('complete ten fixed batches required for recovery')
    checked = []
    items = [warm, *markers['batches']]
    if markers['profile'] == 'term':
        items.append(markers['term'])
    for number, item in enumerate(items):
        label = 'warm' if number == 0 else f'b{number - 1:02}' if markers['profile'] == 'recover' else 'term'
        if item['label'] != label:
            raise ValueError('no missing/reordered/selected faster log batch permitted')
        active, only = check_row(rows, item['active']), check_row(rows, item['log_only'])
        if (not previous < item['active']['trace_index'] < item['log_only']['trace_index']
                or not active['clients'] == active['G'] == active['dns_work'] == active['views'] == 1
                or active['tcp_pending'] != 0 or active['private_content'] <= 0 or not log_only(only)):
            raise ValueError('actual DNS-live to DNS-free/log-only transition missing')
        fill = item['fill']
        if (fill['path'] != SINK or fill['filled_until_eagain'] is not True
                or fill['capacity'] != fill['filler_bytes'] or fill['byte_hex'] != '42' or fill['capacity'] <= 0):
            raise ValueError('actual full FIFO witness missing')
        previous = item['log_only']['trace_index']
        if item['drained'] is not None:
            row = check_row(rows, item['drained'])
            if (item['drained']['trace_index'] <= previous or not internal.drain_row(row)
                    or internal.product_live(row) != internal.product_live(base)
                    or any(row[key] != base[key] for key in internal.BALANCE_FIELDS)):
                raise ValueError('log-context release did not restore warmed object/root/live balances')
            previous = item['drained']['trace_index']
        elif label != 'term':
            raise ValueError('actual recovery drain absent')
        checked.append({'label': label, 'log_only_live_without_registry': internal.product_live(only),
                        'log_only_payload_capacity': only['log_payload_capacity'],
                        'log_only_queue_capacity': only['log_queue_capacity'],
                        'drained_live_without_registry': None if item['drained'] is None else internal.product_live(item['drained']['row'])})
    if markers['profile'] == 'recover':
        final = check_row(rows, markers['final'])
        if (markers['final']['trace_index'] < previous or not internal.drain_row(final)
                or internal.product_live(final) != internal.product_live(base)
                or any(final[key] != base[key] for key in internal.BALANCE_FIELDS)):
            raise ValueError('final warmed log/DNS live balance changed')
        epoch = final['drain_epoch']
        points = [row for row in rows if row['drain_epoch'] == epoch and row['nominal_drain_second'] >= 0]
        if [row['nominal_drain_second'] for row in points] != [0, 1, 5, 15, 60]:
            raise ValueError('complete 0/1/5/15/60 internal drain samples missing')
        for row in points:
            nominal = row['nominal_drain_second'] * 1_000_000_000
            if not internal.drain_row(row) or not nominal <= row['actual_drain_ns'] <= nominal + 1_500_000_000:
                raise ValueError('late/shortened/retained-work internal drain sample')
    elif markers['final'] is not None or markers['term']['drained'] is not None:
        raise ValueError('TERM must not fabricate a post-exit heap drain row')
    return checked


def validate_term(work, observations, pid, markers):
    rows = json.loads((work / 'term-exit-observations.json').read_text())
    samples = json.loads((work / 'term-post-exit-samples.json').read_text())
    signals = [row for row in observations if row['label'] == 'term-signal']
    if len(signals) != 1 or not rows:
        raise ValueError('actual TERM invocation/exit observations missing')
    sent = signals[0]
    if (sent['pid'] != pid or sent['signal'] != signal.SIGTERM or sent['never_released_sink'] is not True
            or sent['actual_fd_absence'] is not True or rows[-1]['running'] is not False
            or not sent['sent_monotonic_ns'] <= rows[0]['monotonic_ns'] <= rows[-1]['monotonic_ns']
            or sent['exited_monotonic_ns'] != rows[-1]['monotonic_ns']
            or not 0 <= sent['exited_monotonic_ns'] - sent['sent_monotonic_ns'] <= 1_000_000_000):
        raise ValueError('bounded TERM exit did not occur with the real sink still full')
    if [row['nominal_second'] for row in samples] != [0, 1, 5, 15, 60]:
        raise ValueError('complete post-exit actual process/FD samples missing')
    for row in samples:
        if (row['pid'] != pid or row['running'] is not False or row['state'] not in ['absent', 'Z']
                or row['fd_identities'] != {}
                or row['live_requested_after_exit'] != 'not-observed; process-exit is not a heap sample'
                or row['monotonic_ns'] < rows[-1]['monotonic_ns']):
            raise ValueError('TERM left a running process/FD or claimed invented heap values')
        if row['state'] == 'Z' and row['stat_raw'][row['stat_raw'].rfind(')') + 2:].split()[0] != 'Z':
            raise ValueError('actual post-exit proc stat does not show the observed zombie')
    for a, b in zip(samples, samples[1:]):
        nominal = (b['nominal_second'] - a['nominal_second']) * 1_000_000_000
        if b['monotonic_ns'] - a['monotonic_ns'] < nominal - 500_000_000:
            raise ValueError('shortened post-exit fixed wait')
    raw = (work / 'term.sink.raw').read_bytes()
    term = markers['term']
    if (driver.sha256(work / 'term.sink.raw') != term['sink_raw_sha256']
            or raw[:term['fill']['filler_bytes']] != b'B' * term['fill']['filler_bytes']):
        raise ValueError('TERM was not performed against the still-full original FIFO')


def rejection_controls(rows, markers):
    results = []
    for name in ['retained-DNS-work', 'retained-view', 'retained-root', 'no-log-slot', 'no-log-record', 'one-byte-leak']:
        changed, altered = copy.deepcopy(rows), copy.deepcopy(markers)
        item = altered['batches'][-1] if altered['profile'] == 'recover' else altered['term']
        point = item['drained'] if name == 'one-byte-leak' and altered['profile'] == 'recover' else item['log_only']
        target = changed[point['trace_index']]
        key = {'retained-DNS-work': 'dns_work', 'retained-view': 'views', 'retained-root': 'old_pinned_content',
               'no-log-slot': 'clients', 'no-log-record': 'log_payload_capacity',
               'one-byte-leak': 'live_requested_including_diagnostic'}[name]
        if name == 'one-byte-leak' and altered['profile'] == 'term':
            # No post-exit heap row exists. A false TERM drain is itself invalid.
            item['drained'] = copy.deepcopy(item['log_only'])
        else:
            target[key] = 0 if name in ['no-log-slot', 'no-log-record'] else target[key] + 1
            point['row'] = copy.deepcopy(target)
        try:
            validate_trace(changed, altered)
        except (ValueError, KeyError):
            results.append({'control': name, 'rejected': True})
        else:
            raise ValueError('S8 collector accepted corrupted retained-owner/log evidence: ' + name)
    return results


def collect(args):
    if args.out.exists():
        raise ValueError('fresh qualification output required')
    folder = args.run
    receipt = json.loads((folder / 'log-lifetime-run-receipt.json').read_text())
    bound = internal.binding(folder / 'bound-receipt.json')
    if (receipt['source_commit'] != bound['source_commit'] or receipt['product_sha256'] != bound['product_elf_sha256']
            or receipt['diagnostic_sha256'] != bound['diagnostic_elf']['sha256']
            or receipt['missing_raw'] or not receipt['tools_unchanged'] or not receipt['completed_without_fixture_errors']
            or receipt['product_cpu_pss_qualification'] is not False):
        raise ValueError('incomplete or differently bound S8 diagnostic run')
    for name, digest in receipt['files'].items():
        if driver.sha256(folder / name) != digest:
            raise ValueError('retained raw/hash identity differs: ' + name)
    for name in TOOLS:
        if (receipt['tools'][name] != driver.sha256(folder / 'drivers' / name)
                or receipt['tools'][name] != driver.sha256(Path(__file__).with_name(name))):
            raise ValueError('frozen S8 dependency changed: ' + name)
    case = 'm6b-internal-log-' + receipt['profile']
    plan = {'case': case, 'mode': receipt['profile'], 'capacity': 150,
            'config': 'log-queries\nlog-facility=' + SINK, 'metrics': True,
            'samples_after_drain_seconds': [0, 1, 5, 15, 60]}
    if json.loads((folder / 'profile-plan.json').read_text()) != plan:
        raise ValueError('frozen S8 caller configuration differs')
    required = {'bound-receipt.json', 'profile-plan.json', 'result.json', 'diagnostic.jsonl',
                *[case + '/' + name for name in ['log-lifetime-markers.json', 'upstream-wire-events.json',
                  'resources.json', 'fifo-metadata.json']]}
    if receipt['profile'] == 'term':
        required |= {case + '/' + name for name in ['term-exit-observations.json', 'term-post-exit-samples.json', 'term.sink.raw']}
    if set(receipt['files']) != required:
        raise ValueError('complete S8 raw hash inventory is required')
    report = json.loads((folder / 'result.json').read_text())
    root = json.loads((folder / 'rootfs-identity.json').read_text())
    provenance = pressure.root_provenance(root)
    if (report['failures'] or report['side'] != 'rust' or report['rust_sha256'] != bound['diagnostic_elf']['sha256']
            or report['c_sha256'] != driver.STOCK_SHA256 or report['syntax'] or report['executed_cases'] != [case]
            or len(report['scenarios']) != 1):
        raise ValueError('complete actual source-bound scenario required')
    scenario = report['scenarios'][0]
    if (scenario['case'] != case or scenario.get('config') != plan['config']
            or scenario.get('failure') or scenario['exit'] != 0
            or scenario['upstream_errors'] or scenario['identity']['sha256'] != bound['diagnostic_elf']['sha256']
            or scenario['identity']['root'] != root['root']):
        raise ValueError('actual diagnostic process, namespace or cleanup failed')
    work = folder / case
    raw = folder / 'diagnostic.jsonl'
    if raw.read_bytes() != (folder / 'rootfs-overlay/upper/m2/internal.jsonl').read_bytes() or not raw.read_bytes().endswith(b'\n'):
        raise ValueError('complete original overlay trace differs')
    markers = json.loads((work / 'log-lifetime-markers.json').read_text())
    if markers['profile'] != receipt['profile']:
        raise ValueError('frozen S8 profile binding differs')
    rows = internal.trace_rows(raw)
    checked = validate_trace(rows, markers)
    metadata = json.loads((work / 'fifo-metadata.json').read_text())
    if (metadata['path'] != SINK or metadata['fifo'] is not True or metadata['mode'] != 0o660
            or metadata['uid'] != 0 or metadata['gid'] != 0):
        raise ValueError('actual accepted FIFO type/ownership differs from exact root caller')
    interleaved.method_controls(args.controls, bound, receipt['files']['bound-receipt.json'])
    for observation in scenario['observations']:
        if 'reply' in observation:
            for kind in ['query', 'reply']:
                if driver.normalized((work / (observation['label'] + '.' + kind)).read_bytes()) != observation[kind]:
                    raise ValueError('actual correct-answer wire/report differs')
            answers = [record for record in observation['reply']['records'] if record['section'] == 'answer']
            if (len(answers) != 1 or answers[0]['type'] != 1 or answers[0]['data'] != '198.51.100.7'
                    or not 0 < answers[0]['ttl'] <= 600):
                raise ValueError('S8 DNS reply was wrong; cannot count it as completed work')
    upstream = json.loads((work / 'upstream-wire-events.json').read_text())
    expected_batch_count = 11 if receipt['profile'] == 'recover' else 2
    wanted = [('udp', host) for host in PREFILL] + [('tcp', HOST)] * expected_batch_count
    observed = []
    for value in upstream:
        query, reply = bytes.fromhex(value['query_wire']), bytes.fromhex(value['reply_wire'])
        if (value['release'] is not False or driver.normalized(query) != value['query']
                or driver.normalized(reply) != value['reply'] or reply[:2] != query[:2]
                or value['reply']['questions'] != value['query']['questions']):
            raise ValueError('actual S8 upstream query/response identity differs')
        observed.append((value['transport'], driver.read_name(query, 12)[0]))
    if observed != wanted:
        raise ValueError('complete fixed S8 upstream packet sequence missing')
    ordinary = [{'host': driver.read_name(bytes.fromhex(value['query_wire']), 12)[0],
                 'transport': value['transport'], 'query': value['query'], 'wire': value['query_wire']}
                for value in upstream]
    if ordinary != scenario['upstream']:
        raise ValueError('retained S8 upstream wires omit or add actual requests')
    for path in work.glob('*.gauge.json'):
        pressure.gauge_receipt(work, path.name, scenario['identity']['pid'], root['root'])
    for path in work.glob('*.metrics.stdout'):
        pressure.metric_receipt(work, path.name.removesuffix('.metrics.stdout'), scenario['identity']['pid'], root['root'])
    for item in [markers['warm_batch'], *markers['batches']]:
        label = item['label']
        if (json.loads((work / (label + '.fifo-fill.json')).read_text()) != item['fill']
                or driver.sha256(work / (label + '.sink.raw')) != item['sink_raw_sha256']):
            raise ValueError('actual FIFO fill/recovery bytes differ from marker')
        payload = (work / (label + '.sink.raw')).read_bytes()
        filler = item['fill']['filler_bytes']
        if payload[:filler] != b'B' * filler or HOST.encode() not in payload[filler:]:
            raise ValueError('accepted child log record disappeared on recovery')
    if receipt['profile'] == 'recover':
        pressure.validate_profile(work, scenario, scenario['identity']['pid'], root['root'])
    else:
        validate_term(work, scenario['observations'], scenario['identity']['pid'], markers)
    result = {'profile': receipt['profile'], 'source_commit': bound['source_commit'],
              'product_sha256': bound['product_elf_sha256'], 'diagnostic_sha256': bound['diagnostic_elf']['sha256'],
              'run_receipt_sha256': driver.sha256(folder / 'log-lifetime-run-receipt.json'),
              'controls_sha256': driver.sha256(args.controls), 'root_provenance': provenance,
              'trace_rows': len(rows), 'batches': checked, 'negative_controls': rejection_controls(rows, markers),
              'internal_log_lifetime_qualified': True, 'product_cpu_pss_qualification': False,
              'scope': 'S8 same-source DNS-owner release/log-only slot then recovery or TERM; known nonblocking FIFO difference, not paired C or feature-off product acceptance'}
    internal.save(args.out, result)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    execute = sub.add_parser('run')
    for name in ['image-root', 'rust', 'bound-receipt', 'out']:
        execute.add_argument('--' + name, type=Path, required=True)
    execute.add_argument('--profile', choices=['recover', 'term'], required=True)
    compare = sub.add_parser('collect')
    for name in ['run', 'controls', 'out']:
        compare.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    return {'run': run, 'collect': collect}[args.action](args)


if __name__ == '__main__':
    raise SystemExit(main())
