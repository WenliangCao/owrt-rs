#!/usr/bin/env python3
"""Three ordinary wildcard UDP ACL callers, using real veth peer ingress.

Supplement only: fresh paired image C / candidate evidence does not replace
the full interface family. No DNS, TCP or HUP occurs between the mutation
and the first peer cache miss. This tool never touches a physical router.
"""
import argparse
import json
import math
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import traceback

import m5_dns_files as files
import m5_listeners as fixture
from dns_service_probe import query, semantics
from m2_rootfs import STOCK_SHA256, command, prepare, process_identity, sha256

CASES = ('late-device', 'recreated-device', 'late-label')
PORT = fixture.DNS_PORT
NAME = 'cached.acl.test'
METRICS = ('dns_cache_inserted', 'dns_cache_live_freed', 'dns_queries_forwarded', 'dns_local_answered')


def save(path, value):
    fixture.save(path, value)


def peer_probe(item):
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        raise RuntimeError('isolated peer required')
    if item['destination'] not in ('10.77.0.1', '10.77.0.3') or item['name'] != NAME or item['port'] != PORT:
        raise ValueError('fixed test endpoints required')
    packet = query(NAME, ident=item['ident'])
    result = {'request': packet.hex(), 'reply': None, 'error': None, 'destination': item['destination']}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'lpeer\0')
        endpoint.bind(('10.77.0.2', 0))
        endpoint.settimeout(1)
        result['client'] = list(endpoint.getsockname())
        result['sent_monotonic_ns'] = time.monotonic_ns()
        try:
            endpoint.sendto(packet, (item['destination'], PORT))
            response, peer = endpoint.recvfrom(65535)
            result.update(reply=response.hex(), peer=list(peer), response=semantics(response))
        except (OSError, ValueError) as error:
            result['error'] = {'kind': type(error).__name__, 'errno': getattr(error, 'errno', None), 'text': str(error)}
        result['completed_monotonic_ns'] = time.monotonic_ns()
    return result


def answer_errors(observed, destination, ident):
    answer = observed.get('response')
    if observed.get('error') or not answer:
        return ['correct peer answer missing']
    errors = []
    if answer['id'] != ident or answer['questions'] != [[NAME, 1, 1]] or answer['flags'] & 15:
        errors.append('transaction/question/rcode differs')
    records = [row for row in answer['records'] if row['section'] == 'answer']
    if len(records) != 1 or any(row['type'] != 1 or row['class'] != 1 or row['name'] != NAME
                              or row['data'] != '192.0.2.7' or not 1 <= row['ttl'] <= 120 for row in records):
        errors.append('exact cached A answer or TTL differs')
    if observed.get('peer') != [destination, PORT]:
        errors.append('reply source differs from queried local address')
    return errors


def upstream_counts(upstream):
    keys = sorted({(row['name'], row['type'], row['transport']) for row in upstream.events})
    return [{'name': name, 'type': kind, 'transport': transport,
             'count': sum(row['name'] == name and row['type'] == kind and row['transport'] == transport
                          for row in upstream.events)} for name, kind, transport in keys]


def metrics(root, out, label, previous=None, wanted=None):
    samples = []
    deadline = time.monotonic() + 2
    while True:
        index = len(samples)
        response = subprocess.run(command(root, '/bin/ubus', 'call', 'acl-metrics', 'metrics', '{}'),
                                  capture_output=True, timeout=2)
        (out / f'{label}-{index}.metrics.stdout').write_bytes(response.stdout)
        (out / f'{label}-{index}.metrics.stderr').write_bytes(response.stderr)
        if response.returncode:
            raise AssertionError('actual ubus metrics request failed')
        value = json.loads(response.stdout)
        projection = {key: value[key] for key in METRICS}
        delta = {key: projection[key] - previous[key] for key in METRICS} if previous is not None else None
        samples.append({'monotonic_ns': time.monotonic_ns(), 'metrics': value, 'delta': delta})
        matched = wanted is None or delta == wanted
        save(out / (label + '.metrics.json'), {'samples': samples, 'passed': matched, 'wanted': wanted})
        if matched:
            if value['tcp_connections'] != 0:
                raise AssertionError('this UDP-only caller must not create TCP views')
            return projection
        if time.monotonic() >= deadline:
            raise AssertionError('cache/admission counters never reached the fixed delta')
        time.sleep(.01)


def run_case(root, side, case, out, rust_sha):
    out.mkdir()
    net = process = bus = upstream = None
    observations = {'case': case, 'rows': [], 'passed': False}
    try:
        net = fixture.Network()
        if case == 'late-device':
            fixture.ip('link', 'del', 'lan')
        elif case == 'late-label':
            fixture.ip('addr', 'del', '10.77.0.3/24', 'dev', 'lan')
        fixture.snapshot(out / 'before-start-network.json')
        upstream = files.FileUpstream([{'name': NAME, 'type': 1, 'reply': '192.0.2.7', 'reply_ttl': 120}],
                                      '127.0.0.1', 0)
        selected = 'lan:0' if case == 'late-label' else 'lan'
        destination = '10.77.0.3' if case == 'late-label' else '10.77.0.1'
        config = (f'port={PORT}\nno-hosts\nno-resolv\nno-0x20-encode\nno-round-robin\n'
                  'strict-order\nuser=root\ngroup=root\npid-file=/m2/acl.pid\n'
                  f'interface={selected}\nserver=127.0.0.1#{upstream.port}\ncache-size=64\n'
                  'host-record=ready.files.test,192.0.2.250\nenable-ubus=acl-metrics\n')
        (root / 'm2/acl.conf').write_text(config)
        (out / 'config').write_text(config)
        syntax = subprocess.run(command(root, side, '--test', '-C', '/m2/acl.conf'), capture_output=True, timeout=5)
        (out / 'syntax.stdout').write_bytes(syntax.stdout)
        (out / 'syntax.stderr').write_bytes(syntax.stderr)
        observations['syntax_exit'] = syntax.returncode
        if syntax.returncode != 0:
            raise AssertionError('ordinary wildcard ACL startup syntax failed')
        with (out / 'ubusd.log').open('wb') as bus_log, (out / 'daemon.log').open('wb') as daemon_log:
            bus = subprocess.Popen(command(root, '/sbin/ubusd'), stdout=bus_log, stderr=bus_log, start_new_session=True)
            files.await_predicate(lambda: subprocess.run(command(root, '/bin/ubus', 'list'),
                                  capture_output=True, timeout=1).returncode == 0, 'ubusd started')
            process = subprocess.Popen(command(root, side, '-k', '-C', '/m2/acl.conf'),
                                       stdout=daemon_log, stderr=daemon_log, start_new_session=True)
            health_samples = []
            deadline = time.monotonic() + 3
            while True:
                health = files.local_health(PORT)
                health_samples.append(health)
                save(out / 'startup-health.json', health_samples)
                if health['healthy'] and (root / 'm2/acl.pid').exists():
                    break
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise AssertionError('correct local startup health never completed')
                time.sleep(.01)
            identity = process_identity(root, process.pid)
            save(out / 'identity.json', identity)
            if identity['sha256'] != (STOCK_SHA256 if side == 'c' else rust_sha):
                raise AssertionError('running ELF identity differs')
            idle = metrics(root, out, 'before-mutation')
            save(out / 'before-mutation-sockets.json', fixture.inventory(process.pid))
            before_links = json.loads(fixture.ip('-j', 'link', 'show').stdout)
            old_index = next((row['ifindex'] for row in before_links if row['ifname'] == 'lan'), None)
            if case == 'late-device':
                if old_index is not None:
                    raise AssertionError('late-device must be absent at startup')
                net.create('lan')
            elif case == 'recreated-device':
                fixture.ip('link', 'del', 'lan')
                net.create('lan')
            else:
                fixture.ip('addr', 'add', '10.77.0.3/24', 'dev', 'lan', 'label', 'lan:0')
            fixture.snapshot(out / 'after-mutation-network.json')
            new_index = next(row['ifindex'] for row in json.loads(fixture.ip('-j', 'link', 'show').stdout)
                             if row['ifname'] == 'lan')
            if case == 'recreated-device' and new_index == old_index:
                raise AssertionError('recreated-device did not witness a new actual ifindex')
            observations['mutation'] = {'old_ifindex': old_index, 'new_ifindex': new_index,
                                        'dns_requests_between_mutation_and_first': 0, 'selected': selected}
            # Kernel address/route settling only. No DNS, TCP, HUP or UBus
            # request can incidentally enumerate before this first ingress.
            time.sleep(.1)
            for index, label in enumerate(('first-miss', 'second-hit')):
                ident = 0x6200 + index
                row = json.loads(net.exec(sys.executable, __file__, '--peer-probe',
                                         json.dumps({'destination': destination, 'name': NAME, 'port': PORT, 'ident': ident})).stdout)
                row.update(label=label, upstream_counts=upstream_counts(upstream),
                           validation_errors=answer_errors(row, destination, ident))
                if row.get('response'):
                    ttl = row['response']['records'][0]['ttl'] if row['response']['records'] else None
                    elapsed = 0 if index == 0 else (row['sent_monotonic_ns'] - observations['rows'][0]['completed_monotonic_ns']) / 1e9
                    if ttl is None or (index == 0 and ttl != 120) or not max(1, 120 - math.ceil(elapsed) - 1) <= ttl <= 120 - math.floor(elapsed):
                        row['validation_errors'].append('TTL decay does not match the actual interval')
                observations['rows'].append(row)
                save(out / (label + '-wire.json'), row)
                (out / (label + '.query')).write_bytes(bytes.fromhex(row['request']))
                if row.get('reply'):
                    (out / (label + '.reply')).write_bytes(bytes.fromhex(row['reply']))
                previous = idle if index == 0 else after_first
                wanted = dict(zip(METRICS, (1, 0, 1, 0) if index == 0 else (0, 0, 0, 1)))
                current = metrics(root, out, label, previous, wanted)
                row['metrics_delta'] = {key: current[key] - previous[key] for key in METRICS}
                after_first = current
                if row['validation_errors']:
                    raise AssertionError('; '.join(row['validation_errors']))
                if len(upstream.events) != 1 or upstream.events[0]['name'] != NAME or upstream.errors:
                    raise AssertionError('exactly one actual upstream request required for miss plus hit')
            final_health = files.local_health(PORT, 0x6310)
            save(out / 'final-health.json', final_health)
            if not final_health['healthy'] or process.poll() is not None:
                raise AssertionError('daemon health lost after peer cache sequence')
            observations['passed'] = True
    except Exception as error:
        observations['failure'] = repr(error)
        (out / 'traceback').write_text(traceback.format_exc())
    finally:
        if upstream:
            observations['upstream_counts'] = upstream_counts(upstream)
            observations['upstream_failures'] = list(upstream.errors)
            save(out / 'upstream.json', {'events': upstream.events,
                 'captured': [{'query': packet.hex(), 'peer': list(peer), 'reply': reply.hex()}
                              for packet, peer, reply in upstream.captured], 'errors': upstream.errors})
            try:
                upstream.close()
            except Exception as error:
                observations['passed'] = False
                observations['upstream_cleanup_failure'] = repr(error)
        cleanup = {'daemon': fixture.stop(process) if process else None,
                   'ubusd': fixture.stop(bus) if bus else None, 'peer': net.close() if net else None,
                   'pid_file': (root / 'm2/acl.pid').exists()}
        save(out / 'cleanup.json', cleanup)
        if cleanup['pid_file'] or (cleanup['daemon'] and
                                  (cleanup['daemon']['forced'] or cleanup['daemon']['returncode'] != 0)) or any(
                row and (row['forced'] or row['returncode'] not in (0, -15))
                for row in (cleanup['ubusd'], cleanup['peer'])):
            observations['passed'] = False
            observations['cleanup_failure'] = cleanup
        save(out / 'result.json', observations)
    return observations


def side(args):
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        raise RuntimeError('root in run_isolated.sh required')
    args.out.mkdir(parents=True, exist_ok=False)
    root = prepare(args.image_root, None, args.out / 'filesystem', args.rust_binary)
    rows = [run_case(root, args.side, case, args.out / case, args.rust_sha256) for case in CASES]
    result = {'side': args.side, 'source_commit': args.source_commit, 'rust_sha256': args.rust_sha256,
              'c_sha256': STOCK_SHA256, 'cases': rows, 'passed': all(row['passed'] for row in rows)}
    save(args.out / 'result.json', result)
    return 0 if result['passed'] else 1


def comparable(report):
    return [{'case': case['case'], 'rows': [{'label': row['label'], 'request': row['request'],
             'questions': row['response']['questions'], 'flags': row['response']['flags'],
             'records': [{**rr, 'ttl': None} for rr in row['response']['records']],
             'peer': row['peer'], 'metrics_delta': row['metrics_delta'], 'upstream_counts': row['upstream_counts']}
             for row in case['rows']]} for case in report['cases']]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peer-probe')
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--rust-binary', type=Path)
    parser.add_argument('--rust-sha256')
    parser.add_argument('--source-commit')
    parser.add_argument('--build-receipt', type=Path)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--side', choices=('c', 'rust', 'both'), default='both')
    args = parser.parse_args()
    if args.peer_probe:
        print(json.dumps(peer_probe(json.loads(args.peer_probe))))
        return 0
    if not all((args.image_root, args.rust_binary, args.rust_sha256, args.source_commit, args.build_receipt, args.out)):
        parser.error('image, copied product, SHA, source commit, build receipt and fresh output required')
    args.out = args.out.resolve()
    if 'private' not in args.out.parts or args.out.exists():
        raise ValueError('fresh private evidence required')
    if sha256(args.rust_binary) != args.rust_sha256:
        raise ValueError('candidate SHA differs')
    if len(args.source_commit) != 40 or any(byte not in '0123456789abcdef' for byte in args.source_commit):
        raise ValueError('full source commit required')
    build = json.loads(args.build_receipt.read_text())
    if build['kind'] != 'release' or build['opt_level'] != '3' or build.get('features'):
        raise ValueError('feature-off opt3 product build required')
    if not any(row['sha256'] == args.rust_sha256 and row['bytes'] == args.rust_binary.stat().st_size for row in build['artifacts']):
        raise ValueError('build receipt does not bind the copied product')
    if args.side != 'both':
        return side(args)
    args.out.mkdir(parents=True)
    driver = args.out / 'driver'; driver.mkdir()
    for filename in ('m6b_interface_acl.py', 'm5_listeners.py', 'm5_dns_files.py', 'm5_dns_endpoints.py',
                     'm5_option_matrix.py', 'm5_option_matrix_probes.py', 'm5_tftp_allocation.py',
                     'dhcp_boot_service_diff.py', 'dns_udp_refusal_diff.py', 'm5_dhcp_tags_options.py',
                     'm2_dhcp_scenarios.py', 'test_single_poll_service.py',
                     'dns_service_probe.py', 'm2_rootfs.py', 'run_isolated.sh'):
        shutil.copy2(Path(__file__).with_name(filename), driver / filename)
    save(args.out / 'identity.json', {'source_commit': args.source_commit, 'rust_sha256': args.rust_sha256,
         'c_sha256': STOCK_SHA256, 'build_receipt_sha256': sha256(args.build_receipt),
         'driver_sha256': {path.name: sha256(path) for path in driver.iterdir()}, 'physical_router': False})
    reports, exits = {}, {}
    for name in ('c', 'rust'):
        argv = ['sh', str(driver / 'run_isolated.sh'), sys.executable, str(driver / 'm6b_interface_acl.py'),
                '--side', name, '--image-root', str(args.image_root.resolve()), '--rust-binary', str(args.rust_binary.resolve()),
                '--rust-sha256', args.rust_sha256, '--source-commit', args.source_commit,
                '--build-receipt', str(args.build_receipt.resolve()), '--out', str(args.out / name)]
        with (args.out / (name + '.log')).open('wb') as log:
            exits[name] = subprocess.run(argv, stdout=log, stderr=log).returncode
        reports[name] = json.loads((args.out / name / 'result.json').read_text())
    passed = not any(exits.values()) and all(report['passed'] for report in reports.values())
    comparison = comparable(reports['c']) == comparable(reports['rust']) if passed else False
    save(args.out / 'result.json', {'passed': passed and comparison, 'exits': exits, 'comparison_equal': comparison,
         'reports': reports, 'qualification': 'supplement only; full frozen source rows remain required', 'physical_router': False})
    return 0 if passed and comparison else 1


if __name__ == '__main__':
    raise SystemExit(main())
