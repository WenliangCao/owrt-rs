#!/usr/bin/env python3
"""Run the unchanged canonical family gates at explicit scheduling boundaries.

The pause file delays only the next family; an executing family is never stopped.
No argument, expected value, inventory or comparator is rewritten. Every family
gets a fresh original-runner output; final success requires all 44 and 67 jobs.
"""
import argparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def run_family(family, args, identities, elf_sha):
    tools, out = args.source / 'tools/dnsmasq', args.out
    folder = out / family['id']
    argv = ['sudo', '-n', 'python3', str(tools / 'audit_20261011_families.py'),
            '--source', str(args.source), '--elf', str(args.elf), '--link-map', str(args.link_map),
            '--commit', args.commit, '--base-identity', str(args.base_identity),
            '--family', family['id'], '--out', str(folder)]
    started = time.time()
    record = {'family': family['id'], 'passed': False, 'argv': argv, 'start_epoch': started}
    try:
        assert all(sha(Path(name)) == digest for name, digest in identities.items())
        with (out / (family['id'] + '.log')).open('w') as log:
            result = subprocess.run(argv, stdout=log, stderr=log)
        record['exit'] = result.returncode
        value = json.loads((folder / 'result.json').read_text())
        required = {family['id'] + '-' + step['id'] for step in family['steps']}
        required.discard('m5_dns_endpoints-local-archive-gate')
        actual = {job['id'] for job in value['commands']}
        record.update(commands=len(value['commands']), job_ids=sorted(actual),
                      result_sha256=sha(folder / 'result.json'))
        record['passed'] = (
            result.returncode == 0 and value['passed'] and value['selected_families'] == [family['id']]
            and value['source_commit'] == args.commit and value['elf_sha256'] == elf_sha
            and actual == required and len(value['commands']) == len(required)
            and value['c_sha256'] == '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
            and all(job['passed'] for job in value['commands']))
        assert all(sha(Path(name)) == digest for name, digest in identities.items())
    except Exception as error:
        record.update(passed=False, error=repr(error))
    record['end_epoch'] = time.time()
    record['elapsed_seconds'] = record['end_epoch'] - started
    return record


def supervise(args, families, identities, report):
    """Only the coordinator thread writes reports; workers own distinct folders."""
    pending = list(families)
    if args.jobs > 1:
        # A's independent family elapsed evidence identifies the longest three.
        # Keep the known strict legacy helper-FD family last so other gates finish.
        # Only family dispatch order changes; comparator and job argv stay frozen.
        longest = {'m5_dns_cache': 0, 'm5_listeners': 1, 'logging-all-scopes': 4}
        pending.sort(key=lambda family: longest.get(family['id'], 3))
    report['dispatch_order'] = [family['id'] for family in pending]
    report['max_parallel_families'] = args.jobs
    completed, active, failed, pause = set(), {}, False, None
    with ThreadPoolExecutor(max_workers=args.jobs) as workers:
        while pending or active:
            paused = (args.out / 'PAUSE').exists()
            if paused and pause is None:
                pause = {'start_epoch': time.time()}
                report['pauses'].append(pause)
            if pause is not None and not paused:
                pause['end_epoch'] = time.time()
                pause = None
            while pending and len(active) < args.jobs and not paused and not failed:
                family = pending.pop(0)
                future = workers.submit(run_family, family, args, identities, report['elf_sha256'])
                active[future] = family['id']
            if pause is not None and not active:
                pause.setdefault('quiet_ready_epoch', time.time())
            state = ('failed-draining' if failed and active else 'failed' if failed else
                     'paused-draining' if paused and active else 'paused-before-family' if paused else
                     'running-families')
            save(args.out / 'state.json', {'state': state, 'active_families': list(active.values()),
                 'remaining_families': [f['id'] for f in pending], 'epoch': time.time()})
            save(args.out / 'result.json', report)
            if not active:
                if failed:
                    break
                time.sleep(1)
                continue
            done, _ = wait(active, timeout=1, return_when=FIRST_COMPLETED)
            for future in done:
                del active[future]
                record = future.result()
                if record['passed']:
                    actual = set(record['job_ids'])
                    if completed & actual:
                        record.update(passed=False, error='duplicate job across families')
                    else:
                        completed |= actual
                failed |= not record['passed']
                report['families'].append(record)
                save(args.out / 'result.json', report)
                print(json.dumps(record), flush=True)
    return completed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'elf', 'link-map', 'base-identity', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--jobs', type=int, choices=(1, 2, 3), default=1,
                        help='independent families; each original family remains serial')
    args = parser.parse_args()
    if sys.flags.optimize:
        parser.error('assertion-enabled Python is required')
    source, out = args.source.resolve(), args.out.resolve()
    args.source, args.out = source, out
    args.elf, args.link_map, args.base_identity = (
        path.resolve() for path in (args.elf, args.link_map, args.base_identity))
    assert 'private' in out.parts
    out.mkdir(parents=True, exist_ok=False)
    tools = source / 'tools/dnsmasq'
    registry_path = tools / 'm5_final_families.draft.json'
    registry = json.loads(registry_path.read_text())
    families = registry['families']
    assert len(families) == len({family['id'] for family in families}) == 44
    omitted = 'm5_dns_endpoints-local-archive-gate'
    expected_jobs = {family['id'] + '-' + step['id'] for family in families for step in family['steps']} - {omitted}
    assert len(expected_jobs) == 67
    identities = {str(path): sha(path) for path in
                  (args.elf, args.link_map, args.base_identity, registry_path,
                   tools / 'audit_20261011_families.py', tools / 'm5_final_validation.py')}
    report = {'source': str(source), 'commit': args.commit, 'elf_sha256': sha(args.elf),
              'identities': identities, 'expected_families': [f['id'] for f in families],
              'expected_jobs': sorted(expected_jobs), 'passed': False, 'families': [], 'pauses': []}
    save(out / 'result.json', report)
    completed = supervise(args, families, identities, report)
    if (len(report['families']) != 44 or completed != expected_jobs
            or not all(record['passed'] for record in report['families'])):
        save(out / 'state.json', {'state': 'failed', 'epoch': time.time()})
        return 1
    assert all(sha(Path(name)) == digest for name, digest in identities.items())
    report['passed'] = True
    report['completed_jobs'] = len(completed)
    save(out / 'result.json', report)
    save(out / 'state.json', {'state': 'complete', 'families': 44, 'jobs': 67, 'epoch': time.time()})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
