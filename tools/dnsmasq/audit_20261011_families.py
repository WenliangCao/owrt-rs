#!/usr/bin/env python3
"""Run the canonical 44 functional families without M5 milestone procedure.

Uses the existing argv expansion, result checks, exact case inventories, and
descendant cleanup. The endpoint archive wait is omitted; its source-row audit
is replaced by the same semantic checks against retained raw files. This never
produces an archive proof, prunes files, or claims the M5/M6b milestone gates.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    temporary.replace(path)


def endpoint_audit(spec, folder):
    """Keep every endpoint semantic requirement, omit only archive procedure."""
    import m5_dns_endpoints as endpoints
    from m2_rootfs import STOCK_SHA256

    tools = Path(spec['tools_root'])
    frozen = read(tools / 'm5_dns_endpoints.json')
    for name, identity in frozen['source_identity'].items():
        if sha(Path(spec['bindings']['reference_source']) / name) != identity['sha256']:
            raise ValueError('matching C source changed: ' + name)
    declared = {mode: {case['id']: json.loads(json.dumps(case)) for case in cases}
                for mode, cases in [('syntax-only', endpoints.syntax_cases()),
                                    ('service', endpoints.service_cases())]}
    cases, services, raw_files = {}, [], {}

    def raw(path):
        raw_files[str(path.relative_to(folder))] = sha(path)
        return read(path)

    for run in ['syntax', 'service']:
        root = folder / run
        report = raw(root / 'result.json')
        schedule = {case['id']: case for case in raw(root / 'schedule.json')}
        if not report['comparison_executed'] or report['c_sha256'] != STOCK_SHA256:
            raise ValueError('exact C/R comparison missing')
        if report['source_commit'] != spec['source_commit'] or report['rust_sha256'] != spec['elf_sha256']:
            raise ValueError('endpoint candidate identity mismatch')
        if set(schedule) != {row['id'] for row in report['cases']}:
            raise ValueError('endpoint schedule/result inventory differs')
        for row in report['cases']:
            ident, errors = row['id'], []
            case = schedule[ident]
            observed = {side: raw(root / ident / side / 'observed.json') for side in ['c', 'rust']}
            if declared[report['mode']].get(ident) != case:
                errors.append('fixture differs from canonical case')
            if report['mode'] == 'syntax-only':
                if endpoints.normal(observed['c']) != endpoints.normal(observed['rust']):
                    errors.append('raw syntax differs')
                if case.get('reference_defect'):
                    errors.append('reference defect cannot qualify service')
            else:
                errors.extend(row['failures'])
                for side, value in observed.items():
                    errors.extend(endpoints.source_guard_errors(value, case))
                    if value['cleanup']['live_pids'] or value['cleanup']['pid_file'] or value.get('forced_kill'):
                        errors.append('incomplete shutdown: ' + side)
                    expected = STOCK_SHA256 if side == 'c' else spec['elf_sha256']
                    if value['startup']['ready'] and value.get('identity', {}).get('sha256') != expected:
                        errors.append('actual ELF mismatch: ' + side)
                services.append(dict(observed=observed, errors=errors, report=report))
            if ident not in cases or not errors:
                cases[ident] = dict(passed=not errors, errors=errors)
    if not services:
        raise ValueError('endpoint service observations missing')
    live = [value for row in services for value in row['observed'].values() if value['startup']['ready']]
    events = [event for value in live for event in value['source_events']]
    checks = {
        '@all-cleanup': all(not row['errors'] for row in services),
        '@all-parent-thread-count': bool(live) and all(value.get('identity', {}).get('threads') == 1 for value in live),
        '@all-source-tuples': bool(events) and all(event.get('wire') and len(event.get('peer', [])) in (2, 4)
                                                  and len(event.get('destination', [])) in (2, 4) for event in events),
        '@negative-controls': all(all(row['report'].get('negative_controls', {}).values())
                                  and set(row['report'].get('lifecycle_negative_controls', []))
                                  >= {'leaked-child', 'leaked-pid', 'startup', 'wrong-server', 'missing-forward'}
                                  for row in services),
        '@candidate-identity': all(value.get('identity', {}).get('sha256') ==
                                   (STOCK_SHA256 if side == 'c' else spec['elf_sha256'])
                                   for row in services for side, value in row['observed'].items()
                                   if value['startup']['ready']),
    }
    rows, omitted = [], []
    for requirement in read(tools / 'm5_dns_endpoints_requirements.json')['required_cases']:
        if requirement['case_ids'] == ['@archive-verification']:
            omitted.append(dict(id=requirement['id'], reason='procedural archive/prune gate excluded by research scope'))
            continue
        missing = [ident for ident in requirement['case_ids']
                   if not (checks.get(ident) if ident.startswith('@') else cases.get(ident, {}).get('passed'))]
        rows.append(dict(id=requirement['id'], passed=bool(requirement['case_ids']) and not missing, missing=missing))
    if len(rows) != 190 or len(omitted) != 1:
        raise ValueError('endpoint requirement inventory changed')
    result = dict(passed=all(row['passed'] for row in rows), semantic_rows=len(rows),
                  passed_rows=sum(row['passed'] for row in rows), rows=rows, checks=checks,
                  omitted_procedural_rows=omitted, raw_sha256=raw_files,
                  source_commit=spec['source_commit'], rust_sha256=spec['elf_sha256'], c_sha256=STOCK_SHA256)
    save(folder / 'semantic-audit.json', result)
    if not result['passed']:
        raise ValueError('endpoint semantic rows failed')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--link-map', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--base-identity', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--family', action='append')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.commit):
        parser.error('--commit requires full commit identity')
    if not args.dry_run and (os.geteuid() != 0 or sys.flags.optimize):
        parser.error('run with sudo and assertion-enabled Python')
    source, output = args.source.resolve(), args.out.resolve()
    tools = source / 'tools/dnsmasq'
    sys.path.insert(0, str(tools))
    import m5_final_validation as final
    from m2_rootfs import STOCK_SHA256

    spec = read(args.base_identity)
    spec.update(source_root=str(source), tools_root=str(tools), source_commit=args.commit,
                elf=str(args.elf.resolve()), elf_sha256=sha(args.elf), selected_families=args.family or [],
                family_registry=read(tools / 'm5_final_families.draft.json'))
    spec.pop('family_tool_overrides', None)
    spec['bindings']['link_map'] = str(args.link_map.resolve())
    families = spec['family_registry']['families']
    selected = set(args.family or [family['id'] for family in families])
    if len(families) != 44 or not selected <= {family['id'] for family in families}:
        parser.error('expected canonical 44 families and valid selection')
    if sha(Path(spec['image_root']) / 'usr/sbin/dnsmasq') != STOCK_SHA256:
        raise ValueError('exact image C identity mismatch')
    build = read(args.elf.parent / 'build.json')
    if build['source'] != str(source) or build.get('features') != '' or build.get('opt_level') != '3':
        raise ValueError('expected final source opt3 feature-off build')
    if build['artifacts'] != [dict(path=args.elf.name, bytes=args.elf.stat().st_size, sha256=spec['elf_sha256'])]:
        raise ValueError('candidate differs from build receipt')
    if build.get('link_map', {}).get('sha256') != sha(args.link_map):
        raise ValueError('candidate link map differs from same-build receipt')
    final.ubus_assets(spec)
    jobs = final.commands(spec, 'families', output)
    procedural = 'm5_dns_endpoints-local-archive-gate'
    jobs = [job for job in jobs if job['id'] != procedural]
    if args.dry_run:
        print(json.dumps(dict(families=len(selected), jobs=jobs,
                             endpoint_source_row_audit='replaced by raw semantic audit; 190 semantic rows, one procedural row omitted'), indent=2))
        return 0
    output.mkdir(parents=True, exist_ok=False)
    result = dict(source_commit=args.commit, elf_sha256=spec['elf_sha256'], c_sha256=STOCK_SHA256,
                  canonical_family_plan_sha256=sha(tools / 'm5_final_families.draft.json'),
                  selected_families=sorted(selected), complete_44_families=False,
                  omitted_procedural_steps=[procedural], commands=[], families={}, passed=False)
    save(output / 'plan.json', jobs)
    save(output / 'result.json', result)
    failed = set()
    for job in jobs:
        if job['family'] in failed:
            continue
        record = dict(job, passed=False)
        started = time.monotonic()
        try:
            if job['id'] == 'm5_dns_endpoints-source-row-audit':
                endpoint_audit(spec, output / 'm5_dns_endpoints')
                record.update(argv=['internal:raw-endpoint-semantic-audit'],
                              result=str(output / 'm5_dns_endpoints/semantic-audit.json'),
                              checks={'passed': True, 'semantic_rows': 190, 'passed_rows': 190}, returncode=0)
            else:
                with (output / (job['id'] + '.log')).open('wb') as log:
                    process = subprocess.Popen(job['argv'], cwd=source, stdout=log, stderr=log, start_new_session=True)
                    descendants = {}
                    try:
                        while process.poll() is None:
                            final.remember_job_processes(process, descendants)
                            if time.monotonic() - started >= job['timeout_seconds']:
                                raise TimeoutError(job['id'])
                            try:
                                process.wait(timeout=1)
                            except subprocess.TimeoutExpired:
                                pass
                    finally:
                        final.stop_job_processes(process, descendants)
                    record['returncode'] = process.returncode
                if process.returncode:
                    raise ValueError('command exited ' + str(process.returncode))
                final.check_result(Path(job['result']), job['checks'], job.get('inventory'))
            record.update(passed=True, result_sha256=sha(record['result']))
        except Exception as error:
            record['error'] = repr(error)
            failed.add(job['family'])
        record['elapsed_seconds'] = time.monotonic() - started
        result['commands'].append(record)
        for family in selected:
            required = {entry['id'] for entry in jobs if entry['family'] == family}
            completed = {entry['id'] for entry in result['commands'] if entry['family'] == family and entry['passed']}
            result['families'][family] = dict(passed=required == completed, completed=len(completed), expected=len(required))
        result['passed'] = all(family['passed'] for family in result['families'].values())
        result['complete_44_families'] = result['passed'] and len(selected) == 44
        save(output / 'result.json', result)
        print(json.dumps(dict(job=job['id'], passed=record['passed'], elapsed_seconds=record['elapsed_seconds'],
                              error=record.get('error'))), flush=True)
    if sha(args.elf) != spec['elf_sha256']:
        raise ValueError('candidate ELF changed while running')
    return int(not result['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
