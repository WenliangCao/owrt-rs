#!/usr/bin/env python3
"""Close only the late original hosts probe; never rerun earlier evidence."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path('/home/ubuntu/dnsmasq-fix3-repair-20261013')
PRIVATE = ROOT / 'private'
SOURCE = ROOT / 'source-types'
SUPPLEMENT = PRIVATE / 'hosts-compat-supplement'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def file(path):
    return dict(path=str(path), sha256=sha(path), bytes=Path(path).stat().st_size)


report = dict(passed=False, created_ns=time.time_ns(), checks={}, inputs={},
              scope='Incremental evidence and cleanup check only; prior 596-check closure retained unchanged.')


def check(name, value):
    if not value:
        raise ValueError(name)
    report['checks'][name] = True


try:
    check('root_and_assertions', os.geteuid() == 0 and not sys.flags.optimize)
    prior_path = PRIVATE / 'types-final-closure-01.json'
    check('prior_closure_unchanged', sha(prior_path) == 'efa811d8bf922d0062c31823eb7f495e8cda7002f647b2161ef22d8eca1059d3')
    prior = read(prior_path)
    check('prior_closure_passed', prior['passed'])
    witness_path = PRIVATE / 'git-witness-hosts-supplement.json'
    witness = read(witness_path)
    identity = read(PRIVATE / 'source-types-identity.json')
    sys.path.insert(0, str(SOURCE / 'tools/dnsmasq'))
    import build_package
    from audit_20261011_pie_cost import foreign_workloads
    check('same_frozen_source_and_current_git', witness['passed']
          and witness['source_commit'] == identity['source_commit']
          and witness['source_files'] == identity['source_files'] == build_package.inputs(SOURCE)
          and sha(PRIVATE / 'source-types-identity.json') == prior['inputs']['source_identity']['sha256'])
    plan, run, result = [read(SUPPLEMENT / name) for name in ('plan.json', 'run.json', 'probe/result.json')]
    check('actual_command_and_results', run['argv'] == plan['argv'] and run['returncode'] == 0
          and run['plan_sha256'] == sha(SUPPLEMENT / 'plan.json')
          and run['log_sha256'] == sha(SUPPLEMENT / 'driver.log')
          and run['result_sha256'] == sha(SUPPLEMENT / 'probe/result.json'))
    check('supplement_assets', all(sha(path) == value for path, value in plan['assets'].items()))
    rust = Path(plan['argv'][plan['argv'].index('--rust') + 1])
    original_script = Path(plan['argv'][5])
    check('same_SDK_and_original_script', plan['source_commit'] == witness['source_commit']
          and sha(rust) == result['identities']['rust'] == '61b02fa66a1c2b07753c236c79b4d2be5cbbf4ddc34125b3c00a1aff171671b6'
          and result['identities']['c'] == '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
          and result['script_sha256'] == sha(original_script))
    expected = {f'{kind}-debug{debug}' for kind in ('addn-hosts', 'directory', 'hostsdir') for debug in (False, True)}
    check('six_original_configurations', len(result['cases']) == len(expected)
          and {row['id'] for row in result['cases']} == expected)
    counts = {'udp': 0, 'tcp': 0}
    for case in result['cases']:
        normalized = {}
        for side in ('c', 'rust'):
            observed = case['observed'][side]
            check(case['id'] + '_' + side + '_exit', observed['exit'] == 0)
            phases = json.loads(json.dumps(observed['phases']))
            check(case['id'] + '_' + side + '_phases', [p['reload'] for p in phases] == [False, True]
                  and all(p['alive'] for p in phases) and [len(p['answers']) for p in phases] == [9, 10])
            fixture = str(SUPPLEMENT / 'probe' / (case['id'] + '-' + side))
            for phase in phases:
                phase['notices'] = [notice.replace(fixture, '<fixture>') for notice in phase['notices']]
                for answer in phase['answers'].values():
                    check(case['id'] + '_' + side + '_UDP_TCP', set(answer) == {'udp', 'tcp'} and answer['udp'] == answer['tcp'])
                    if side == 'c':
                        for protocol in counts:
                            counts[protocol] += 1
            normalized[side] = phases
        check(case['id'] + '_matched', case['matched'] and normalized['c'] == normalized['rust'])
    check('answer_pair_inventory', counts == {'udp': plan['expected']['UDP_C_Rust_pairs'], 'tcp': plan['expected']['TCP_C_Rust_pairs']}
          and sum(counts.values()) == plan['expected']['C_Rust_answer_pairs'])
    perf = plan['previous_performance_run']
    check('no_overlap_with_completed_performance', sha(perf['path']) == perf['sha256']
          == prior['inputs']['performance_run.json']['sha256']
          and read(perf['path'])['ended_ns'] == perf['ended_ns'] < run['started_ns'] < run['ended_ns'] < report['created_ns'])
    report['remaining_workloads'] = foreign_workloads()
    check('no_remaining_workloads', not report['remaining_workloads'])
    report['answer_pairs'] = counts
    report['product_input_count'] = len(identity['source_files'])
    for name, path in {'prior_closure': prior_path, 'git_witness': witness_path,
                       'source_identity': PRIVATE / 'source-types-identity.json',
                       **{name: SUPPLEMENT / name for name in ('plan.json', 'run.json', 'driver.log', 'probe/result.json', 'verification.json', 'raw-index.json')},
                       'verifier': Path(__file__)}.items():
        report['inputs'][name] = file(path)
    report['passed'] = True
except Exception as error:
    report['error'] = repr(error)
with (PRIVATE / 'hosts-supplement-closure.json').open('x') as stream:
    json.dump(report, stream, indent=2)
    stream.write('\n')
print(json.dumps(dict(passed=report['passed'], checks=len(report['checks']), error=report.get('error'))))
raise SystemExit(int(not report['passed']))
