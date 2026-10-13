#!/usr/bin/env python3
"""Check downloaded final functional evidence and local endpoint archives only."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[6]
REMOTE = Path('/home/ubuntu/dnsmasq-fix4-repair-20261013/private')
SDK = '55ea363f626f3e14279f280b1dba708a1d751877ab22a3503d312985c9efd6ca'
C = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
OLD = ROOT / 'docs/dnsmasq/audits/20261012/fix3_repairs/functional'
sys.path.insert(0, str(ROOT / 'tools/dnsmasq'))
sys.path.insert(0, str(OLD))
from m5_option_matrix_archive import verify as verify_archive
from wire_compare import canonical, common_udp_case, parity_checks
from result_checks import check_matrix, check_n2, check_acl, observe_stale
from types_result_checks import check_original_dns


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def need(value, label):
    if not value:
        raise ValueError(label)


def field(value, name):
    for part in name.split('.'):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def family_check(value, job):
    for name, expected in job['checks'].items():
        actual = field(value, name)
        need(type(actual) is type(expected) and actual == expected, 'frozen family assertion: ' + job['id'] + '/' + name)
    inventory = job.get('inventory')
    if inventory:
        rows = field(value, inventory['field'])
        actual = [row[inventory['key']] if inventory.get('key') else row for row in rows]
        need(len(actual) == len(inventory['ids']) and set(actual) == set(inventory['ids']), 'complete family case inventory')


def main(args, report):
    directory, raw, endpoints = args.directory, args.raw, args.endpoints
    final = read(directory / 'validation.json')
    closure = read(directory.parent / 'build/final-closure.json')
    plan = read(raw / 'functional-final-plan.json')
    state = read(raw / 'functional-final/state.json')
    invocation = read(raw / 'functional-final-invocation.json')
    reused = [OLD / name for name in ('wire_compare.py', 'result_checks.py', 'types_result_checks.py', 'historical-differences.json')]
    reused.append(ROOT / 'tools/dnsmasq/m5_option_matrix_archive.py')
    for path in reused:
        remote = str(Path(plan['source']) / path.relative_to(ROOT))
        need(sha(path) == plan['assets'][remote], 'reused offline checker differs from frozen version')
    report['reused_checker_sha256'] = {str(path.relative_to(ROOT)): sha(path) for path in reused}
    need(final['SDK_elf']['sha256'] == plan['rust_sha256'] == state['elf_sha256'] == SDK, 'final SDK identity')
    need(final['source_commit'] == state['source_commit'] == plan['source_commit'] == closure['source_commit'], 'source revision')
    need(plan['source_files'] == final['source_files'] == read(directory.parent / 'build/final-identity.json')['source_files'],
         'all functional commands use the final 178 product inputs')
    plan_sha = sha(raw / 'functional-final-plan.json')
    need(plan_sha == state['plan_sha256'] == final['plan']['sha256'], 'plan identity')
    need(sha(raw / 'functional-final/state.json') == final['state']['sha256'], 'state identity')
    need(state['passed'] and invocation['passed'] and invocation['returncode'] == 0, 'persistent run completed successfully')
    driver_log = raw / 'functional-final-driver.log'
    need(sha(driver_log) == invocation['log_sha256'] and driver_log.read_text().rstrip().endswith('ALL PASS'), 'durable ALL PASS log')
    need(len(plan['jobs']) == len(state['commands']) == len(final['commands']) == 49, 'all 49 jobs retained')
    index = read(directory / 'raw-index.json')['files']
    indexed = {row['path']: row for row in index}
    results, families, explicit_elf_args, artifact_fields = {}, Counter(), 0, 0
    for job, record, exported in zip(plan['jobs'], state['commands'], final['commands']):
        need(all(record[key] == value for key, value in job.items()), 'state matches frozen job')
        need(record['passed'] and record['returncode'] == exported['returncode'] == 0 and job['id'] == exported['id'], 'successful job sequence')
        path = raw / Path(job['result']).relative_to(REMOTE)
        digest = sha(path)
        need(digest == record['result_sha256'] == exported['result']['sha256'] == indexed[job['result']]['sha256'], 'result hashes')
        result = results[job['id']] = read(path)
        flags = ('--rust', '--rust-binary', '--fix', '--elf')
        bound = [job['argv'][job['argv'].index(flag) + 1] for flag in flags if flag in job['argv']]
        need(all(value == plan['rust'] for value in bound), 'runtime ELF argument differs from final SDK')
        explicit_elf_args += bool(bound)
        for key in ('rust_sha256', 'candidate_sha256', 'elf_sha256'):
            if key in result:
                need(result[key] == SDK, 'candidate result identity: ' + job['id'])
                artifact_fields += 1
        for key in ('rust', 'fix'):
            if key in result.get('identities', {}):
                need(result['identities'][key] == SDK, 'directed candidate identity: ' + job['id'])
                artifact_fields += 1
        if 'family' in job:
            family_check(result, job)
            families[job['family']] += 1
    need(len(families) == 14 and sum(families.values()) == 35, '14 families and 35 commands')
    need({name: {'passed': True, 'commands': count} for name, count in families.items()}
         == state['families'] == final['complete_families'], 'family completion counts')
    native = results['config-state-probe']
    need(native['cases'] == len(native['results']) == 19 and not native['failures']
         and all(row['match'] for row in native['results']), 'native probe separately passed')
    need(plan['SDK_daemon_family_commands'] == 48 and plan['native_state_probe_commands'] == 1, 'SDK/native scopes separate')
    n1 = results['N1-filter-cname']
    need(len(n1['runs']) == 72 and len({row['name'] for row in n1['runs']}) == 72, 'N1 inventory')
    for row in n1['runs']:
        a, b = row['sides']['c'], row['sides']['fix']
        need(a['response'] == b['response'] and a['response']['status'] == 'reply', 'N1 full dictionary/hex/TTL')
        need(len(a['upstream']) == len(b['upstream']) and all(s['alive'] and s['exit'] == 0 for s in (a, b)), 'N1 upstream/health')
        if row['warmth'] != 'cold':
            need(a['warm_response'] == b['warm_response'] and len(a['warm_upstream']) == len(b['warm_upstream']), 'N1 warmup exact')
    # Reapply the frozen baseline comparators to raw results, not their passed flags.
    baseline = {}
    for name, comparator in (('review3-matrix', check_matrix), ('N2-intentional-permissions', check_n2),
                             ('O3-auth-ACL', check_acl), ('F08-stale-observation', observe_stale),
                             ('A10-and-original-DNS', check_original_dns)):
        actual = comparator(results[name])
        record = next(row for row in state['commands'] if row['id'] == name)
        need(actual == record['strict_result'] and actual['passed'], 'declared baseline recheck: ' + name)
        baseline[name] = actual
    need(sum(baseline['review3-matrix']['case_counts'].values()) == 1852, 'review3 matrix count')
    parity, count, common = results['TCP-UDP-parity'], 0, 0
    need(parity['passed'] and not parity['failures'] and len(parity['profiles']) == 56, 'parity inventory')
    for profile in parity['profiles']:
        for label, case in profile['cases'].items():
            use_udp = common_udp_case(profile['name'].rsplit('-debug', 1)[0], label)
            checks = parity_checks(*(case[side][transport]['response'] for side, transport in
                (('c', 'udp'), ('c', 'tcp'), ('rust', 'udp'), ('rust', 'tcp'))), common_udp=use_udp)
            need(all(value for key, value in checks.items() if key != 'transport_size_difference'), 'parity full canonical responses')
            for transport in ('udp', 'tcp'):
                expected_transport = 'udp' if use_udp and transport == 'tcp' else transport
                need(len(case['c'][expected_transport]['upstream']) == len(case['rust'][transport]['upstream']), 'parity upstream')
                need(canonical(case['c'][transport]['warm']) == canonical(case['rust'][transport]['warm'])
                     and case['c'][transport]['warm_upstream_count'] == case['rust'][transport]['warm_upstream_count'], 'parity warmup')
            common += use_udp
            count += 1
        need(all(p['alive'] and p['exit'] == 0 and p['health']['status'] == 'reply' for p in profile['processes'].values()), 'parity health')
    need(count == parity['case_count'] == final['TCP_UDP_parity_cases'] == 1736, '1736 parity pairs')
    archive_checks, manifests = {}, {}
    for name in ('syntax', 'service'):
        exported = final['endpoint_archives'][name]
        manifest = manifests[name] = read(endpoints / (name + '.manifest.json'))
        for suffix in ('.tar.gz', '.manifest.json', '.local-verification.json'):
            need(sha(endpoints / (name + suffix)) == exported['files'][suffix]['sha256'], 'endpoint artifact identity')
        archive_checks[name] = verify_archive(endpoints / (name + '.tar.gz'), endpoints / (name + '.manifest.json'), None)
        need(archive_checks[name]['entries'] == exported['entries'], 'archive entry count')
        original = endpoints / name / 'result.json'
        need(sha(original) == manifest['entries']['result.json']['sha256']
             == sha(raw / 'functional-final/families/m5_dns_endpoints' / name / 'result.json'), 'archived original result bytes')
    need(sum(value['entries'] for value in archive_checks.values()) == 4282, 'all 4282 metadata entries')
    audit = results['m5_dns_endpoints-source-row-audit']
    need(audit['required_rows'] == audit['passed_rows'] == len(audit['rows']) == 191
         and audit['rust_sha256'] == SDK and audit['c_sha256'] == C, '191 source/evidence rows bound to final artifact')
    observations, identity_count = {}, 0
    for row in audit['rows']:
        need(row['passed'] and not row['missing'] and row['evidence'] and row['source_anchors'], 'source row has concrete witnesses')
        for evidence in row['evidence']:
            if 'paths' not in evidence:
                need(evidence['passed'], 'aggregate source evidence check')
                continue
            need(not evidence['errors'], 'source evidence mismatch')
            for side, remote in evidence['paths'].items():
                relative = str(Path(remote).relative_to(REMOTE / 'functional-final/families/m5_dns_endpoints' / evidence['run']))
                path = endpoints / evidence['run'] / relative
                need(sha(path) == manifests[evidence['run']]['entries'][relative]['sha256'], 'source witness bound to actual archive')
                observed = observations.setdefault(str(path), read(path))
                need(all((len(observed[key]) if key == 'rows' else observed.get(key)) == value
                         for key, value in evidence['witness'][side].items()), 'source witness fields equal raw observation')
                identities = [observed.get('identity')] + [r.get('identity') for r in observed.get('endpoint_receipts', [])]
                for identity in identities:
                    if identity:
                        need(identity['sha256'] == (SDK if side == 'rust' else C), 'actual endpoint runtime ELF identity')
                        identity_count += 1
    need(closure['passed'] and len(closure['checks']) == 77 and all(closure['checks'].values()), 'closure checks')
    need(closure['locks_released'] and not closure['remaining_workloads'], 'retained Oracle release receipt')
    need(closure['bindings']['functional_derived']['sha256'] == sha(directory / 'validation.json')
         and closure['bindings']['functional_plan']['sha256'] == plan_sha, 'closure binds this result and plan')
    for name, path, expected in (('functional', directory / 'raw-index.json', 35025),
                                 ('new_DHCP', directory / 'dhcp-sdk-raw-index.json', 1398)):
        need(closure['raw_indexes'][name]['index']['sha256'] == sha(path)
             and closure['raw_indexes'][name]['verified_files'] == len(read(path)['files']) == expected, 'closure raw index binding')
    report.update(status='passed', SDK_elf_sha256=SDK, source_commit=plan['source_commit'],
        fresh_commands=49, family_commands=35, complete_families=14, SDK_daemon_family_commands=48, native_probe_commands=1,
        explicit_final_ELF_argument_commands=explicit_elf_args, candidate_result_identity_fields=artifact_fields,
        N1_exact_cases=72, matrix_cases=1852, parity_cases=count, parity_declared_common_udp_cases=common,
        retained_forward_pointer_cases=2, retained_ACL_cases=len(baseline['O3-auth-ACL']['inherited_refusal_representation_differences']),
        stale_equivalence_claim=baseline['F08-stale-observation']['equivalence_claim'],
        archive_metadata_entries=4282, archives=archive_checks, source_audit_rows=191,
        unique_raw_source_observations=len(observations), runtime_identity_observations=identity_count,
        closure_checks=77, closure_functional_files=35025, closure_DHCP_files=1398)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--raw', type=Path, required=True)
    parser.add_argument('--endpoints', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not args.output.exists(), 'fresh output required')
    report = {'schema': 1, 'status': 'failed', 'script_sha256': sha(Path(__file__)),
              'inputs': {name: sha(args.directory / name) for name in ('validation.json', 'raw-index.json')},
              'scope': 'Local raw-result and tar-content/metadata verification. Frozen declared-baseline comparators and canonical decoder reused; N1 exact dictionaries and archive witness binding checked independently. Remote 35,025/1,398-file rehash is verified by bound closure receipt, not rerun. No Oracle access or experiments.'}
    try:
        main(args, report)
    except Exception as error:
        report['error'] = repr(error)
        raise
    finally:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'output': str(args.output), 'status': report['status'], 'sha256': sha(args.output)}))
