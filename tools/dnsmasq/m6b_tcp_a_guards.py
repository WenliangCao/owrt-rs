#!/usr/bin/env python3
"""Run local retained-view gates and safe mutation negative controls.

Variants live in fresh ignored source copies. They model discarded COW
content/index state, omitted rotation/expiry and shortened generation; no
shared mutable alias or undefined behavior is injected. These are primitive
guards, not image-daemon or Oracle performance qualification.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


MUTATIONS = {
    'discard-content-on-detach': (
        '&mut Arc::make_mut(&mut self.content[slot / CONTENT_BLOCK_SLOTS]).entries\n'
        '            [slot % CONTENT_BLOCK_SLOTS]',
        'let block = &mut self.content[slot / CONTENT_BLOCK_SLOTS]; '
        'if Arc::strong_count(block) > 1 { *block = Arc::new(ContentBlock { '
        'entries: vec![None; block.entries.len()].into_boxed_slice() }); } '
        '&mut Arc::make_mut(block).entries[slot % CONTENT_BLOCK_SLOTS]'),
    'discard-index-on-detach': (
        'Arc::make_mut(&mut self.names[Self::key_shard(key)]).get_mut(key)',
        '{ let shard = &mut self.names[Self::key_shard(key)]; '
        'if Arc::strong_count(shard) > 1 { *shard = Arc::new(NameIndex::new()); } '
        'Arc::make_mut(shard).get_mut(key) }'),
    'disable-rrset-rotation': (
        'if round_robin && found.len() > 1 {',
        'if false && round_robin && found.len() > 1 {'),
    'preserve-expired-reverse': (
        'if self.policy.expired(self.entry(slot).unwrap().expires, now) {',
        'if false && self.policy.expired(self.entry(slot).unwrap().expires, now) {'),
    'reuse-slot-generation': (
        '.generation\n                .checked_add(1)',
        '.generation\n                .checked_add(0)'),
}


EXPECTED_FAILURES = {
    'discard-content-on-detach': {'tcp_snapshot_content_and_name_roots_detach_only_on_mutation',
                                  'tcp_retained_view_keeps_negative_reverse_lease_and_rotation_private'},
    'discard-index-on-detach': {'tcp_snapshot_content_and_name_roots_detach_only_on_mutation',
                                'tcp_view_isolates_mutation_shares_payload_and_imports_only_child_transaction'},
    'disable-rrset-rotation': {'tcp_retained_view_keeps_negative_reverse_lease_and_rotation_private',
                              'real_mixed_rrset_rotation_keeps_unique_many_allocation_and_snapshot_order'},
    'preserve-expired-reverse': {'tcp_retained_view_keeps_negative_reverse_lease_and_rotation_private'},
    'reuse-slot-generation': {'cname_preserves_same_name_replacement_but_not_evicted_target',
                             'bounded_state_survives_repeated_abort_expiry_and_reuse'},
}


def copied_variant(args):
    # Import only in copied mode; prepare/local-native do not need this adapter.
    import rust_lib_probe as probe
    out = args.out.resolve()
    if 'private' not in out.parts or out.exists():
        raise ValueError('fresh ignored/private copied-guard output required')
    out.mkdir(parents=True)
    result = {'variant': args.run_variant, 'scope': __doc__, 'accepted': False, 'passed': False,
              'tests_executed': False, 'qualification': False, 'failures': [],
              'mode': 'copied-release-lib-test', 'cargo_invoked': False}
    try:
        plan_sha = probe.digest(args.plan)
        raw = json.loads(args.plan.read_text())
        records = raw.get('records', [raw])
        matches = [record for record in records if record.get('variant') == args.run_variant]
        if len(matches) != 1:
            raise ValueError('one exact prepared variant plan required')
        plan = matches[0]
        expected_failures = sorted(EXPECTED_FAILURES.get(args.run_variant, []))
        if (plan.get('status') != 'prepared-not-built-not-run' or plan.get('qualification') is not False
                or plan.get('oracle_build_kind') != 'probe-tests' or plan.get('libtest_filter') != 'dns::cache::tests'
                or plan.get('test_threads') != 1 or plan.get('expected_failure_tests') != expected_failures
                or not re.fullmatch('[0-9a-f]{40}', str(plan.get('source_commit', '')))
                or raw.get('source_commit') != plan['source_commit']):
            raise ValueError('prepared mutation/filter/source plan differs')
        binding = probe.validate(args.rust_test_binary, args.rust_source_root, args.rust_build_receipt)
        if binding['source_files'] != plan.get('source_inputs'):
            raise ValueError('copied lib test is not the prepared mutation source')
        result.update(source_commit=plan['source_commit'], plan_sha256=plan_sha, binding=binding,
                      expected_failure_tests=expected_failures, runner_sha256=probe.digest(Path(__file__)))
        # A module filter is a substring selector: --exact or --ignored here
        # would accidentally execute zero normal cache tests.
        argv = [binding['test_binary'], 'dns::cache::tests', '--test-threads=1']
        result['argv'] = argv
        process = None
        with (out / 'stdout').open('xb') as stdout, (out / 'stderr').open('xb') as stderr:
            process = subprocess.Popen(argv, stdout=stdout, stderr=stderr)
            try:
                result['exit'] = process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
                result['exit'] = process.returncode
                raise ValueError('copied guard timed out; raw failure retained')
            except BaseException:
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
                raise
        probe.recheck(binding)
        result['binding_after'] = probe.validate(args.rust_test_binary, args.rust_source_root, args.rust_build_receipt)
        if (probe.digest(args.plan) != plan_sha or result['binding_after'] != binding
                or probe.digest(Path(__file__)) != result['runner_sha256']):
            raise ValueError('copied ELF/source/build/plan/runner changed during guard')
        stdout = (out / 'stdout').read_text()
        summaries = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', stdout, re.MULTILINE)
        running = re.findall(r'^running (\d+) tests?$', stdout, re.MULTILINE)
        if len(summaries) != 1 or len(running) != 1:
            raise ValueError('one complete actual libtest execution required')
        status, passed, failed, ignored = summaries[0]
        passed, failed, ignored = map(int, [passed, failed, ignored])
        if passed + failed <= 0 or int(running[0]) != passed + failed + ignored:
            raise ValueError('module filter executed no tests or count differs')
        failed_names = re.findall(r'^test dns::cache::tests::(\w+) \.\.\. FAILED$', stdout, re.MULTILINE)
        result.update(tests_executed=True, passed_tests=passed, failed_tests=failed,
                      ignored_tests=ignored, failed_test_names=failed_names,
                      designated_failure_observed=bool(set(failed_names) & set(expected_failures)))
        if args.run_variant == 'positive':
            accepted = result['exit'] == 0 and status == 'ok' and failed == 0
        else:
            accepted = result['exit'] != 0 and status == 'FAILED' and failed > 0 and result['designated_failure_observed']
        result.update(accepted=accepted, passed=accepted)
        if not accepted:
            result['failures'].append('positive failed or designated negative mutation was not rejected by executed tests')
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result['failures'].append(repr(error))
    finally:
        for name in ['stdout', 'stderr']:
            path = out / name
            if path.is_file(): result[name + '_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return int(not result['accepted'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repository', type=Path)
    p.add_argument('--source')
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--local-native', action='store_true', help='explicit local cargo; never Oracle')
    p.add_argument('--prepare-only', action='store_true', help='export variants for locked oracle_build.sh probe-tests; no build/run')
    p.add_argument('--run-variant', choices=['positive', *MUTATIONS], help='run one already copied lib test; no cargo')
    p.add_argument('--plan', type=Path, help='prepare result.json or one variant-plan.json')
    p.add_argument('--rust-test-binary', type=Path)
    p.add_argument('--rust-source-root', type=Path)
    p.add_argument('--rust-build-receipt', type=Path)
    args = p.parse_args()
    if args.run_variant:
        if (args.prepare_only or args.local_native or args.repository or args.source
                or not all([args.plan, args.rust_test_binary, args.rust_source_root, args.rust_build_receipt])):
            p.error('copied variant requires plan/test-binary/source-root/build-receipt only; no cargo modes')
        return copied_variant(args)
    if (not args.repository or not args.source
            or any([args.plan, args.rust_test_binary, args.rust_source_root, args.rust_build_receipt])):
        p.error('preparation/local-native requires repository/source; copied inputs require run-variant')
    repo, out = args.repository.resolve(), args.out.resolve()
    if args.prepare_only and args.local_native:
        p.error('select prepare-only or explicit local-native')
    if not args.prepare_only and (not args.local_native or str(repo).startswith('/home/ubuntu') or str(out).startswith('/home/ubuntu')):
        p.error('Oracle must use prepared variants and oracle_build.sh; legacy cargo is local-native only')
    if 'private' not in out.parts:
        p.error('output must be ignored/private')
    out.mkdir(parents=True, exist_ok=False)
    commit = subprocess.check_output(['git', 'rev-parse', args.source], cwd=repo, text=True).strip()
    inputs = {}
    for part in ['dnsmasq', 'ubus']:
        for name in subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', commit, 'components/' + part], cwd=repo, text=True).splitlines():
            inputs[name] = subprocess.check_output(['git', 'show', f'{commit}:{name}'], cwd=repo)
    records = []
    for variant in ['positive', *MUTATIONS]:
        work = out / variant
        source = work / 'source'
        for name, value in inputs.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
        cache = source / 'components/dnsmasq/src/dns/cache.rs'
        if variant != 'positive':
            old, new = MUTATIONS[variant]
            text = cache.read_text()
            if text.count(old) != 1:
                raise RuntimeError(f'{variant}: mutation anchor count {text.count(old)}')
            cache.write_text(text.replace(old, new))
        generated = {str(path.relative_to(source)): hashlib.sha256(path.read_bytes()).hexdigest()
                     for part in ['dnsmasq', 'ubus'] for path in sorted((source / 'components' / part).rglob('*'))
                     if path.is_file() and 'target' not in path.relative_to(source).parts}
        plan = {'source_commit': commit, 'variant': variant, 'source_root': str(source),
                'source_inputs': generated, 'oracle_build_kind': 'probe-tests',
                'libtest_filter': 'dns::cache::tests', 'test_threads': 1,
                'expected_failure_tests': sorted(EXPECTED_FAILURES.get(variant, [])),
                'status': 'prepared-not-built-not-run', 'qualification': False}
        (work / 'variant-plan.json').write_text(json.dumps(plan, indent=2) + '\n')
        if args.prepare_only:
            records.append(plan)
            continue
        argv = ['cargo', 'test', '--manifest-path', str(source / 'components/dnsmasq/Cargo.toml'),
                '--lib', 'dns::cache::tests', '--target-dir', str(out / 'target'), '--', '--test-threads=1']
        run = subprocess.run(argv, cwd=source, capture_output=True, text=True)
        (work / 'stdout').write_text(run.stdout)
        (work / 'stderr').write_text(run.stderr)
        tested = bool(re.search(r'running [1-9][0-9]* tests', run.stdout)) and 'test result:' in run.stdout
        failed = re.findall(r'^test dns::cache::tests::(\w+) \.\.\. FAILED$', run.stdout, re.MULTILINE)
        designated = variant == 'positive' or bool(set(failed) & EXPECTED_FAILURES[variant])
        row = {'variant': variant, 'argv': argv, 'exit': run.returncode,
               'tests_executed': tested, 'cache_sha256': hashlib.sha256(cache.read_bytes()).hexdigest(),
               'accepted': tested and designated and (run.returncode == 0 if variant == 'positive' else run.returncode != 0),
               'designated_failure_observed': designated, 'expected_failure_tests': plan['expected_failure_tests'],
               'failed_tests': [line for line in run.stdout.splitlines() if line.startswith('test ') and line.endswith('FAILED')]}
        (work / 'command.json').write_text(json.dumps(row, indent=2) + '\n')
        records.append(row)
    result = {'source_commit': commit, 'scope': __doc__, 'records': records,
              'passed': False if args.prepare_only else all(row['accepted'] for row in records),
              'status': 'prepared-not-built-not-run' if args.prepare_only else 'local-native-executed',
              'qualification': False,
              'source_inputs': {name: hashlib.sha256(value).hexdigest() for name, value in inputs.items()}}
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'source_inputs'}, indent=2))
    return 0 if args.prepare_only else int(not result['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
