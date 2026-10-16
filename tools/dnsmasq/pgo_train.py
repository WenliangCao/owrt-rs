#!/usr/bin/env python3
"""One frozen eleven-scene training pass, then one unchanged-recipe use build."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

from perf_opt_device_run import SCENES, validate
from perf_opt_oracle_run import archive_window
from pgo_sdk_smoke import check_baseline_paths, group_exists, interrupted, save, sha, stop_group


def lifecycle_source(original, fragment):
    begin = original.index('static int end_child(void) {')
    end = original.index('static unsigned read16', begin)
    return original[:begin] + fragment + '\n' + original[end:]


def training_case(original, out, runtime, seed=0x293001):
    assert original.count('--name-prefix m6a.test') == 2
    assert original.count('out=$root/runs/$label') == 1
    assert original.count('--seed 0x293001') == 2
    return original.replace('/tmp/dnsmasq-perf-20261015', str(out)).replace(
        'out=$root/runs/$label', 'out=' + str(runtime) + '/$label').replace(
        '--name-prefix m6a.test', '--name-prefix pgo.test').replace(
        '--seed 0x293001', '--seed ' + hex(seed))


def profile_rows(folder, scene, directory, seed=0x293001):
    if scene[1].startswith('life-'):
        rows = [json.loads(line) for line in (folder / 'lifecycle.jsonl').read_text().splitlines()]
        exits = [json.loads(line.split(' ', 1)[1]) for line in (folder / 'lifecycle.stderr').read_text().splitlines()
                 if line.startswith('pgo_child_exit ')]
        expected = 20 if scene[1] == 'life-startup' else 21 if scene[1] == 'life-config' else 1
        assert len(exits) == len({row['pid'] for row in exits}) == expected
        assert all(row['exited'] and row['exit_code'] == 0 and not row['wait_errno']
                   and not row['signal'] and not row['forced'] for row in exits)
        pids = {row['pid'] for row in exits}
        assert {row['pid'] for row in rows} <= pids
        assert len({row['pid'] for row in rows}) == (1 if scene[1] == 'life-hup' else 20)
    else:
        pids = {int((folder / 'actual.pid').read_text())}
        # The unchanged set-e case reaches COMPLETE only after wait(daemon)==0.
        exits = [{'pid': next(iter(pids)), 'exit_code': 0, 'basis': 'case exit0 and COMPLETE after daemon wait'}]
        load = json.loads((folder / 'client.json').read_text())
        assert load['name_prefix'] == 'pgo.test' and load['seed'] == seed
        if (folder / 'prewarm.json').exists():
            prewarm = json.loads((folder / 'prewarm.json').read_text())
            assert prewarm['name_prefix'] == 'pgo.test' and not prewarm['interrupted'] and not prewarm['output_failed']
            assert prewarm['seed'] == seed
            assert all(prewarm['measurement'][key] == 1000 for key in ('scheduled', 'sent', 'correct'))
            assert not any(prewarm['measurement'][key] for key in ('timeout', 'wrong', 'transport_error', 'scheduled_skipped'))
    paths = sorted(directory.glob('*.profraw'))
    assert {path.name for path in paths} == {str(pid) + '.profraw' for pid in pids}
    assert all(path.is_file() and not path.is_symlink() and path.stat().st_size > 0 for path in paths)
    return exits, [{'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path)} for path in paths]


def collect(plan, inputs):
    assert os.geteuid() == 0 and os.uname().nodename.startswith('instance-')
    assert plan['scenes'] == [list(scene) for scene in SCENES]
    base = Path(plan['attempt'])
    out, runtime = Path(plan['training_directory']), Path(plan['runtime_directory'])
    out.mkdir()
    (out / 'runs').mkdir()
    (out / 'profiles').mkdir()
    runtime.mkdir()
    result = {'status': 'running', 'scenes': [], 'active': None, 'plan_sha256': sha(inputs / 'plan.json')}
    state = out / 'collection.json'
    try:
        for name, item in plan['workload_tools'].items():
            assert sha(item['path']) == item['sha256']
            shutil.copy2(item['path'], out / name)
        helper = base / 'device_perf_lifecycle'
        build = json.loads((base / 'helper-build.json').read_text())
        assert sha(helper) == build['elf_sha256']
        shutil.copy2(helper, out / 'device_perf_lifecycle')
        shutil.copy2(plan['generate_elf']['path'], out / 'dnsmasq-rust')
        assert sha(out / 'dnsmasq-rust') == plan['generate_elf']['sha256']
        original = (inputs / 'perf_opt_device_case.sh').read_text()
        seed = plan.get('training_seed', 0x293001)
        (out / 'device_perf_case.sh').write_text(training_case(original, out, runtime, seed))
        assert sha(out / 'device_perf_case.sh') == plan['training_case_sha256']
        (out / 'guard.pid').write_text(str(os.getpid()) + '\n')
        result['tools'] = {p.name: sha(p) for p in out.iterdir() if p.is_file()}
        for scene in plan['scenes']:
            label = 'train-' + scene[0]
            profiles = out / 'profiles' / scene[0]
            profiles.mkdir()
            argv = ['taskset', '-c', str(plan['cpu']), str(out / 'nice10'), str(out / 'device_perf_netns'),
                    '/bin/sh', str(out / 'device_perf_case.sh'), str(out), 'rust', label, *map(str, scene[1:])]
            env = dict(os.environ, LLVM_PROFILE_FILE=str(profiles / '%p.profraw'))
            process = None
            row = {'scene': scene, 'label': label, 'argv': argv,
                   'llvm_profile_file': env['LLVM_PROFILE_FILE'], 'errors': []}
            try:
                with (out / (label + '.stdout')).open('xb') as stdout, (out / (label + '.stderr')).open('xb') as stderr:
                    process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                                               stdout=stdout, stderr=stderr, start_new_session=True)
                    result['active'] = {'label': label, 'pid': process.pid}
                    save(state, result)
                    row['returncode'] = process.wait(timeout=100)
                    assert row['returncode'] == 0, 'training case did not exit zero'
            except BaseException as error:
                row['errors'].append(repr(error))
            finally:
                try:
                    if process is not None:
                        row['cleanup'] = stop_group(process)
                        row['returncode'] = process.returncode
                    result['active'] = None
                    folder = archive_window(out, runtime / label, label)
                    row['errors'].extend(validate(folder, scene, plan['generate_elf']['sha256']))
                    row['exits'], row['profiles'] = profile_rows(folder, scene, profiles, seed)
                except Exception as error:
                    row['errors'].append('cleanup/archive/validation: ' + repr(error))
                row['valid'] = not row['errors']
                result['scenes'].append(row)
                save(state, result)
            assert row['valid'], row
            assert all(sha(out / name) == digest for name, digest in result['tools'].items())
        assert len(result['scenes']) == 11
        assert not any(Path(plan['generate_default_profile_directory']).iterdir())
        result['status'] = 'complete'
    except BaseException as error:
        result.update(status='failed', error=repr(error))
        raise
    finally:
        save(state, result)
        if runtime.exists() and not any(runtime.iterdir()):
            runtime.rmdir()


def execute(plan, inputs):
    base = Path(plan['attempt'])
    state = {'status': 'preflight', 'commands': [], 'plan_sha256': sha(inputs / 'plan.json')}
    state_path = base / 'state.json'
    with state_path.open('x') as stream:
        stream.write('{}\n')

    def run(label, argv, env=None, timeout=900):
        row = {'label': label, 'argv': list(map(str, argv))}
        process = None
        try:
            with (base / (label + '.stdout')).open('xb') as stdout, (base / (label + '.stderr')).open('xb') as stderr:
                process = subprocess.Popen(row['argv'], env=dict(os.environ, **(env or {})),
                                           stdout=stdout, stderr=stderr, start_new_session=True)
                state['active'] = {'label': label, 'pid': process.pid}
                save(state_path, state)
                row['returncode'] = process.wait(timeout=timeout)
                assert row['returncode'] == 0, label
        finally:
            try:
                if process is not None:
                    row['cleanup'] = stop_group(process)
                    row['returncode'] = process.returncode
            except BaseException as error:
                row['cleanup_error'] = repr(error)
                raise
            finally:
                for suffix in ('stdout', 'stderr'):
                    path = base / (label + '.' + suffix)
                    if path.exists():
                        row[suffix + '_sha256'] = sha(path)
                state['commands'].append(row)
                if process is None or not group_exists(process.pid):
                    state['active'] = None
                save(state_path, state)
        return (base / (label + '.stdout')).read_text()

    try:
        assert inputs == base / 'inputs'
        os.sched_setaffinity(0, {plan['cpu']})
        assert all(sha(inputs / name) == digest for name, digest in plan['input_sha256'].items())
        assert all(sha(path) == digest for path, digest in plan['fixed_tool_sha256'].items())
        assert sha(plan['generate_elf']['path']) == plan['generate_elf']['sha256']
        assert sha(plan['generate_build']['path']) == plan['generate_build']['sha256']
        assert sha(plan['smoke_state']['path']) == plan['smoke_state']['sha256']
        assert json.loads(Path(plan['smoke_state']['path']).read_text())['status'] == 'complete'
        assert sha(plan['profdata']['path']) == plan['profdata']['sha256']
        assert sha(plan['builder']) == plan['builder_sha256']
        assert sha(Path(plan['builder']).with_name('build_package.py')) == plan['build_helper_sha256']
        assert sha(plan['baseline_receipt']['path']) == plan['baseline_receipt']['sha256']
        baseline = json.loads(Path(plan['baseline_receipt']['path']).read_text())
        check_baseline_paths(plan, baseline)
        assert all(sha(Path(plan['source']) / name) == digest for name, digest in baseline['source_files'].items())
        assert all(sha(Path(plan['sdk']) / name) == digest for name, digest in baseline['sdk']['files'].items())
        source = lifecycle_source((inputs / 'device_perf_lifecycle.c').read_text(), (inputs / 'pgo_lifecycle_exit.c').read_text())
        (base / 'device_perf_lifecycle.c').write_text(source)
        assert sha(base / 'device_perf_lifecycle.c') == plan['training_lifecycle_source_sha256']
        run('helper-build', plan['helper_build_argv'], {'STAGING_DIR': plan['sdk_toolchain']})
        save(base / 'helper-build.json', {'source_sha256': sha(base / 'device_perf_lifecycle.c'),
                                        'elf_sha256': sha(base / 'device_perf_lifecycle'),
                                        'compiler_sha256': sha(plan['sdk_cc']), 'argv': plan['helper_build_argv']})
        state['status'] = 'training'
        run('collect', ['sudo', '-n', 'python3', str(Path(__file__).resolve()), str(inputs / 'plan.json'), '--collect'])
        collection = json.loads((Path(plan['training_directory']) / 'collection.json').read_text())
        assert collection['status'] == 'complete' and len(collection['scenes']) == 11
        profiles = [p for row in collection['scenes'] for p in row['profiles']]
        assert len(profiles) == 50 and len({p['path'] for p in profiles}) == 50
        assert all(sha(p['path']) == p['sha256'] for p in profiles)
        assert sha(plan['profdata']['path']) == plan['profdata']['sha256']
        run('profile-merge', [plan['profdata']['path'], 'merge', '-o', plan['merged_profile'], *[p['path'] for p in profiles]])
        shown = run('profile-show', [plan['profdata']['path'], 'show', '--all-functions', '--counts', plan['merged_profile']])
        for key in ('Total functions', 'Maximum function count'):
            assert int(re.search(r'^\s*' + key + r':\s*(\d+)\s*$', shown, re.M)[1]) > 0
        assert not (base / 'profile-merge.stderr').read_text().strip()
        assert not (base / 'profile-show.stderr').read_text().strip()
        save(Path(plan['profile_receipt']), {'status': 'training-complete', 'plan_sha256': state['plan_sha256'],
             'generate_elf_sha256': plan['generate_elf']['sha256'], 'profiles': profiles,
             'collection_sha256': sha(Path(plan['training_directory']) / 'collection.json'),
             'merged_profile': {'path': plan['merged_profile'], 'sha256': sha(plan['merged_profile'])}})
        wrapper = Path(plan['wrapper_remote_path'])
        wrapper.parent.mkdir()
        shutil.copy2(inputs / 'pgo_train_cargo.py', wrapper)
        wrapper.chmod(0o755)
        wrapper.with_name('rustc').symlink_to(plan['rustc'])
        state['status'] = 'profile-use-build'
        stage, = plan['stages']
        run('use-build', stage['argv'], stage['environment'])
        built = json.loads((Path(plan['outputs']['use']) / 'build.json').read_text())
        assert built['status'] == 'built-unqualified' and built['source_unchanged']
        for key in ('source_commit', 'source_date_epoch', 'source_digest', 'builder_sha256', 'build_helper_sha256'):
            assert built[key] == plan[key]
        assert built['source_files'] == baseline['source_files'] and built['sdk'] == baseline['sdk']
        assert built['elf_layout'] == baseline['elf_layout']
        artifact, = built['artifacts']
        budget = plan.get('budget', built['budget'])
        state['budget'] = budget
        state['within_budget'] = (artifact['bytes'] <= budget['elf_max_bytes']
                                  and built['artifact']['bytes'] <= budget['apk_max_bytes'])
        assert state['within_budget'], 'declared ELF/APK budget exceeded'
        assert sha(Path(plan['outputs']['use']) / artifact['path']) == artifact['sha256']
        output = Path(plan['outputs']['use'])
        assert sha(output / 'link.map') == built['link_map']['sha256']
        assert sha(output / 'dnsmasq-prestrip') == built['prestrip']['sha256']
        link_map = (output / 'link.map').read_text()
        assert 'profiler_builtins' not in link_map and '__llvm_profile_' not in link_map
        invocation = json.loads(Path(plan['invocation_receipts']['use']).read_text())
        assert invocation['plan_sha256'] == state['plan_sha256'] and invocation['wrapper_sha256'] == plan['wrapper_sha256']
        assert invocation['cargo_sha256'] == sha(plan['cargo']) and invocation['rustc_sha256'] == sha(plan['rustc'])
        assert invocation['rustc_environment'] == plan['rustc']
        assert invocation['profile'] == json.loads(Path(plan['profile_receipt']).read_text())
        assert invocation['effective_rustflags'] == plan['recipe_rustflags'] + ' -Cprofile-use=' + plan['merged_profile'] + ' -Cllvm-args=-pgo-warn-missing-function'
        log = (Path(plan['outputs']['use']) / 'compile.log').read_text()
        diagnostics = [line for line in log.splitlines() if re.search('profile|mismatch', line, re.I)]
        assert not re.search('no profile data available|hash mismatch|control flow change|profile data may be out of date', log, re.I)
        state.update(status='trained-use-built-unqualified', artifacts=built['artifacts'],
                     use_build_sha256=sha(Path(plan['outputs']['use']) / 'build.json'),
                     profile_receipt_sha256=sha(plan['profile_receipt']), profile_diagnostics=diagnostics)
        assert all(sha(Path(plan['source']) / name) == digest for name, digest in baseline['source_files'].items())
        assert all(sha(Path(plan['sdk']) / name) == digest for name, digest in baseline['sdk']['files'].items())
        assert all(sha(inputs / name) == digest for name, digest in plan['input_sha256'].items())
        assert all(sha(path) == digest for path, digest in plan['fixed_tool_sha256'].items())
        assert sha(plan['merged_profile']) == json.loads(Path(plan['profile_receipt']).read_text())['merged_profile']['sha256']
    except BaseException as error:
        state.update(status='failed', error=repr(error))
        raise
    finally:
        save(state_path, state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', type=Path)
    parser.add_argument('--collect', action='store_true')
    args = parser.parse_args()
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    plan = json.loads(args.plan.read_text())
    (collect if args.collect else execute)(plan, args.plan.resolve().parent)
