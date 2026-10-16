#!/usr/bin/env python3
"""One frozen-profile SDK build; no collection, threshold search or timing."""
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

from pgo_sdk_smoke import check_baseline_paths, group_exists, interrupted, save, sha, stop_group


def main():
    path = Path(sys.argv[1]).resolve()
    plan = json.loads(path.read_text())
    base = Path(plan['attempt'])
    assert path == base / 'inputs/plan.json'
    assert plan['hot_callsite_threshold'] == 250
    with (base / 'state.json').open('x') as stream:
        stream.write('{}\n')
    state = {'status': 'preflight', 'plan_sha256': sha(path), 'pid': os.getpid(), 'commands': []}
    process = None
    try:
        os.sched_setaffinity(0, {0})
        assert all(sha(path.parent / name) == digest for name, digest in plan['input_sha256'].items())
        assert all(sha(filename) == digest for filename, digest in plan['fixed_tool_sha256'].items())
        assert sha(plan['builder']) == plan['builder_sha256']
        assert sha(Path(plan['builder']).with_name('build_package.py')) == plan['build_helper_sha256']
        assert sha(plan['baseline_receipt']['path']) == plan['baseline_receipt']['sha256']
        baseline = json.loads(Path(plan['baseline_receipt']['path']).read_text())
        check_baseline_paths(plan, baseline)
        assert sha(plan['prior_use_build']['path']) == plan['prior_use_build']['sha256']
        previous = json.loads(Path(plan['prior_use_build']['path']).read_text())
        assert previous['status'] == 'built-unqualified' and not previous['within_existing_budget']
        assert previous['source_files'] == baseline['source_files'] and previous['sdk'] == baseline['sdk']
        assert sha(plan['profile_receipt']) == plan['profile_receipt_sha256']
        profile = json.loads(Path(plan['profile_receipt']).read_text())
        assert profile['status'] == 'training-complete' and profile['plan_sha256'] == plan['training_plan_sha256']
        assert len(profile['profiles']) == 50 and len({row['path'] for row in profile['profiles']}) == 50
        assert all(sha(row['path']) == row['sha256'] for row in profile['profiles'])
        assert sha(plan['merged_profile']) == profile['merged_profile']['sha256'] == plan['merged_profile_sha256']
        assert all(sha(Path(plan['source']) / name) == digest for name, digest in baseline['source_files'].items())
        assert all(sha(Path(plan['sdk']) / name) == digest for name, digest in baseline['sdk']['files'].items())
        wrapper = Path(plan['wrapper_remote_path'])
        wrapper.parent.mkdir()
        shutil.copy2(path.parent / 'pgo_hot250_cargo.py', wrapper)
        shutil.copy2(path.parent / 'pgo_train_cargo.py', wrapper.with_name('pgo_train_cargo.py'))
        wrapper.chmod(0o755)
        wrapper.with_name('rustc').symlink_to(plan['rustc'])
        stage, = plan['stages']
        row = {'argv': stage['argv'], 'environment_updates': stage['environment']}
        state.update(status='building', active=row)
        save(base / 'state.json', state)
        try:
            with (base / 'build.stdout').open('xb') as stdout, (base / 'build.stderr').open('xb') as stderr:
                process = subprocess.Popen(stage['argv'], env=dict(os.environ, **stage['environment']),
                                           stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL, start_new_session=True)
                row['pid'] = process.pid
                save(base / 'state.json', state)
                row['returncode'] = process.wait(timeout=900)
                assert row['returncode'] == 0
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
                    filename = base / ('build.' + suffix)
                    if filename.exists():
                        row[suffix + '_sha256'] = sha(filename)
                state['commands'].append(row)
                if process is None or not group_exists(process.pid):
                    state['active'] = None
                save(base / 'state.json', state)
        out = Path(plan['outputs']['use'])
        built = json.loads((out / 'build.json').read_text())
        state.update(build_receipt_sha256=sha(out / 'build.json'), artifacts=built.get('artifacts'),
                     within_existing_budget=built.get('within_existing_budget'))
        assert built['status'] == 'built-unqualified' and built['source_unchanged']
        for key in ('source_commit', 'source_date_epoch', 'source_digest', 'builder_sha256', 'build_helper_sha256'):
            assert built[key] == plan[key]
        assert built['source_files'] == baseline['source_files'] and built['sdk'] == baseline['sdk']
        assert built['elf_layout'] == baseline['elf_layout']
        assert sha(out / 'dnsmasq-rs') == built['artifacts'][0]['sha256']
        assert sha(out / 'link.map') == built['link_map']['sha256']
        assert sha(out / 'dnsmasq-prestrip') == built['prestrip']['sha256']
        invocation = json.loads(Path(plan['invocation_receipts']['use']).read_text())
        assert invocation['plan_sha256'] == state['plan_sha256'] and invocation['profile'] == profile
        assert invocation['wrapper_sha256'] == plan['wrapper_sha256'] and invocation['base_wrapper_sha256'] == plan['base_wrapper_sha256']
        assert invocation['cargo_sha256'] == sha(plan['cargo']) and invocation['rustc_sha256'] == sha(plan['rustc'])
        assert invocation['rustc_environment'] == plan['rustc']
        assert invocation['base_use_rustflags'] == plan['prior_use_rustflags']
        assert invocation['effective_rustflags'] == plan['prior_use_rustflags'] + ' -Cllvm-args=-hot-callsite-threshold=250'
        log = (out / 'compile.log').read_text()
        state['profile_diagnostics'] = [line for line in log.splitlines() if re.search('profile|mismatch', line, re.I)]
        assert not re.search('hash mismatch|control flow change|profile data may be out of date', log, re.I)
        mapping = (out / 'link.map').read_text()
        assert 'profiler_builtins' not in mapping and '__llvm_profile_' not in mapping
        assert sha(plan['profile_receipt']) == plan['profile_receipt_sha256']
        assert sha(plan['merged_profile']) == plan['merged_profile_sha256']
        assert all(sha(row['path']) == row['sha256'] for row in profile['profiles'])
        assert all(sha(filename) == digest for filename, digest in plan['fixed_tool_sha256'].items())
        assert all(sha(Path(plan['source']) / name) == digest for name, digest in baseline['source_files'].items())
        assert all(sha(Path(plan['sdk']) / name) == digest for name, digest in baseline['sdk']['files'].items())
        assert built['within_existing_budget'], 'original release ELF/APK budget exceeded'
        state['status'] = 'built-unqualified'
    except BaseException as error:
        state.update(status='failed', error=repr(error))
        raise
    finally:
        save(base / 'state.json', state)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    main()
