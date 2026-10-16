#!/usr/bin/env python3
"""Build one profile-generate artifact using an already verified exact control."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys

from pgo_sdk_smoke import check_baseline_paths, check_build, interrupted, save, sha, stop_group


def main():
    path = Path(sys.argv[1]).resolve()
    plan = json.loads(path.read_text())
    base = Path(plan['attempt'])
    assert path == base / 'inputs/plan.json'
    assert not (base / 'state.json').exists()
    state = {'status': 'preflight', 'commands': [], 'plan_sha256': sha(path)}
    save(base / 'state.json', state)

    def run(label, argv, env=None):
        process = None
        row = {'label': label, 'argv': argv}
        try:
            with (base / (label + '.stdout')).open('xb') as stdout, (base / (label + '.stderr')).open('xb') as stderr:
                process = subprocess.Popen(argv, env=dict(os.environ, **(env or {})),
                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
                row['pid'] = process.pid
                state['active'] = row
                save(base / 'state.json', state)
                row['returncode'] = process.wait(timeout=900)
                assert row['returncode'] == 0
        finally:
            if process is not None:
                row['cleanup'] = stop_group(process)
            state['commands'].append(row)
            state['active'] = None
            save(base / 'state.json', state)

    try:
        os.sched_setaffinity(0, {plan['cpu']})
        assert all(sha(path.parent / name) == digest for name, digest in plan['input_sha256'].items())
        assert all(sha(filename) == digest for filename, digest in plan['fixed_tool_sha256'].items())
        assert sha(plan['builder']) == plan['builder_sha256']
        assert sha(Path(plan['builder']).with_name('build_package.py')) == plan['build_helper_sha256']
        assert sha(plan['baseline_receipt']['path']) == plan['baseline_receipt']['sha256']
        baseline = json.loads(Path(plan['baseline_receipt']['path']).read_text())
        check_baseline_paths(plan, baseline)
        control = Path(plan['baseline_receipt']['path']).parent
        assert sha(control / 'dnsmasq-rs') == plan['expected_control_elf_sha256']
        assert sha(control / 'link.map') == baseline['link_map']['sha256']
        assert all(sha(Path(plan['source']) / name) == digest for name, digest in baseline['source_files'].items())
        assert all(sha(Path(plan['sdk']) / name) == digest for name, digest in baseline['sdk']['files'].items())
        wrapper = Path(plan['wrapper_remote_path'])
        wrapper.parent.mkdir()
        shutil.copy2(path.parent / 'pgo_smoke_cargo.py', wrapper)
        wrapper.chmod(0o755)
        wrapper.with_name('rustc').symlink_to(plan['rustc'])
        Path(plan['default_profile_directory']).mkdir()
        stage, = plan['stages']
        assert stage['mode'] == 'generate'
        run('generate-build', stage['argv'], stage['environment'])
        built = check_build(plan, 'generate', sha(path), {key: sha(plan[key]) for key in ('cargo', 'rustc')})
        assert built['source_files'] == baseline['source_files'] and built['sdk'] == baseline['sdk']
        state['status'] = 'runtime'
        save(base / 'state.json', state)
        run('isolated-runtime', ['sudo', '-n', 'sh', plan['isolator']['path'], 'python3',
            str(path.parent / 'pgo_sdk_smoke.py'), str(path), '--runtime',
            '--parent-netns', os.readlink('/proc/self/ns/net'), '--parent-mntns', os.readlink('/proc/self/ns/mnt')])
        result = json.loads((Path(plan['runtime']['directory']) / 'runtime.json').read_text())
        assert result['status'] == 'complete' and not result['forced_cleanup']
        assert sha(result['profile']['path']) == result['profile']['sha256']
        assert all(sha(Path(plan['source']) / name) == digest for name, digest in baseline['source_files'].items())
        assert sha(control / 'dnsmasq-rs') == plan['expected_control_elf_sha256']
        state.update(status='complete', generate_build_sha256=sha(Path(plan['outputs']['generate']) / 'build.json'),
            artifacts=built['artifacts'], excluded_smoke_profile=result['profile'])
    except BaseException as error:
        state.update(status='failed', error=repr(error))
        raise
    finally:
        save(base / 'state.json', state)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    main()
