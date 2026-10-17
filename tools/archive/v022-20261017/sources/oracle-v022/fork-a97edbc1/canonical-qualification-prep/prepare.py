#!/usr/bin/env python3
"""Bind a canonical CI candidate to existing Oracle runtime tools; never builds/runs it."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path('/srv/owrt-archive/dnsmasq-work')
BASE = ROOT / 'private/fork-a97edbc1'
SOURCE = ROOT / 'source-tools-0c05f477'
COMMIT = 'a97edbc1382fc92b83110ed0822284aafeee7461'
DIGEST = 'c47f95e99a966ec6433f37e0a7d36a8d8a7e9b360f63de6e905e0993e1bfc671'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def adapt(original, target, replacements):
    text = original.read_text()
    for old, new in replacements:
        assert text.count(old) == 1, (original, old)
        text = text.replace(old, new)
    target.write_text(text)
    compile(text, str(target), 'exec')
    return {'original_path': str(original), 'original_sha256': sha(original), 'adapted_sha256': sha(target)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ci', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--ci-run-id', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    ci, out = args.ci.resolve(), args.out.resolve()
    assert out.is_relative_to(BASE) and not out.exists()
    manifest_path = ci / 'manifest.json'
    assert sha(manifest_path) == args.manifest_sha256
    m = json.loads(manifest_path.read_text())
    assert m['status'] == 'created-unqualified-pgo-candidate'
    assert m['pgo_stage'] == 'candidate-use' and m['pgo']['mode'] == 'use'
    assert m['source_commit'] == COMMIT and m['source_digest'] == DIGEST
    assert str(m['source_date_epoch']) == '1792244626'
    assert len(m['source_files']) == 193
    assert hashlib.sha256(json.dumps(m['source_files'], sort_keys=True, separators=(',', ':')).encode()).hexdigest() == DIGEST
    binding_path = BASE / 'correctness/tools-source-binding.json'
    binding = json.loads(binding_path.read_text())
    assert binding['product_source_files'] == m['source_files']
    assert binding['source_root'] == str(SOURCE)
    assert all(sha(SOURCE / path) == digest for path, digest in m['source_files'].items())
    assert m['warnings']['strict_compiler_warnings_zero'] and m['compiler_warnings']['strict_compiler_warnings_zero']
    assert m['pgo']['profile_diagnostics'] == []
    invocation = m['pgo']['invocation']
    assert invocation['mode'] == 'use' and '-Cprofile-generate' not in invocation['effective_rustflags']
    assert invocation['profile_sha256'] == m['pgo']['profile_sha256']
    assert '--features' not in invocation['argv'] and '--release' in invocation['argv']
    assert m['budget'] == {'elf_max_bytes': 2500000, 'apk_max_bytes': 1400000}
    assert m['elf']['size'] <= 2500000 and m['artifact']['size'] <= 1400000
    artifacts = {'dnsmasq-rs': (m['elf']['sha256'], m['elf']['size']),
                 m['artifact']['name']: (m['artifact']['sha256'], m['artifact']['size']),
                 'pgo-compilation/link.map': (m['link_map']['sha256'], m['link_map']['bytes'])}
    prestrip = m['pgo']['compilation_evidence']['dnsmasq-prestrip']
    artifacts['pgo-compilation/dnsmasq-prestrip'] = (prestrip['sha256'], prestrip['bytes'])
    for name, (digest, size) in artifacts.items():
        assert sha(ci / name) == digest and (ci / name).stat().st_size == size
        assert m['retained'][name] == {'sha256': digest, 'bytes': size}
    assert b'__llvm_profile_runtime' not in (ci / 'dnsmasq-rs').read_bytes()
    out.mkdir()
    use = out / 'input'
    use.mkdir()
    for name in ('dnsmasq-rs', m['artifact']['name']):
        shutil.copy2(ci / name, use / name)
    (use / 'dnsmasq-rs').chmod(0o755)
    shutil.copy2(ci / 'pgo-compilation/link.map', use / 'link.map')
    build = {'status': 'ci-built-runtime-adapter-unqualified',
             'scope': 'Runtime adapter only. Built by canonical x86 CI; Oracle performs no build.',
             'source': str(SOURCE), 'source_commit': COMMIT, 'source_digest': DIGEST,
             'source_files': m['source_files'], 'source_date_epoch': m['source_date_epoch'],
             'features': '', 'opt_level': '3',
             'artifacts': [{'path': 'dnsmasq-rs', 'bytes': m['elf']['size'], 'sha256': m['elf']['sha256']}],
             'artifact': m['artifact'], 'link_map': {'path': 'link.map', 'sha256': m['link_map']['sha256'], 'bytes': m['link_map']['bytes']},
             'provenance': {'producer': 'canonical-x86_64-GitHub-Actions', 'ci_run_id': args.ci_run_id,
                            'manifest_path': str(manifest_path), 'manifest_sha256': sha(manifest_path),
                            'runner_commit': m['runner_commit'], 'tools_source_binding_sha256': sha(binding_path),
                            'source_manifest_sha256': sha(ci / 'source-manifest.json'),
                            'prestrip_sha256': prestrip['sha256'], 'profile_sha256': m['pgo']['profile_sha256']}}
    save(use / 'build.json', build)
    changed = {}
    boundary = out / 'runtime'
    boundary.mkdir()
    for name in ('selfexec_jail_boundary.py', 'selfexec_fd_headroom.py', 'tool-identity.json'):
        shutil.copy2(BASE / 'final-runtime' / name, boundary / name)
    changed['runtime/run.py'] = adapt(BASE / 'final-runtime/run.py', boundary / 'run.py', [
        ("OUT=BASE/'final-runtime';SOURCE=ROOT/'source-a97edbc1'", "OUT=Path(" + repr(str(boundary)) + ");SOURCE=ROOT/'source-tools-0c05f477'"),
        ("train=BASE/'pgo/train-stage';built=json.loads((train/'use/build.json').read_text());state=json.loads((train/'state.json').read_text());assert state['status']=='trained-use-built-unqualified'", "use=Path(" + repr(str(use)) + ");built=json.loads((use/'build.json').read_text());assert built['status']=='ci-built-runtime-adapter-unqualified'"),
        ("candidate=train/'use/dnsmasq-rs'", "candidate=use/'dnsmasq-rs'"),
        ("actual finalPGO runtime qualification; K pressure references unchanged same-tool plain preflight control", "actual canonical CI ELF runtime qualification; K pressure references unchanged same-tool plain preflight control")])
    changed['run_shipping.py'] = adapt(BASE / 'correctness/run_shipping.py', out / 'run_shipping.py', [
        ("SOURCE=ROOT/'source-a97edbc1';USE=BASE/'pgo/train-stage/use';OUT=BASE/'correctness/shipping'", "SOURCE=ROOT/'source-tools-0c05f477';USE=Path(" + repr(str(use)) + ");OUT=Path(" + repr(str(out / 'shipping')) + ")"),
        ("built=json.loads((USE/'build.json').read_text());state=json.loads((BASE/'pgo/train-stage/state.json').read_text());assert state['status']=='trained-use-built-unqualified'", "built=json.loads((USE/'build.json').read_text());assert built['status']=='ci-built-runtime-adapter-unqualified'")])
    startup = out / 'startup'
    startup.mkdir()
    old_startup = BASE / 'startup-tools-7a6f3b0e'
    runtime = '/tmp/owrt-archive-v022-slot-08' + args.ci_run_id
    assert args.ci_run_id.isdigit()
    for name in ('device_selfexec_lifecycle.c', 'device_selfexec_lifecycle', 'build-result.json', 'safe_v022_startup_run.py'):
        shutil.copy2(old_startup / name, startup / name)
    assert sha(startup / 'device_selfexec_lifecycle') == '7de91a0c55b4e4137b4a243c4374f1fbedb1b3a8039bb23548368fd1dc8c8e0b'
    for name in ('safe_v022_startup_case.sh', 'safe_v022_startup_group.sh'):
        original = old_startup / name
        text = original.read_text()
        old_root = 'root=/tmp/owrt-archive-v022-slot-01'
        assert text.count(old_root) == 1
        (startup / name).write_text(text.replace(old_root, 'root=' + runtime))
        changed['startup/' + name] = {'original_sha256': sha(original), 'adapted_sha256': sha(startup / name), 'change': 'runtime root only'}
    changed['startup/run_preview.py'] = adapt(old_startup / 'run_preview.py', startup / 'run_preview.py', [
        ("OUT=ROOT/'private/fork-a97edbc1/startup-tools-7a6f3b0e';runtime=Path('/tmp/owrt-archive-v022-slot-01')", "OUT=Path(" + repr(str(startup)) + ");runtime=Path(" + repr(runtime) + ")"),
        ("use=ROOT/'private/fork-a97edbc1/pgo/train-stage/use'", "use=Path(" + repr(str(use)) + ")"),
        ("assert json.loads((use.parent/'state.json').read_text())['status']=='trained-use-built-unqualified'", "assert json.loads((use/'build.json').read_text())['status']=='ci-built-runtime-adapter-unqualified'")])
    shutil.copy2(BASE / 'correctness/run_family_gates.py', out / 'run_family_gates.py')
    save(out / 'preparation.json', {'status': 'prepared-not-executed', 'ci_run_id': args.ci_run_id,
         'elf_sha256': m['elf']['sha256'], 'build_adapter_sha256': sha(use / 'build.json'), 'adapted_tools': changed,
         'family_runner_sha256': sha(out / 'run_family_gates.py'), 'source_tools_binding_sha256': sha(binding_path),
         'plan': ['no-proc plus FD2/3/4/8 vs same-tool K control', 'shipping three starts RELRO/NX',
                  '44 families/67 jobs max3parallel corrected fixtures', '40 startup tool-preview starts'],
         'stop': 'first new failing gate; retain results; no selective retries',
         'reused_source_only': 'native988 and8sourcecorp remain bound to source193/digest',
         'cost_model': 'Artifact identity is the remaining uncertainty. Canonical CI may change code layout but must preserve behavior. This run predicts zero new mismatches; any new mismatch rejects qualification. Runtime latency is not judged here.'})
    print(json.dumps({'status': 'prepared-not-executed', 'out': str(out), 'elf_sha256': m['elf']['sha256']}))


if __name__ == '__main__':
    main()
