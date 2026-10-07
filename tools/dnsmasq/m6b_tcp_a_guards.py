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


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repository', required=True, type=Path)
    p.add_argument('--source', required=True)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    repo, out = args.repository.resolve(), args.out.resolve()
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
        argv = ['cargo', 'test', '--manifest-path', str(source / 'components/dnsmasq/Cargo.toml'),
                '--lib', 'dns::cache::tests', '--target-dir', str(out / 'target')]
        run = subprocess.run(argv, cwd=source, capture_output=True, text=True)
        (work / 'stdout').write_text(run.stdout)
        (work / 'stderr').write_text(run.stderr)
        tested = bool(re.search(r'running [1-9][0-9]* tests', run.stdout)) and 'test result:' in run.stdout
        row = {'variant': variant, 'argv': argv, 'exit': run.returncode,
               'tests_executed': tested, 'cache_sha256': hashlib.sha256(cache.read_bytes()).hexdigest(),
               'accepted': tested and (run.returncode == 0 if variant == 'positive' else run.returncode != 0),
               'failed_tests': [line for line in run.stdout.splitlines() if line.startswith('test ') and line.endswith('FAILED')]}
        (work / 'command.json').write_text(json.dumps(row, indent=2) + '\n')
        records.append(row)
    result = {'source_commit': commit, 'scope': __doc__, 'records': records,
              'passed': all(row['accepted'] for row in records),
              'source_inputs': {name: hashlib.sha256(value).hexdigest() for name, value in inputs.items()}}
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'source_inputs'}, indent=2))
    return int(not result['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
