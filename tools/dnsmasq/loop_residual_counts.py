#!/usr/bin/env python3
"""Oracle-only native instruction screens, excluded from timing acceptance.

Preserve complete commands, compiler/source/ELF identities and raw perf output.
The ppoll skip is an ideal removed-call control, not an owner implementation.
The inline set is a rejected standalone prototype, not a product container.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    assert 'private' in out.parts and not out.exists()
    out.mkdir(parents=True)
    source = Path(__file__).resolve().parent
    commands = []

    def run(argv, label):
        argv = list(map(str, argv))
        commands.append({'label': label, 'argv': argv})
        result = subprocess.run(argv, capture_output=True, text=True)
        (out / (label + '.stdout')).write_text(result.stdout)
        (out / (label + '.stderr')).write_text(result.stderr)
        (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        result.check_returncode()
        return result.stdout

    gcc = run(['gcc', '--version'], 'gcc-version').splitlines()[0]
    rustc = '/home/ubuntu/.cargo/bin/rustc'
    rust = run([rustc, '+1.98.1', '-Vv'], 'rustc-version')
    kernel = run(['uname', '-srvm'], 'kernel').strip()
    run(['gcc', '-O2', '-Wall', '-Wextra', '-Werror', source / 'loop_ppoll_screen.c',
         '-o', out / 'ppoll-screen'], 'build-ppoll')
    run([rustc, '+1.98.1', '-O', source / 'loop_socket_owners_screen.rs',
         '-o', out / 'owners-screen'], 'build-owners')
    results = {}
    cases = [('ppoll-' + mode, out / 'ppoll-screen', mode, '100000')
             for mode in ('skip', 'empty', 'ready')]
    cases += [('owners-' + mode + '-' + str(count), out / 'owners-screen', mode,
               str(count), '10000')
              for count in (1, 2, 16, 150) for mode in ('baseline', 'inline')]
    for label, executable, *arguments in cases:
        output = run(['taskset', '-c', '2', 'perf', 'stat', '-x,',
                      '-e', 'instructions,cycles', '-o', out / (label + '.perf'),
                      executable, *arguments], label)
        rows = [line.split(',') for line in (out / (label + '.perf')).read_text().splitlines()
                if line and not line.startswith('#')]
        counters = {row[2]: int(row[0]) for row in rows if row[2] in ('instructions', 'cycles')}
        assert set(counters) == {'instructions', 'cycles'}
        assert all(float(row[4]) == 100 for row in rows if row[2] in counters)
        results[label] = {'result': json.loads(output), 'counters': counters,
                          'perf_sha256': sha(out / (label + '.perf'))}
    report = {'scope': __doc__, 'timing_eligible': False, 'compiler': {'gcc': gcc, 'rustc': rust},
              'kernel': kernel, 'affinity_cpu': 2, 'commands': commands,
              'sources': {name: sha(source / name) for name in
                          ('loop_ppoll_screen.c', 'loop_socket_owners_screen.rs')},
              'elfs': {name: sha(out / name) for name in ('ppoll-screen', 'owners-screen')},
              'cases': results}
    (out / 'counts.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'out': str(out), 'cases': len(results), 'timing_eligible': False}))


if __name__ == '__main__':
    main()
