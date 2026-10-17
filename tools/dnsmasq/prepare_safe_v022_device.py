#!/usr/bin/env python3
"""Recover the archived device tools locally; never build or contact a device.

The output is a new reconstruction, not the deleted K runtime bundle. Historical
Python modules remain byte-identical and must only be imported by the new runner,
which binds its own production identity, root, schedule and restoration slots.
"""
import argparse
import hashlib
import json
from pathlib import Path
import py_compile
import subprocess


ARCHIVE = '8788be287ea1024ac44cbd6d5d71e509582da47c'
ORIGINAL = '51b039597af13f9c9cf07c9f80e388e25cd8ae5d'
ROOT = '/tmp/dnsmasq-perf-v022-20261017'
OLD_ROOT = '/tmp/dnsmasq-perf-20261015'
BASE = 'tools/dnsmasq/'
PYTHON = (
    'perf_opt_device_run.py', 'perf_opt_analyze.py', 'research_device_run.py',
    'research_full_analyze.py', 'udp_stage_device_run.py', 'device_health_baseline.py',
)
TESTS = (
    'test_device_perf_case_observer.py', 'test_perf_opt_miss_cohort.py',
    'test_perf_opt_mixed_cohort.py', 'test_device_health_baseline.py',
    'test_perf_opt_device_guard_boundary.py', 'test_perf_opt_device_prune.py',
    'test_research_window_deadline.py',
)
C_SOURCES = {
    'research_cpu_clock_probe': 'device_cpu_clock_probe.c',
    'm6a_loadgen': 'm6a_loadgen.c',
    'm6a_upstream_mixed_cohort': 'm6a_upstream.c',
    'device_perf_guard': 'device_perf_guard.c',
    'device_perf_netns': 'device_perf_netns.c',
    'device_perf_lifecycle': 'device_perf_lifecycle.c',
    'device_perf_resource_probe': 'device_perf_resource_probe.c',
    'nice10': 'perf_opt_nice10.c',
}
OBSERVER_EDITS = (
    ('PID validation and observer reaping',
     'starttime() { awk \'{print $22}\' "/proc/$1/stat" 2>/dev/null; }',
     '''starttime() {
    # An empty PID otherwise reads /proc//stat, the system-wide stat file.
    case "$1" in ''|*[!0-9]*) return 1;; esac
    awk '{print $22}' "/proc/$1/stat" 2>/dev/null
}
reap_observer() {
    [ -n "$observer" ] || return 0
    observer_status=0
    wait "$observer" || observer_status=$?
    printf '%s\\n' "$observer_status" > "$out/observer.exit"
    observer=
}''', 1),
    ('retain observer cleanup status',
     '    for pid in $observer $daemon $upstream $timer $client_timer; do wait "$pid" 2>/dev/null || :; done',
     '    reap_observer\n    for pid in $daemon $upstream $timer $client_timer; do wait "$pid" 2>/dev/null || :; done', 1),
    ('two atomic PID publishers',
     'echo $$ > "$1"; shift; exec "$@"',
     'echo $$ > "$1.tmp" && mv "$1.tmp" "$1" || exit 1; shift; exec "$@"', 2),
    ('observer invocation and identity',
     '''"$root/device_perf_resource_probe" monitor "$daemon" "$((warm+seconds+5))" "$client" "$upstream" > "$out/resources.jsonl" 2> "$out/resources.stderr" &
observer=$!
observer_start=$(starttime "$observer")''',
     '''printf '%s\\n' "$daemon" "$((warm+seconds+5))" "$client" "$upstream" > "$out/observer.args"
"$root/device_perf_resource_probe" monitor "$daemon" "$((warm+seconds+5))" "$client" "$upstream" > "$out/resources.jsonl" 2> "$out/resources.stderr" &
observer=$!
printf '%s\\n' "$observer" > "$out/observer.pid"
observer_start=$(starttime "$observer")
printf '%s\\n' "$observer_start" > "$out/observer.starttime"''', 1),
    ('reject observer failures and empty output',
     'wait "$observer" 2>/dev/null || :\nobserver=',
     '''reap_observer
# The sampler returns 1 on our normal SIGTERM, 0 if its duration elapsed.
[ "$observer_status" -le 1 ]
[ -s "$out/resources.jsonl" ]
[ ! -s "$out/resources.stderr" ]''', 1),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def replace(text, edit):
    label, old, new, count = edit
    if text.count(old) != count:
        raise ValueError(f'{label}: expected {count} exact matches, got {text.count(old)}')
    return text.replace(old, new)


def transform(text, edits):
    result = text
    for edit in edits:
        result = replace(result, edit)
    inverse = result
    for label, old, new, count in reversed(edits):
        inverse = replace(inverse, ('inverse ' + label, new, old, count))
    if inverse != text:
        raise ValueError('inverse substitution did not recover the exact source')
    return result


def case_edits(kind):
    name = f'safe_v022_{kind}_case.sh'
    old_tools = ('sha256sum "$root/m6a_loadgen" "$root/m6a_upstream" '
                 '"$root/device_perf_resource_probe" "$root/device_perf_lifecycle" '
                 '"$root/device_perf_case.sh" > "$out/tools.sha256"')
    selection = '''upstream_binary=$root/m6a_upstream
upstream_extra=
if [ "$mode" = udp ] && [ "$profile" = mixed ]; then
    upstream_binary=$root/m6a_upstream_mixed_cohort
    upstream_extra=--audit-fixed-mixed-cohort
fi
'''
    tools = ('sha256sum "$root/m6a_loadgen" "$upstream_binary" '
             '"$root/device_perf_resource_probe" "$root/device_perf_lifecycle" '
             f'"$root/{name}" "$root/safe_v022_group.sh" '
             '"$root/research_cpu_clock_probe" > "$out/tools.sha256"')
    edits = [*OBSERVER_EDITS,
        ('isolated root', OLD_ROOT, ROOT, 2),
        ('actual case/group/helper identities and mixed-only routing', old_tools, selection + tools, 1),
        ('selected upstream executable', 'sh "$out/upstream.pid" "$root/m6a_upstream" --port',
         'sh "$out/upstream.pid" "$upstream_binary" --port', 1),
        ('optional strict cohort flag', '--steady-seconds "$seconds" >',
         '--steady-seconds "$seconds" $upstream_extra >', 1),
        ('UDP CPU-clock before at original boundary',
         '"$root/device_perf_resource_probe" monitor "$daemon" 1 > "$out/before.jsonl"',
         '''"$root/device_perf_resource_probe" monitor "$daemon" 1 > "$out/before.jsonl"
if [ "$mode" = udp ]; then
    "$root/research_cpu_clock_probe" read "$daemon" "$daemon_start" > "$out/cpu-before.jsonl"
fi''', 1),
        ('UDP CPU-clock after original one-second drain',
         '"$root/device_perf_resource_probe" monitor "$daemon" 1 > "$out/after.jsonl"',
         '''if [ "$mode" = udp ]; then
    "$root/research_cpu_clock_probe" read "$daemon" "$daemon_start" > "$out/cpu-after.jsonl"
fi
"$root/device_perf_resource_probe" monitor "$daemon" 1 > "$out/after.jsonl"''', 1),
    ]
    if kind != 'full':
        edits += [
            ('public representative local rules', 'server=127.0.0.1#15354\n',
             '''server=127.0.0.1#15354
# Public representative rules; these are not copied production configuration.
local=/lan/
server=/bind/
server=/invalid/
server=/local/
server=/localhost/
server=/onion/
server=/test/
''', 1),
            ('public query suffix', '--name-prefix m6a.test', '--name-prefix m6a.example', 2),
        ]
    if kind == 'dual':
        prewarm = ('    "$root/m6a_loadgen" --mode udp --host 127.0.0.1 --port 15353 '
                   '--clients 32 --duration-seconds 5 --warmup-seconds 0 --rate 200 '
                   '--seed 0x293001 --name-prefix m6a.example --profile hit --qtype aaaa30 '
                   '--cache-names 800 --timeout-ms 1000 --output "$out/prewarm" '
                   '> "$out/prewarm.stdout" 2> "$out/prewarm.stderr"')
        a = prewarm.replace('--qtype aaaa30', '--qtype a').replace('--cache-names 800', '--cache-names 400').replace('prewarm', 'prewarm-a')
        aaaa = prewarm.replace('--qtype aaaa30', '--qtype aaaa').replace('--cache-names 800', '--cache-names 400')
        edits += [
            ('same-name A then AAAA excluded prewarm', prewarm, a + '\n' + aaaa, 1),
            ('400-name main dual fixture',
             '--profile "$profile" --qtype aaaa30 --cache-names 800',
             '--profile "$profile" --qtype aaaa30 --cache-names 400', 1),
        ]
    return edits


def prepare(repo, out):
    private = (repo / 'private').resolve()
    out = out.resolve()
    if out == private or private not in out.parents:
        raise ValueError('--out must be a new directory beneath this repository/private')
    out.mkdir(parents=True, exist_ok=False)
    for folder in ('modules', 'source', 'runtime', 'originals', 'checks', 'bin'):
        (out / folder).mkdir()
    inputs, outputs, proofs = {}, {}, {}

    def source(path, ref=ARCHIVE):
        key = ref + ':' + path
        body = git(repo, 'show', key)
        inputs[key] = {'git_blob': git(repo, 'rev-parse', key).decode().strip(),
                       'sha256': sha(body), 'bytes': len(body)}
        return body

    def save(path, body):
        if isinstance(body, str):
            body = body.encode()
        target = out / path
        target.write_bytes(body)
        outputs[path] = {'sha256': sha(body), 'bytes': len(body)}

    for name in PYTHON + TESTS:
        save('modules/' + name, source(BASE + name))
    save('originals/research_dual_family_screen.patch', source(BASE + 'research_dual_family_screen.patch'))
    frozen = json.loads(source('docs/dnsmasq/audits/perf-opt-20261015/frozen-inputs.json'))
    prior = json.loads(source('docs/dnsmasq/audits/perf-opt-20261015/f-e-tool-inputs-preparation.json'))
    save('originals/f-e-tool-inputs-preparation.json', json.dumps(prior, indent=2) + '\n')
    for binary, filename in C_SOURCES.items():
        save('source/' + binary + '.c', source(BASE + filename))
    ordinary = source(BASE + 'm6a_upstream.c', ORIGINAL)
    if sha(ordinary) != frozen['files'][BASE + 'm6a_upstream.c']:
        raise ValueError('ordinary upstream does not match original frozen source manifest')
    save('source/m6a_upstream.c', ordinary)
    if outputs['source/m6a_loadgen.c']['sha256'] != prior['repairs']['queue_loadgen']['new_source_sha256']:
        raise ValueError('loadgen is not the repaired f7c7 source')

    original_case = source(BASE + 'perf_opt_device_case.sh').decode()
    fixed_case = source(BASE + 'device_perf_case.sh').decode()
    observer_fixed = transform(original_case, OBSERVER_EDITS)
    if observer_fixed != fixed_case.replace('/tmp/dnsmasq-perf-20261014-v3', OLD_ROOT):
        raise ValueError('observer edits differ from archived ade5309e implementation')
    save('originals/perf_opt_device_case.sh', original_case)
    save('originals/device_perf_case_observer_fixed.sh', fixed_case)
    for kind in ('full', 'public', 'dual'):
        edits = case_edits(kind)
        filename = f'runtime/safe_v022_{kind}_case.sh'
        save(filename, transform(original_case, edits))
        proofs[filename] = {'base_sha256': sha(original_case.encode()),
                            'inverse_exact': True, 'changes': [edit[0] for edit in edits]}
    # Existing event-controlled observer tests inspect their sibling case file.
    save('modules/device_perf_case.sh', (out / 'runtime/safe_v022_full_case.sh').read_bytes())

    original_group = source(BASE + 'perf_opt_device_group.sh').decode()
    route = '''[ "$#" = 9 ]
kind=$1
shift
case "$kind" in
    full) case_script=$root/safe_v022_full_case.sh ;;
    public) [ "$3:$4" = udp:hit ]; case_script=$root/safe_v022_public_case.sh ;;
    dual) [ "$3:$4" = udp:hit ]; case_script=$root/safe_v022_dual_case.sh ;;
    *) exit 2 ;;
esac
'''
    group_edits = [
        ('new isolated root', OLD_ROOT, ROOT, 1),
        ('explicit case whitelist before publishing active group',
         'root=' + ROOT + '\n', 'root=' + ROOT + '\n' + route, 1),
        ('route to the whitelisted case', '"$root/device_perf_case.sh"', '"$case_script"', 1),
    ]
    save('runtime/safe_v022_group.sh', transform(original_group, group_edits))
    save('originals/perf_opt_device_group.sh', original_group)
    proofs['runtime/safe_v022_group.sh'] = {
        'base_sha256': sha(original_group.encode()), 'inverse_exact': True,
        'changes': [edit[0] for edit in group_edits],
    }
    for path in sorted((out / 'runtime').glob('*.sh')):
        subprocess.run(['/bin/sh', '-n', str(path)], check=True, capture_output=True)
    for path in sorted((out / 'modules').glob('*.py')):
        py_compile.compile(str(path), cfile=str(out / 'checks' / (path.name + 'c')), doraise=True)

    binaries = {}
    for name in [*C_SOURCES, 'm6a_upstream']:
        historical = prior['measurement_artifacts'].get(name, {})
        if name == 'research_cpu_clock_probe':
            historical = {'sha256': '7f8eeef4f2a1333174f480090f953f4dfc43807b9d396b7c16fc6c3eec0d11c8', 'bytes': 430888}
        elif name == 'm6a_upstream_mixed_cohort':
            historical = {'sha256': '9479c5ecf096bc7fd32e033ad99d3fc46638654d4fc8707e5614bacc10db03e2', 'bytes': 452448}
        binaries[name] = {'source': 'source/' + name + '.c',
                          'expected_historical_artifact': historical,
                          'missing_in_bundle': True, 'build_or_verified_copy_required': True}
    manifest = {
        'schema': 1, 'status': 'LOCAL_SOURCE_PREPARATION_ONLY', 'archive_commit': ARCHIVE,
        'tool_sha256': sha(Path(__file__).read_bytes()), 'device_root': ROOT,
        'source_inputs': inputs, 'files': outputs, 'inverse_proofs': proofs,
        'observer_diff_matches_ade5309e': True,
        'checks': {'shell_syntax': 4, 'python_compile': len(PYTHON + TESTS), 'device_access': False, 'binary_build': False},
        'support_binaries': binaries,
        'group_argv': ['full|public|dual', 'c|rust', 'label', 'mode', 'profile', 'rate', 'warmup_seconds', 'measurement_seconds', 'dhcp_clients'],
        'limits': [
            'Reconstructed runtime scripts have new identities; historical private scripts and raw are deleted.',
            'Recovered Python algorithms are unchanged. Do not run their historical main/prepare entry points.',
            'The new runner must bind ROOT, production identity, health identity and restoration slots.',
            'Only full mixed uses the strict helper; its cohort contract remains 200qps, 5+20 seconds, m6a.test.',
            'Dual-family validator additions remain in the archived research_dual_family_screen.patch; the new runner must apply those original checks.',
        ],
    }
    save('manifest.json', json.dumps(manifest, indent=2) + '\n')
    return {'bundle': str(out), 'manifest_sha256': outputs['manifest.json']['sha256'],
            'missing_support_binaries': list(binaries), 'device_access': False, 'binary_build': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    repo = Path(git(Path(__file__).resolve().parent, 'rev-parse', '--show-toplevel').decode().strip())
    print(json.dumps(prepare(repo, args.out), indent=2))


if __name__ == '__main__':
    main()
