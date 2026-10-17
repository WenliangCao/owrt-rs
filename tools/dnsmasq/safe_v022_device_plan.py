#!/usr/bin/env python3
"""Freeze the v0.2.2 device schedule locally; this tool cannot run a device.

The reconstructed bundle is checked before deriving commands. Artifact binding,
new PGO qualification and the execution controller are separate prerequisites.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from prepare_safe_v022_device import ROOT


K_SHA256 = 'f6710d37912bd414e01b32be97fd73b2ed4cf2ddf637eaa1254fa660603eba08'
BUNDLE_SHA256 = '9cfe77a4c3c6dc767da0014265c3dfe2a3a9f35d49c6d3e29c4c4ed8fe55cee5'
SCENES = (
    ('udp-hit', 'udp', 'hit', 200, 5, 45, 150),
    ('udp-miss', 'udp', 'miss', 200, 5, 20, 150),
    ('udp-mixed', 'udp', 'mixed', 200, 5, 20, 150),
    ('tcp-hit', 'tcp', 'hit', 200, 5, 20, 150),
    ('tcp-miss', 'tcp', 'miss', 200, 5, 20, 150),
    ('dhcp-home6', 'dhcp', 'hit', 100, 5, 20, 6),
    ('dhcp', 'dhcp', 'hit', 100, 5, 20, 150),
    ('startup-small', 'life-startup', 7, 6, 20, 1000, 150),
    ('config-small', 'life-config', 7, 6, 20, 1000, 150),
    ('hup-small', 'life-hup', 7, 6, 20, 1000, 150),
    ('hup-large', 'life-hup', 999, 150, 20, 1000, 150),
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def schedule(prefix):
    if not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', prefix):
        raise ValueError('prefix must contain only lowercase letters, digits and single hyphens')
    rows = []

    def pairs(stage, group, kind, scene, count, left='k', right='candidate'):
        for number in range(1, count + 1):
            for side in (('c', 'rust') if number % 2 else ('rust', 'c')):
                label = f'{prefix}-{group}-r{number}-{side}'
                lifecycle = str(scene[1]).startswith('life-')
                rows.append({
                    'stage': stage, 'group': group, 'round': number, 'side': side,
                    'left': left, 'right': right,
                    'artifact': left if side == 'c' else right,
                    'label': label, 'case_kind': kind, 'scene': list(scene),
                    'group_argv': [kind, side, label, *map(str, scene[1:])],
                    'deadline_seconds': 100 if lifecycle else max(100, scene[4] + scene[5] + 40),
                    'cpu_operations': 20 if lifecycle else scene[3] * (scene[4] + scene[5]),
                    'cpu_clock_scope': 'single-stable-process-only' if scene[1] == 'udp' else None,
                })

    for name, kind, scene in (
        ('ordinary', 'full', SCENES[0]),
        ('dual', 'dual', ('dual-hit', 'udp', 'hit', 200, 5, 95, 150)),
        ('mixed', 'full', SCENES[2]),
    ):
        pairs('calibration', name + '-aa', kind, scene, 2, right='k')
    # Preserve all eleven original scene definitions. Only UDP-hit is extended
    # to nine pairs / 45 seconds, exactly as in the accepted 118-window protocol.
    for scene in SCENES:
        pairs('full118', 'full-' + scene[0], 'full', scene, 9 if scene[0] == 'udp-hit' else 5)
    pairs('dual-confirm', 'dual-confirm', 'dual',
          ('dual-hit', 'udp', 'hit', 200, 5, 95, 150), 9)
    if len(rows) != 148 or len({row['label'] for row in rows}) != len(rows):
        raise ValueError('schedule membership or label uniqueness failed')
    return rows


def verify_bundle(bundle):
    manifest = bundle / 'manifest.json'
    if digest(manifest) != BUNDLE_SHA256:
        raise ValueError('recovered bundle manifest identity differs')
    value = json.loads(manifest.read_text())
    if value['device_root'] != ROOT:
        raise ValueError('bundle device root differs')
    files = value['files']
    for name, expected in files.items():
        path = bundle / name
        if path.is_symlink() or not path.is_file() or digest(path) != expected['sha256']:
            raise ValueError('recovered bundle file differs: ' + name)
    return {name: row['sha256'] for name, row in files.items()}


def make_plan(prefix, bundle):
    files = verify_bundle(bundle)
    windows = schedule(prefix)
    return {
        'schema': 1,
        'status': 'PREPARATION_ONLY_EXECUTION_BLOCKED',
        'device_root': ROOT,
        'prefix': prefix,
        'production_sha256': K_SHA256,
        'baseline_artifact_sha256': K_SHA256,
        'candidate_artifact': None,
        'bundle_manifest_sha256': BUNDLE_SHA256,
        'recovered_files': files,
        'plan_tool_sha256': digest(Path(__file__)),
        'stage_window_counts': {'calibration': 12, 'full118': 118, 'dual-confirm': 18},
        'execution_order': ['fresh-health-baseline', 'startup40', 'calibration12', 'full118', 'dual-confirm18'],
        'schedule': windows,
        'startup_supplement': {
            'tool': 'device_selfexec_lifecycle', 'modes': ['helper', 'resolver'],
            'artifacts': ['k', 'candidate'], 'starts_per_mode_artifact': 10,
            'total_starts': 40, 'cadence_ms': 500,
            'target_boundary': 'private mount/PID namespace and minimal chroot, root exec then UID/GID453 and CapEff0x3400',
            'proc_by_mode': {'helper': 'absent', 'resolver': 'present'},
            'nofile_soft_hard': [1024, 4096],
            'resolver_limitation': 'exact K runtime lookup fails before fork without proc; retain one functional negative control, no failure timing rank',
            'readiness': {'helper': 'exact old callback and correct local DNS reply',
                          'resolver': 'servers-file hostname route and correct upstream reply'},
            'cpu': 'subreaper RUSAGE_CHILDREN after all owned descendants reaped; retain whole CPU and '
                   'child pre-exec RUSAGE_SELF setup baseline separately; timed CPU subtracts measured setup only',
            'resource': 'post-ready RSS/Anon/FD snapshot; no peak/PSS/USS claim',
            'observer_resolution_ms': 1,
            'stop': 'any failed start, incomplete reaping, forced cleanup or cadence overrun',
            'regression_review_ms': 1,
            'cpu_review': 'whole and timed tree CPU separately; >=9/10 positive ordinal differences and '
                          'median delta greater than both6us and K internal adjacent-pair maxabs => stop for root review; '
                          'sequential blocks are not randomized pairs or proof of significance',
            'qualification': 'SDK build and Oracle rehearsal still required',
        },
        'entry_requirements': [
            'fixed product source and source-bound fresh PGO ELF/APK',
            'ELF <= 2500000 bytes and APK <= 1400000 bytes',
            'original 44 families/67 jobs retained and all unexpected differences resolved',
            'explicit helper selfexec FD structural contract passes separately from legacy count',
            'no-proc/uid453/mount+PID namespace qualification, including b861 negative control',
            'all nine reconstructed device support binaries SDK-built and hashes bound',
            'startup supplement SDK-built and Oracle-rehearsed',
            'pending resolver resource and 2/4/8 FD-pressure fixtures qualified',
            'controller binds recovered modules to current root/production/idle K slots',
            'plan/artifact/tool hashes frozen before first window',
        ],
        'health': {
            'fresh_baseline_seconds': 125, 'required_prestop_prefix_seconds': 120,
            'entry_mem_available_kib': 90112, 'live_mem_available_kib': 65536,
            'external_ipv4_ipv6_https_interval_seconds': 30,
            'production_identity': 'exact exe SHA selects one host PID plus stable starttime and boot',
            'guard': 'unchanged independent DNS/HTTP/route/memory/production-identity guard',
            'guard_segments': 'calibration groups, each original scene, dual confirmation and supplement',
            'on_failure': 'stop only the exact owned isolated group; retain STOP and raw; no restart',
        },
        'slots': {
            'immutable': ['artifact-k', 'artifact-candidate'],
            'working': ['dnsmasq-c', 'dnsmasq-rust'],
            'idle_restore': {'dnsmasq-c': 'k', 'dnsmasq-rust': 'k'},
            'mutation_boundary': 'only current task root; verify no owned daemon before replacing slots',
        },
        'workload_contracts': {
            'dual': '400 same names; separate 1000 A + 1000 AAAA excluded prewarms; '
                    '800 upstream fills; steady upstream 0; first prewarm to end <120s',
            'mixed': 'original m6a.test, seed/qtype/epoch, 800 fills +200 warmup misses '
                     '+800 measurement misses =1800 requests/replies; no duplicates/unexpected',
            'dhcp': '6 or150 initial DORA clients in warmup; measured phase exactly2000 renews; CPU2500 ops',
            'lifecycle': 'original20 repetitions and1ms latency comparison floor unchanged',
            'cpu_clock': 'UDP only when all samples show one stable PID/start/thread, '
                         'no truncation/disappeared child and unchanged waited-child CPU',
        },
        'decision_rules': {
            'objective': 'no discernible regression; lack of detection is not strict equivalence',
            'minimum_effect_of_interest_cpu_us': 5,
            'instrument_resolution_limit_cpu_us': 5 / 3,
            'calibration_noise': 'per-scene maximum absolute CPU pair difference from its two K/K pairs',
            'paired_regression': 'five valid pairs, all5 positive CPU deltas, '
                                 'median positive delta exceeds same-scene K/K noise and clock resolution '
                                 'requires stop/review, except fixed small-delta extension below; '
                                 '4/5 direction alone is a trend, not this CPU-clock regression gate',
            'noise_review': 'K/K noise >=4us (near the5us effect of interest) blocks inference '
                            'until root reviews instrument/model',
            'model_review': 'candidate median adverse CPU delta >=5us requires explanation even if noisy',
            'full118': 'all original33 W/direction/tick/lifecycle-resolution gates retained; '
                       'any discernible adverse direction blocks acceptance',
            'full_cpu_clock': 'retain all UDP endpoints and9-pair d2/d8 plus3 block medians; '
                              'supplemental evidence, not a replacement for original33 gates',
            'dual_confirmation': 'nine valid pairs; d2 exceeds same-batch dual K/K noise '
                                 'and all3 block medians positive => regression',
            'small_consistent_delta': 'positive median below5us with all5 directions and beyond '
                                      'same-scene AA is not an automatic pass; ordinary hit already '
                                      'continues to9 pairs, mixed appends the fixed4 pairs below',
            'latency': 'original p50/p95 W comparisons also retained for dual confirmation',
            'resource': 'tree CPU/FD/RSS retained; expected extra pipe FDs must match explicit contract; '
                        'unexpected FD/socket growth or pressure recovery failure blocks acceptance',
            'fd_accounting': 'owner retained executable O_PATH+1; helper two underlying pipes each dup =>+2; '
                             'pending resolver pipe and any recreated stdio measured explicitly on Oracle; '
                             'normal extra FDs never excuse pressure failure',
            'stage_gate': 'any unexpected correctness/health/resource failure or discernible '
                          'regression stops progression; no automatic retries for effect or noise',
        },
        'conditional_mixed_extension': {
            'trigger': 'original mixed5 pairs all positive, median>AA noise and clock resolution, '
                       'median<5us, with no earlier stop condition',
            'additional_rounds': [6, 7, 8, 9], 'additional_windows': 8,
            'case_kind': 'full', 'scene': list(SCENES[2]),
            'order': 'round6 rust/c; round7 c/rust; round8 rust/c; round9 c/rust',
            'labels': [f'{prefix}-full-udp-mixed-r{n}-{s}' for n in range(6, 10)
                       for s in (('c', 'rust') if n % 2 else ('rust', 'c'))],
            'placement': 'after original mixed5 pairs, before advancing to the next scene',
            'judgment': 'all9 original+new pairs retained; d2>same-scene AA noise and '
                        'all3 chronological block medians positive blocks acceptance; '
                        'unresolved strong trend goes to root review, never automatic acceptance',
            'scope': 'fixed additional observations, never replacement of an adverse original window',
        },
        'evidence': {
            'attempts': 'archive every attempted window before any task-root raw pruning',
            'replacements': 'at most one whole-pair replacement after stage only for classified '
                            'generator scheduled_skipped with every sent reply correct and no other error; '
                            'both original sides retained; no candidate/health/deadline retry',
            'no_historical_pooling': True,
            'legacy_private_raw': 'deleted; this is source-based reconstruction, not replay of old bytes',
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--prefix', default='v022')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    out = args.out.resolve()
    if (repo / 'private').resolve() not in out.parents:
        parser.error('--out must be under this repository/private')
    plan = make_plan(args.prefix, args.bundle.resolve())
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('x') as stream:
        stream.write(json.dumps(plan, indent=2) + '\n')
    print(json.dumps({'status': plan['status'], 'windows': len(plan['schedule']),
                      'startup_supplement': 40, 'sha256': digest(out)}))


if __name__ == '__main__':
    main()
