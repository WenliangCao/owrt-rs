#!/usr/bin/env python3
"""Validate and render a private reload-config four-side collection."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics as st
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'tools/benchmark'))
from analyze_candidate import derive

PERFORMANCE = {
    'mean_us': 'mean µs', 'p50_us': 'p50 µs', 'p95_us': 'p95 µs', 'p99_us': 'p99 µs',
    'ops_per_s': '成功吞吐 ops/s', 'command_tree_cpu_us_per_op': '命令树 CPU µs',
    'client_cpu_clock_us_per_op': 'caller CPU µs', 'ubusd_cpu_clock_us_per_op': 'C ubusd CPU µs',
    'receiver_cpu_clock_us_per_op': 'receiver CPU µs', 'logd_cpu_clock_us_per_op': 'private logd CPU µs',
    'dependency_own_cpu_clock_us_per_op': '依赖 CPU 合计 µs',
    'prepare_us_per_op': '计时外准备 µs', 'validation_us_per_op': '计时外校验和重复 µs',
}
RESOURCES = {
    'maxrss_kib': 'wait4 maxrss KiB', 'minor_faults': 'wait4 minor faults',
    'major_faults': 'wait4 major faults', 'user_us': 'wait4 诊断 user CPU µs',
    'system_us': 'wait4 诊断 system CPU µs', 'voluntary_switches': 'wait4 voluntary switches',
    'involuntary_switches': 'wait4 involuntary switches',
}
TASKS = {
    'processes': 'ptrace process births', 'threads': 'ptrace total task births',
    'additional_threads': 'ptrace additional thread births', 'peak_live_tasks': 'ptrace peak live tasks',
    'fork_events': 'ptrace fork events', 'vfork_events': 'ptrace vfork events',
    'clone_events': 'ptrace clone events', 'exec_events': 'ptrace exec events',
    'live_remaining': 'ptrace live remaining',
}


def audit(root, data):
    checked = cycles = events = 0
    archives = {}
    first_production = None
    for index, side in enumerate(data['order'], 1):
        local = root / f'{index:02d}-{side}'; raw = local / 'raw'
        result = json.loads((local / 'result.json').read_text())
        assert result['exit'] == 0 and result['failures'] == [] and result['remote_evidence_retained'] is None
        for line in (local / 'raw.sha256').read_text().splitlines():
            sha, name = line.split(None, 1); path = (raw / name).resolve()
            assert path.is_relative_to(raw.resolve()) and hashlib.sha256(path.read_bytes()).hexdigest() == sha
            checked += 1
        for group in ('config', 'mounts', 'production'):
            suffix = '.sha256' if group == 'config' else '.txt'
            assert (local / (group + '-before' + suffix)).read_bytes() == (local / (group + '-after' + suffix)).read_bytes()
        assert (local / 'config-before.sha256').read_bytes() == (root / 'config-before.sha256').read_bytes()
        production = (local / 'production-before.txt').read_bytes()
        if first_production is None: first_production = production
        assert production == first_production, 'production identity changed between windows'
        for lane in data['summary']:
            native = json.loads((raw / (lane + '.json')).read_text())
            total = native['successful'] + native['warmup'] + native['resource_samples'] + native['task_samples']
            cycles += total
            events += total * {'single_change': 1, 'multi_change': 3}.get(lane, 0)
        archives[local.name] = hashlib.sha256((local / 'raw.tar.gz').read_bytes()).hexdigest()
    before = json.loads((root / 'health-before.json').read_text())
    after = json.loads((root / 'health-after.json').read_text())
    assert before == after, 'pilot/final health changed'
    return {'checksummed_files': checked, 'prepared_cycles': cycles, 'reload_executions_including_repeat': cycles * 2,
            'accepted_events': events, 'initial_final_health_equal': True,
            'all_window_production_config_mounts_equal': True, 'source_archive_sha256': archives}


def budget(root, data, count, warmup, blocks):
    windows = []
    seen = set()
    pilot_window_total = 0
    for index, side in enumerate(data['order'], 1):
        if side in seen: continue
        seen.add(side)
        window = root / f'{index:02d}-{side}'
        # Local artifact timestamps bracket collection/validation/cleanup.
        # Remote uptime provides a second clock scope in the retained evidence.
        wall = (window / 'COMPLETE').stat().st_mtime - (window / 'host-before.json').stat().st_mtime
        assert wall > 0
        observed = projected = 0
        for lane in data['summary']:
            raw = window / 'raw'
            native = json.loads((raw / (lane + '.json')).read_text())
            observed += native['envelope_s']
            records = [json.loads(line) for line in (raw / lane / 'samples.jsonl').read_text().splitlines()][1::2]
            costs = {phase: [(r['latency_ns'] + r['prepare_ns'] + r['validation_ns']) / 1e9
                            for r in records if r['phase'] == phase]
                     for phase in ('warmup', 'measured', 'resource', 'tasks')}
            overhead_per_cycle = max(0, native['envelope_s'] - sum(map(sum, costs.values()))) / len(records)
            diagnostic_cycles = len(costs['resource']) + len(costs['tasks'])
            projected += (count + warmup) * (st.mean(costs['measured']) + overhead_per_cycle)
            projected += sum(costs['resource']) + sum(costs['tasks']) + diagnostic_cycles * overhead_per_cycle
        fixed = wall - observed
        assert fixed >= 0
        windows.append({'side': side, 'pilot_window_seconds': wall, 'pilot_workload_envelope_seconds': observed,
                        'fixed_setup_collection_cleanup_seconds': fixed,
                        'estimated_formal_window_seconds': projected + fixed})
        pilot_window_total += wall
    total = (root / 'COMPLETE').stat().st_mtime - (root / 'STARTED').stat().st_mtime
    one_block_pilot = len(data['order']) == len(seen)
    global_fixed = max(0, total - pilot_window_total) if one_block_pilot else None
    projected_total = blocks * sum(w['estimated_formal_window_seconds'] for w in windows)
    if global_fixed is not None: projected_total += global_fixed
    return {'observed_collection_seconds': total, 'method': 'first complete block per-side measured cycle mean plus retained diagnostic and collection costs; artifact mtime estimate, not measured formal duration',
            'target_measured_per_lane': count, 'target_warmup_per_lane': warmup, 'target_blocks': blocks,
            'pilot_initial_upload_health_final_cleanup_seconds': global_fixed,
            'estimated_total_seconds': projected_total, 'windows': windows}


def evidence(directions, separated, stage):
    if len(directions) == 1: return '单轮 pilot，仅方向线索' if stage == 'pilot' else '单轮，仅方向线索'
    if set(directions) == {'='}: return '全部实测同值，不证明等价'
    if len(set(directions)) == 1: return '各轮同向且范围分离' if separated else '各轮同向，范围重叠'
    return '方向混合，保留全部数值'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('output', type=Path, help='Markdown path; matching JSON is also written')
    parser.add_argument('--stage', choices=('pilot', 'formal'), default='pilot')
    parser.add_argument('--label', default='reload-config 四侧 AX3000T')
    parser.add_argument('--budget-seconds', type=float, help='previously frozen collection budget')
    parser.add_argument('--estimate-count', type=int, default=100)
    parser.add_argument('--estimate-warmup', type=int, default=5)
    parser.add_argument('--estimate-blocks', type=int, default=4)
    args = parser.parse_args()
    root = args.collection.resolve(); settings = json.loads((root / 'settings.json').read_text())
    data = derive(root, args.label)
    assert data['component'] == 'reload-config' and data['acceptance_eligible'] and data['host_gates_passed']
    sides = list(data['measured_sides']); assert sides == ['stock', 'r89', 'r94', 'candidate']
    blocks = len(data['order']) // len(sides)
    n = settings['iterations'] // 20; warmup = settings['reload_warmup']
    audited = audit(root, data)
    estimated = budget(root, data, args.estimate_count, args.estimate_warmup, args.estimate_blocks)
    if args.budget_seconds is not None:
        estimated['frozen_budget_seconds'] = args.budget_seconds
        estimated['within_budget'] = estimated['observed_collection_seconds'] <= args.budget_seconds
    budget_note = (f'事先冻结预算为{args.budget_seconds:g} s。' if args.budget_seconds is not None else '')
    lines = [f'# {args.label}：{args.stage}', '',
        f'每侧 {blocks} 轮完整随机块，每负载每轮 {n} 次计量、{warmup} 次预热，{settings["reload_packages"]} 个配置包。' +
        ('这是 SDK pilot，用于正确性门、机制方向和预算；不作为最终正式成绩。' if args.stage == 'pilot' else '产物的 canonical 源码/构建身份须结合主报告的正式构建记录核验。'), '',
        '数值为逐轮统计的中位数 [最小, 最大]。Δ 为候选减基线及百分比；方向按完整随机块逐轮配对，箭头表示数值变化。证据强度是描述性证据，不是显著性检验。p99 为每轮有限样本尾部次序统计。', '',
        '命令树 CPU 来自每次 exec 前后的 getrusage(RUSAGE_CHILDREN)，包含被回收的 shell/UCI/md5sum/ubus 等后代。caller、C ubusd、事件 receiver、private logd 的 CPU 分开列出。准备、完整校验、重复调用和诊断阶段在正常计时外。吞吐 = 成功次数 / 正常 exec 时长总和，包含接收端 STATUS 完成与基线提交。', '',
        '依赖 CPU 仅覆盖立即包围 exec 的窗口；异步尾部 syslog 工作可能在稍后完成。JSON 另保留包括预热、重复、诊断的完整依赖 envelope CPU，不将其当作每操作成本。1 µs 计数编码和1 ns时钟分辨率均不代表实际测量精度。', '']
    rows = []
    for lane in data['summary']:
        lines += ['## ' + lane, '', '| 指标 | C | R89 | R94 | 候选 | Δ C；逐轮方向 | Δ R89；逐轮方向 | Δ R94；逐轮方向 | 证据 |',
                  '|---|---:|---:|---:|---:|---:|---:|---:|---|']
        for group, names in (('performance', PERFORMANCE), ('resource', RESOURCES), ('tasks', TASKS)):
            for metric, label in names.items():
                values = {}
                for side in sides:
                    runs = [r for r in data['runs'] if r['workload'] == lane and r['side'] == side]
                    if group == 'performance': values[side] = [r[metric] for r in runs]
                    else:
                        field = 'resources' if group == 'resource' else 'task_diagnostics'
                        samples_per_window = 3 if group == 'resource' else 1
                        assert all(len(r[field]) == samples_per_window for r in runs)
                        values[side] = [st.median(sample[metric] for sample in r[field]) for r in runs]
                medians = {side: st.median(values[side]) for side in sides}
                cells = [label] + [f'{medians[s]:.3f} [{min(values[s]):.3f}, {max(values[s]):.3f}]' for s in sides]
                comparisons = {}; strengths = []
                for side in sides[:-1]:
                    absolute = medians['candidate'] - medians[side]
                    percent = absolute / medians[side] * 100 if medians[side] else None
                    pairs = [a - b for a, b in zip(values['candidate'], values[side])]
                    directions = ['↓' if delta < 0 else '↑' if delta > 0 else '=' for delta in pairs]
                    separated = max(values['candidate']) < min(values[side]) or min(values['candidate']) > max(values[side])
                    strength = evidence(directions, separated, args.stage)
                    comparisons[side] = {'absolute': absolute, 'percent': percent, 'paired_absolute_by_block': pairs,
                                         'directions': directions, 'range_separated': separated, 'evidence': strength}
                    percentage = f'{percent:+.2f}%' if percent is not None else '基线为0'
                    cells.append(f'{absolute:+.3f} ({percentage}) ' + ''.join(directions))
                    strengths.append(side + ':' + strength)
                cells.append('；'.join(strengths)); lines.append('| ' + ' | '.join(cells) + ' |')
                rows.append({'lane': lane, 'group': group, 'metric': metric, 'rounds': values,
                             'medians': medians, 'differences': comparisons})
        lines += ['']
    lines += ['## 校验与资源边界', '',
        f'校验了 {audited["checksummed_files"]} 个原始文件 SHA256；{audited["prepared_cycles"]} 次独立准备/执行/全量核验，加同次数静默重复，共 {audited["reload_executions_including_repeat"]} 次成功调用；接收 {audited["accepted_events"]} 条按原始包名字节、顺序、次数和结果核验的事件。错误/超时均为0。各窗口生产配置、运行身份和挂载保持一致，前后健康门一致。', '',
        'wait4 每窗口每负载取3次完整生命周期样本的中位数，再跨轮汇总；资源 CPU 为独立诊断，不能替代正常命令 CPU。maxrss 是命令或已回收后代的峰值，不是并发进程树 RSS 总和；包含小型 launcher fork→exec 区间。ptrace每窗口每负载1次，total task births包括进程主线程，additional thread births单列；peak live tasks是在ptrace调度扰动下观察到的并发任务数，不代表未插桩运行的并发峰值。所有 live_remaining必须为0。ptrace时延、CPU和内存均不用于正常性能。', '',
        '所有配置与基线位于私有 tmpfs，保留同步与原子 rename；不外推 flash 持久化。事件接收代表 service.event 接受，不代表下游服务完成重载。R94 是已知存在后续修复缺口的历史 SDK 原 ELF，仅作为通过输出和事件门的性能参考。', '',
        '## 完整耗时预算', '',
        (f'正式采集已完成，用时 {estimated["observed_collection_seconds"]:.2f} s。{budget_note}下表保留首个完整区组的每侧实测窗口，以及按相同循环数回算的估计；不是新批次计划。' if args.stage == 'formal' else f'本批pilot采集用时 {estimated["observed_collection_seconds"]:.2f} s；按完整循环与采集/回收开销估计正式四块需 {estimated["estimated_total_seconds"] / 60:.2f} min，正式耗时以新批次为准。'), '',
        '| 侧 | 本批窗口 s | 固定准备/采集/回收 s | 按相同负载回算窗口 s |', '|---|---:|---:|---:|']
    for w in estimated['windows']:
        lines.append(f'| {w["side"]} | {w["pilot_window_seconds"]:.3f} | {w["fixed_setup_collection_cleanup_seconds"]:.3f} | {w["estimated_formal_window_seconds"]:.3f} |')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text('\n'.join(lines) + '\n')
    result = {'schema': 1, 'stage': args.stage, 'label': args.label, 'subjects': data['subjects'],
              'order': data['order'], 'rows': rows, 'audit': audited, 'budget': estimated,
              'benchmark_sha256': data['benchmark_sha256'], 'namespace_sha256': data['namespace_sha256'],
              'harness_sha256': data['harness_sha256'], 'dependency_envelopes': [
                  {'run': r['run'], 'side': r['side'], 'workload': r['workload'],
                   'envelope_s': r['envelope_s'], 'cpu_us': r['dependency_envelope_cpu_us']} for r in data['runs']],
              'errors': sum(r['errors'] for r in data['runs']), 'timeouts': sum(r['timeouts'] for r in data['runs']),
              'host_gates_passed': True, 'acceptance_eligible': True}
    args.output.with_suffix('.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'rendered_rows': len(rows), 'checksummed_files': audited['checksummed_files'],
                      'prepared_cycles': audited['prepared_cycles'], 'estimated_minutes': estimated['estimated_total_seconds'] / 60}))


if __name__ == '__main__': main()
