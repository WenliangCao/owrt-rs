#!/usr/bin/env python3
"""Offline derivation of unchanged v3 statistics; never mixes failed attempts."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import struct


def quantiles(values):
    ordered = sorted(values)
    def q(p):
        return ordered[max(0, math.ceil(len(ordered)*p)-1)] if ordered else None
    return {'n':len(ordered), 'min':q(0), 'p50':q(.5), 'p95':q(.95),
            'p99':q(.99) if len(ordered)>=10000 else None, 'max':q(1)}


def spread(values):
    return {'median':statistics.median(values), 'min':min(values), 'max':max(values), 'rounds':values}


def json_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def cpu_ticks(process):
    return sum(process[k] for k in ('user_ticks','system_ticks','waited_child_user_ticks','waited_child_system_ticks'))


def traffic(folder, row, warmup_seconds=5, measurement_seconds=20):
    load = json.loads((folder/'client.json').read_text())
    for phase, seconds in (('warmup',warmup_seconds), ('measurement',measurement_seconds)):
        counts=load[phase]
        expected=load['rate']*seconds
        if row['valid']:
            assert all(counts[k]==expected for k in ('scheduled','sent','correct'))
            assert not any(counts[k] for k in ('timeout','wrong','transport_error','scheduled_skipped'))
    if (folder/'prewarm.json').exists():
        prewarm=json.loads((folder/'prewarm.json').read_text())
        counts=prewarm['measurement']
        assert all(counts[k]==1000 for k in ('scheduled','sent','correct'))
        assert all(counts[k]==0 for k in ('timeout','wrong','transport_error','scheduled_skipped'))
        assert not prewarm['interrupted'] and not prewarm['output_failed']
    lat = list(struct.iter_unpack('<QQQHHBBBB', (folder/'client.latencies.bin').read_bytes()))
    lag_rows = list(struct.iter_unpack('<QQ', (folder/'client.send-lag.bin').read_bytes()))
    lag = dict(lag_rows)
    assert len(lat)==len(lag_rows)==len(lag)==load['measurement']['sent']
    assert {v[0] for v in lat}==set(lag)
    assert all(v[6]==1 and v[8]==0 for v in lat)
    for status, key in enumerate(('correct','timeout','wrong','transport_error')):
        assert sum(v[5]==status for v in lat)==load['measurement'][key]
    good = [v for v in lat if v[5]==0]
    before, after = [json_lines(folder/name)[0] for name in ('before.jsonl','after.jsonl')]
    assert len(before['processes'])==len(after['processes'])==1, 'unreaped child endpoint'
    b, a = before['processes'][0], after['processes'][0]
    assert (b['pid'],b['starttime_ticks'])==(a['pid'],a['starttime_ticks'])
    keys = ('user_ticks','system_ticks','waited_child_user_ticks','waited_child_system_ticks')
    assert all(a[k]>=b[k] for k in keys)
    ticks = cpu_ticks(a)-cpu_ticks(b)
    hz = before['clock_ticks_per_second']
    assert hz==after['clock_ticks_per_second']==100
    completed = load['warmup']['correct']+load['measurement']['correct']
    epochs = json.loads((folder/'epoch.json').read_text())
    resources = json_lines(folder/'resources.jsonl')
    samples = [v for v in resources if epochs['measurement_start_ns']<=v['monotonic_ns']<=epochs['measurement_end_ns']]
    assert samples and not any(v['tree_truncated'] for v in samples)
    parents = [next(p for p in v['processes'] if p['pid']==b['pid'] and p['starttime_ticks']==b['starttime_ticks']) for v in samples]
    up = json.loads((folder/'upstream.json').read_text())
    result = {
        'latency_ms':quantiles([v[1]/1e6 for v in good]),
        'scheduled_latency_ms':quantiles([(v[1]+lag[v[0]])/1e6 for v in good]),
        'send_lag_ms':quantiles([lag[v[0]]/1e6 for v in good]),
        'cpu_ticks':ticks, 'cpu_hz':hz, 'cpu_operations':completed,
        'cpu_us_per_operation':ticks/hz*1e6/completed,
        'cpu_endpoint_seconds':(after['monotonic_ns']-before['monotonic_ns'])/1e9,
        'counts':{p:load[p] for p in ('warmup','measurement')},
        'upstream':up, 'resource_samples':len(samples),
        'rss_median_kib':statistics.median(p['rss_kib'] for p in parents),
        'rss_peak_kib':max(p['rss_kib'] for p in parents),
        'anon_peak_kib':max(p['rss_anon_kib'] for p in parents),
        'file_peak_kib':max(p['rss_file_kib'] for p in parents),
        'shmem_peak_kib':max(p['rss_shmem_kib'] for p in parents),
        'tree_rss_peak_kib':max(v['tree_rss_kib'] for v in samples),
        'tree_fd_peak':max(sum(p['fd_count'] for p in v['processes']) for v in samples),
        'parent_fd_peak':max(p['fd_count'] for p in parents),
        'thread_peak':max(sum(p['thread_count'] for p in v['processes']) for v in samples),
        'process_peak':max(len(v['processes']) for v in samples),
        'pss_uss':'unavailable on device; RSS and RssAnon are not private memory',
        'tool_cpu_endpoints': {'first':resources[0].get('helper_self_cpu'), 'last':resources[-1].get('helper_self_cpu')},
        'observer_cpu_endpoints': {'first':resources[0].get('observer_self_cpu'), 'last':resources[-1].get('observer_self_cpu')},
    }
    if (folder/'client.dhcp-dora.jsonl').exists():
        dora = json_lines(folder/'client.dhcp-dora.jsonl')
        result['dora'] = dora
        result['dora_latency_ms'] = quantiles([(v['ack_ns']-v['sent_ns'])/1e6 for v in dora])
        assert len(dora)==load['clients']==load['warmup']['dora_correct']
    return result


def lifecycle(folder, row):
    values = json_lines(folder/'lifecycle.jsonl')
    assert len(values)==20 and all(v['ok'] for v in values)
    cpu, hz = map(int,re.search(r'children_cpu_usec=(\d+) clk_tck=(\d+)',(folder/'lifecycle.stderr').read_text()).groups())
    return {
        'latency_ms':quantiles([v['latency_ns']/1e6 for v in values]),
        'cpu_ticks':cpu/1e6*hz, 'cpu_hz':hz, 'cpu_operations':20,
        'cpu_us_per_operation':cpu/20,
        'cpu_scope':'whole-round RUSAGE_CHILDREN including startup, idle and shutdown',
        'rss_median_kib':statistics.median(v['rss_kib'] for v in values),
        'rss_peak_kib':max(v['rss_kib'] for v in values),
        'anon_peak_kib':max(v['anon_kib'] for v in values),
        'file_peak_kib':max(v['file_kib'] for v in values),
        'shmem_peak_kib':max(v['shmem_kib'] for v in values),
        'tree_fd_peak':max(v['fds'] for v in values),
        'parent_fd_peak':max(v['fds'] for v in values),
        'resource_scope':'readiness snapshots, not transient peak',
        'observer_resolution_ms':1,
    }


def compare(left, right, cpu=None, resolution=0):
    a,b = spread(left),spread(right)
    delta=(b['median']-a['median'])/a['median'] if a['median'] else 0
    w=max((a['max']-a['min'])/a['median'] if a['median'] else 0,
          (b['max']-b['min'])/b['median'] if b['median'] else 0)
    direction = sum((y-x)*delta>0 for x,y in zip(left,right))
    precision = (cpu is None or (min(cpu[0]+cpu[1])>=10 and abs(statistics.median(cpu[1])-statistics.median(cpu[0]))>8))
    discernible = abs(delta)>w and direction>=4 and precision and abs(b['median']-a['median'])>=resolution
    return {'left':a,'right':b,'relative_change_pct':delta*100,'W_pct':w*100,
            'same_direction_pairs':direction,'precision_ok':precision,
            'discernible':discernible,'direction':('faster' if delta<0 else 'slower') if discernible else 'within_variation_or_resolution'}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('root',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args();root=args.root
    assert not (root/'DISQUALIFIED.md').exists(), 'entire harness attempt is excluded'
    progress=json.loads((root/'progress.json').read_text())
    identity=json.loads((root/'identity.json').read_text())
    windows=[]; failures=[]
    for row in progress:
        folder=root/'runs'/row['label']
        try:
            manifest=json.loads((root/(row['label']+'.archive.json')).read_text())
            for name,digest in manifest['files'].items():
                assert hashlib.sha256((folder/name).read_bytes()).hexdigest()==digest
            expected=identity['comparison'][row['side']]
            assert (folder/'elf.sha256').read_text().split()[0]==expected
            if not (folder/'lifecycle.jsonl').exists():
                assert (folder/'live.sha256').read_text().split()[0]==expected
            result=lifecycle(folder,row) if (folder/'lifecycle.jsonl').exists() else traffic(folder,row)
            windows.append({**row,**result,'elf_sha256':expected,'raw_verified_files':len(manifest['files'])})
        except Exception as error:
            failures.append({'label':row['label'],'error':repr(error)})
    comparisons={}
    for scene in sorted({r['scene'] for r in windows}):
        sides={s:sorted([r for r in windows if r['scene']==scene and r['side']==s],key=lambda r:r['round']) for s in ('c','rust')}
        if any(len(v)!=5 or any(not r['valid'] for r in v) or [r['round'] for r in v]!=list(range(1,6)) for v in sides.values()):
            continue
        a,b=sides['c'],sides['rust'];life=any(x in scene for x in ('small','large'))
        result={}
        for key in ('p50','p95'):
            result[key+'_ms']=compare([r['latency_ms'][key] for r in a],[r['latency_ms'][key] for r in b],resolution=1 if life else 0)
        result['cpu_us']=compare([r['cpu_us_per_operation'] for r in a],[r['cpu_us_per_operation'] for r in b],cpu=([r['cpu_ticks'] for r in a],[r['cpu_ticks'] for r in b]))
        if scene in ('dhcp', 'dhcp-home6'):
            result['dora_all_min_max_ms']={
                'left':[min(r['dora_latency_ms']['min'] for r in a),max(r['dora_latency_ms']['max'] for r in a)],
                'right':[min(r['dora_latency_ms']['min'] for r in b),max(r['dora_latency_ms']['max'] for r in b)]}
            for key in ('p50','p95'):
                left,right=[r['dora_latency_ms'][key] for r in a],[r['dora_latency_ms'][key] for r in b]
                result['dora_'+key+'_ms']=(compare(left,right) if scene=='dhcp' else
                    {'left':spread(left),'right':spread(right),'ranked':False,'reason':'only 6 DORA samples per round; descriptive only'})
        for key in ('rss_median_kib','rss_peak_kib','anon_peak_kib','file_peak_kib','shmem_peak_kib','tree_fd_peak','parent_fd_peak'):
            result[key]={'left':spread([r[key] for r in a]),'right':spread([r[key] for r in b])}
        comparisons[scene]=result
    summary={'schema':1,'scope':'device-safe v3; attempted windows retained; no historical pooling',
             'complete':len(comparisons)==11 and len(windows)==110 and not failures,
             'identity':identity,'window_count':len(windows),'valid_windows':sum(r['valid'] for r in windows),
             'parse_failures':failures,'comparisons':comparisons,'windows':windows,
             'analyzer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    args.output.write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:summary[k] for k in ('complete','window_count','valid_windows','parse_failures')}))


if __name__=='__main__':
    main()
