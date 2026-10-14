#!/usr/bin/env python3
"""Derive redacted Oracle-only summaries from the frozen supplement's raw files."""
import argparse
from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import struct


def quantiles(values):
    values = sorted(values)
    def q(fraction): return values[max(0, math.ceil(len(values)*fraction)-1)] if values else None
    return {'n':len(values),'min':q(0),'p50':q(.5),'p95':q(.95),
            'p99':q(.99) if len(values)>=10000 else None,'max':q(1)}


def spread(values):
    return {'n':len(values),'median':statistics.median(values), 'min':min(values), 'max':max(values)}


def traffic(folder):
    load=json.loads((folder/'client.json').read_text())
    identity=json.loads((folder/'daemon-identity.json').read_text())
    mapped=identity['mapped_files']
    side=folder.name.rsplit('-',1)[1]
    required=('097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87' if side=='c' else
              '50e591a9d9dc1e6578888b14690b5b38415a9db886a492a2960a0c75b3eeb57c')
    assert required in mapped.values(), 'actual mapped daemon identity'
    if side=='c':
        expected={'8afe4bccb74f595fd45e3c499c1e7e2520ac03c0881f439a8ccb994bf8d3ee5b',
                  '33a47a54f9d8d901055aa0812dfcb4b1b4630061c9c0052f9b8e267c7279c16c',
                  'a808d6aeff85a7ba31c8a87dda9496692b0b1b349a6012404f4a76d1fbbe4063',
                  '2967f7ce6e29e290eac0b76e88fc6b5d639763fa78be1e1b889fb088d9acda04'}
        assert expected <= set(mapped.values()), 'exact image library identities'
    lat=list(struct.iter_unpack('<QQQHHBBBB',(folder/'client.latencies.bin').read_bytes()))
    lag_rows=list(struct.iter_unpack('<QQ',(folder/'client.send-lag.bin').read_bytes()))
    lag=dict(lag_rows)
    assert len(lag)==len(lag_rows)==len(lat)==len({r[0] for r in lat})
    assert set(lag)=={r[0] for r in lat}
    assert all(r[6]==1 and r[8]==0 and r[5] in (0,1,2,3) for r in lat)
    count=load['measurement']
    assert len(lat)==count['sent']==sum(count[k] for k in ('correct','timeout','wrong','transport_error'))
    for status,key in enumerate(('correct','timeout','wrong','transport_error')):
        assert sum(r[5]==status for r in lat)==count[key]
    good=[r for r in lat if r[5]==0]
    assert len(good)==load['measurement']['correct']
    resources=[json.loads(x) for x in (folder/'resources.stdout').read_text().splitlines()]
    epochs=json.loads((folder/'epoch.json').read_text())
    measured=[r for r in resources if epochs['measurement_start_ns']<=r['monotonic_ns']<=epochs['measurement_end_ns']]
    assert measured
    base=json.loads((folder/'result.json').read_text())
    for phase in ('warmup','measurement'):
        if any(load[phase][key] for key in ('timeout','wrong','transport_error','scheduled_skipped')):
            base['valid']=False; base['errors'].append(phase+' failure counters')
    before=json.loads((folder/'before.json').read_text());after=json.loads((folder/'after.json').read_text())
    assert before['starttime_ticks']==after['starttime_ticks'] and before['pid']==after['pid']
    assert all(b>=a for a,b in zip(before['ticks'],after['ticks']))
    warm=load['warmup']; expected=round(load['rate']*load['warmup_seconds'])
    if any(warm[key]!=expected for key in ('scheduled','sent','correct')):
        base['valid']=False; base['errors'].append('warmup completion counts')
    if load.get('renew_setup_failed'):
        base['valid']=False; base['errors'].append('DHCP setup failed')
    if load['mode']=='dhcp' and (warm['dora_correct']!=150 or warm['renew_correct']!=350):
        base['valid']=False; base['errors'].append('DHCP warmup DORA/renew split')
    upstream=json.loads((folder/'upstream.json').read_text()); totals=upstream['total']
    if totals['requests']!=totals['replies'] or any(totals[k] for k in ('disabled_requests','dropped_requests','invalid_queries')) or upstream['delay_queue_dropped']:
        base['valid']=False; base['errors'].append('upstream completeness')
    root_pid=before['pid']
    parents=[next(p for p in r['processes'] if p['pid']==root_pid) for r in measured]
    cpu_us=base['window_cpu_ticks']/base['clock_ticks_per_second']*1e6/base['window_completions']
    value={'valid':base['valid'],'errors':base['errors'],'measurement_counts':load['measurement'],
       'warmup_counts':load['warmup'],'throughput_qps':load['measurement']['correct_in_window']/load['measurement_seconds'],
       'response_latency_us':quantiles([r[1]/1000 for r in good]),
       'scheduled_latency_us':quantiles([(r[1]+lag[r[0]])/1000 for r in good]),
       'send_lag_us':quantiles([lag[r[0]]/1000 for r in good]),
       'window_cpu_ticks':base['window_cpu_ticks'],'cpu_us_per_completion':cpu_us,
       'cpu_rank_resolution_ok':base['window_cpu_ticks']>=10,
       'window_cpu_denominator':base['window_completions'],
       'measurement_samples':len(measured),'parent_rss_kib':quantiles([p['rss_kib'] for p in parents]),
       'parent_anon_kib':quantiles([p['rss_anon_kib'] for p in parents]),
       'parent_shmem_kib':quantiles([p['rss_shmem_kib'] for p in parents]),
       'parent_fd_peak':max(p['fd_count'] for p in parents),
       'tree_fd_peak':max(sum(p['fd_count'] for p in r['processes']) for r in measured),
       'tree_rss_peak_kib':max(r['tree_rss_kib'] for r in measured),
       'tree_pss_peak_kib':max((r['tree_pss_kib'] for r in measured if r['tree_pss_kib'] is not None),default=None),
       'tree_private_peak_kib':(max(sum(p['private_clean_kib']+p['private_dirty_kib'] for p in r['processes']) for r in measured)
           if all(p['pss_kib'] is not None for r in measured for p in r['processes']) else None),
       'tree_process_peak':max(len(r['processes']) for r in measured),
       'threads_peak':max(sum(p['thread_count'] for p in r['processes']) for r in measured),
       'upstream_steady_requests':base['upstream_steady_requests'],
       'upstream':upstream,
       'helpers':{name:json.loads((folder/(name+'.usage.json')).read_text()) for name in ('client','upstream','resources')},
       'full_daemon_usage':json.loads((folder/'daemon.usage.json').read_text()),
       'tcp_connections':load['tcp_connections'],'tcp_reconnections':load['tcp_reconnections']}
    if (folder/'client.dhcp-dora.jsonl').exists():
        dora=[json.loads(x) for x in (folder/'client.dhcp-dora.jsonl').read_text().splitlines()]
        value['initial_dora_latency_us']=quantiles([x['latency_ns']/1000 for x in dora])
        value['lease_count']=base['leases']
    return value


def lifecycle(folder):
    rows=[json.loads(x) for x in (folder/'lifecycle.stdout').read_text().splitlines()]
    err=(folder/'lifecycle.stderr').read_text()
    match=re.search(r'children_cpu_usec=(\d+)',err)
    collector=json.loads((folder/'result.json').read_text())
    usage=json.loads((folder/'lifecycle.usage.json').read_text())
    return {'valid':len(rows)==10 and collector['valid'] and usage['exit']==0 and all(x['ok'] for x in rows),'samples':len(rows),'hosts':rows[0]['hosts'],
            'initial_leases':rows[0]['initial_leases'],'latency_us':quantiles([x['latency_ns']/1000 for x in rows]),
            'cpu_ticks':sum(x['cpu_ticks'] for x in rows),'cpu_scope':rows[0]['cpu_scope'],
            'children_whole_run_cpu_us':int(match.group(1)) if match else None,
            'rss_kib':quantiles([x['rss_kib'] for x in rows]),
            'anon_kib':quantiles([x['anon_kib'] for x in rows]),'fd_peak':max(x['fds'] for x in rows),
            'whole_helper_and_children':json.loads((folder/'lifecycle.usage.json').read_text())}


def main():
    p=argparse.ArgumentParser();p.add_argument('raw',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    complete=json.loads((a.raw/'complete.json').read_text());assert complete['complete']
    groups=defaultdict(lambda:defaultdict(list));windows={}
    for folder in sorted((a.raw/'runs').iterdir()):
        scenario,round_,side=folder.name.rsplit('-',2)
        v=traffic(folder) if (folder/'client.json').exists() else lifecycle(folder)
        v['round']=int(round_[1:]);windows[folder.name]=v;groups[scenario][side].append(v)
    summaries={}
    for scenario,sides in sorted(groups.items()):
        assert set(sides)=={'c','rust'} and all(len(rows)==5 for rows in sides.values())
        selected=(['throughput_qps','window_cpu_ticks','cpu_us_per_completion','parent_fd_peak','tree_fd_peak','tree_rss_peak_kib',
                   'tree_pss_peak_kib','tree_private_peak_kib'] if 'throughput_qps' in sides['c'][0]
                  else ['children_whole_run_cpu_us','fd_peak'])
        summary={}
        for side,rows in sides.items():
            fields={key:spread([v[key] for v in rows]) for key in selected if all(v[key] is not None for v in rows)}
            for latency in ('response_latency_us','scheduled_latency_us','send_lag_us','initial_dora_latency_us','latency_us'):
                if latency in rows[0]:
                    for q in ('p50','p95'):fields[latency+'_'+q]=spread([v[latency][q] for v in rows])
            for mem in ('parent_rss_kib','parent_anon_kib','parent_shmem_kib','rss_kib','anon_kib'):
                if mem in rows[0]:fields[mem+'_median']=spread([v[mem]['p50'] for v in rows])
            fields['valid_windows']=sum(v['valid'] for v in rows)
            if 'cpu_rank_resolution_ok' in rows[0]:fields['cpu_all_windows_at_least_10_ticks']=all(v['cpu_rank_resolution_ok'] for v in rows)
            summary[side]=fields
        comparisons={}
        for key in summary['c']:
            c=summary['c'][key];r=summary['rust'][key]
            if not isinstance(c,dict) or not c['median']:continue
            delta=100*(r['median']/c['median']-1)
            noise=max((c['max']-c['min'])/c['median'],(r['max']-r['min'])/r['median'] if r['median'] else 0)*100
            def metric(row):
                if key in row:return row[key]
                for suffix in ('_p50','_p95','_median'):
                    if key.endswith(suffix):return row[key[:-len(suffix)]][suffix[1:] if suffix!='_median' else 'p50']
                raise KeyError(key)
            paired_c={v['round']:v for v in sides['c']};paired_r={v['round']:v for v in sides['rust']}
            assert set(paired_c)==set(paired_r)==set(range(1,6))
            differences=[metric(paired_r[i])-metric(paired_c[i]) for i in range(1,6)]
            same_direction=sum(d>0 for d in differences) if delta>0 else sum(d<0 for d in differences) if delta<0 else 0
            all_valid=all(v['valid'] for rows in sides.values() for v in rows)
            comparisons[key]={'rust_vs_c_percent':delta,'max_relative_range_percent':noise,
                              'absolute_percent_difference_exceeds_range':abs(delta)>noise,
                              'paired_differences':differences,'pairs_in_median_direction':same_direction,
                              'all_ten_windows_valid':all_valid,
                              'direction_supported':all_valid and same_direction>=4 and abs(delta)>noise}
        if 'window_cpu_ticks' in summary['c']:
            tick_gap=abs(summary['rust']['window_cpu_ticks']['median']-summary['c']['window_cpu_ticks']['median'])
            summary['cpu_ranking_resolution_ok']=(tick_gap>8 and
                summary['c']['cpu_all_windows_at_least_10_ticks'] and
                summary['rust']['cpu_all_windows_at_least_10_ticks'])
            summary['cpu_median_tick_gap']=tick_gap
            for key in ('window_cpu_ticks','cpu_us_per_completion'):
                comparisons[key]['resolution_ok']=summary['cpu_ranking_resolution_ok']
                comparisons[key]['direction_supported'] &= summary['cpu_ranking_resolution_ok']
        summary['comparisons']=comparisons;summaries[scenario]=summary
    result={'environment':'Oracle supplementary only; not AX3000T performance',
      'identity_sha256':hashlib.sha256((a.raw/'identity.json').read_bytes()).hexdigest(),
      'protocol_sha256':hashlib.sha256((a.raw/'protocol.md').read_bytes()).hexdigest(),
      'complete':complete,'summaries':summaries,'windows':windows,
      'notes':['No p99: each round has fewer than 10000 correct replies.',
               'CPU rankings require at least 10 service ticks in every window, more than 8 median ticks between versions, and difference greater than range.',
               'Helper and full daemon wait4 figures are separate from warmup+measurement service tick CPU.',
               'Tree RSS includes shared mappings and is not private memory.',
               'Lifecycle whole-run children CPU includes shutdown and idle; signal-to-ready tick counters remain in raw.']}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'windows':len(windows),'all_valid':all(x['valid'] for x in windows.values())}))


if __name__=='__main__':main()
