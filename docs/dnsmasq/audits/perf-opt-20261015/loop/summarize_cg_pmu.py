"""Summarize all fixed PMU windows, retaining raw counts and actual N."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import statistics

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('plan', type=Path)
parser.add_argument('output', type=Path)
args = parser.parse_args()
plan = json.loads(args.plan.read_text())
sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
read = lambda path: json.loads(Path(path).read_text())
rows = []
for window in plan['windows']:
    path = Path(window['output'])
    complete, client = read(path/'complete.json'), read(path/'client.json')
    assert complete['valid_count_profile'] and complete['tree_tail_complete']
    assert not client['interrupted'] and not client['output_failed']
    for phase, seconds in [('warmup',5),('measurement',20)]:
        part = client[phase]
        assert part['scheduled'] == part['sent'] == part['correct'] > 0
        assert not any(part[k] for k in ('timeout','wrong','transport_error','scheduled_skipped'))
        assert window['rate'] == 0 or part['correct'] == seconds*window['rate']
    operations = client['warmup']['correct'] + client['measurement']['correct']
    assert operations == complete['completed_operations']
    controls = read(path/'perf-controls.json')
    enable, disable = controls['controls']
    assert enable['command'] == 'enable' and disable['command'] == 'disable'
    assert enable['sent_ns'] <= enable['acknowledged_ns'] <= controls['load_start_ns']
    assert controls['load_end_ns'] <= disable['sent_ns'] <= disable['acknowledged_ns']
    tree = read(path/'tree-tail.json')
    assert tree['complete'] and not tree['remaining_children']
    assert controls['load_end_ns'] <= tree['drain_started_ns']
    assert tree['drain_ended_ns'] - tree['drain_started_ns'] >= 1000000000
    assert tree['drain_ended_ns'] <= disable['sent_ns']
    text, verbose = (path/'perf-stat.csv').read_text(), (path/'perf-stat.stderr').read_text()
    expected = plan['groups'][window['group']]['events']
    attrs = verbose.split('perf_event_attr:')[1:]
    opened = re.findall(r'sys_perf_event_open: pid (\d+)\s+cpu -1\s+group_fd (-?\d+)\s+flags \S+ = (\d+)', verbose)
    pid = read(path/'process-identity.json')['pid']
    assert len(attrs) == len(opened) == len(expected)
    assert opened[0][1] == '-1' and all(x[1] == opened[0][2] for x in opened[1:])
    assert all(int(x[0]) == pid for x in opened)
    assert all(re.search(r'^\s*inherit\s+1\s*$', a, re.M) for a in attrs)
    assert all(re.search(r'^\s*exclude_kernel\s+1\s*$', a, re.M) for a in attrs)
    events = {}
    for fields in csv.reader(text.splitlines()):
        if len(fields) < 5 or fields[2] not in expected:
            continue
        event = fields[2]
        assert event not in events and re.fullmatch(r'\d+(?:\.\d+)?', fields[0]), fields
        raw = re.findall(r'^'+re.escape(event)+r': (\d+) (\d+) (\d+)\s*$', text, re.M)
        assert len(raw) == 1, event
        count, enabled, running = map(int,raw[0])
        assert 0 < running == enabled, 'retain invalid multiplexed window; no replacement'
        assert abs(float(fields[4])-100*running/enabled) <= .011
        assert float(fields[0]) == count, ('expected --no-scale', fields, count)
        events[event] = {'raw_count':count,'raw_per_query':count/operations,
            'time_enabled_ns':enabled,'time_running_ns':running,
            'running_fraction':running/enabled,'multiplexed':running!=enabled,
            'reported_count':fields[0],'csv_runtime_ns':fields[3],'csv_running_percent':fields[4]}
    assert set(events) == set(expected), (window['id'], events.keys(), expected)
    assert len({(e['time_enabled_ns'], e['time_running_ns']) for e in events.values()}) == 1, 'one group must share scheduling interval'
    rows.append({k:window[k] for k in ('id','side','rate','pair','group')} | {
        'actual_N':operations,'warmup_N':client['warmup']['correct'],
        'measurement_N':client['measurement']['correct'],'events':events,
        'IPC':events['instructions:u']['raw_count']/events['cycles:u']['raw_count'],
        'controls':controls,'sender_cpu':read(path/'client-cpu.json'),
        'measurement':client['measurement']})
def stats(values):
    return {'median':statistics.median(values),'minimum':min(values),'maximum':max(values),'all':values}

summary = []
for group in plan['groups']:
    for side in dict.fromkeys(w['side'] for w in plan['windows']):
        for rate in dict.fromkeys(w['rate'] for w in plan['windows']):
            matching = [r for r in rows if r['group']==group and r['side']==side and r['rate']==rate]
            assert len(matching) == 3
            summary.append({'group':group,'side':side,'rate':rate,
                'actual_N':stats([r['actual_N'] for r in matching]),
                'IPC':stats([r['IPC'] for r in matching]),
                'events':{event:stats([r['events'][event]['raw_per_query'] for r in matching])
                          for event in plan['groups'][group]['events']}})
result = {'scope':'Oracle UDP-hit association diagnostic; no physical A53 or causal inference',
    'plan_sha256':sha(args.plan),'events':plan['event_semantics'],
    'windows':rows,'summary':summary,
    'uncertainty':'Three windows per cell; report all observations and full range, not a confidence interval. All admitted event groups must have time_running == time_enabled; multiplexed/uncounted rows are invalid and retained without replacement. Misses/refills are events, not working-set bytes. Low IPC does not by itself prove cache stalls.',
    'raw_files':{str(p.relative_to(Path(plan['raw_root']))):sha(p)
                 for p in sorted(Path(plan['raw_root']).rglob('*')) if p.is_file()}}
with args.output.open('x') as output:
    output.write(json.dumps(result,indent=2)+'\n')
print(json.dumps({'output':str(args.output),'sha256':sha(args.output),'windows':len(rows)}))
