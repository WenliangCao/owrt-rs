#!/usr/bin/env python3
"""Independently reconcile R131 memory CSV with raw proc snapshots and archives."""
import argparse
import csv
import json
from pathlib import Path
import re
import r124_event_memory_report as raw
import r131_memory_supplement as collection


def audit_event(window, spec, plan):
    folder=window/'raw'; sizes=[1024,8192,32768] if spec['kind']=='fanout' else [32768,262144,786432]
    if spec['order']==2:sizes.reverse()
    rows=list(csv.DictReader((folder/'memory.csv').open()))
    assert [(int(x['payload_bytes']),x['phase'],int(x['delay_seconds'])) for x in rows]==[(size,phase,delay) for size in sizes for phase,delay in raw.PHASES]
    ids=set(); sha=plan['subjects'][spec['subject']]['sha256']
    for size in sizes:
        case=folder/str(size); pid,start=raw.process_identity(case/'stat-start.txt');assert (pid,start) not in ids;ids.add((pid,start))
        base=int((case/'baseline-fds.txt').read_text());assert base>0
        helpers=[json.loads(s) for s in (case/'helper.jsonl').read_text().splitlines()]
        assert len({x['helper_pid'] for x in helpers})==1
        assert helpers[0]['monotonic_ns']<helpers[1]['monotonic_ns']<helpers[2]['monotonic_ns']
        for i,h in enumerate(helpers):
            assert h['subject_pid']==pid and h['base_fds']==base
            assert h['subject_cpu']==1 and h['client_cpu']==0
            assert h['large_payload_bytes']==size and h['payload_bytes']==(16 if i==0 else size)
            assert all(h[k]==v for k,v in raw.encoded_lengths(h['payload_bytes']).items())
        assert (case/'helper-exit.txt').read_text().strip()=='0' and not (case/'helper.log').read_bytes()
        assert (case/'daemon-exit.txt').read_text().strip() in ('0','143')
        previous=None
        for row in (x for x in rows if int(x['payload_bytes'])==size):
            phase=row['phase']; delay=int(row['delay_seconds']);prefix=case/f'{phase}-{delay}'
            for when in ('before','after'):assert raw.process_identity(Path(str(prefix)+f'-stat-{when}.txt'))==(pid,start)
            values=raw.status_metrics(Path(str(prefix)+'-status.txt'),pid);values['pss_kb']=raw.pss_value(prefix)
            assert all(row[k]==str(v) for k,v in values.items())
            fds=Path(str(prefix)+'-fds.txt').read_text().splitlines();expected=base+(2 if phase in ('connected','held') else 0)
            assert len(fds)==len(set(fds))==int(row['fds'])==expected and all(x.isdecimal() for x in fds)
            assert int(row['daemon_pid'])==pid
            assert raw.hashes(Path(str(prefix)+'-exe.sha256'))=={f'/proc/{pid}/exe':sha}
            assert Path(str(prefix)+'-cmdline.txt').read_text().splitlines()==['/sbin/ubusd','-s',raw.SOCKET]
            observed=raw.uptime(Path(str(prefix)+'-uptime.txt'))
            assert previous is None or observed>previous;previous=observed
            if phase!='empty':assert observed-raw.uptime(case/f'{phase}-start-uptime.txt')>=raw.Decimal(delay)-raw.Decimal('0.02')
    return rows


def audit_idle(window):
    folder=window/'raw';rows=list(csv.DictReader((folder/'memory.csv').open()))
    assert [int(x['clients']) for x in rows]==[0,1,8,32,64]
    for row in rows:
        n=int(row['clients']);snapshots=[]
        for suffix in ('-before',''):
            path=folder/f'status-{n}{suffix}.txt'
            pid=int(re.search(r'^Pid:\s+(\d+)',path.read_text(),re.M)[1]);values=raw.status_metrics(path,pid);snapshots.append((pid,values))
        assert snapshots[0][0]==snapshots[1][0]
        for col,key in [('vmrss','vmrss_kb'),('rssanon','rssanon_kb'),('vmdata','vmdata_kb')]:
            for i,phase in enumerate(('before','after')):assert int(row[f'{col}_{phase}_kb'])==snapshots[i][1][key]
        if n:
            helper=json.loads((folder/f'clients-{n}.json').read_text());assert helper['replies_validated'] and helper['holding']
    return rows


def main():
    p=argparse.ArgumentParser();p.add_argument('plan',type=Path);p.add_argument('root',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    plan=collection.load(a.plan);collection.verify_inputs(plan)
    assert (a.root/'COMPLETE').exists() and collection.load(a.root/'plan.json')==plan
    expected={x['name'] for x in plan['runs']};assert {x.name for x in a.root.iterdir() if x.is_dir()}==expected
    windows=[]
    for spec in plan['runs']:
        base=collection.verify_window(a.root,spec,plan);window=a.root/spec['name'];hashes=raw.verify_archive(window)
        before=collection.load(window/'health-before.json');after=collection.load(window/'health-after.json');assert before==after and before['mode']=='stock'
        metrics=audit_idle(window) if spec['kind']=='idle' else audit_event(window,spec,plan)
        windows.append({**base,'raw_sha256':hashes,'proc_snapshot_verified':True,'memory':metrics})
    result={'scope':'R131 supplemental router memory audit','plan_sha256':raw.digest(a.plan),'reporter_sha256':raw.digest(Path(__file__)),'windows':windows,'passed':True,
            'limits':['Idle snapshots have no archived live exe/cmdline/starttime or FD listing; workload enforced mask and FD transitions at run time.','Event snapshots include exact live exe, argv, PID/starttime, FD, nominal 1/5s delay checks.','No peak/PSS/allocator or kernel-socket memory superiority claim.']}
    a.output.write_text(json.dumps(result,indent=2)+'\n');print('VERIFIED',len(windows),'windows')
if __name__=='__main__':main()
