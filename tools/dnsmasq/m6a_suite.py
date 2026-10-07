#!/usr/bin/env python3
"""Frozen, serial M6a windows with an explicit local archive verification gate."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import socket
import subprocess
import sys
import time

from m2_rootfs import STOCK_SHA256, sha256
import m5_option_matrix_archive as archive

PRODUCT = 'dc1b740d7973838e2ae7f098d0726b0484e55074'
R3 = '37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b'
ORDERS = [('c','r3','rs'),('r3','rs','c'),('rs','c','r3'),('c','rs','r3'),('rs','r3','c')]
PROFILES = [
    ('udp-hit','hit','hit',10000,30,4096),
    ('udp-miss','miss','hit',10000,30,4096),
    ('dns-mixed','mixed','hit',10000,30,256),
    ('upstream-fault','fault','hit',1000,0,256),
    ('tcp-local','tcp','local',10000,30,4096),
    ('tcp-cache','tcp','hit',10000,30,4096),
    ('tcp-miss','tcp','miss',10000,30,4096),
    ('dhcp-lease','dhcp','hit',20,0,256),
    ('reload-concurrent','reload','hit',1000,0,256),
]
TARGET = Path('/home/ubuntu/dnsmasq-cargo-target')

def save(path, value):
    temp=path.with_suffix(path.suffix+'.new')
    temp.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n');temp.replace(path)

def file_map(root):
    return {str(p.relative_to(root)):sha256(p) for p in sorted(root.rglob('*'))
            if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}

def pid_state():
    result={}
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:
            stat=(p/'stat').read_text(); f=stat[stat.rfind(')')+2:].split()
            args=(p/'cmdline').read_bytes().split(b'\0')
            names=[Path(os.fsdecode(x)).name for x in args if x]
            result[int(p.name)]={'parent':int(f[1]),'start':int(f[19]),'names':names,
                                 'cmdline_sha256':hashlib.sha256(b'\0'.join(args)).hexdigest()}
        except (FileNotFoundError,PermissionError,ProcessLookupError):pass
    return result

def related(pid, rows):
    seen=set()
    while pid and pid not in seen:
        if pid==os.getpid():return True
        seen.add(pid);pid=rows.get(pid,{}).get('parent',0)
    return False

def foreign_load():
    rows=pid_state(); ancestors=set();pid=os.getpid()
    while pid and pid not in ancestors:
        ancestors.add(pid);pid=rows.get(pid,{}).get('parent',0)
    suspects=[]
    for pid,row in rows.items():
        if pid in ancestors or related(pid,rows):continue
        names=[n for n in row['names'] if n in {'cargo','cargo-fuzz','rustc','make','cc','gcc','clang',
               'dnsmasq','dnsmasq-rs','dns_wire','dhcp_packet','config_line','pytest'}
               or n in {'m6a_loadgen','m6a_upstream'}
               or n.endswith(('-gcc','-clang'))
               or re.fullmatch(r'(?:m[23456]_.*|m6a_.*|test_.*)\.py',n)]
        if names:suspects.append({'pid':pid,'start':row['start'],'names':names,
                                  'cmdline_sha256':row['cmdline_sha256']})
    # A namespace child can be born between the process table and candidate read.
    fresh=pid_state()
    foreign=[r for r in suspects if fresh.get(r['pid'],{}).get('start')==r['start']
             and not related(r['pid'],fresh)]
    for row in foreign:
        chain=[];pid=row['pid'];seen=set()
        while pid and pid not in seen:
            seen.add(pid);witness=fresh.get(pid)
            if witness is None:break
            chain.append({'pid':pid,**witness});pid=witness['parent']
        row['ancestry']=chain
        proc=Path('/proc')/str(row['pid'])
        for filename in ['status','cgroup']:
            try:row[filename]=(proc/filename).read_text()
            except (FileNotFoundError,ProcessLookupError):row[filename]=None
        for filename in ['root','exe']:
            try:row[filename]=os.readlink(proc/filename)
            except (FileNotFoundError,ProcessLookupError,PermissionError):row[filename]=None
    return foreign

def prepare(args):
    root=args.root.resolve(); private=root/'private'; private.mkdir(exist_ok=True)
    manifest=private/'manifest.json'
    if manifest.exists():raise ValueError('fresh frozen manifest required')
    tools=root/'tools/dnsmasq'; native=private/'native'
    native.mkdir(exist_ok=True)
    if (not args.m6b and sha256(args.r3)!=R3) or sha256(args.image_root/'usr/sbin/dnsmasq')!=STOCK_SHA256:
        raise ValueError('M5 or exact-image identity differs')
    r3_build=json.loads(args.r3_build.read_text());rs_build=json.loads(args.rs_build.read_text())
    frozen=json.loads(args.product_freeze.read_text())
    source_commit = args.source_commit or PRODUCT
    if not args.m6b and (frozen['source_commit']!=PRODUCT or frozen['elf_sha256']!=R3):
        raise ValueError('M5 product source freeze differs')
    if frozen['source_commit'] != source_commit:
        raise ValueError('source commit differs from freeze')
    for build,level,elf in [(r3_build,'3',args.r3),(rs_build,'s',args.rs)]:
        if (build['kind']!='release' or build['opt_level']!=level
                or build['source']!=frozen['source_root'] or build['cargo_target_dir']!=str(TARGET)
                or build['artifacts']!=[{'path':'dnsmasq-rs','bytes':elf.stat().st_size,'sha256':sha256(elf)}]):
            raise ValueError('release build/source/artifact identity differs')
    flags=lambda build:re.sub(r' -Clink-arg=-Wl,-Map=\S+','',build['rustflags'])
    if flags(r3_build)!=flags(rs_build):raise ValueError('s changed non-optimization build flags')
    source=Path(frozen['source_root'])
    for name,digest in frozen['source_files'].items():
        if sha256(source/name)!=digest:raise ValueError('frozen product input changed: '+name)
    compiler=subprocess.run(['cc','--version'],check=True,capture_output=True,text=True).stdout
    for name in ['m6a_loadgen','m6a_upstream']:
        binary=native/name
        subprocess.run(['cc','-O2','-std=c11','-Wall','-Wextra','-Werror',str(tools/(name+'.c')),
                        '-o',str(binary)],check=True)
    protocol_path=root/('docs/dnsmasq/M6B_PROTOCOL.md' if args.m6b else 'docs/dnsmasq/M6A_PROTOCOL.md')
    spec={'schema':1,'source_commit':source_commit,'m6b':args.m6b,'root':str(root),'protocol':str(protocol_path),
          'protocol_sha256':sha256(protocol_path),'tools_files':file_map(tools),
          'source_files':frozen['source_files'],'source_root':str(source),
          'product_freeze':{'path':str(args.product_freeze),'sha256':sha256(args.product_freeze)},
          'image_root':str(args.image_root),
          'groups':{'c':{'elf':str(args.image_root/'usr/sbin/dnsmasq'),'sha256':STOCK_SHA256},
                    'r3':{'elf':str(args.r3),'sha256':sha256(args.r3),'bytes':args.r3.stat().st_size},
                    'rs':{'elf':str(args.rs),'sha256':sha256(args.rs),'bytes':args.rs.stat().st_size}},
          'builds':{'r3':{'path':str(args.r3_build),'sha256':sha256(args.r3_build)},
                    'rs':{'path':str(args.rs_build),'sha256':sha256(args.rs_build)}},
          'native':{name:{'path':str(native/name),'sha256':sha256(native/name)}
                    for name in ['m6a_loadgen','m6a_upstream']},
          'compiler':compiler,'kernel':os.uname().release,'machine':os.uname().machine,
          'cpu_count':os.cpu_count(),'allowed_cpus':sorted(os.sched_getaffinity(0)),
          'clock_ticks':os.sysconf('SC_CLK_TCK'),'page_bytes':os.sysconf('SC_PAGE_SIZE'),
          'cpuinfo':Path('/proc/cpuinfo').read_text(),'profiles':PROFILES,'orders':ORDERS,
          'formal_rounds':5,'formal_warmup_seconds':30,'formal_duration_seconds':120,
          'product_modified':False,'physical_router':False,'m6b_executed':False}
    if spec['allowed_cpus']!=[0,1,2,3]:raise ValueError('four expected CPUs required')
    save(manifest,spec);save(private/'state.json',{'manifest_sha256':sha256(manifest),'windows':{},
         'formal_valid_windows':0,'expected_windows':135,'status':'prepared','events':[]})
    print(json.dumps({'manifest':str(manifest),'manifest_sha256':sha256(manifest),
                      's_sha256':spec['groups']['rs']['sha256'],'s_bytes':spec['groups']['rs']['bytes']}))

def verify(spec, manifest):
    if sha256(Path(spec['protocol']))!=spec['protocol_sha256']:raise ValueError('protocol changed')
    if file_map(Path(spec['root'])/'tools/dnsmasq')!=spec['tools_files']:raise ValueError('frozen tool tree changed')
    for group in spec['groups'].values():
        if sha256(Path(group['elf']))!=group['sha256']:raise ValueError('ELF changed')
    for asset in [*spec['native'].values(),*spec['builds'].values(),spec['product_freeze']]:
        if sha256(Path(asset['path']))!=asset['sha256']:raise ValueError('frozen asset changed')
    for name,digest in spec['source_files'].items():
        if sha256(Path(spec['source_root'])/name)!=digest:raise ValueError('product input changed')

def command_for(spec, profile, group, round_no, output, pilot):
    _,scenario,tcp,rate,sat,bank=profile;root=Path(spec['root']);tools=root/'tools/dnsmasq'
    artifact=spec['groups']['r3' if group=='c' else group]
    cmd=['sh',str(tools/'run_isolated.sh'),'python3',str(tools/'m6a_window.py'),
         '--implementation',group,'--rust',artifact['elf'],'--expected-rust-sha',artifact['sha256'],
         '--image-root',spec['image_root'],'--loadgen',spec['native']['m6a_loadgen']['path'],
         '--upstream',spec['native']['m6a_upstream']['path'],'--protocol',spec['protocol'],
         '--scenario',scenario,'--tcp-profile',tcp,'--round',str(round_no),'--rate',str(rate),
         '--cache-names',str(bank),'--output',str(output),'--warmup','2' if pilot else '30',
         '--duration','10' if pilot else '120','--saturation-seconds',str(3 if pilot and sat else sat),
         '--seed',str(0x4d364100+round_no), '--idle-seconds','60', '--wake-metrics',
         '--drain-timeout-seconds','65', '--drain-sample-seconds','0,1,5,60']
    if spec.get('m6b'):
        cmd += ['--allow-rust-identity-change']
    if pilot:cmd+=['--preflight','--fault-start','3','--fault-end','6','--reload-period','3']
    return cmd

def execute(cmd, path, state, state_path):
    record={'argv':cmd,'started_ns':time.time_ns(),'returncode':None,'foreign_load':[]}
    record['host_cpu_before']=Path('/proc/stat').read_text()
    record['host_load_before']=Path('/proc/loadavg').read_text()
    save(path.with_suffix('.command.json'),record)
    with path.open('wb') as log:
        proc=subprocess.Popen(cmd,stdout=log,stderr=log,start_new_session=True)
        last=0
        try:
            while proc.poll() is None:
                if time.monotonic()-last>=1:
                    busy=foreign_load();last=time.monotonic()
                    if busy:
                        record['foreign_load']=busy;raise RuntimeError('exclusive window contaminated')
                    state['heartbeat_unix_ns']=time.time_ns();save(state_path,state)
                try:proc.wait(timeout=.2)
                except subprocess.TimeoutExpired:pass
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid,signal.SIGTERM)
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=5)
            record.update(returncode=proc.returncode,finished_ns=time.time_ns())
            record['host_cpu_after']=Path('/proc/stat').read_text()
            record['host_load_after']=Path('/proc/loadavg').read_text()
            save(path.with_suffix('.command.json'),record)
    return record

def pilot_behavior(report, profile):
    m=report.get('measurement',{}).get('load',{}).get('measurement',{})
    if not m.get('correct'):return False
    if profile[1]!='fault' and any(m.get(k,0) for k in ['wrong','transport_error','timeout']):return False
    b=report.get('behavior_checks',{})
    if profile[1]=='dhcp' and not b.get('dhcp_release_endstate',{}).get('leasefile_empty'):return False
    if profile[1]=='reload':
        published=b.get('reload_publications',[])
        if len(published)!=3 or not all(r.get('publication_correct') for r in published):return False
        tftp=b.get('tftp',{})
        if not tftp.get('correct') or tftp.get('errors'):return False
    return True

def archive_gate(spec, attempt, record, state, state_path):
    private=Path(spec['root'])/'private'; folder=private/'archives'/record['job_id']/attempt.name
    existing=state.get('archive_gate')
    if existing:
        if existing['job_id']!=record['job_id'] or existing['attempt']!=record['attempt']:
            raise ValueError('must finish the previous archive gate first')
        packed=existing
    else:
        folder.mkdir(parents=True,exist_ok=True)
        if (folder/'manifest.json').exists():
            m=json.loads((folder/'manifest.json').read_text())
            if archive.inventory(attempt)!=m['entries'] or sha256(folder/'archive.tar.gz')!=m['archive_sha256']:
                raise ValueError('partial archival no longer matches the finished attempt')
            packed={'archive_sha256':m['archive_sha256'],'entries':len(m['entries']),'archive_bytes':m['archive_bytes']}
        else:packed=archive.pack(attempt,folder/'archive.tar.gz',folder/'manifest.json')
    state['status']='awaiting-local-archive-verification'
    state['archive_gate']={'job_id':record['job_id'],'attempt':record['attempt'],
                           'run':str(attempt),'archive_folder':str(folder),**packed}
    save(state_path,state)
    proof_path=folder/'local-verification.json'
    while not proof_path.exists():
        state['heartbeat_unix_ns']=time.time_ns();save(state_path,state);time.sleep(1)
    proof=json.loads(proof_path.read_text())
    already_pruned=(folder/'prune.json').exists()
    if (not proof.get('verified') or not proof.get('local_full_metadata_verified')
        or proof.get('verifier_host')==socket.gethostname()
        or proof.get('archive_sha256')!=packed['archive_sha256']
        or proof.get('manifest_sha256')!=sha256(folder/'manifest.json')):
        raise ValueError('local archive proof differs')
    inventory=json.loads((folder/'manifest.json').read_text())['entries']
    keep=[p for p,row in inventory.items() if row['kind']=='file' and Path(p).suffix in {'.json','.log','.jsonl'}]
    selected={Path('.')}
    for name in keep:selected.add(Path(name));selected.update(Path(name).parents)
    if already_pruned:pruned=json.loads((folder/'prune.json').read_text())
    else:
        if sha256(folder/'archive.tar.gz')!=packed['archive_sha256']:raise ValueError('remote archive changed')
        intent=folder/'prune-intent.json'
        if not intent.exists():
            archive.assert_finished(attempt)
            if archive.inventory(attempt)!=inventory:
                raise ValueError('raw run changed after packing; preserve all new content')
            save(intent,{'run':str(attempt),'archive_sha256':packed['archive_sha256'],
                         'local_full_metadata_verified':True,
                         'allocated_bytes':sum(p.lstat().st_blocks*512 for p in [attempt,*attempt.rglob('*')])})
        if attempt.exists() and archive.inventory(attempt)==inventory:
            pruned=archive.prune(attempt,folder/'manifest.json')
        else:
            # The only writer at this point is our completed archival transaction.
            # Full local verification and the unchanged tar precede the intent.
            started=json.loads(intent.read_text())
            if started['run']!=str(attempt) or started['archive_sha256']!=packed['archive_sha256']:
                raise ValueError('interrupted prune intent belongs to another run')
            if attempt.exists():
                archive.assert_finished(attempt)
                shutil.rmtree(attempt)
            pruned={'removed':str(attempt),'allocated_bytes_removed':started['allocated_bytes'],
                    'archive_sha256':packed['archive_sha256'],'recovered_interrupted_prune':True}
        members=[str(Path(attempt.name)/p) for p in sorted(selected,key=lambda p:(len(p.parts),str(p)))]
        subprocess.run(['tar','--no-recursion','--xattrs','--xattrs-include=*','--acls','--numeric-owner',
                        '-xpf',str(folder/'archive.tar.gz'),'-C',str(attempt.parent),'--',*members],check=True)
    restored=archive.inventory(attempt)
    if not all(restored[p]==inventory[p] for p in keep):raise ValueError('retained gates changed')
    pruned.update(retained_gate_files=len(keep),retained_full_metadata_verified=True)
    save(folder/'prune.json',pruned);(folder/'archive.tar.gz').unlink(missing_ok=True)
    record['archive']={'folder':str(folder),'archive_sha256':packed['archive_sha256'],
                       'local_verified':True,'pruned':True};state.pop('archive_gate',None)
    save(state_path,state)

def run(args):
    if not args.pilot_only and (args.profile or args.group):
        raise ValueError('formal suite cannot filter or reorder the frozen schedule')
    manifest=args.manifest.resolve();spec=json.loads(manifest.read_text());verify(spec,manifest)
    private=Path(spec['root'])/'private';state_path=private/'state.json';state=json.loads(state_path.read_text())
    if state['manifest_sha256']!=sha256(manifest):raise ValueError('state belongs to another freeze')
    os.sched_setaffinity(0,{3});os.environ['PYTHONDONTWRITEBYTECODE']='1'
    state['controller_pid']=os.getpid()
    state['status']='running';save(state_path,state)
    # Complete an interrupted archive barrier before scheduling any new window.
    pending=state.get('archive_gate')
    if pending:
        window=state['windows'][pending['job_id']]
        record=next(x for x in window['attempts'] if x['attempt']==pending['attempt'])
        attempt=private/'runs'/record['job_id']/f"attempt-{record['attempt']}"
        archive_gate(spec,attempt,record,state,state_path)
        if record['methodology_valid']:window['valid_attempt']=record['attempt']
        state['formal_valid_windows']=sum(w['valid_attempt'] is not None for w in state['windows'].values())
        save(state_path,state)
    for round_no,order in enumerate(ORDERS,1):
        for profile in PROFILES:
            if args.profile and profile[0] not in args.profile:continue
            for group in order:
                if args.group and group not in args.group:continue
                job=f'r{round_no:02d}-{profile[0]}-{group}'
                window=state['windows'].setdefault(job,{'round':round_no,'profile':profile[0],
                    'group':group,'attempts':[],'valid_attempt':None})
                if window['valid_attempt'] is not None:continue
                number=len(window['attempts'])+1;attempt=private/'runs'/job/f'attempt-{number}'
                attempt.mkdir(parents=True,exist_ok=False)
                record={'job_id':job,'round':round_no,'profile':profile[0],'group':group,
                        'attempt':number,'manifest_sha256':sha256(manifest),'source_commit':spec['source_commit'],
                        'protocol_sha256':spec['protocol_sha256'],'elf_sha256':spec['groups'][group]['sha256'],
                        'methodology_valid':False,'pilot_only':args.pilot_only,'failures':[]}
                state['current_job']=job;state['current_attempt']=number;state['status']='running'
                window['attempts'].append(record);save(state_path,state)
                try:
                    with (TARGET/'.dnsmasq-build.lock').open('a') as lock:
                        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        if foreign_load():raise RuntimeError('other build/test active before window')
                        if sha256(manifest)!=state['manifest_sha256']:raise ValueError('manifest changed during suite')
                        verify(spec,manifest)
                        pilot=command_for(spec,profile,group,round_no,attempt/'pilot',True)
                        record['pilot_command']=execute(pilot,attempt/'pilot.log',state,state_path)
                        if record['pilot_command']['returncode']!=0:raise RuntimeError('pilot command failed')
                        p=json.loads((attempt/'pilot/result.json').read_text())
                        record['pilot_result_sha256']=sha256(attempt/'pilot/result.json')
                        if not p.get('measurement_valid') or not pilot_behavior(p,profile):
                            raise RuntimeError('pilot methodology/behavior failed; retain excluded pilot')
                        if not args.pilot_only:
                            formal=command_for(spec,profile,group,round_no,attempt/'formal',False)
                            record['formal_command']=execute(formal,attempt/'formal.log',state,state_path)
                            if record['formal_command']['returncode']!=0:raise RuntimeError('formal command failed')
                            result=json.loads((attempt/'formal/result.json').read_text())
                            record['formal_result_sha256']=sha256(attempt/'formal/result.json')
                            record['methodology_valid']=bool(result.get('measurement_valid'))
                            if not record['methodology_valid']:raise RuntimeError('formal methodology invalid')
                        else:record['pilot_passed']=True
                except Exception as error:record['failures'].append(repr(error))
                save(attempt/'receipt.json',record);save(state_path,state)
                archive_gate(spec,attempt,record,state,state_path)
                if record['methodology_valid']:
                    window['valid_attempt']=number
                    state['formal_valid_windows']=sum(w['valid_attempt'] is not None for w in state['windows'].values())
                state['status']='running' if not record['failures'] else 'failed-tools-or-environment'
                save(state_path,state)
                print(json.dumps({'job':job,'attempt':number,'formal_valid_windows':state['formal_valid_windows'],
                                  'pilot_only':args.pilot_only,'failures':record['failures']}),flush=True)
                if record['failures']:return 1
        if args.pilot_only:break
    expected={f'r{n:02d}-{p[0]}-{g}' for n in range(1,6) for p in PROFILES for g in ['c','r3','rs']}
    valid={job for job,w in state['windows'].items() if w['valid_attempt'] is not None}
    state['status']='pilots-complete' if args.pilot_only else 'complete' if valid==expected else 'partial-complete'
    save(state_path,state);return 0

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    p=sub.add_parser('prepare');p.add_argument('--root',type=Path,required=True)
    for name in ['r3','rs','r3-build','rs-build','image-root','product-freeze']:
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--source-commit');p.add_argument('--m6b',action='store_true')
    p=sub.add_parser('run');p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--pilot-only',action='store_true');p.add_argument('--profile',action='append');p.add_argument('--group',action='append')
    args=parser.parse_args()
    return prepare(args) if args.action=='prepare' else run(args)

if __name__=='__main__':raise SystemExit(main())
