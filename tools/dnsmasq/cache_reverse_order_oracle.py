#!/usr/bin/env python3
"""Frozen C-only multi-PTR hash-chain, transfer, LRU and pressure study.

Seven profiles, native/SDK each three invocations: exactly 42 top-level oracle
runs. Real hash topology selects names from a fixed 257-name pool before cache
operations. Full raw order is retained, never sorted into a candidate pass.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess

from cache_transfer_diff import CACHE_SHA, IDENTITY_SHA, NATIVE_SHA, TARGET_IDENTITY_SHA, command, save, sha

BASELINE_SHA = '96fc7eed20067ebc134853620a799aa4a779afdcdf0fdb306815740c339dc941'
PROFILES = ['D', 'C', 'M', 'E', 'I', 'S1', 'S2']
PHASES = ['parent-seed','parent-between','child-before','child-after1','child-after2',
          'parent-before','parent-after1','parent-after2','parent-victim','parent-spill','parent-final']
QUERIES = ['child-first','child-repeat','parent-first','parent-repeat','promote-parent',
           'promote-seed','parent-removed','retained-parent','retained-seed','inserted-new']


def build(args, out):
    # Reuse only the previously audited non-cache objects. Source and header
    # identities are rechecked before compiling the new unchanged-cache driver.
    base = args.transfer_baseline.resolve()
    assert sha(base/'identity.json') == BASELINE_SHA
    old = json.loads((base/'identity.json').read_text())
    objects = args.reference_build.resolve()/'dnsmasq'
    assert sha(objects/'dnsmasq') == NATIVE_SHA and sha(objects/'cache.c') == CACHE_SHA
    assert sha(args.source_identity) == IDENTITY_SHA
    source = json.loads(args.source_identity.read_text())
    for name, digest in source['patched_files'].items():
        if name.startswith('src/'): assert sha(objects/name[4:]) == digest, name
    for name, digest in old['native_objects'].items():
        assert sha((base if name == 'dnsmasq-renamed.o' else objects)/name) == digest, name
    for name, digest in old['target_objects'].items(): assert sha(base/'target-objects'/name) == digest, name
    for name, digest in old['sdk_files'].items(): assert sha(args.sdk/name) == digest, name
    target = args.target_reference.resolve()
    assert sha(target/'identity.json') == TARGET_IDENTITY_SHA
    target_identity = json.loads((target/'identity.json').read_text())
    for name, row in target_identity['files'].items(): assert sha(target/name) == row['sha256'], name
    driver = Path(__file__).with_name('cache_reverse_order_driver.c').resolve()
    binaries = {}
    for label in ['native','target']:
        old_command = json.loads((base/f'{label}-build.command.json').read_text())
        assert old_command['exit'] == 0
        argv = old_command['argv']
        where = [i for i, word in enumerate(argv) if word.endswith('/cache_transfer_driver.c')]
        assert len(where) == 1 and argv[-2] == '-o'
        argv[where[0]] = str(driver); argv[-1] = str(out/(label+'-oracle'))
        command(args,out,label+'-build',argv,env=dict(os.environ,STAGING_DIR=str(args.sdk/'staging_dir')))
        binaries[label] = out/(label+'-oracle')
    prefix = [target/'lib/libc.so','--library-path',target/'lib']
    command(args,out,'target-dependencies',[*prefix,'--list',binaries['target']])
    save(out/'identity.json',dict(scope=__doc__,original_transfer_identity_sha256=BASELINE_SHA,
        native_reference_sha256=NATIVE_SHA,cache_source_sha256=CACHE_SHA,source_identity_sha256=IDENTITY_SHA,
        target_reference_identity_sha256=TARGET_IDENTITY_SHA,reused_object_identity=old,
        driver_sha256=sha(driver),tool_sha256=sha(Path(__file__)),
        native_oracle_sha256=sha(binaries['native']),target_oracle_sha256=sha(binaries['target'])))
    return [binaries['native']], [*prefix,binaries['target']]


def parse(text):
    result = dict(pool=[],selected=[],states={},queries={},inserts=[],commits=[],imports=[])
    for line in text.splitlines():
        w = line.split(); kind = w[0]
        if kind == 'META':
            assert 'meta' not in result; result['meta'] = [w[1],int(w[2]),int(w[3])]
        elif kind == 'MIX':
            assert 'mix' not in result; result['mix'] = w[1]; assert len(bytes.fromhex(w[1])) == 64
        elif kind == 'POOL': result['pool'].append([int(w[1]),w[2],int(w[3])])
        elif kind == 'SELECT': result['selected'].append([int(w[1]),int(w[2]),w[3],int(w[4]),int(w[5])])
        elif kind == 'STATE':
            assert w[1] not in result['states']
            result['states'][w[1]] = dict(now=int(w[2]),inserted=int(w[3]),freed=int(w[4]),error=int(w[5]),hash=[])
        elif kind in ['LRU','TAIL']:
            state = result['states'][w[1]]; field = kind.lower(); assert field not in state
            state[field] = w[2:] if kind == 'LRU' else w[2]
        elif kind == 'HASH': result['states'][w[1]]['hash'].append([int(w[2]),w[3:]])
        elif kind in ['A','Q']:
            assert w[1] not in result['queries']; result['queries'][w[1]] = [kind,w[2:]]
        elif kind == 'INSERT': result['inserts'].append([w[1],int(w[2])])
        elif kind == 'COMMIT': result['commits'].append([w[1],int(w[2])])
        elif kind == 'IMPORT': result['imports'].append(int(w[1]))
        else: raise ValueError('unexpected row '+kind)
    if list(result['states']) != PHASES or list(result['queries']) != QUERIES:
        raise ValueError('missing or reordered observation boundary')
    for state in result['states'].values():
        assert {'now','inserted','freed','error','hash','lru','tail'} == set(state)
    return result


def selected_indices(profile, pool):
    if profile == 'D':
        chosen = []; used = set()
        for index, _, bucket in pool:
            if bucket not in used:
                chosen.append(index); used.add(bucket)
                if len(chosen) == 3: return chosen
        raise ValueError('fixed pool lacks three distinct buckets')
    if profile in ['C','M','I']:
        bucket = next(b for b in range(64) if sum(r[2] == b for r in pool) >= 3)
        chosen = [r[0] for r in pool if r[2] == bucket][:3]
        if profile == 'M': chosen[2] = next(r[0] for r in pool if r[2] != bucket)
        if profile == 'I': chosen[2] = chosen[0]
        return chosen
    return [0] * (2 if profile.startswith('S') else 3)


def reverse_chains(state):
    return [[bucket,[token for token in chain if token.startswith('R4:')]]
            for bucket,chain in state['hash'] if any(token.startswith('R4:') for token in chain)]


def model_chains(records, buckets, commit_order):
    """Only cache_hash's insertion point rule, using the observed C buckets.

    Equal names are skipped only while consecutive at the current head. An
    A/B/A chain is never collapsed into one global group for target A.
    """
    chains = {}
    for token in commit_order:
        name = token.split(':')[1]; chain = chains.setdefault(buckets[name],[]); at = 0
        while at < len(chain) and chain[at].split(':')[1].lower() == name.lower(): at += 1
        chain.insert(at,token)
    return [[bucket,chains[bucket]] for bucket in range(64) if bucket in chains]


def audit(profile, trace):
    checks = []
    def check(label, actual, expected): checks.append(dict(check=label,actual=actual,expected=expected,passed=actual==expected))
    capacity = 4 if profile.startswith('S') else 5
    count = capacity - 2
    check('meta',trace['meta'],[profile,64,capacity])
    check('pool-size',len(trace['pool']),257)
    check('pool-spelling-and-range',all(r[0]==i and r[1]==f'mp{i:03}.test' and 0<=r[2]<64 for i,r in enumerate(trace['pool'])),True)
    chosen = selected_indices(profile,trace['pool'])
    ttls = [30,60,90] if profile in ['E','I'] else ([10,60] if profile=='S1' else [60,10] if profile=='S2' else [120]*3)
    expected_selected = [[i,index,trace['pool'][index][1],trace['pool'][index][2],ttls[i]] for i,index in enumerate(chosen)]
    check('fixed-selector',trace['selected'],expected_selected)
    records = [f'R4:{r[2]}:{100+r[4]}:c0000201' for r in expected_selected]
    by_name = {r[2]:r[3] for r in expected_selected}
    seed='F4:seed.test:220:c0000221'; parent='F4:parent.test:221:c0000222'; new='F4:new.test:240:c0000223'
    check('insertion-successes',trace['inserts'],[['seed',1],['between',1]]+[['child',1]]*count+[['pressure',1]])
    check('commit-successes',trace['commits'],[[n,1] for n in ['seed','between','child','pressure']])
    check('single-complete-import',trace['imports'],[1])
    s=trace['states']; q=trace['queries']
    check('parent-seed-lru',s['parent-seed']['lru'],[seed])
    check('parent-between-lru',s['parent-between']['lru'],[parent,seed])
    check('child-prelookup-order',s['child-before']['lru'],records+[seed])
    check('parent-prelookup-double-reversal',s['parent-before']['lru'],list(reversed(records))+[parent,seed])
    check('child-hash-insertion-rule',reverse_chains(s['child-before']),model_chains(records,by_name,reversed(records)))
    check('parent-hash-insertion-rule',reverse_chains(s['parent-before']),model_chains(records,by_name,records))
    for owner in ['child','parent']:
        for index, label in [(1,'first'),(2,'repeat')]:
            before = s[owner+'-before'] if index==1 else s[owner+'-after1']
            after = s[f'{owner}-after{index}']
            walk=[record for _,chain in before['hash'] for record in chain if record.startswith('R4:')]
            answer=q[owner+'-'+label][1]
            check(owner+'-'+label+'-address-kind',q[owner+'-'+label][0],'A')
            check(owner+'-'+label+'-reverse-hash-walk',answer,list(reversed(walk)))
            check(owner+'-'+label+'-lru-prefix',after['lru'][:count],answer)
            check(owner+'-'+label+'-hash-unchanged',after['hash'],before['hash'])
        check(owner+'-repeat-stable',q[owner+'-repeat'],q[owner+'-first'])
    child_answer=q['child-first'][1]; parent_answer=q['parent-first'][1]
    if profile=='D': check('distinct-bucket-child-parent-equal',parent_answer,child_answer)
    elif profile in ['C','E','I','S1','S2']: check('single-bucket-child-parent-reversal',parent_answer,list(reversed(child_answer)))
    else:
        collision=expected_selected[0][3]
        child_group=[r for r in child_answer if by_name[r.split(':')[1]]==collision]
        parent_group=[r for r in parent_answer if by_name[r.split(':')[1]]==collision]
        check('mixed-collision-subsequence-reversal',parent_group,list(reversed(child_group)))
    if profile=='I':
        check('child-noncontiguous-ABA-chain',reverse_chains(s['child-before'])[0][1],records)
        check('parent-noncontiguous-ABA-chain',reverse_chains(s['parent-before'])[0][1],list(reversed(records)))
    check('promote-parent',q['promote-parent'],['Q',[parent]])
    check('promote-seed',q['promote-seed'],['Q',[seed]])
    check('pressure-prefix-and-group',s['parent-victim']['lru'],[seed,parent]+parent_answer)
    tail=s['parent-victim']['tail']
    check('actual-tail-is-last-address-record',tail,parent_answer[-1])
    # Exactly C's difftime(now, tail->ttd)<0. Do not ask whether any other
    # member of the selected reverse RRset remains fresh.
    live=int(120 < int(tail.split(':')[2]))
    if profile=='S1': check('stale-selected-tail',live,0)
    elif profile=='S2': check('fresh-selected-tail',live,1)
    else: check('fresh-selected-tail',live,1)
    check('whole-address-group-removed',s['parent-spill']['lru'],[new,seed,parent])
    check('old-address-miss',q['parent-removed'],['A',[]])
    for label,token in [('retained-parent',parent),('retained-seed',seed),('inserted-new',new)]: check(label,q[label],['Q',[token]])
    check('final-forward-lru',s['parent-final']['lru'],[new,seed,parent])
    for phase,state in s.items():
        inserted=1 if phase=='parent-seed' else 2 if phase=='parent-between' else count+1 if phase.startswith('child-') else count+3 if phase in ['parent-spill','parent-final'] else count+2
        freed=live if phase in ['parent-spill','parent-final'] else 0
        check(phase+'-real-counters',[state['inserted'],state['freed'],state['error']],[inserted,freed,0])
        check(phase+'-clock',state['now'],100 if phase=='parent-seed' else 103 if phase=='parent-between' else 120)
        check(phase+'-tail',state['tail'],'-' if len(state['lru'])<capacity else state['lru'][-1])
        check(phase+'-hash-bucket-order',all(a[0]<b[0] for a,b in zip(state['hash'],state['hash'][1:])),True)
    return checks


def calibrations(profile, text, parsed):
    # Mutate observations only; no new oracle or selection run.
    assert all(c['passed'] for c in audit(profile,parsed))
    changed=copy.deepcopy(parsed)
    changed['queries']['child-first'][1][:2]=reversed(changed['queries']['child-first'][1][:2])
    assert any(not c['passed'] for c in audit(profile,changed))
    counter=copy.deepcopy(parsed);counter['states']['parent-spill']['freed']+=1
    assert any(not c['passed'] for c in audit(profile,counter))
    shortened='\n'.join(line for line in text.splitlines() if not line.startswith('TAIL parent-final '))+'\n'
    try: parse(shortened)
    except (AssertionError,ValueError,KeyError): pass
    else: raise AssertionError('missing observation accepted')
    return dict(identical_trace=True,changed_order_rejected=True,changed_counter_rejected=True,missing_row_rejected=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['reference-build','source-identity','sdk','target-reference','transfer-baseline','out']:
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
    assert [name for _,name in socket.if_nameindex()]==['lo']
    out=args.out.resolve();assert 'private' in out.parts;out.mkdir(parents=True,exist_ok=False)
    save(out/'plan.json',dict(profiles=PROFILES,repeats=3,runtimes=['native','target'],oracle_invocations=42,pool_count=257,pool_pattern='mp%03u.test',seed_clock=100,import_clock=103,lookup_pressure_clock=120,capacity_regular=5,capacity_stale=4))
    report=dict(scope=__doc__,planned_invocations=42,runs=[],failures=[],status='incomplete')
    try:
        native,target=build(args,out)
        for profile in PROFILES:
            folder=out/profile;folder.mkdir()
            config=folder/'config';config.write_text('no-hosts\nno-resolv\ncache-size='+('4' if profile.startswith('S') else '5')+'\n'+('use-stale-cache=0\n' if profile.startswith('S') else ''))
            for runtime,prefix in [('native',native),('target',target)]:
                for repeat in range(3):
                    label=f'{runtime}-{repeat}';argv=list(map(str,[*prefix,config,profile]))
                    run=subprocess.run(argv,text=True,capture_output=True)
                    (folder/(label+'.stdout')).write_text(run.stdout);(folder/(label+'.stderr')).write_text(run.stderr)
                    save(folder/(label+'.command.json'),dict(argv=argv,exit=run.returncode))
                    row=dict(profile=profile,runtime=runtime,repeat=repeat,exit=run.returncode,stdout_sha256=sha(folder/(label+'.stdout')),stderr_sha256=sha(folder/(label+'.stderr')))
                    try:
                        assert run.returncode==0,'oracle failed'
                        trace=parse(run.stdout);checks=audit(profile,trace)
                        save(folder/(label+'.relations.json'),checks)
                        row.update(checks=len(checks),passed=sum(c['passed'] for c in checks),failed=sum(not c['passed'] for c in checks),pool_sha256=hashlib.sha256(json.dumps(trace['pool'],separators=(',',':')).encode()).hexdigest(),mix_sha256=hashlib.sha256(bytes.fromhex(trace['mix'])).hexdigest(),relations_sha256=sha(folder/(label+'.relations.json')))
                        assert row['failed']==0,'source relation calibration failed'
                        row['calibration']=calibrations(profile,run.stdout,trace)
                    except Exception as error:
                        row['failure']=repr(error);report['failures'].append(dict(profile=profile,runtime=runtime,repeat=repeat,error=repr(error)))
                    report['runs'].append(row);save(out/'result.json',report)
        assert len(report['runs'])==42
        report['status']='C-relations-complete' if not report['failures'] else 'C-relations-failed'
    except Exception as error:report['failures'].append(dict(build_or_schedule=repr(error)))
    report['completed_invocations']=len(report['runs'])
    report['relation_checks']=sum(r.get('checks',0) for r in report['runs'])
    report['passed_relations']=sum(r.get('passed',0) for r in report['runs'])
    report['failed_relations']=sum(r.get('failed',0) for r in report['runs'])
    save(out/'result.json',report)
    print(json.dumps({k:v for k,v in report.items() if k not in ['runs','scope']}))
    return bool(report['failures'])


if __name__=='__main__':raise SystemExit(main())
