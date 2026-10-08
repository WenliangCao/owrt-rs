#!/usr/bin/env python3
"""Prepare and collect the existing 21-case reverse gate's read-only sidecars.

No product edit, old comparator change, new matrix, sorting, or permutation
whitelist. The 12-row strict comparison remains separate and may fail.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile

import cache_reverse_transfer_cases as corpus
from cache_reverse_order_oracle import model_chains
import rust_lib_probe

HERE = Path(__file__).resolve().parent
TEST = 'dns::cache::reverse_transfer_gate::exact_c_reverse_transfer_probe'
PLAN_SHA = '2d546b0e47749a2dce5e3863be6136f336155db2dd05c680452f26f7717e468d'
CASE = 'multiple-ptr-export-order'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('exact source/adapter anchor required: ' + old[:100])
    return text.replace(old, new)


def prepare(args):
    repo, out = args.repository.resolve(), args.out.resolve()
    if (out.exists() or not out.is_relative_to(repo / 'private')
            or not re.fullmatch('[0-9a-f]{40}', args.source_commit)):
        raise ValueError('full product commit and fresh private preparation required')
    if subprocess.check_output(['git', 'rev-parse', args.source_commit+'^{commit}'], cwd=repo, text=True).strip() != args.source_commit:
        raise ValueError('product source commit differs')
    out.mkdir(parents=True)
    archive = out / 'product-components.tar'
    with archive.open('wb') as stream:
        subprocess.run(['git','archive','--format=tar',args.source_commit,'components/dnsmasq','components/ubus'],cwd=repo,stdout=stream,check=True)
    source = out / 'source'; source.mkdir()
    with tarfile.open(archive) as stream:
        if stream.pax_headers.get('comment') != args.source_commit:
            raise ValueError('product archive commit differs')
        stream.extractall(source, filter='data')
    before = rust_lib_probe.source_files(source)
    cache = source / 'components/dnsmasq/src/dns/cache.rs'
    text = cache.read_text()
    if 'fn entry(&self,' not in text or 'fn slot_index(' not in text:
        raise ValueError('current separated A content/links API required')
    if 'mod reverse_transfer_gate' in text or 'm6b_reverse_order_sidecar' in text:
        raise ValueError('pure product source required, not a previously generated probe')
    final = '    ((value ^ (value >> 16)) as usize) & (size - 1)\n'
    hook = ('    let bucket = ((value ^ (value >> 16)) as usize) & (size - 1);\n'
            '    #[cfg(test)]\n'
            '    m6b_reverse_order_sidecar::bucket(name, bucket, &mixer, size);\n'
            '    bucket\n')
    text = replace_once(text, final, hook)
    adapter = (HERE / 'cache_reverse_transfer_probe.rs').read_text()
    adapter = replace_once(adapter, '        for line in commands.lines() {',
        '        for (command_index, line) in commands.lines().enumerate() {')
    anchor = '            let words: Vec<_> = line.split_whitespace().collect();'
    adapter = replace_once(adapter, anchor, anchor+'\n'
        '            m6b_reverse_order_sidecar::context(stage, command_index, words[0]);\n'
        '            if matches!(words[0], "A" | "T") {\n'
        '                m6b_reverse_order_sidecar::snapshot(&self.cache, &self.counters, "before");\n'
        '            }')
    anchor = '            write!(row, " | {} {}", self.counters.inserted, self.counters.live_freed).unwrap(); output.push(row);'
    adapter = replace_once(adapter, anchor,
        '            if matches!(words[0], "A" | "T") {\n'
        '                m6b_reverse_order_sidecar::snapshot(&self.cache, &self.counters, "after");\n'
        '            }\n'+anchor)
    adapter = replace_once(adapter, '    for transaction in child.transactions {',
        '    for (command_index, transaction) in child.transactions.into_iter().enumerate() {\n'
        '        m6b_reverse_order_sidecar::context("R", command_index, "IMPORT");')
    meter = source / 'components/dnsmasq/src/dns/m6b_reverse_order_rust.rs'
    meter.write_bytes((HERE / 'm6b_reverse_order_rust.rs').read_bytes())
    cache.write_text(text+'\n#[cfg(test)]\nmod m6b_reverse_order_sidecar { include!("m6b_reverse_order_rust.rs"); }\n'
        +'\n#[cfg(test)]\nmod reverse_transfer_gate {\n'+adapter+'\n}\n')
    from m6b_reverse_order_c import prepare_c
    cdir = out / 'c'
    c = prepare_c(args.reference_source.resolve(), HERE / 'cache_reverse_transfer_driver.c', cdir)
    # Keep the existing C 21-case execution/calibrations/fresh-receipt implementation,
    # changing only where each invocation's auxiliary trace is written.
    builder = (HERE / 'cache_reverse_transfer_oracle.py').read_text()
    builder = replace_once(builder, "driver = Path(__file__).with_name('cache_reverse_transfer_driver.c').resolve()",
        "driver = Path(__file__).with_name('m6b_reverse_order_driver.c').resolve()")
    builder = replace_once(builder, "args.target_reference, Path(__file__).with_name('cache_reverse_transfer_driver.c'),",
        "args.target_reference, Path(__file__).parent,")
    anchor = "                    lines = command(args, folder, f'{label}-{repeat}', [*prefix, *suffix])"
    builder = replace_once(builder, anchor,
        "                    sidecar = folder / f'{label}-{repeat}.sidecar.jsonl'\n"
        "                    if sidecar.exists(): raise ValueError('fresh sidecar required')\n"
        "                    lines = command(args, folder, f'{label}-{repeat}', [*prefix, *suffix],\n"
        "                        env=dict(os.environ, DNSMASQ_REVERSE_ORDER_SIDECAR=str(sidecar)))")
    (cdir / 'cache_reverse_transfer_oracle.py').write_text(builder)
    (cdir / 'cache_reverse_transfer_cases.py').write_bytes((HERE / 'cache_reverse_transfer_cases.py').read_bytes())
    receipt = {'schema':1,'kind':'m6b-reverse-order-sidecar-source','source_commit':args.source_commit,
        'product_archive_sha256':sha(archive),'product_source_inputs':before,
        'source_root':str(source),'generated_source_inputs':rust_lib_probe.source_files(source),
        'c':c,'c_builder_sha256':sha(cdir / 'cache_reverse_transfer_oracle.py'),
        'c_cases_sha256':sha(cdir / 'cache_reverse_transfer_cases.py'),
        'generator_sha256':sha(__file__),'rust_template_sha256':sha(HERE / 'm6b_reverse_order_rust.rs'),
        'adapter_template_sha256':sha(HERE / 'cache_reverse_transfer_probe.rs'),
        'status':'prepared-not-built-not-run','product_source_modified':False,
        'corpus':'unchanged21; C native/SDK each3; no added processes/matrix',
        'qualification':False,'method':'actual Rust reverse_bucket return hook and read-only chains; actual C hash_bucket hook; original stdout unchanged'}
    save(out / 'source-receipt.json',receipt)
    print(json.dumps({'source':str(source),'receipt':str(out / 'source-receipt.json'),'c_builder':str(cdir / 'cache_reverse_transfer_oracle.py'),'built':False}))


def validate_source(receipt_path, source):
    receipt_path, source = Path(receipt_path).resolve(), Path(source).resolve()
    receipt = json.loads(receipt_path.read_text())
    if (receipt.get('kind') != 'm6b-reverse-order-sidecar-source' or receipt.get('schema') != 1
            or receipt.get('generator_sha256') != sha(__file__)
            or receipt['generated_source_inputs'] != rust_lib_probe.source_files(source)):
        raise ValueError('frozen sidecar preparation/source identity differs')
    archive = receipt_path.parent / 'product-components.tar'
    if sha(archive) != receipt['product_archive_sha256']:
        raise ValueError('product archive changed')
    with tarfile.open(archive) as stream:
        if stream.pax_headers.get('comment') != receipt['source_commit']:
            raise ValueError('product archive commit changed')
        base = {member.name:hashlib.sha256(stream.extractfile(member).read()).hexdigest()
                for member in stream.getmembers() if member.isfile()}
    if base != receipt['product_source_inputs']:
        raise ValueError('actual archived base inputs differ')
    if (receipt['rust_template_sha256'] != sha(HERE / 'm6b_reverse_order_rust.rs')
            or receipt['adapter_template_sha256'] != sha(HERE / 'cache_reverse_transfer_probe.rs')):
        raise ValueError('frozen Rust sidecar/adapter template changed')
    if receipt['c']['tool_sha256'] != sha(HERE / 'm6b_reverse_order_c.py'):
        raise ValueError('C sidecar generator changed')
    for name,expected in receipt['c']['files'].items():
        if sha(receipt_path.parent / 'c' / name) != expected:
            raise ValueError('frozen C private include/header/driver changed')
    for name,key in [('cache_reverse_transfer_oracle.py','c_builder_sha256'),('cache_reverse_transfer_cases.py','c_cases_sha256')]:
        if sha(receipt_path.parent / 'c' / name) != receipt[key]:
            raise ValueError('frozen C sidecar builder/corpus changed')
    return receipt


def c_binding(prep, croot, c_receipt):
    path = Path(prep).resolve().parent / 'c/cache_reverse_transfer_oracle.py'
    value = module(path, 'm6b_sidecar_c_builder')
    return value.validate_fresh_reverse(Path(croot), Path(c_receipt))


def run_rust(args):
    receipt = validate_source(args.source_receipt,args.rust_source_root)
    binding = rust_lib_probe.validate(args.rust_test_binary,args.rust_source_root,args.rust_build_receipt)
    c = c_binding(args.source_receipt,args.c_baseline,args.fresh_c_receipt)
    out = args.out.resolve()
    if out.exists() or 'private' not in out.parts: raise ValueError('fresh private run required')
    out.mkdir(parents=True)
    plan = args.c_baseline / 'plan.json'
    if sha(plan) != PLAN_SHA: raise ValueError('original 21-case corpus differs')
    rows=[]
    for case in json.loads(plan.read_text()):
        label=case['label'];folder=out/label;folder.mkdir()
        trace=folder/'sidecar.jsonl'
        argv=rust_lib_probe.argv(args.rust_test_binary,TEST)
        env=dict(__import__('os').environ,DNSMASQ_REVERSE_TRANSFER_CASE=str((args.c_baseline/label).resolve()),
                 DNSMASQ_REVERSE_TRANSFER_NOW=str(case['now']),DNSMASQ_REVERSE_ORDER_SIDECAR=str(trace))
        try:
            run=subprocess.run(argv,env=env,capture_output=True,text=True,timeout=120)
        except (OSError,subprocess.TimeoutExpired) as error:
            raw_out=getattr(error,'stdout',None) or '';raw_err=getattr(error,'stderr',None) or repr(error)
            if isinstance(raw_out,bytes):raw_out=raw_out.decode(errors='replace')
            if isinstance(raw_err,bytes):raw_err=raw_err.decode(errors='replace')
            run=subprocess.CompletedProcess(argv,-1,raw_out,raw_err)
        (folder/'stdout').write_text(run.stdout);(folder/'stderr').write_text(run.stderr)
        row={'case':label,'argv':argv,'exit':run.returncode,'stdout_sha256':sha(folder/'stdout'),
             'stderr_sha256':sha(folder/'stderr'),'sidecar_sha256':sha(trace) if trace.exists() else None}
        save(folder/'run.json',row);rows.append(row)
        run.check_returncode();rust_lib_probe.require_one_test(run.stdout,TEST)
        rust_lib_probe.recheck(binding)
    save(out/'run-receipt.json',{'source_commit':receipt['source_commit'],'source_receipt_sha256':sha(args.source_receipt),
        'rust_probe':binding,'fresh_c':c,'cases':rows,'tool_sha256':sha(__file__),
        'qualification':False,'scope':'same21 diagnostic observations only; collector/strict comparator remain separate'})


def snapshots(events):
    rows={}
    for event in events:
        if event['event']=='snapshot':
            key=(event['owner'],event['command'],event['op'],event['when'])
            if key in rows:raise ValueError('duplicate snapshot boundary')
            rows[key]=event
    return rows


def tokens(line):
    body, counters=line.split(' | ')
    return body.split()[2:],list(map(int,counters.split()))


def ordered_relations(lines,events):
    """Existing model_chains, reverse(walk), and post-lookup LRU; no sorting."""
    checks=[]
    def check(name,actual,expected):checks.append({'check':name,'passed':actual==expected,'actual':actual,'expected':expected})
    rows=snapshots(events);buckets={};mixes=set();hash_sizes=set()
    for event in events:
        if event['event']=='bucket':
            raw=bytes.fromhex(event['name_hex']);mix=bytes.fromhex(event['mix'])
            if len(mix)!=64 or event['hash_size']!=64 or not 0<=event['bucket']<64:
                raise ValueError('actual 64-bucket/mix observation invalid')
            name=raw.decode('ascii').lower();mixes.add(event['mix']);hash_sizes.add(event['hash_size'])
            if name in buckets and buckets[name]!=event['bucket']:
                raise ValueError('one runtime changed name bucket')
            buckets[name]=event['bucket']
    if len(mixes)!=1 or hash_sizes!={64}:raise ValueError('within-runtime mix/size changed or unobserved')
    case=next(row for row in corpus.cases() if row['label']==CASE)
    records=[]
    for command in case['child']:
        words=command.split()
        if words[0]=='V':records.append(f'R{words[2]}:{words[1]}:{int(words[5])+int(words[4])}:{words[3]}')
    by_name={token.split(':')[1]:buckets[token.split(':')[1].lower()] for token in records}
    for owner,commands,commit in [('CH',case['child'],list(reversed(records))),('P2',case['after'],records)]:
        indices=[i for i,line in enumerate(commands) if line.split()[0] in ('T','A')]
        if len(indices)!=3 or [commands[i].split()[0] for i in indices]!=['T','A','T']:
            raise ValueError('original T/A/T boundaries differ')
        first,answer,last=indices
        before=rows[(owner,answer,'A','before')];after=rows[(owner,answer,'A','after')]
        pre=rows[(owner,first,'T','before')];post=rows[(owner,last,'T','after')]
        lru_expected=records if owner=='CH' else list(reversed(records))
        check(owner+'-prelookup-transfer-reversal',pre['lru'],lru_expected)
        check(owner+'-actual-name-buckets',dict((bytes.fromhex(name).decode('ascii'),bucket) for name,bucket in pre['name_buckets']),by_name)
        expected_chains=model_chains(records,by_name,commit)
        check(owner+'-cache-hash-insertion-point',pre['chains'],expected_chains)
        check(owner+'-T-does-not-change-chain',before['chains'],pre['chains'])
        check(owner+'-T-does-not-change-lru',before['lru'],pre['lru'])
        check(owner+'-actual-bucket-ascending',[bucket for bucket,_ in before['chains']],list(dict.fromkeys(bucket for bucket,_ in expected_chains)))
        walk=[token for _,chain in before['chains'] for token in chain]
        stdout=[line for line in lines if line.startswith(owner+' A ')]
        if len(stdout)!=1:raise ValueError('missing/repeated original address output')
        returned,counters=tokens(stdout[0]);mapped=[]
        for item in returned:
            name,expiry,local=item.split(':')
            if local!='0':raise ValueError('ordering fixture gained local prefix')
            matches=[record for record in records if record.split(':')[1:3]==[name,expiry]]
            if len(matches)!=1:raise ValueError('returned record identity/deadline differs')
            mapped.append(matches[0])
        check(owner+'-answer-reverse-actual-walk',mapped,list(reversed(walk)))
        check(owner+'-postlookup-lru-equals-answer',after['lru'],mapped)
        check(owner+'-chain-unchanged-by-lookup',after['chains'],before['chains'])
        check(owner+'-subsequent-T-equals-lru',post['lru'],after['lru'])
        check(owner+'-lookup-counter',counters,[3,0])
        check(owner+'-metadata-counter',after['counter'],counters)
        actual_t=[line for line in lines if line.startswith(owner+' T')]
        if len(actual_t)!=2:raise ValueError('missing original T rows')
        check(owner+'-pre-T-source-row',tokens(actual_t[0])[0],pre['lru'])
        check(owner+'-post-T-source-row',tokens(actual_t[1])[0],post['lru'])
    return checks,{'mix':next(iter(mixes)),'name_buckets':by_name}


def collect(args):
    receipt=validate_source(args.source_receipt,args.rust_source_root)
    binding=rust_lib_probe.validate(args.rust_test_binary,args.rust_source_root,args.rust_build_receipt)
    c=c_binding(args.source_receipt,args.c_baseline,args.fresh_c_receipt)
    run=json.loads((args.rust_run/'run-receipt.json').read_text())
    if [row['case'] for row in run['cases']] != [row['label'] for row in corpus.cases()]:
        raise ValueError('complete original21 Rust case inventory required')
    if (run['source_receipt_sha256']!=sha(args.source_receipt) or run['rust_probe']!=binding
            or run['fresh_c']!=c or run['tool_sha256']!=sha(__file__) or len(run['cases'])!=21):
        raise ValueError('complete source/build/fresh-C run receipts required')
    evidence=[];fingerprints=[]
    for label in ['native','target']:
        for repeat in range(3):
            folder=args.c_baseline/CASE;stem=f'{label}-{repeat}'
            lines=(folder/(stem+'.stdout')).read_text().splitlines()
            events=[json.loads(line) for line in (folder/(stem+'.sidecar.jsonl')).read_text().splitlines()]
            checks,fp=ordered_relations(lines,events)
            evidence.append({'runtime':stem,'checks':checks,'passed':all(row['passed'] for row in checks),
                'stdout_sha256':sha(folder/(stem+'.stdout')),'sidecar_sha256':sha(folder/(stem+'.sidecar.jsonl'))})
            fingerprints.append({'runtime':stem,**fp})
    for row in run['cases']:
        folder=args.rust_run/row['case']
        if (row['exit']!=0 or sha(folder/'stdout')!=row['stdout_sha256'] or sha(folder/'stderr')!=row['stderr_sha256']
                or sha(folder/'sidecar.jsonl')!=row['sidecar_sha256']):raise ValueError('Rust raw run receipt differs')
    folder=args.rust_run/CASE;stdout=(folder/'stdout').read_text()
    rust_lib_probe.require_one_test(stdout,TEST)
    lines=rust_lib_probe.records(stdout,TEST,('P0 ','P1 ','R ','CH ','P2 '))
    events=[json.loads(line) for line in (folder/'sidecar.jsonl').read_text().splitlines()]
    checks,fp=ordered_relations(lines,events)
    evidence.append({'runtime':'rust','checks':checks,'passed':all(row['passed'] for row in checks),
        'stdout_sha256':sha(folder/'stdout'),'sidecar_sha256':sha(folder/'sidecar.jsonl')})
    fingerprints.append({'runtime':'rust',**fp})
    strict={}
    for label in ['native','target']:
        for repeat in range(3):
            expected=(args.c_baseline/CASE/f'{label}-{repeat}.stdout').read_text().splitlines()
            if len(expected)!=12 or len(lines)!=12:raise ValueError('original12 count differs')
            strict[f'{label}-{repeat}']=[{'row':i,'c':left,'rust':right} for i,(left,right) in enumerate(zip(expected,lines)) if left!=right]
    # Negative controls alter a single ordered state, a bucket, and completeness.
    controls=[]
    for control in ['wrong-lru','wrong-bucket','missing-snapshot']:
        bad=copy.deepcopy(events)
        if control=='wrong-lru':
            item=next(row for row in bad if row['event']=='snapshot' and row['owner']=='CH' and row['op']=='A' and row['when']=='after')
            item['lru'][0],item['lru'][1]=item['lru'][1],item['lru'][0]
        elif control=='wrong-bucket':next(row for row in bad if row['event']=='bucket')['bucket']^=1
        else:bad.remove(next(row for row in bad if row['event']=='snapshot' and row['owner']=='P2' and row['op']=='A' and row['when']=='before'))
        try:
            tested,_=ordered_relations(lines,bad);rejected=not all(row['passed'] for row in tested)
        except (ValueError,KeyError):rejected=True
        controls.append({'control':control,'rejected':rejected})
    passed=all(row['passed'] for row in evidence) and all(row['rejected'] for row in controls)
    result={'schema':1,'source_commit':receipt['source_commit'],'source_receipt_sha256':sha(args.source_receipt),
        'rust_probe':binding,'fresh_c':c,'ordered_relation_gate_passed':passed,'evidence':evidence,
        'mix_and_actual_name_buckets':fingerprints,'strict_original12_comparisons':strict,'negative_controls':controls,
        'full_original_primitive_passed':False,'product_cpu_pss_qualification':False,
        'scope':'existing12 ordered source relations on actual diagnostic layout only; strict differences retained; not7profile pressure/completeprimitive'}
    save(args.out,result);print(json.dumps({'ordered_relation_gate_passed':passed,'full_original_primitive_passed':False}));return int(not passed)


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    prep=sub.add_parser('prepare');prep.add_argument('--repository',type=Path,required=True);prep.add_argument('--source-commit',required=True)
    prep.add_argument('--reference-source',type=Path,required=True);prep.add_argument('--out',type=Path,required=True)
    for name in ['run-rust','collect']:
        run=sub.add_parser(name)
        for key in ['source-receipt','rust-source-root','rust-test-binary','rust-build-receipt','c-baseline','fresh-c-receipt','out']:
            run.add_argument('--'+key,type=Path,required=True)
        if name=='collect':run.add_argument('--rust-run',type=Path,required=True)
    args=parser.parse_args()
    return {'prepare':prepare,'run-rust':run_rust,'collect':collect}[args.action](args)


if __name__=='__main__':raise SystemExit(main())
