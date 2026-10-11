"""Build and run the complete frozen ordinary unit suite in private namespaces."""
from pathlib import Path
import hashlib,json,os,subprocess,time
ROOT=Path('/home/ubuntu/dnsmasq-relro-hosts-20261011')
SOURCE=ROOT/'source'; OUT=ROOT/'private/units-01'
OUT.mkdir(exist_ok=False)
plan=json.loads((ROOT/'private/source-identity.json').read_text())
commands=[['sh',str(SOURCE/'tools/dnsmasq/oracle_build.sh'),str(SOURCE),str(OUT/'build'),'tests']]
report=dict(source_commit=plan['source_commit'],passed=False,commands=[])
def save(): (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
def run(name,argv):
    row=dict(name=name,argv=argv,started=time.time());report['commands'].append(row);save()
    with (OUT/(name+'.log')).open('wb') as log:
        row['returncode']=subprocess.run(argv,cwd=SOURCE,stdout=log,stderr=log).returncode
    row['log_sha256']=hashlib.sha256((OUT/(name+'.log')).read_bytes()).hexdigest()
    row['elapsed_seconds']=time.time()-row['started'];save()
    assert row['returncode']==0, row
run('build',commands[0])
report['build_receipt']=json.loads((OUT/'build/build.json').read_text())
for name in ['lib-dnsmasq_rs','bin-dnsmasq-rs']:
    binary=OUT/'build'/name
    run(name,['sudo','-n','sh',str(SOURCE/'tools/dnsmasq/run_isolated.sh'),'sh','-c',
        'mount -t tmpfs -o mode=1777 tmpfs /tmp; exec "$@"','unit',str(binary),'--test-threads=1'])
    report['commands'][-1]['elf_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest();save()
report['passed']=True;save();print(json.dumps(report))
