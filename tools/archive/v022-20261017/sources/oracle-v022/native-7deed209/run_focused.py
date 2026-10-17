import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import tomllib

ROOT=Path('/srv/owrt-archive/dnsmasq-work')
OUT=ROOT/'private/native-7deed209'
SOURCE=ROOT/'source-7deed209'
CARGO='/srv/owrt-archive/cargo/bin/cargo'
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
identity=json.loads((OUT/'source-manifest.json').read_text())
assert identity['commit']=='7deed20953169e8988c982ca640ccd02edae22d0'
assert sha(OUT/'git-source.tar')==identity['archive_sha256']
assert not SOURCE.exists()
SOURCE.mkdir()
subprocess.run(['tar','-xf',str(OUT/'git-source.tar'),'-C',str(SOURCE)],check=True)
for name,digest in identity['files'].items():assert sha(SOURCE/name)==digest,name
base_env=os.environ.copy()
for key in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET','CARGO_TARGET_DIR','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC','LLVM_PROFILE_FILE'):
    base_env.pop(key,None)
base_env.update(PATH='/srv/owrt-archive/cargo/bin:'+base_env['PATH'],RUSTUP_TOOLCHAIN='1.98.1',CARGO_HOME='/srv/owrt-archive/cargo',RUSTUP_HOME='/srv/owrt-archive/rustup',RUSTFLAGS='-Dwarnings',CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='2',CARGO_TARGET_DIR=str(OUT/'target'),TMPDIR=str(OUT/'tmp'))
(OUT/'tmp').mkdir()
report={'status':'running','commit':identity['commit'],'source_digest':identity['source_digest'],'source_files':identity['files_count'],'source_archive_sha256':identity['archive_sha256'],'host':subprocess.check_output(['uname','-a'],text=True).strip(),'rustc':subprocess.check_output(['/srv/owrt-archive/cargo/bin/rustc','+1.98.1','-Vv'],text=True).strip(),'phases':[],'pgo':False,'router':False,'correctness44_67':False}
def save(): (OUT/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
save()
def run(name,args,isolated=False,timeout=600):
    if isolated:
        args=['sudo','-n','env',*[key+'='+base_env[key] for key in ('PATH','RUSTUP_TOOLCHAIN','CARGO_HOME','RUSTUP_HOME','RUSTFLAGS','CARGO_INCREMENTAL','CARGO_BUILD_JOBS','CARGO_TARGET_DIR','TMPDIR')],'sh',str(SOURCE/'tools/dnsmasq/run_isolated.sh'),*args]
    row={'name':name,'command':args,'isolated':isolated,'started':time.time()}
    report['phases'].append(row);save()
    with (OUT/(name+'.log')).open('wb') as stream:
        try:
            result=subprocess.run(args,cwd=SOURCE,env=base_env,stdout=stream,stderr=subprocess.STDOUT,timeout=timeout)
            row['returncode']=result.returncode
        except subprocess.TimeoutExpired:
            row['returncode']='timeout';raise
        finally:
            row['ended']=time.time();row['log_sha256']=sha(OUT/(name+'.log'));save()
    text=(OUT/(name+'.log')).read_text(errors='replace')
    clean=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',text)
    row['test_results']=[{'result':m[0],'passed':int(m[1]),'failed':int(m[2]),'ignored':int(m[3]),'measured':int(m[4]),'filtered':int(m[5])} for m in re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out',clean)]
    row['warning_lines']=[line for line in clean.splitlines() if re.match(r'^\s*warning(?:\[[^\]]+\])?:',line)]
    save()
    print(json.dumps({key:row[key] for key in ('name','returncode','test_results','warning_lines')}),flush=True)
    assert row['returncode']==0,name+' failed'
    assert not row['warning_lines'],name+' compiler warnings'
    if isolated: assert sum(r['passed'] for r in row['test_results'])>0,name+' selected no passing tests'


manifest=str(SOURCE/'components/dnsmasq/Cargo.toml')
common=[CARGO,'test','--locked','--offline','--target','aarch64-unknown-linux-gnu','--manifest-path',manifest]
main_tests=[
('main-hup-helper','hosts_initial_hup_tests::hup_during_first_hosts_fifo_keeps_dns_dhcp_and_helper_admission_closed'),
('main-resolver-helper','hostsdir_init_tests::polling_resolver_keeps_initial_hostsdir_dhcp_and_helper_work_behind_publication'),
('main-dhcp-helper','tests::frozen_dhcp_callbacks_resume_after_pipe_capacity_returns'),
('main-tftp-helper','tests::last_tftp_completion_wakes_helper_without_another_packet')]
try:
    run('compile-native-lib-main',[*common,'--lib','--bin','dnsmasq-rs','--no-run'])
    for name,test in main_tests:
        run(name,[*common,'--bin','dnsmasq-rs',test,'--','--exact','--test-threads=1'],isolated=True,timeout=180)
    run('focused-helper',[*common,'--lib','helper::','--','--test-threads=1'],isolated=True,timeout=180)
    run('focused-lookup',[*common,'--lib','config::dns::lookup::','--','--test-threads=1'],isolated=True,timeout=180)
    for name,digest in identity['files'].items():assert sha(SOURCE/name)==digest,name
    report['source_unchanged']=True;report['status']='passed'
except BaseException as error:
    report['status']='failed';report['error']=repr(error)
    raise
finally:
    save()
