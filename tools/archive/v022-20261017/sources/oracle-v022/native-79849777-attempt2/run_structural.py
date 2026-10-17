import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import tomllib

ROOT=Path('/srv/owrt-archive/dnsmasq-work')
OUT=ROOT/'private/native-79849777-attempt2'
SOURCE=ROOT/'source-79849777-attempt2'
CARGO='/srv/owrt-archive/cargo/bin/cargo'
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
identity=json.loads((OUT/'source-manifest.json').read_text())
assert identity['commit']=='79849777dc07fe4c91535343342359050db28428'
assert sha(OUT/'git-source.tar')==identity['archive_sha256']
assert SOURCE.is_dir()
for name,digest in identity['files'].items():assert sha(SOURCE/name)==digest,name
# The standalone platform crate has no committed lock of its own. Derive its
# lock from the frozen parent lock, removing only the two unrelated local roots.
lock=SOURCE/'components/dnsmasq/Cargo.lock'
sections=lock.read_text().split('[[package]]')
platform_lock=sections[0]+''.join('[[package]]'+section for section in sections[1:] if tomllib.loads('[[package]]'+section)['package'][0]['name'] not in ('dnsmasq-rs','owrt-ubus'))
assert (SOURCE/'components/dnsmasq/platform/Cargo.lock').read_text() == platform_lock
assert all(p.get('source') is None or p in tomllib.loads(lock.read_text())['package'] for p in tomllib.loads(platform_lock)['package'])
base_env=os.environ.copy()
for key in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET','CARGO_TARGET_DIR','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC','LLVM_PROFILE_FILE'):
    base_env.pop(key,None)
base_env.update(PATH='/srv/owrt-archive/cargo/bin:'+base_env['PATH'],RUSTUP_TOOLCHAIN='1.98.1',CARGO_HOME='/srv/owrt-archive/cargo',RUSTUP_HOME='/srv/owrt-archive/rustup',RUSTFLAGS='-Dwarnings',CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='2',CARGO_TARGET_DIR=str(OUT/'target'),TMPDIR=str(OUT/'tmp'))
(OUT/'tmp').mkdir(exist_ok=True)
report={'status':'running','commit':identity['commit'],'source_digest':identity['source_digest'],'source_files':identity['files_count'],'source_archive_sha256':identity['archive_sha256'],'host':subprocess.check_output(['uname','-a'],text=True).strip(),'rustc':subprocess.check_output(['/srv/owrt-archive/cargo/bin/rustc','+1.98.1','-Vv'],text=True).strip(),'platform_derived_lock_sha256':sha(SOURCE/'components/dnsmasq/platform/Cargo.lock'),'phases':[],'pgo':False,'router':False,'correctness44_67':False}
def save(): (OUT/'structural-summary.json').write_text(json.dumps(report,indent=2)+'\n')
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
platform_manifest=str(SOURCE/'components/dnsmasq/platform/Cargo.toml')
common=[CARGO,'test','--locked','--offline','--target','aarch64-unknown-linux-gnu','--manifest-path',manifest]
tests=[
('dhcp-device','--lib','dhcp::service::tests::device_binding_linux_sockets_retry_and_relay_gate'),
('dhcp-ack','--lib','dhcp::service::tests::socket_listener_processes_local_ack_and_replies_to_peer'),
('dhcp-pktinfo','--lib','dhcp::service::tests::receive_once_admits_loopback_pktinfo_and_preserves_addresses'),
('dhcp-v6-reject','--lib','dhcp::service::tests::receive_once_rejects_ipv6_for_dhcpv4'),
('dhcp-poll','--lib','dhcp::service::tests::poll_once_is_nonblocking_and_stop_aware'),
('interface-snapshot','--lib','interfaces::linux::tests::isolated_loopback_snapshot_matches_kernel_configuration'),
('listener-metadata','--lib','listeners::tests::dns_socket_bound_ipv4_metadata_policy'),
('tftp-port-range','--lib','tftp_listener::tests::port_range_upper_bound_exhaustion_and_zero_start'),
('tftp-tid','--lib','tftp_listener::tests::dedicated_tid_idle_tick_and_cleanup_on_ipv4_and_ipv6'),
('tftp-capacity','--lib','tftp_listener::tests::integrated_dual_stack_shares_capacity_and_pending_mac_does_not_block'),
('tftp-reject-name','--bin','tftp_admission_tests::tftp_live_name_rejects_old_ipv6_name_after_the_shared_collector'),
('tftp-label','--bin','tftp_admission_tests::tftp_label_exception_resumes_the_original_rrq_without_another_packet'),
('tftp-static','--bin','tftp_admission_tests::tftp_static_ipv4_keeps_its_cached_owner_and_dedicated_keeps_its_live_name')]
failures=[]
commands=[('platform-tests',[CARGO,'test','--locked','--offline','--target','aarch64-unknown-linux-gnu','--manifest-path',platform_manifest,'--','--test-threads=1'])]
commands += [('ignored-'+name,[*common,kind,*(['dnsmasq-rs'] if kind=='--bin' else []),test,'--','--exact','--ignored','--test-threads=1']) for name,kind,test in tests]
for name,args in commands:
    try:run(name,args,isolated=True,timeout=300)
    except (AssertionError,subprocess.TimeoutExpired) as error:
        failures.append({'phase':name,'error':repr(error)})
for name,digest in identity['files'].items():assert sha(SOURCE/name)==digest,name
assert sha(SOURCE/'components/dnsmasq/platform/Cargo.lock')==report['platform_derived_lock_sha256']
report.update(status='failed' if failures else 'passed',failures=failures,source_unchanged=True)
save()
raise SystemExit(bool(failures))
