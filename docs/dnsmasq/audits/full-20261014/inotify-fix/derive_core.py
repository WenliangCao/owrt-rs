import hashlib,json,re,tarfile
from pathlib import Path
base=Path('.')
archive=base/'private/inotify-core-20261014/evidence-complete.tar.gz'
expected='9993148e0cf57c714666f1bcce8e3cf6f2e77a2cbc9938fadf4cfc2137ffd01f'
assert hashlib.sha256(archive.read_bytes()).hexdigest()==expected
out=base/'docs/dnsmasq/audits/full-20261014/inotify-fix';out.mkdir(parents=True,exist_ok=True)
with tarfile.open(archive) as t:
 def raw(name):return t.extractfile(name).read()
 def data(name):return json.loads(raw(name))
 def digest(name):return hashlib.sha256(raw(name)).hexdigest()
 units=[]
 for name,kind in [('unit-lib-core.log','musl library'),('unit-bin-core.log','musl binary'),('allocator-core.log','native allocator')]:
  m=re.search(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored',raw(name).decode());assert m,name
  units.append(dict(kind=kind,passed=int(m[1]),failed=int(m[2]),ignored=int(m[3]),log=name,sha256=digest(name)))
 tcp=data('core-tcp-hup/result.json');snap=data('core-tcp-snapshot/result.json');hup=data('core-held-hup-cache/result.json')
 elf='edb5b4f91bac4486dd006400adc0c65380e0ec6fc36d36115d5ebc9475d3276d'
 for r in [tcp,snap,hup]:assert r['rust_sha256']==elf
 assert snap['matched'] and all(r['alive'] for r in snap['runs'])
 tcp_rows=[]
 for c in tcp['runs']:
  events={k:int(v) for k,v in (line.split() for line in c['final_cgroup']['memory.events'].splitlines())}
  assert len(c['connections'])==20 and c['udp_after'] and all(v==0 for v in events.values())
  tcp_rows.append(dict(side=c['side'],connections=len(c['connections']),hup_old_answers=len(c['hup']['old_answers']),hup_new_answers=len(c['hup']['new_answers']),peak_bytes=int(c['final_cgroup']['memory.peak']),memory_events=events,udp_after=c['udp_after'],exit=c['exit'],cgroup_removed=c['cgroup_removed']))
 hup_rows=[{k:v for k,v in c.items() if not isinstance(v,(list,dict))} for c in hup['cases']]
 assert all(c['passed'] and c['hup_cache_purged'] and c['held_tcp_snapshot_stable'] and c['rust_atomic_samples'] and c['rust_tcp_atomic_samples'] for c in hup_rows if c['side']=='rust')
 assert len([c for c in hup_rows if c['side']=='rust'])==3
 record=dict(source_commit='340ed73e83e58ba845e0a645eb21e9ead0d0f108',elf_sha256=elf,oracle_root='/dev/shm/full-inotify-fix-20261014/private',unit_tests=units,build=data('release-final/build.json'),test_build=data('tests-core/build.json'),suite_exits=data('core-suite.json'),tcp64_hup=tcp_rows,snapshots=dict(matched=snap['matched'],observations_per_side=[len(c['observations']) for c in snap['runs']]),held_hup_cache=dict(paired_driver_passed=hup['passed'],candidate_all_three_passed=True,cases=hup_rows,classification='Paired driver exit1 retained: exact C ready UDP timeouts at256/512KiB and freshTCP shortframes at all3 headrooms; C survived and recovered. All new Rust cases passed.'),raw_backup=dict(path=str(archive),sha256=expected,bytes=archive.stat().st_size,excluded='reproducible staged rootfs-overlay directories'),result_hashes={name:digest(name) for name in ['core-tcp-hup/result.json','core-tcp-snapshot/result.json','core-held-hup-cache/result.json']},commands={name:data(name) for name in ['core-tcp-hup.command.json','core-tcp-snapshot.command.json','core-held-hup-cache.command.json']})
 (out/'core.json').write_text(json.dumps(record,indent=2)+'\n')
 (out/'run_core.py').write_bytes(raw('run_core.py'))
print('Derived new candidate core receipts from verified archive')
