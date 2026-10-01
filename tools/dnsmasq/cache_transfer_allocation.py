#!/usr/bin/env python3
"""Untimed allocation audit of opt-in cache transaction capture.

Compare the unchanged pre-transfer commit with current ordinary commit, then
report the explicit capture cost. Reuse the existing standalone allocator
instrumentation; none is added to production source.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import dns_cache_diff

ROOT = Path(__file__).resolve().parents[2]
BASE_SHA = '8c73672d4ebe3959d8172cecf5b951afef61f23ec568c52b27f6b00ae081e9a5'
DRIVER = r'''
use cache::{Cache,CacheCounters,Policy,Record,Kind};
fn main() {
 let args:Vec<_>=std::env::args().collect(); let case=&args[1];
 let start=allocation::snapshot();
 let mut cache=Cache::new(128,Policy::default()); let mut counters=CacheCounters::default();
 cache.start_insert();
 let count=match case.as_str(){"empty"=>0,"one"=>1,"many"=>128,"dangling"=>1,"failed"=>2,_=>panic!()};
 for index in 0..count {
  let name=wire::Name::from_ascii(&format!("n{index}.test")).unwrap();
  let kind=if case=="dangling" {Kind::Cname}else{Kind::Ipv4};
  let record=Record{name,kind,negative:false,data:if kind==Kind::Cname{vec![]}else{vec![7;4]}};
  let result=cache.insert_counted(record,100,if case=="failed"&&index==1{0}else{60},&mut counters);
  assert_eq!(result.is_ok(),!(case=="failed"&&index==1));
 }
 let before=allocation::snapshot();
 #[cfg(capture)] let transfer=cache.capture_commit_counted(&mut counters);
 #[cfg(capture)] let committed=transfer.is_some();
 #[cfg(not(capture))] let committed=cache.commit_counted(&mut counters);
 let after=allocation::snapshot();
 std::hint::black_box(&cache);
 #[cfg(capture)] {std::hint::black_box(&transfer);drop(transfer);}
 drop(cache); let final_stats=allocation::snapshot();
 let delta:Vec<_>=(0..4).map(|index|after[index]-before[index]).collect();
 println!("{{\"committed\":{committed},\"inserted\":{},\"freed\":{},\"commit_allocation\":{delta:?},\"balance\":{},\"cache_bytes\":{}}}",
 counters.inserted,counters.live_freed,final_stats[3]-start[3],std::mem::size_of::<Cache>());
}
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-cache', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rustc', default='rustc')
    args = parser.parse_args()
    out = args.out.resolve()
    assert 'private' in out.parts
    out.mkdir(parents=True, exist_ok=False)
    assert sha(args.baseline_cache) == BASE_SHA
    allocator = (ROOT / 'tools/dnsmasq/cache_expiry_screen.rs').read_text()
    allocator = allocator[allocator.index('#[cfg(allocation_tracking)]'):allocator.index('#[repr(C)]')]
    report = {'scope': __doc__, 'baseline_cache_sha256': BASE_SHA,
              'current_cache_sha256': sha(ROOT / 'components/dnsmasq/src/dns/cache.rs'),
              'allocator_source_sha256': hashlib.sha256(allocator.encode()).hexdigest(),
              'tool_sha256': sha(Path(__file__)), 'runs': [], 'binaries': {}}
    for label in ['baseline', 'ordinary', 'capture']:
        source_root = out / label
        source = source_root / 'components/dnsmasq/src/dns'
        source.mkdir(parents=True)
        for name in ['cache.rs', 'wire.rs', 'lease_names.rs']:
            origin = args.baseline_cache if label == 'baseline' and name == 'cache.rs' else ROOT / 'components/dnsmasq/src/dns' / name
            shutil.copyfile(origin, source / name)
        driver = source_root / 'driver.rs'
        driver.write_text(dns_cache_diff.rust_modules(source_root) + allocator + DRIVER)
        binary = source_root / 'probe'
        command = [args.rustc, '+1.98.1', '--edition=2021', '-A', 'dead_code', '-O', '--cfg', 'allocation_tracking',
                   str(driver), '-o', str(binary)]
        if label == 'capture':
            command += ['--cfg', 'capture']
        build = subprocess.run(command, capture_output=True, text=True)
        (source_root / 'build.stdout').write_text(build.stdout)
        (source_root / 'build.stderr').write_text(build.stderr)
        (source_root / 'build-command.json').write_text(json.dumps({'argv': command, 'exit': build.returncode}, indent=2) + '\n')
        assert build.returncode == 0, label
        report['binaries'][label] = {'sha256': sha(binary), 'driver_sha256': sha(driver)}
        for case in ['empty', 'one', 'many', 'dangling', 'failed']:
            run = subprocess.run([str(binary), case], capture_output=True, text=True)
            (source_root / f'{case}.stdout').write_text(run.stdout)
            (source_root / f'{case}.stderr').write_text(run.stderr)
            assert run.returncode == 0
            report['runs'].append({'implementation': label, 'case': case, 'exit': run.returncode, **json.loads(run.stdout)})
    for case in ['empty', 'one', 'many', 'dangling', 'failed']:
        rows = {row['implementation']: row for row in report['runs'] if row['case'] == case}
        assert rows['baseline']['commit_allocation'] == rows['ordinary']['commit_allocation'], case
        for key in ['committed', 'inserted', 'freed', 'balance', 'cache_bytes']:
            assert len({row[key] for row in rows.values()}) == 1, (case, key)
        assert rows['ordinary']['balance'] == 0
    report['ordinary_allocation_matches_baseline'] = True
    report['status'] = 'passed-untimed-allocation-audit'
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'runs': len(report['runs'])}))


if __name__ == '__main__':
    main()
