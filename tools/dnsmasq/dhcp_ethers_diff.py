#!/usr/bin/env python3
"""Compare read-ethers generations with the matching C body and host observer.

Only the ethers file path is redirected; no listeners or system files change.
Raw inputs, generated probes, both outputs and every difference stay private.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

import dhcp_config_diff as base
import dhcp_host_config_diff as host


def c_driver(source):
    start = source.index('void dhcp_read_ethers(void)')
    brace = source.index('{', start); depth = 1; end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}'); end += 1
    body = source[start:end].replace('void dhcp_read_ethers(void)', 'static void fixture_read_ethers(void)')
    original = host.C_DRIVER
    begin = original.index('  int index=0;'); finish = original.index('  char context[8192]')
    printer = original[begin:finish]
    helpers = original[:original.index('static int decode(')]
    return helpers + '\n#undef ETHERSFILE\n#define ETHERSFILE fixture_path\nstatic const char *fixture_path;\n' + body + '''
int main(int argc, char **argv) {
  rand_init(); read_opts(argc, argv, "ethers-state");
  char path[8192]; int generation=0;
  while(fgets(path,sizeof(path),stdin)) {
    path[strcspn(path,"\\n")]=0; fixture_path=path;
    fixture_read_ethers(); printf("generation=%d\\n",generation++);
''' + printer + '\n  }\n  return 0;\n}\n'


def rust_driver():
    original = host.RUST_DRIVER
    begin = original.index(' for (i,c)'); finish = original.index(' for line in io::stdin()')
    printer = original[begin:finish].replace('dhcp.hosts.iter()', 'ethers.hosts().iter()')
    prefix = original[:begin]
    return prefix + '''
 let mut ethers=config::ethers::Ethers::new(&dhcp.hosts);
 for (generation,line) in io::stdin().lock().lines().enumerate() {
   let path=line.unwrap();let _=ethers.reload(Path::new(&path));
   println!("generation={generation}");
''' + printer + '\n }\n}\n'


def corpus():
    mac = '02:00:00:00:00:01'
    explicit = f'dhcp-host={mac},192.0.2.40,old'
    yield 'empty', explicit, ['', None]
    yield 'created-replaced', '', [f'{mac} 192.0.2.40\n', f'{mac} 192.0.2.41\n', '', None]
    yield 'inline-mutations-persist', explicit, [f'{mac} renamed\n', '', None]
    yield 'merge-address', 'dhcp-host=02:00:00:00:00:02,192.0.2.40,old', [f'{mac} 192.0.2.40\n']
    yield 'merge-name', 'dhcp-host=02:00:00:00:00:02,192.0.2.40,old', [f'{mac} OLD\n']
    yield 'duplicate-created', '', [f'{mac} 192.0.2.40\n02:00:00:00:00:02 192.0.2.40\n', f'{mac} One\n02:00:00:00:00:02 one\n']
    yield 'same-mac-joins-address-name', '', [f'{mac} 192.0.2.40\n{mac} Mixed.lan\n']
    for index, value in enumerate(['020000000001', '2:0:0:0:0:1', '02-00-00-00-00-01', '02:00:00:00:00:01:ff', '02:00:00:00:00:01:gg', 'gg:00:00:00:00:01', '02:00:00:00:00', ':020000000001']):
        yield f'mac-{index}', '', [f'{value} 192.0.2.40\n']
    for index, value in enumerate(['192.0.2.40', '192.0.2.040', '999.0.2.40', 'fixed.', 'Mixed.lan', '_bad', '-bad', 'bad name', 'a_b', 'a.b_c', '123', '', 'x' * 256]):
        yield f'value-{index}', '', [f'{mac} {value}\n']
    yield 'line-boundaries', '', ['#comment\n+nis\n\n 02:00:00:00:00:01 bad\n02:00:00:00:00:01 good\t \n02:00:00:00:00:02 nul\x00ignored\n']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference-build', type=Path, required=True)
    parser.add_argument('--rustc', default=shutil.which('rustc') or 'rustc')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(); args.c_only = True
    out = args.out.resolve(); assert 'private' in out.parts and not out.exists(); out.mkdir(parents=True)
    args.source = out / 'reference'
    args.source.mkdir()
    (args.source / 'src').symlink_to((args.reference_build / 'dnsmasq').resolve(), target_is_directory=True)
    source = args.reference_build / 'dnsmasq/dhcp.c'
    base.C_DRIVER = c_driver(source.read_text()); base.RUST_DRIVER = rust_driver()
    base.build(args, out)
    driver = base.RUST_DRIVER.replace('#[path = "CONFIG"] mod config;', 'use dnsmasq_rs::config;').replace('#[path = "HOSTS"] mod hosts;', '')
    (out / 'state.rs').write_text(driver)
    deps = base.ROOT / 'components/dnsmasq/target/debug/deps'
    libraries = list(deps.glob('libdnsmasq_rs-*.rlib'))
    assert len(libraries) == 1, libraries
    subprocess.run([args.rustc, '--edition=2021', '-A', 'unused_imports', str(out / 'state.rs'),
                    '--extern', 'dnsmasq_rs=' + str(libraries[0]), '-L', 'dependency=' + str(deps),
                    '-o', str(out / 'rust-state')], check=True)
    rows = []
    for index, (label, config, generations) in enumerate(corpus()):
        folder = out / f'{index:02}-{label}'; folder.mkdir()
        cfg = folder / 'config'; cfg.write_text(config + '\n')
        paths = []
        for generation, contents in enumerate(generations):
            path = folder / f'{generation}.ethers'; paths.append(str(path))
            if contents is not None: path.write_text(contents)
        stdin = ('\n'.join(paths) + '\n').encode()
        outputs = []
        for side in ('c', 'rust'):
            result = subprocess.run([str(out / (side + '-state')), '-C', str(cfg)], input=stdin, capture_output=True)
            (folder / (side + '.stdout')).write_bytes(result.stdout)
            (folder / (side + '.stderr')).write_bytes(result.stderr)
            outputs.append(result)
        left, right = outputs
        rows.append({'label': label, 'generations': len(generations), 'match': base.matches(left, right), 'c_exit': left.returncode, 'rust_exit': right.returncode})
    assert not base.matches(subprocess.CompletedProcess([], 0, b'host=0'), subprocess.CompletedProcess([], 0, b'host=1'))
    summary = {'cases': len(rows), 'generations': sum(row['generations'] for row in rows), 'failures': [row for row in rows if not row['match']],
               'source_sha256': base.sha(source), 'rows': rows}
    (out / 'result.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({key: value for key, value in summary.items() if key != 'rows'}))
    return int(bool(summary['failures']))


if __name__ == '__main__': raise SystemExit(main())
