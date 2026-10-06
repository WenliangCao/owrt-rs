#!/usr/bin/env python3
"""Controlled C rendering at signed display boundaries, not daemon exhaustion."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(args):
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        raise SystemExit('run only through run_isolated.sh')
    out = args.output.resolve()
    if out.exists() or 'private' not in out.parts: raise SystemExit('fresh private output required')
    out.mkdir(parents=True)
    source = re.sub(r'\s+', '', args.reference_cache.read_text())
    for fragment in ['int display_id = daemon->log_display_id;',
                     'proto = (display_id < 0) ? "TCP " : "UDP ";',
                     'if (display_id < 0) display_id = -display_id;',
                     'my_syslog(LOG_INFO, "%s%u %s %s%s%s %s%s", proto, display_id']:
        assert re.sub(r'\s+', '', fragment) in source
    driver = Path(__file__).with_name('logging_id_wrap.c')
    shutil.copy2(driver, out/driver.name);shutil.copy2(args.reference_cache, out/'reference-cache.c')
    rows = []
    for optimisation in ['-Os', '-O2']:
        elf = out/('probe-' + optimisation[1:])
        command = [str(args.cc), optimisation, '-static', str(driver), '-o', str(elf)]
        result = subprocess.run(command, capture_output=True)
        (out/('compile-' + optimisation[1:] + '.stdout')).write_bytes(result.stdout)
        (out/('compile-' + optimisation[1:] + '.stderr')).write_bytes(result.stderr)
        result.check_returncode()
        for value in [0, 1, 0xffffffff, 0x7fffffff, 0x80000000]:
            result = subprocess.run([str(elf), str(value)], capture_output=True)
            result.check_returncode()
            rows.append({'optimisation': optimisation, 'display_word': value,
                         'stdout_hex': result.stdout.hex(), 'stderr_hex': result.stderr.hex(), 'elf_sha256': sha(elf)})
    report = {'kind': 'matching-C-source-control', 'source': 'cache.c:2496-2509',
              'reference_cache_sha256': sha(args.reference_cache), 'driver_sha256': sha(driver), 'rows': rows,
              'actual_daemon_counter_exhaustion_executed': False,
              'scope': 'The exact C signed-negation and unsigned-display expressions, compiled with the SDK at Os/O2. No packet load and no patched daemon state. Rust uses explicit wrapping at counter and parent-reservation boundaries; its unsigned_abs display avoids the C undefined signed arithmetic.'}
    (out/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'source_controls': len(rows), 'renderings': [bytes.fromhex(row['stdout_hex']).decode().strip() for row in rows[:5]]}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc', type=Path, required=True);parser.add_argument('--reference-cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    main(parser.parse_args())
