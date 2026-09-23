#!/usr/bin/env python3
"""R134 router windows: C (stock) vs one candidate per component, ABBA x4
(8 windows per side) in private namespaces on the all-C AX3000T; production
is never switched. Stops at the first failing component.
Usage: device_matrix.py OUTPUT_DIR COMPONENT=BINARY..."""
import datetime, hashlib, json, pathlib, subprocess, sys
root = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / 'tools'))
from r84_device_probe import probe
MATRIX = {'httpd', 'rpcd', 'procd', 'ubusd', 'netifd'}
out = pathlib.Path(sys.argv[1]).resolve()
pairs = [a.split('=', 1) for a in sys.argv[2:]]
out.mkdir(mode=0o700, parents=True, exist_ok=False)
subjects = {}
for comp, binary in pairs:
    b = pathlib.Path(binary).resolve()
    subjects[comp] = {'path': str(b), 'sha256': hashlib.sha256(b.read_bytes()).hexdigest(), 'bytes': b.stat().st_size}
(out / 'candidates.json').write_text(json.dumps(subjects, indent=2) + '\n')
(out / 'health-before.json').write_text(json.dumps(probe(mode='stock', interface='en0'), indent=2) + '\n')
results = []
for comp, binary in pairs:
    cmd = [sys.executable, 'tools/benchmark/run_candidate.py', subjects[comp]['path'], str(out / comp),
           '--component', comp, '--interface', 'en0', '--access', 'wifi', '--stack', 'stock',
           '--sides', 'stock', 'candidate', '--schedule', 'two-side-balanced', '--repeats', '4']
    if comp in MATRIX:
        cmd.append('--matrix')
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(json.dumps({'step': comp, 'at': start}), flush=True)
    with (out / (comp + '.log')).open('xb') as log:
        rc = subprocess.run(cmd, cwd=root, stdout=log, stderr=subprocess.STDOUT).returncode
    results.append({'step': comp, 'exit': rc, 'started': start,
                    'ended': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'command': cmd})
    (out / 'driver-results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps({'step': comp, 'exit': rc}), flush=True)
    if rc:
        (out / 'FAILED').touch()
        raise SystemExit(rc)
(out / 'health-after.json').write_text(json.dumps(probe(mode='stock', interface='en0'), indent=2) + '\n')
(out / 'COMPLETE').touch()
print('COMPLETE', flush=True)
