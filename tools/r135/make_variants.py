#!/usr/bin/env python3
"""Materialize all eight R134 ablations outside the runtime working tree."""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import shutil
import subprocess

BASE = 'c84108b'
BASE_BINARY_SHA = '98d7ff9ddd04db45d9d71b8f7a4f317f193c3539752532c30f01075e0e7197c0'


def replace_once(path, old, new):
    text = path.read_text()
    if text.count(old) != 1:
        raise RuntimeError(f'expected one replacement in {path}')
    path.write_text(text.replace(old, new))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out', type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    if args.out.exists():
        raise RuntimeError('output must not already exist')
    args.out.mkdir(parents=True)
    # Use a committed snapshot, never uncommitted runtime edits.
    archive = subprocess.check_output(['git', '-C', str(repo), 'archive', BASE, 'components'])
    subprocess.run(['tar', '-xf', '-', '-C', str(args.out)], input=archive, check=True)
    source = args.out / 'components'
    previous = subprocess.check_output([
        'git', '-C', str(repo), 'show', '45a1947^:components/ubusd/src/sys.rs'
    ], text=True)
    original_random = previous[previous.index('/// getrandom(2) GRND_INSECURE:'):previous.index('fn sockaddr(')]
    variants = []
    for short, batch, keyed in itertools.product((0, 1), repeat=3):
        label = f's{short}b{batch}k{keyed}'
        dest = args.out / label / 'components'
        shutil.copytree(source, dest)
        client = dest / 'ubusd/src/client.rs'
        server = dest / 'ubusd/src/server.rs'
        sys = dest / 'ubusd/src/sys.rs'
        if not short:
            replace_once(client,
                'self.rx_drained = n < RX_SIZE - began && fd.is_none();',
                'self.rx_drained = false; // R135: probe until EAGAIN.')
        if not batch:
            replace_once(server, '''        if request.header.ty == ty::ADD_OBJECT && self.monitors.is_empty() {
            if let Some(c) = self.clients.get_mut(&client) {
                c.send_data_status_reply(header, &blob[..len]);
                self.touched.push(client);
            }
            return Outcome::NoStatus;
        }
''', '')
        if not keyed:
            text = sys.read_text()
            start = text.index('/// Generate ID candidates with a thread-local keyed counter hash')
            end = text.index('fn sockaddr(')
            sys.write_text(text[:start] + original_random + text[end:])
            replace_once(sys, '    fn umask(mask: u32) -> u32;',
                '    #[cfg(target_os = "linux")]\n    fn getrandom(buf: *mut u8, len: usize, flags: u32) -> isize;\n    fn umask(mask: u32) -> u32;')
        hashes = {str(p.relative_to(dest)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sorted(dest.rglob('*')) if p.is_file()}
        variants.append(dict(label=label, short_yield=bool(short), add_batch=bool(batch),
                             keyed_id=bool(keyed), source_sha256=hashes))
    shutil.rmtree(source)
    (args.out / 'variants.json').write_text(json.dumps(dict(
        base_commit=BASE, base_binary_sha256=BASE_BINARY_SHA, variants=variants), indent=2) + '\n')


if __name__ == '__main__':
    main()
