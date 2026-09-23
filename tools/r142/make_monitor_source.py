#!/usr/bin/env python3
"""Freeze one monitor-only source candidate; do not build or run it."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

PROOF_SHA = '50a4b4433f68ca9af7690512720cae69d83a1ec3e9c4f0f9f7204195ef1e9503'
CONTROL_SHA = 'ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330'
SERVER = 'ubusd/src/server.rs'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace(text, old, new, count=1):
    if text.count(old) != count:
        raise ValueError(f'expected {count} occurrences: {old[:80]}')
    return text.replace(old, new)


def monitor_source(text):
    text = replace(text, '    monitors: Vec<(u32, u16)>,', '''    monitors: Vec<(u32, u16)>,
    /// Independent mirror storage: lazy so an unmonitored daemon allocates
    /// nothing here. Like C's static mb, retain capacity after a large frame.
    monitor_scratch: Option<BlobBuf>,''')
    text = replace(text, '            monitors: Vec::new(),',
                   '            monitors: Vec::new(),\n            monitor_scratch: None,')
    text = replace(text, '&mut self.monitors, &mut self.touched,',
                   '&mut self.monitors, &mut self.monitor_scratch, &mut self.touched,', 7)
    start = text.index('    fn mirror(')
    end = text.index('\n}\n\n/// The type', start)
    return text[:start] + '''    fn mirror(clients: &mut HashMap<u32, Box<Client>>, monitors: &mut [(u32, u16)], scratch: &mut Option<BlobBuf>, touched: &mut Vec<u32>, client: u32, header: &Header, blob: &[u8], send: bool) {
        if monitors.is_empty() {
            return;
        }
        // Keep mirror assembly separate: blob may borrow Server::scratch.
        let b = scratch.get_or_insert_with(BlobBuf::new);
        b.reset();
        // attribute order as ubusd_monitor_message puts them: CLIENT, PEER,
        // SEQ, TYPE, SEND, DATA
        b.put_u32(0, client); // UBUS_MONITOR_CLIENT
        b.put_u32(1, header.peer); // UBUS_MONITOR_PEER
        b.put_u32(3, header.seq as u32); // UBUS_MONITOR_SEQ
        b.put_u32(4, header.ty as u32); // UBUS_MONITOR_TYPE
        b.put_u8(2, u8::from(send)); // UBUS_MONITOR_SEND
        b.put(5, if blob.len() > 4 { &blob[4..] } else { &[] }); // UBUS_MONITOR_DATA
        let payload = b.as_bytes();

        // monitor.add removes the old entry before appending a unique id.
        // Client sends cannot mutate this list or recursively mirror frames.
        for (m, seq) in monitors {
            *seq = seq.wrapping_add(1);
            if let Some(c) = clients.get_mut(m) {
                c.send_borrowed(Header { ty: ty::MONITOR, seq: *seq, peer: 0 }, payload, None);
                touched.push(*m);
            }
        }
    }''' + text[end:]


def main():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--components', type=Path, default=root / 'components')
    parser.add_argument('--source-proof', type=Path, default=root / 'private/r140/build-01/frozen-plan.json')
    parser.add_argument('--output', type=Path, default=root / 'private/r142/source-01')
    args = parser.parse_args()
    proof_bytes = args.source_proof.read_bytes()
    if sha(proof_bytes) != PROOF_SHA:
        parser.error('expected the frozen R140 same-source proof')
    proof = json.loads(proof_bytes)
    sources = proof['variants'][0]['source_sha256']
    if len(sources) != 30 or any(v['source_sha256'] != sources for v in proof['variants']):
        parser.error('expected one exact 30-file source snapshot')
    data = {name: (args.components / name).read_bytes() for name in sources}
    if any(sha(data[name]) != digest for name, digest in sources.items()):
        parser.error('input source differs from generic R136/R140/R141')
    candidate = data.copy()
    regression = Path(__file__).with_name('monitor_regression.rs').read_bytes()
    changed = monitor_source(data[SERVER].decode())
    marker = '    #[cfg(target_os = "linux")]\n    #[test]\n    fn monitored_event_fanout_keeps_one_mirror_per_frame()'
    candidate[SERVER] = replace(changed, marker, regression.decode() + marker).encode()
    args.output.mkdir(parents=True, exist_ok=False)
    records = []
    for label, files in [('control', data), ('monitor', candidate)]:
        dest = args.output / label / 'components'
        for name, content in files.items():
            path = dest / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        records.append({'label': label, 'components': str(dest.resolve()),
                        'source_sha256': {name: sha(content) for name, content in files.items()},
                        'expected_sha256': CONTROL_SHA if label == 'control' else None})
    diff = ''.join(difflib.unified_diff(data[SERVER].decode().splitlines(True),
                                      candidate[SERVER].decode().splitlines(True),
                                      fromfile='a/' + SERVER, tofile='b/' + SERVER))
    (args.output / 'candidate.diff').write_text(diff)
    (args.output / 'sources.json').write_text(json.dumps({
        'schema': 1, 'scope': 'R142 monitor assembly and borrowed direct send only; unbuilt',
        'source_proof_sha256': PROOF_SHA, 'generator_sha256': sha(Path(__file__).read_bytes()),
        'regression_source_sha256': sha(regression),
        'changed_files': [SERVER], 'candidate_diff_sha256': sha(diff.encode()),
        'variants': records}, indent=2) + '\n')


if __name__ == '__main__':
    main()
