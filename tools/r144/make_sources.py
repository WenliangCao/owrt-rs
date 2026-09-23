#!/usr/bin/env python3
"""Generate one caller reply-borrow candidate from the exact historical inputs."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

BASE_SHA = '46e1f79c01e685e3b92017b0983a3a105c159cd0d80bc6607734a9b8f6ed58c2'
CONN = 'components/ubus/src/conn.rs'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace(text, old, new):
    assert text.count(old) == 1, old[:80]
    return text.replace(old, new)


def main():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, default=root / 'private/r144/base-01')
    parser.add_argument('--output', type=Path, default=root / 'private/r144/source-01')
    args = parser.parse_args()
    proof = (args.base / 'sources.json').read_bytes()
    assert sha(proof) == BASE_SHA
    expected = json.loads(proof)['source_sha256']
    assert len(expected) == 18
    control = {name: (args.base / 'root' / name).read_bytes() for name in expected}
    assert all(sha(control[name]) == digest for name, digest in expected.items())
    candidate = control.copy()
    text = control[CONN].decode()
    start = text.index('        loop {\n            let mut message = self.recv_until(deadline)?;', text.index('    fn request_until('))
    end = text.index('\n    }\n\n    /// Resolve an object path', start)
    text = text[:start] + '''        loop {
            let (header, fd, body) = self.take_frame(false, deadline)?
                .expect("a waiting frame read yields a frame");
            if header.seq == seq && header.peer == peer && matches!(header.ty, ty::DATA | ty::STATUS) {
                // Only pending messages need an intermediate owned Message.
                // A matching DATA owns its final payload once; STATUS only
                // needs its scalar and descriptor before this body is reused.
                let bytes = match &body {
                    Body::Buffered(range) => &self.rx[range.clone()],
                    Body::Owned(blob) => blob.as_slice(),
                };
                if header.ty == ty::DATA {
                    reply.data.push(bytes[4..].to_vec());
                } else {
                    reply.status = Message::attrs_from(bytes)[attr::STATUS as usize]
                        .and_then(|a| a.as_u32().map(|v| v as i32))
                        .unwrap_or(status::INVALID_ARGUMENT);
                    reply.fd = fd;
                    return Ok(reply);
                }
            } else {
                self.pending.push_back(Message { header, blob: self.blob_of(body), fd });
            }
        }''' + text[end:]
    regression = Path(__file__).with_name('reply_regression.rs').read_bytes()
    marker = '    #[test]\n    fn request_deadline_covers_partial_header_and_body()'
    text = replace(text, marker, regression.decode() + marker)
    candidate[CONN] = text.encode()
    args.output.mkdir(parents=True, exist_ok=False)
    records = []
    for label, data in [('control', control), ('candidate', candidate)]:
        dest = args.output / label / 'root'
        for name, content in data.items():
            path = dest / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        records.append({'label': label, 'root': str(dest.resolve()),
                        'source_sha256': {name: sha(content) for name, content in data.items()}})
    diff = ''.join(difflib.unified_diff(control[CONN].decode().splitlines(True), text.splitlines(True),
                                      fromfile='a/' + CONN, tofile='b/' + CONN))
    (args.output / 'candidate.diff').write_text(diff)
    (args.output / 'sources.json').write_text(json.dumps({'schema': 1, 'base_manifest_sha256': BASE_SHA,
        'generator_sha256': sha(Path(__file__).read_bytes()), 'regression_sha256': sha(regression),
        'sole_changed_file': CONN, 'diff_sha256': sha(diff.encode()), 'variants': records}, indent=2) + '\n')


if __name__ == '__main__':
    main()
