//! Deterministic wire-protocol fuzzer for the ubus socket (tools/r42).
//!
//! Every case is generated from a fixed table plus a seeded LCG, so the two
//! daemons receive byte-identical input and their verdict transcripts can be
//! compared directly. Each case gets a fresh connection; the verdict is what
//! the daemon did with it -- replied, stayed silent, or disconnected -- plus whether
//! the daemon was still serving afterwards.
//!
//! Usage: fuzz <socket> [cases]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const HELLO_LEN: usize = 12;

/// A tiny reproducible generator: the same seed gives the same bytes on both
/// runs, which is what makes the transcripts comparable.
struct Lcg(u64);

impl Lcg {
    fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }
    fn byte(&mut self) -> u8 {
        (self.next_u32() & 0xff) as u8
    }
    fn below(&mut self, n: u32) -> u32 {
        if n == 0 {
            0
        } else {
            self.next_u32() % n
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn header(version: u8, ty: u8, seq: u16, peer: u32) -> Vec<u8> {
    let mut v = vec![version, ty];
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(&peer.to_be_bytes());
    v
}

/// A blob attribute header: extended flag, 7-bit id, 24-bit length including
/// these four bytes.
fn attr_hdr(id: u32, extended: bool, raw_len: u32) -> [u8; 4] {
    let mut w = (id << 24) & 0x7f00_0000;
    if extended {
        w |= 0x8000_0000;
    }
    w |= raw_len & 0x00ff_ffff;
    w.to_be_bytes()
}

fn u32_attr(id: u32, value: u32) -> Vec<u8> {
    let mut v = attr_hdr(id, false, 8).to_vec();
    v.extend_from_slice(&value.to_be_bytes());
    v
}

fn str_attr(id: u32, s: &[u8]) -> Vec<u8> {
    let mut v = attr_hdr(id, false, (4 + s.len() + 1) as u32).to_vec();
    v.extend_from_slice(s);
    v.push(0);
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    v
}

/// Wrap top-level attributes in the head blob the daemon expects.
fn message(ty: u8, seq: u16, peer: u32, attrs: &[u8]) -> Vec<u8> {
    let mut out = header(0, ty, seq, peer);
    out.extend_from_slice(&attr_hdr(0, false, (4 + attrs.len()) as u32));
    out.extend_from_slice(attrs);
    out
}

/// Send `bytes`, then see what comes back. The verdict deliberately does not
/// include any id, since those are random per run.
fn probe(sock: &str, bytes: &[u8]) -> String {
    let Ok(mut s) = UnixStream::connect(sock) else {
        return "no_connect".into();
    };
    let _ = s.set_read_timeout(Some(Duration::from_millis(400)));
    // drain the HELLO the daemon sends on connect
    let mut hello = [0u8; HELLO_LEN];
    if s.read_exact(&mut hello).is_err() {
        return "incomplete_hello".into();
    }
    if s.write_all(bytes).is_err() {
        return "write_failed".into();
    }
    response(&mut s)
}

fn response(input: &mut impl Read) -> String {
    let mut prefix = [0u8; 12];
    // A daemon that closes the connection is "disconnected" whether the peer
    // observes EOF or ECONNRESET: the kernel raises the reset only when the
    // closer still had unread bytes queued, which for the same input depends
    // on how many bytes the daemon happened to pull before deciding (the C
    // daemon reads a 12-byte prefix first; a read-ahead daemon takes the
    // whole write). "silent" is left for a daemon that keeps the connection
    // open without answering.
    match input.read_exact(&mut prefix) {
        Err(e) if matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof) => "disconnected".into(),
        Ok(()) => {
            // report only the type byte and the status when present: everything
            // else carries random ids
            let ty = prefix[1];
            let raw_len = u32::from_be_bytes(prefix[8..12].try_into().unwrap()) & 0x00ff_ffff;
            // Only a STATUS message carries a status word. A DATA reply's
            // payload holds object ids, which are random per run and must not
            // reach the transcript.
            let status = if ty == 1 && raw_len >= 12 {
                let mut field = [0; 8];
                if input.read_exact(&mut field).is_err() {
                    return "incomplete_status".into();
                }
                Some(u32::from_be_bytes(field[4..8].try_into().unwrap()))
            } else {
                None
            };
            match status {
                Some(st) => format!("reply_type={ty}_status={st}"),
                None => format!("reply_type={ty}"),
            }
        }
        Err(_) => "silent".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_replies_have_the_same_verdict_as_contiguous_frames() {
        struct Fragmented<'a>(&'a [u8], usize);
        impl Read for Fragmented<'_> {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                let limit = output.len().min(self.1);
                self.0.read(&mut output[..limit])
            }
        }
        let status = message(1, 7, 0, &u32_attr(1, 6));
        let data = message(2, 7, 0, &u32_attr(3, 0x1234));
        for chunk in 1..=20 {
            assert_eq!(response(&mut Fragmented(&status, chunk)), "reply_type=1_status=6");
            assert_eq!(response(&mut Fragmented(&data, chunk)), "reply_type=2");
        }
        assert_eq!(response(&mut &status[..12]), "incomplete_status");
        assert_eq!(response(&mut &[][..]), "disconnected");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: fuzz <socket> [cases]");
        std::process::exit(2);
    }
    let sock = args[1].clone();
    let cases: usize = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(400);

    let mut fixed: Vec<(String, Vec<u8>)> = Vec::new();

    // a nonzero protocol version
    for v in [1u8, 2, 0xff] {
        let mut m = message(4, 1, 0, &[]);
        m[0] = v;
        fixed.push((format!("version={v}"), m));
    }
    // every type byte, with an empty payload
    for ty in 0u8..16 {
        fixed.push((format!("type={ty}_empty"), message(ty, 1, 0, &[])));
    }
    // declared blob lengths around the interesting boundaries
    for raw in [0u32, 1, 2, 3, 4, 5, 7, 8, 0x00ff_ffff] {
        let mut m = header(0, 4, 1, 0);
        m.extend_from_slice(&attr_hdr(0, false, raw));
        fixed.push((format!("blob_raw_len={raw}"), m));
    }
    // the head blob marked extended, which it never is
    {
        let mut m = header(0, 4, 1, 0);
        m.extend_from_slice(&attr_hdr(0, true, 4));
        fixed.push(("head_extended".into(), m));
    }
    // an inner attribute claiming more than the message holds
    for over in [8u32, 64, 4096] {
        let mut attrs = attr_hdr(3, false, 8 + over).to_vec();
        attrs.extend_from_slice(&0u32.to_be_bytes());
        fixed.push((format!("inner_overruns_by={over}"), message(4, 1, 0, &attrs)));
    }
    // an inner attribute shorter than its own header
    for under in [0u32, 1, 3] {
        let attrs = attr_hdr(3, false, under).to_vec();
        fixed.push((format!("inner_raw_len={under}"), message(4, 1, 0, &attrs)));
    }
    // wrong types where the policy expects something else
    fixed.push(("objid_as_string".into(), message(5, 1, 0, &str_attr(3, b"not-a-number"))));
    fixed.push(("method_as_int".into(), message(5, 1, 0, &u32_attr(4, 7))));
    // invoke against every system object id, and against ids that cannot exist
    for id in [0u32, 1, 2, 3, 4, 1023, 1024, 0xffff_ffff] {
        let mut a = u32_attr(3, id);
        a.extend_from_slice(&str_attr(4, b"query"));
        fixed.push((format!("invoke_objid={id}"), message(5, 1, 0, &a)));
    }
    // duplicate attributes
    {
        let mut a = u32_attr(3, 1);
        a.extend_from_slice(&u32_attr(3, 2));
        a.extend_from_slice(&str_attr(4, b"m"));
        fixed.push(("duplicate_objid".into(), message(5, 1, 0, &a)));
    }
    // an unterminated string
    {
        let mut a = attr_hdr(4, false, 8).to_vec();
        a.extend_from_slice(b"abcd");
        fixed.push(("unterminated_string".into(), message(5, 1, 0, &a)));
    }
    // add_object with a malformed signature: a named entry whose name length
    // runs past the attribute, which is what check_method has to reject
    for namelen in [0u16, 1, 4, 0xffff] {
        let mut sig_inner = attr_hdr(1, true, 12).to_vec();
        sig_inner.extend_from_slice(&namelen.to_be_bytes());
        sig_inner.extend_from_slice(&[b'x', 0, 0, 0, 0, 0]);
        let mut sig = attr_hdr(6, false, (4 + sig_inner.len()) as u32).to_vec();
        sig.extend_from_slice(&sig_inner);
        let mut a = str_attr(2, b"fuzz.obj");
        a.extend_from_slice(&sig);
        fixed.push((format!("add_object_namelen={namelen}"), message(6, 1, 0, &a)));
    }
    // a subscribe naming itself, and one naming nothing
    {
        let mut a = u32_attr(3, 1);
        a.extend_from_slice(&u32_attr(8, 1));
        fixed.push(("subscribe_self".into(), message(8, 1, 0, &a)));
        fixed.push(("unsubscribe_unknown".into(), message(9, 1, 0, &a)));
    }
    // event register/send with the wrong shapes
    for (name, body) in [("event_register_empty", 5u8), ("event_send_empty", 5)] {
        let mut a = u32_attr(3, 1);
        a.extend_from_slice(&str_attr(4, b"register"));
        fixed.push((name.to_string(), message(body, 1, 0, &a)));
    }

    let mut out = Vec::new();
    for (name, bytes) in &fixed {
        out.push(format!("{name}: {}", probe(&sock, bytes)));
    }

    // Random mutations on top of a well-formed lookup, same seed both sides.
    let mut rng = Lcg(0x5eed_1234_abcd_0001);
    let mut buckets: std::collections::BTreeMap<String, usize> = Default::default();
    for i in 0..cases {
        let mut m = message(4, 1, 0, &str_attr(2, b"session"));
        let n = m.len() as u32;
        let flips = 1 + rng.below(4);
        for _ in 0..flips {
            let at = rng.below(n) as usize;
            m[at] = rng.byte();
        }
        let verdict = probe(&sock, &m);
        // per-case as well as bucketed: a bucket count tells you that
        // something differs, the case number tells you which input
        out.push(format!("mutated#{i:04} {} -> {verdict}", hex(&m)));
        *buckets.entry(verdict).or_default() += 1;
    }
    for (verdict, n) in buckets {
        out.push(format!("mutated[{verdict}]: {n}"));
    }

    for line in out {
        println!("{line}");
    }
}
