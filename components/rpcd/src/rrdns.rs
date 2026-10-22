//! rpcd-mod-rrdns port (`network.rrdns` object, rrdns.c @ luci 20170710):
//! reverse DNS lookups over one UDP socket with a bounded number of queries
//! in flight; deferred reply carries `addr -> name` for every PTR answer.

use crate::session::{arg, arg_str, Reply};
use crate::Deferrer;
use owrt_ubus::blob::{self, MsgType};
use owrt_ubus::{status, BlobBuf, Request};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

const MAX_TIMEOUT: i32 = 5000;
const DEF_TIMEOUT: i32 = 250;
const MAX_LIMIT: i32 = 1000;
const DEF_LIMIT: i32 = 10;

pub fn signature() -> Vec<(&'static str, Vec<(&'static str, MsgType)>)> {
    use MsgType::*;
    vec![(
        "lookup",
        vec![
            ("addrs", Array),
            ("timeout", Int32),
            ("server", String),
            ("port", Int16),
            ("limit", Int32),
        ],
    )]
}

/// rrdns_find_nameserver: first `nameserver` line of /etc/resolv.conf that
/// parses as an IPv6 or IPv4 address.
fn find_nameserver() -> Option<String> {
    let text = crate::util::read_lossy("/etc/resolv.conf").ok()?;
    for line in text.split_inclusive('\n') {
        let mut it = line.split([' ', '\t']).filter(|t| !t.is_empty());
        if it.next() != Some("nameserver") {
            continue;
        }
        let Some(p) = it.next() else { continue };
        let p = p.trim_end_matches(['\r', '\n']);
        if p.parse::<Ipv6Addr>().is_ok() || p.parse::<Ipv4Addr>().is_ok() {
            return Some(p.to_owned());
        }
    }
    None
}

/// inet_pton(AF_INET6) then inet_pton(AF_INET), as rrdns_next_query does.
/// Returns the 16-byte key the C code uses for duplicate detection (IPv4 in
/// the first four bytes, rest zero), the family and the PTR query name.
fn parse_addr(s: &str) -> Option<([u8; 16], bool, String)> {
    if let Ok(v6) = s.parse::<Ipv6Addr>() {
        let o = v6.octets();
        let hex = b"0123456789abcdef";
        let mut name = String::with_capacity(73);
        for i in 0..16 {
            let b = o[15 - i];
            name.push(hex[(b % 16) as usize] as char);
            name.push('.');
            name.push(hex[(b / 16) as usize] as char);
            name.push('.');
        }
        name.push_str("ip6.arpa");
        return Some((o, true, name));
    }
    if let Ok(v4) = s.parse::<Ipv4Addr>() {
        let o = v4.octets();
        let mut key = [0u8; 16];
        key[..4].copy_from_slice(&o);
        return Some((
            key,
            false,
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]),
        ));
    }
    None
}

/// res_mkquery(QUERY, dname, C_IN, T_PTR): standard query, RD set.
fn mkquery(id: u16, dname: &str) -> Option<Vec<u8>> {
    let mut m = Vec::with_capacity(512);
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00]); // RD
    m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in dname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&[0, 12, 0, 1]); // T_PTR, C_IN
    if m.len() > 512 {
        return None;
    }
    Some(m)
}

fn random_id() -> u16 {
    let mut b = [0u8; 2];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut f, &mut b);
    }
    u16::from_be_bytes(b)
}

/// ns_name_uncompress: expand a (possibly compressed) name at `off` into
/// presentation form without a trailing dot (root is ".").
fn uncompress(msg: &[u8], mut off: usize) -> Option<String> {
    let mut out = String::new();
    let mut hops = 0;
    loop {
        let &len = msg.get(off)?;
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            let &lo = msg.get(off + 1)?;
            off = (((len & 0x3f) as usize) << 8) | lo as usize;
            hops += 1;
            if hops > 128 {
                return None;
            }
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let label = msg.get(off + 1..off + 1 + len as usize)?;
        if !out.is_empty() {
            out.push('.');
        }
        for &c in label {
            // ns_name_ntop escapes '.'/'\\' and non-printables the same way
            match c {
                b'.' | b'\\' | b'"' | b'(' | b')' | b';' | b'@' | b'$' => {
                    out.push('\\');
                    out.push(c as char);
                }
                0x21..=0x7e => out.push(c as char),
                _ => out.push_str(&format!("\\{:03}", c)),
            }
        }
        off += 1 + len as usize;
    }
    if out.is_empty() {
        out.push('.');
    }
    Some(out)
}

/// Skip a name (compressed or not) starting at `off`; returns the next offset.
fn skip_name(msg: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let &len = msg.get(off)?;
        if len == 0 {
            return Some(off + 1);
        }
        if len & 0xc0 == 0xc0 {
            msg.get(off + 1)?;
            return Some(off + 2);
        }
        off += 1 + len as usize;
    }
}

/// `ns_initparse`: walk every record of all four sections and bounds-check it
/// before a single answer is handed out. A truncated or malformed message
/// fails here, which is why C rejects such a response whole (-EINVAL) instead
/// of emitting the PTR names it managed to read.
fn initparse(msg: &[u8]) -> Option<()> {
    let count = |i: usize| u16::from_be_bytes([msg[4 + i * 2], msg[5 + i * 2]]) as usize;
    let mut off = 12;
    for section in 0..4 {
        for _ in 0..count(section) {
            off = skip_name(msg, off)?;
            if section == 0 {
                // QTYPE + QCLASS
                off = off.checked_add(4)?;
            } else {
                let hdr = msg.get(off..off.checked_add(10)?)?;
                let rdlen = u16::from_be_bytes([hdr[8], hdr[9]]) as usize;
                off = off.checked_add(10)?.checked_add(rdlen)?;
            }
            if off > msg.len() {
                return None;
            }
        }
    }
    Some(())
}

struct Pending {
    key: [u8; 16],
    v6: bool,
}

struct Lookup {
    sock: UdpSocket,
    addrs: Vec<Option<String>>, // remaining addr strings in array order (None = non-string attr)
    next: usize,
    by_id: BTreeMap<u16, Pending>,
    seen: BTreeSet<[u8; 16]>,
    out: BlobBuf,
}

impl Lookup {
    /// rrdns_next_query: returns false when no address was left to take.
    fn next_query(&mut self) -> Result<(), ()> {
        let Some(slot) = self.addrs.get(self.next) else {
            return Err(());
        };
        self.next += 1;
        let Some(addr) = slot else { return Err(()) };
        let Some((key, v6, dname)) = parse_addr(addr) else {
            return Err(());
        };
        let id = random_id();
        let Some(msg) = mkquery(id, &dname) else {
            return Err(());
        };
        if self.seen.contains(&key) {
            return Err(()); // -ENOTUNIQ
        }
        if self.sock.send(&msg).map(|n| n != msg.len()).unwrap_or(true) {
            return Err(());
        }
        self.by_id.insert(id, Pending { key, v6 });
        self.seen.insert(key);
        Ok(())
    }

    /// rrdns_parse_response: Err(true) for -ENODATA/-ENOENT (no follow-up query).
    fn parse_response(&mut self) -> Result<(), bool> {
        let mut res = [0u8; 512];
        let len = match self.sock.recv(&mut res) {
            Ok(n) => n,
            Err(_) => return Err(true),
        };
        if len < 12 {
            return Err(true);
        }
        let res = &res[..len];
        let id = u16::from_be_bytes([res[0], res[1]]);
        let Some(req) = self.by_id.remove(&id) else {
            return Err(true);
        };
        initparse(res).ok_or(false)?;
        let qd = u16::from_be_bytes([res[4], res[5]]) as usize;
        let an = u16::from_be_bytes([res[6], res[7]]) as usize;
        let mut off = 12;
        for _ in 0..qd {
            off = skip_name(res, off).ok_or(false)?;
            off += 4;
        }
        let addr_str = if req.v6 {
            Ipv6Addr::from(req.key).to_string()
        } else {
            Ipv4Addr::new(req.key[0], req.key[1], req.key[2], req.key[3]).to_string()
        };
        for _ in 0..an {
            off = skip_name(res, off).ok_or(false)?;
            let hdr = res.get(off..off + 10).ok_or(false)?;
            let ty = u16::from_be_bytes([hdr[0], hdr[1]]);
            let rdlen = u16::from_be_bytes([hdr[8], hdr[9]]) as usize;
            let rdata = off + 10;
            if res.len() < rdata + rdlen {
                return Err(false);
            }
            if ty == 12 {
                let name = uncompress(res, rdata).ok_or(false)?;
                self.out.msg_string(&addr_str, &name);
            }
            off = rdata + rdlen;
        }
        Ok(())
    }
}

fn run(mut lk: Lookup, limit: i32, timeout_ms: i32) -> Reply {
    for _ in 0..limit {
        let _ = lk.next_query();
    }
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    while !lk.by_id.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let _ = lk.sock.set_read_timeout(Some(deadline - now));
        let mut probe = [0u8; 1];
        match lk.sock.peek(&mut probe) {
            Ok(_) => {
                let err = lk.parse_response();
                if !matches!(err, Err(true)) {
                    let _ = lk.next_query();
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(_) => {
                // socket error: consume it like recv() would, drop nothing
                let _ = lk.sock.recv(&mut probe);
            }
        }
    }
    Reply::one(status::OK, lk.out.into_payload())
}

pub enum Outcome {
    Now(Request, Reply),
    Deferred,
}

/// usock(USOCK_UDP): resolve the server name and try each address returned by
/// libc until socket/connect succeeds. Resolution failure is UNKNOWN_ERROR.
fn connect_server(server: &str, port: u16) -> std::io::Result<UdpSocket> {
    let mut last = std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "no nameserver address",
    );
    for peer in (server, port).to_socket_addrs()? {
        let bind = if peer.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        match UdpSocket::bind(bind).and_then(|sock| sock.connect(peer).map(|()| sock)) {
            Ok(sock) => return Ok(sock),
            Err(error) => last = error,
        }
    }
    Err(last)
}

/// In-process equivalent of `ubus call network.rrdns lookup {addrs, timeout,
/// limit}` with the default server/port (luci-rpc's getHostHints path). None
/// mirrors a failed invoke (no nameserver / socket error); Some(pairs) is the
/// reply table in reply order.
pub fn resolve(addrs: &[String], timeout_ms: i32, limit: i32) -> Option<Vec<(String, String)>> {
    if limit <= 0 || limit > MAX_LIMIT || timeout_ms <= 0 || timeout_ms > MAX_TIMEOUT {
        return None;
    }
    let server = find_nameserver()?;
    let sock = connect_server(&server, 53).ok()?;
    let lk = Lookup {
        sock,
        addrs: addrs.iter().cloned().map(Some).collect(),
        next: 0,
        by_id: BTreeMap::new(),
        seen: BTreeSet::new(),
        out: BlobBuf::new(),
    };
    let reply = run(lk, limit, timeout_ms);
    let payload = reply.data.iter().next().unwrap_or_default();
    Some(
        blob::fields(payload)
            .filter_map(|f| f.as_str().map(|v| (f.name.to_owned(), v.to_owned())))
            .collect(),
    )
}

pub fn call(req: Request, deferrer: &Deferrer) -> Outcome {
    if req.method != "lookup" {
        return Outcome::Now(req, Reply::empty(status::METHOD_NOT_FOUND));
    }
    let raw = &req.data;
    let port: i32 = arg(raw, "port", MsgType::Int16)
        .and_then(|f| f.as_u32())
        .map(|v| v as u16 as i32)
        .unwrap_or(53);
    let limit: i32 = arg(raw, "limit", MsgType::Int32)
        .and_then(|f| f.as_u32())
        .map(|v| v as i32)
        .unwrap_or(DEF_LIMIT);
    let timeout: i32 = arg(raw, "timeout", MsgType::Int32)
        .and_then(|f| f.as_u32())
        .map(|v| v as i32)
        .unwrap_or(DEF_TIMEOUT);
    let server = arg_str(raw, "server").map(str::to_owned);
    let Some(addrs) = arg(raw, "addrs", MsgType::Array) else {
        return Outcome::Now(req, Reply::empty(status::INVALID_ARGUMENT));
    };
    if port <= 0 || limit <= 0 || limit > MAX_LIMIT || timeout <= 0 || timeout > MAX_TIMEOUT {
        return Outcome::Now(req, Reply::empty(status::INVALID_ARGUMENT));
    }
    let server = match server.filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => match find_nameserver() {
            Some(s) => s,
            None => return Outcome::Now(req, Reply::empty(status::NOT_FOUND)),
        },
    };
    let sock = match connect_server(&server, port as u16) {
        Ok(s) => s,
        Err(_) => return Outcome::Now(req, Reply::empty(status::UNKNOWN_ERROR)),
    };
    let list: Vec<Option<String>> = blob::iter(addrs.data)
        .map(|a| {
            a.field().and_then(|f| {
                if f.ty == MsgType::String as u32 {
                    f.as_str().map(str::to_owned)
                } else {
                    None
                }
            })
        })
        .collect();
    let lk = Lookup {
        sock,
        addrs: list,
        next: 0,
        by_id: BTreeMap::new(),
        seen: BTreeSet::new(),
        out: BlobBuf::new(),
    };
    match deferrer.defer(req, move || run(lk, limit, timeout)) {
        None => Outcome::Deferred,
        Some((req, reply)) => Outcome::Now(req, reply),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptr_names() {
        assert_eq!(
            parse_addr("192.168.1.20").unwrap().2,
            "20.1.168.192.in-addr.arpa"
        );
        assert_eq!(
            parse_addr("2001:db8::1").unwrap().2,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        assert!(parse_addr("nope").is_none());
    }

    /// A PTR response for 1.2.3.4 -> "host.lan" plus `extra` bytes of junk
    /// appended to the wire message.
    fn ptr_response(id: u16, ancount: u16, arcount: u16) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&[0x81, 0x80]); // QR + RD + RA
        m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        m.extend_from_slice(&ancount.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes()); // nscount
        m.extend_from_slice(&arcount.to_be_bytes());
        let qname: Vec<u8> = {
            let mut q = Vec::new();
            for label in ["4", "3", "2", "1", "in-addr", "arpa"] {
                q.push(label.len() as u8);
                q.extend_from_slice(label.as_bytes());
            }
            q.push(0);
            q
        };
        m.extend_from_slice(&qname);
        m.extend_from_slice(&[0, 12, 0, 1]); // PTR, IN
        for _ in 0..ancount {
            m.extend_from_slice(&[0xc0, 0x0c]); // name -> qname
            m.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 60]); // PTR, IN, ttl
            let mut rd = Vec::new();
            for label in ["host", "lan"] {
                rd.push(label.len() as u8);
                rd.extend_from_slice(label.as_bytes());
            }
            rd.push(0);
            m.extend_from_slice(&(rd.len() as u16).to_be_bytes());
            m.extend_from_slice(&rd);
        }
        m
    }

    /// One pending IPv4 lookup whose socket is connected to `peer`.
    fn lookup_for(id: u16, peer: &UdpSocket) -> Lookup {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.connect(peer.local_addr().unwrap()).unwrap();
        let mut key = [0u8; 16];
        key[..4].copy_from_slice(&[1, 2, 3, 4]);
        let mut by_id = BTreeMap::new();
        by_id.insert(id, Pending { key, v6: false });
        Lookup {
            sock,
            addrs: vec![],
            next: 0,
            by_id,
            seen: BTreeSet::new(),
            out: BlobBuf::new(),
        }
    }

    fn names(lk: Lookup) -> Vec<(String, String)> {
        let payload = lk.out.into_payload();
        blob::fields(&payload)
            .filter_map(|f| f.as_str().map(|v| (f.name.to_owned(), v.to_owned())))
            .collect()
    }

    /// ns_initparse walks every section before rrdns_parse_response hands out a
    /// single answer, so a response that is cut short is rejected whole. Parsing
    /// answer-by-answer instead published the PTR names read before the cut.
    #[test]
    fn a_truncated_response_yields_no_ptr_at_all() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let full = ptr_response(0x1234, 2, 0);
        // control: the intact message must actually produce both answers
        let mut lk = lookup_for(0x1234, &peer);
        peer.send_to(&full, lk.sock.local_addr().unwrap()).unwrap();
        assert!(lk.parse_response().is_ok());
        assert_eq!(
            names(lk),
            vec![("1.2.3.4".to_owned(), "host.lan".to_owned()); 2]
        );

        // the same message minus its last byte: the first answer is complete
        for cut in 1..=3 {
            let mut lk = lookup_for(0x1234, &peer);
            peer.send_to(&full[..full.len() - cut], lk.sock.local_addr().unwrap())
                .unwrap();
            assert_eq!(lk.parse_response(), Err(false), "cut {cut}");
            assert!(names(lk).is_empty(), "cut {cut} leaked a partial answer");
        }

        // a truncated *additional* section, with every answer intact
        let mut trunc = ptr_response(0x1234, 1, 1);
        trunc.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]); // name + type + class, no ttl/rdlength
        let mut lk = lookup_for(0x1234, &peer);
        peer.send_to(&trunc, lk.sock.local_addr().unwrap()).unwrap();
        assert_eq!(lk.parse_response(), Err(false));
        assert!(
            names(lk).is_empty(),
            "an intact answer must not survive a bad additional section"
        );
    }

    #[test]
    fn name_uncompress() {
        let msg = [
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0, 0xc0, 4,
        ];
        assert_eq!(uncompress(&msg, 0).unwrap(), "www.example.com");
        assert_eq!(uncompress(&msg, 17).unwrap(), "example.com");
        assert_eq!(uncompress(&[0], 0).unwrap(), ".");
    }
}
