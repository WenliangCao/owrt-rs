//! The rtnetlink transport: one socket, request/ACK, dumps and event groups.
//!
//! netifd's C side goes through libnl-tiny (`system_rtnl_call` =
//! `nl_send_auto_complete` + `nl_wait_for_ack`). The shape here is the same:
//! every write is a single request that is acknowledged before the next one is
//! sent, so a failure is attributed to the operation that caused it.
//!
//! Netlink is little-endian on every architecture Linux supports, so the
//! encoders below use `to_le_bytes` unconditionally rather than native order.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use rustix::net::{AddressFamily, SocketType, SocketFlags, RecvFlags, SendFlags};

const EVENT_BUFFER: i32 = 65535;
// Growth is only a mitigation; correctness comes from a fresh link dump.
// Bound requests even on a kernel with a very large rmem_max.
const MAX_EVENT_BUFFER: i32 = 4 * 1024 * 1024;
pub const ENOBUFS: i32 = 105;

pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;

pub const NLM_F_REQUEST: u16 = 0x001;
pub const NLM_F_MULTI: u16 = 0x002;
pub const NLM_F_ACK: u16 = 0x004;
pub const NLM_F_DUMP: u16 = 0x100 | 0x200;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;

/// Multicast group ids for `bind`, as a bitmask (`1 << (RTNLGRP_x - 1)`).
pub const RTNLGRP_LINK: u32 = 1;
#[cfg(test)]
pub const RTNLGRP_IPV4_IFADDR: u32 = 5;
#[cfg(test)]
pub const RTNLGRP_IPV6_IFADDR: u32 = 9;

/// `1 << (grp - 1)`, the bitmask form `bind(2)` takes for the first 32 groups.
pub const fn grp(g: u32) -> u32 {
    1 << (g - 1)
}

/// One received netlink message: header type/flags/seq and the payload that
/// follows the 16-byte header.
#[derive(Clone, Debug)]
pub struct Msg {
    pub ty: u16,
    pub flags: u16,
    pub seq: u32,
    pub payload: Vec<u8>,
}

impl Msg {
    /// The fixed part of the payload (ifinfomsg, ifaddrmsg, rtmsg …) followed
    /// by the attribute area. `fixed` is the size of that fixed part.
    pub fn attrs(&self, fixed: usize) -> Vec<(u16, &[u8])> {
        if self.payload.len() < fixed {
            return Vec::new();
        }
        parse_attrs(&self.payload[fixed..])
    }
}

/// Walk an rtattr area: `(type, value)` in wire order, stopping at the first
/// malformed header rather than guessing.
pub fn parse_attrs(data: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 4 <= data.len() {
        let len = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
        let ty = u16::from_le_bytes([data[off + 2], data[off + 3]]);
        if len < 4 || off + len > data.len() {
            break;
        }
        out.push((ty, &data[off + 4..off + len]));
        off += (len + 3) & !3;
    }
    out
}

/// Find one attribute by type; the first match wins, as in libnl's parser.
pub fn attr<'a>(attrs: &[(u16, &'a [u8])], ty: u16) -> Option<&'a [u8]> {
    attrs.iter().find(|(t, _)| *t == ty).map(|(_, v)| *v)
}

pub fn attr_u32(attrs: &[(u16, &[u8])], ty: u16) -> Option<u32> {
    attr(attrs, ty).filter(|v| v.len() >= 4).map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

#[cfg(test)]
pub fn attr_u8(attrs: &[(u16, &[u8])], ty: u16) -> Option<u8> {
    attr(attrs, ty).filter(|v| !v.is_empty()).map(|v| v[0])
}

/// A NUL-terminated string attribute, with the terminator removed.
pub fn attr_str<'a>(attrs: &[(u16, &'a [u8])], ty: u16) -> Option<&'a str> {
    let v = attr(attrs, ty)?;
    let end = v.iter().position(|&b| b == 0).unwrap_or(v.len());
    std::str::from_utf8(&v[..end]).ok()
}

/// Attribute encoder. Nesting is open/close by byte offset, matching
/// `nla_nest_start`/`nla_nest_end`, so a nest can be built incrementally.
#[derive(Default, Clone)]
pub struct Attrs {
    buf: Vec<u8>,
}

impl Attrs {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn bytes(&mut self, ty: u16, v: &[u8]) -> &mut Self {
        let len = 4 + v.len();
        self.buf.extend_from_slice(&(len as u16).to_le_bytes());
        self.buf.extend_from_slice(&ty.to_le_bytes());
        self.buf.extend_from_slice(v);
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
        self
    }

    /// A NUL-terminated string, as `nla_put_string` writes it.
    pub fn str0(&mut self, ty: u16, s: &str) -> &mut Self {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        self.bytes(ty, &v)
    }

    pub fn u8(&mut self, ty: u16, v: u8) -> &mut Self {
        self.bytes(ty, &[v])
    }

    pub fn u16(&mut self, ty: u16, v: u16) -> &mut Self {
        self.bytes(ty, &v.to_le_bytes())
    }

    pub fn u32(&mut self, ty: u16, v: u32) -> &mut Self {
        self.bytes(ty, &v.to_le_bytes())
    }

    /// Open a nest; the returned offset must be handed to `nest_end`.
    pub fn nest_start(&mut self, ty: u16) -> usize {
        let at = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_le_bytes());
        self.buf.extend_from_slice(&(ty | NLA_F_NESTED).to_le_bytes());
        at
    }

    pub fn nest_end(&mut self, at: usize) {
        let len = (self.buf.len() - at) as u16;
        self.buf[at..at + 2].copy_from_slice(&len.to_le_bytes());
    }
}

pub const NLA_F_NESTED: u16 = 0x8000;

/// A netlink socket. One request in flight at a time on the command socket;
/// the event socket is opened separately with multicast groups.
pub struct Netlink {
    fd: OwnedFd,
    seq: u32,
    event_buffer: i32,
    /// Reply storage for `dump_one`, kept across calls: a fresh 64 KiB
    /// allocation per query cost an mmap/munmap pair and a page fault.
    reply: Vec<u8>,
}

impl Netlink {
    /// `groups` is the multicast bitmask; 0 for a command socket.
    pub fn open(groups: u32) -> io::Result<Self> {
        let fd = rustix::net::socket_with(AddressFamily::NETLINK, SocketType::RAW, SocketFlags::CLOEXEC, None)?;
        rustix::net::bind(&fd, &rustix::net::netlink::SocketAddrNetlink::new(0, groups))?;
        // Older kernels may refuse NETLINK_EXT_ACK; retain best-effort setup.
        let _ = owrt_platform::netifd::enable_netlink_ext_ack(&fd);
        let mut socket = Self { fd, seq: 0, event_buffer: EVENT_BUFFER, reply: Vec::new() };
        if groups != 0 {
            socket.set_event_buffer(EVENT_BUFFER)?;
        }
        Ok(socket)
    }

    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    fn set_event_buffer(&mut self, bytes: i32) -> io::Result<()> {
        rustix::net::sockopt::set_socket_recv_buffer_size(&self.fd, bytes as usize)?;
        self.event_buffer = bytes;
        Ok(())
    }

    /// system-linux.c doubles the event receive buffer after NLE_NOMEM.
    /// Always resynchronise too, even when growth is capped or refused.
    pub fn grow_event_buffer(&mut self) -> io::Result<()> {
        self.set_event_buffer((self.event_buffer * 2).min(MAX_EVENT_BUFFER))
    }

    /// O_NONBLOCK, for the event socket read from the poll loop.
    pub fn set_nonblocking(&self) -> io::Result<()> {
        let flags = rustix::fs::fcntl_getfl(&self.fd)?;
        Ok(rustix::fs::fcntl_setfl(&self.fd, flags | rustix::fs::OFlags::NONBLOCK)?)
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        if self.seq == 0 {
            self.seq = 1;
        }
        self.seq
    }

    fn send_msg(&mut self, ty: u16, flags: u16, hdr: &[u8], attrs: &[u8]) -> io::Result<u32> {
        let seq = self.next_seq();
        let hdr_pad = (hdr.len() + 3) & !3;
        let total = 16 + hdr_pad + attrs.len();
        let mut req = Vec::with_capacity(total);
        req.extend_from_slice(&(total as u32).to_le_bytes());
        req.extend_from_slice(&ty.to_le_bytes());
        req.extend_from_slice(&flags.to_le_bytes());
        req.extend_from_slice(&seq.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes());
        req.extend_from_slice(hdr);
        req.resize(16 + hdr_pad, 0);
        req.extend_from_slice(attrs);
        rustix::net::send(&self.fd, &req, SendFlags::empty())?;
        Ok(seq)
    }

    /// One request that is acknowledged: `NLM_F_REQUEST | NLM_F_ACK | flags`.
    /// Returns the kernel's errno as an `io::Error` when the ACK is negative,
    /// which is how netifd distinguishes "already exists" from a real failure.
    pub fn request(&mut self, ty: u16, flags: u16, hdr: &[u8], attrs: &[u8]) -> io::Result<()> {
        let seq = self.send_msg(ty, flags | NLM_F_REQUEST | NLM_F_ACK, hdr, attrs)?;
        let mut buf = vec![0u8; 32768];
        loop {
            let (_, n) = rustix::net::recv(&self.fd, &mut buf, RecvFlags::empty())?;
            for m in split(&buf[..n as usize]) {
                if m.seq != seq {
                    continue;
                }
                if m.ty == NLMSG_ERROR {
                    if m.payload.len() < 4 {
                        return Err(io::Error::other("short NLMSG_ERROR"));
                    }
                    let e = i32::from_le_bytes([
                        m.payload[0],
                        m.payload[1],
                        m.payload[2],
                        m.payload[3],
                    ]);
                    return if e == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(-e)) };
                }
                if m.ty == NLMSG_DONE {
                    return Ok(());
                }
            }
        }
    }

    /// A dump: every multipart message until `NLMSG_DONE`.
    pub fn dump(&mut self, ty: u16, hdr: &[u8]) -> io::Result<Vec<Msg>> {
        let seq = self.send_msg(ty, NLM_F_REQUEST | NLM_F_DUMP, hdr, &[])?;
        let mut out = Vec::new();
        let mut buf = vec![0u8; 1 << 17];
        loop {
            let (_, n) = rustix::net::recv(&self.fd, &mut buf, RecvFlags::empty())?;
            for m in split(&buf[..n as usize]) {
                if m.seq != seq {
                    continue;
                }
                match m.ty {
                    NLMSG_DONE => return Ok(out),
                    NLMSG_NOOP => {}
                    NLMSG_ERROR => {
                        if m.payload.len() >= 4 {
                            let e = i32::from_le_bytes([
                                m.payload[0],
                                m.payload[1],
                                m.payload[2],
                                m.payload[3],
                            ]);
                            if e != 0 {
                                return Err(io::Error::from_raw_os_error(-e));
                            }
                        }
                        return Ok(out);
                    }
                    _ => {
                        let multi = m.flags & NLM_F_MULTI != 0;
                        out.push(m);
                        if !multi {
                            return Ok(out);
                        }
                    }
                }
            }
        }
    }

    /// A request that returns a single reply rather than a dump — `RTM_GETLINK`
    /// with `IFLA_IFNAME`, which the kernel answers with one `RTM_NEWLINK` or
    /// an error. `Ok(None)` means the kernel acknowledged with no payload.
    pub fn dump_one(&mut self, ty: u16, hdr: &[u8], attrs: &[u8]) -> io::Result<Option<Msg>> {
        let seq = self.send_msg(ty, NLM_F_REQUEST, hdr, attrs)?;
        // Reserve the same receive capacity without touching pages beyond
        // the kernel's reply. recv initializes exactly its returned length.
        self.reply.clear();
        self.reply.reserve(1 << 16);
        loop {
            self.reply.clear();
            let (_, n) = rustix::net::recv(&self.fd,
                rustix::buffer::spare_capacity(&mut self.reply), RecvFlags::empty())?;
            for m in split(&self.reply[..n as usize]) {
                if m.seq != seq {
                    continue;
                }
                match m.ty {
                    NLMSG_ERROR => {
                        if m.payload.len() < 4 {
                            return Err(io::Error::other("short NLMSG_ERROR"));
                        }
                        let e = i32::from_le_bytes([
                            m.payload[0],
                            m.payload[1],
                            m.payload[2],
                            m.payload[3],
                        ]);
                        return if e == 0 {
                            Ok(None)
                        } else {
                            Err(io::Error::from_raw_os_error(-e))
                        };
                    }
                    NLMSG_DONE => return Ok(None),
                    NLMSG_NOOP => {}
                    _ => return Ok(Some(m)),
                }
            }
        }
    }

    /// Drain whatever the event socket has; `Ok(vec![])` when it would block.
    pub fn recv_events(&self) -> io::Result<Vec<Msg>> {
        let mut buf = vec![0u8; 1 << 17];
        let (_, n) = match rustix::net::recv(&self.fd, &mut buf, RecvFlags::TRUNC) {
            Ok(result) => result,
            Err(rustix::io::Errno::AGAIN) => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        if n as usize > buf.len() {
            // recv(MSG_TRUNC) reports the full datagram size. A discarded
            // tail loses events just like a receive-queue overflow.
            return Err(io::Error::from_raw_os_error(ENOBUFS));
        }
        Ok(split(&buf[..n as usize]))
    }
}

/// Split a received buffer into whole netlink messages, ignoring a trailing
/// partial header rather than reading past it.
fn split(buf: &[u8]) -> Vec<Msg> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 16 <= buf.len() {
        let len = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
        if len < 16 || off + len > buf.len() {
            break;
        }
        out.push(Msg {
            ty: u16::from_le_bytes([buf[off + 4], buf[off + 5]]),
            flags: u16::from_le_bytes([buf[off + 6], buf[off + 7]]),
            seq: u32::from_le_bytes([buf[off + 8], buf[off + 9], buf[off + 10], buf[off + 11]]),
            payload: buf[off + 16..off + len].to_vec(),
        });
        off += (len + 3) & !3;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_encoding_pads_to_four() {
        let mut a = Attrs::new();
        a.str0(3, "br-lan");
        // 4 header + 7 payload = 11, padded to 12
        assert_eq!(a.as_bytes().len(), 12);
        assert_eq!(&a.as_bytes()[..2], &11u16.to_le_bytes());
        assert_eq!(&a.as_bytes()[2..4], &3u16.to_le_bytes());
        assert_eq!(&a.as_bytes()[4..11], b"br-lan\0");
        assert_eq!(a.as_bytes()[11], 0);
    }

    #[test]
    fn nesting_records_its_own_length() {
        let mut a = Attrs::new();
        let outer = a.nest_start(18);
        a.str0(1, "bridge");
        let inner = a.nest_start(2);
        a.u32(1, 0);
        a.nest_end(inner);
        a.nest_end(outer);

        let top = parse_attrs(a.as_bytes());
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].0, 18 | NLA_F_NESTED);
        let mid = parse_attrs(top[0].1);
        assert_eq!(attr_str(&mid, 1), Some("bridge"));
        let data = parse_attrs(attr(&mid, 2 | NLA_F_NESTED).unwrap());
        assert_eq!(attr_u32(&data, 1), Some(0));
    }

    #[test]
    fn parse_stops_at_a_truncated_attribute() {
        let mut a = Attrs::new();
        a.u32(1, 7);
        a.u32(2, 8);
        let mut buf = a.as_bytes().to_vec();
        buf.truncate(buf.len() - 2);
        let got = parse_attrs(&buf);
        assert_eq!(got.len(), 1);
        assert_eq!(attr_u32(&got, 1), Some(7));
    }

    #[test]
    fn parse_rejects_a_zero_length_header() {
        // len < 4 must stop the walk instead of looping forever
        let buf = [0u8, 0, 1, 0, 0, 0, 0, 0];
        assert!(parse_attrs(&buf).is_empty());
    }

    #[test]
    fn split_ignores_a_trailing_partial_message() {
        let mut buf = Vec::new();
        for seq in 1u32..=2 {
            buf.extend_from_slice(&20u32.to_le_bytes());
            buf.extend_from_slice(&16u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&seq.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
        }
        buf.extend_from_slice(&[0u8; 9]);
        let msgs = split(&buf);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].seq, 1);
        assert_eq!(msgs[1].seq, 2);
        assert_eq!(msgs[1].payload.len(), 4);
    }

    #[test]
    fn group_mask_matches_the_kernel_shift() {
        assert_eq!(grp(RTNLGRP_LINK), 1);
        assert_eq!(grp(RTNLGRP_IPV4_IFADDR), 0x10);
        assert_eq!(grp(RTNLGRP_IPV6_IFADDR), 0x100);
    }

    #[test]
    fn a_string_attribute_round_trips_without_its_terminator() {
        let mut a = Attrs::new();
        a.str0(3, "wan");
        let got = parse_attrs(a.as_bytes());
        assert_eq!(attr_str(&got, 3), Some("wan"));
        assert_eq!(attr(&got, 3).unwrap(), b"wan\0");
    }
}
