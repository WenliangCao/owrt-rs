//! Raw generic-netlink transport standing in for libnl-tiny as used by
//! iwinfo_nl80211.c: socket setup (`nl80211_init`/`nl80211_close`), message
//! construction (`genlmsg_put` + `NLA_PUT_*`), attribute parsing
//! (`nla_parse`, `nla_parse_nested`, `nla_for_each_nested`) and the
//! `nl80211_send` receive loop with libnl's default callback semantics
//! (sequence check, NLMSG_DONE => finish, NLMSG_ERROR => error/ack).

use super::sys::{EINVAL, ENOENT, ENOLINK, ENOMEM};
use std::cell::RefCell;
use std::os::fd::OwnedFd;
use std::rc::Rc;

pub const NLMSG_NOOP: u16 = 0x1;
pub const NLMSG_ERROR: u16 = 0x2;
pub const NLMSG_DONE: u16 = 0x3;
pub const NLMSG_OVERRUN: u16 = 0x4;

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_DUMP: u16 = 0x300;

pub const NLMSG_HDRLEN: usize = 16;
pub const GENL_HDRLEN: usize = 4;
pub const NLA_HDRLEN: usize = 4;
/// sizeof(struct nlmsgerr) = int error + struct nlmsghdr msg
pub const NLMSGERR_LEN: usize = 4 + NLMSG_HDRLEN;

pub const GENL_ID_CTRL: u16 = 0x10;
pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
pub const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
pub const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
pub const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;
pub const CTRL_ATTR_MCAST_GRP_MAX: usize = 2;

/// nla_type(): strip NLA_F_NESTED / NLA_F_NET_BYTEORDER.
pub const NLA_TYPE_MASK: u16 = 0x3fff;

/// libnl error codes surfaced by the receive loop (returned negative like
/// `-NLE_*`); iwinfo ignores nl_recvmsgs() return values, so only the sign
/// ever matters.
pub const NLE_RANGE: i32 = 8;
pub const NLE_SEQ_MISMATCH: i32 = 16;
pub const NLE_MSG_OVERFLOW: i32 = 17;
pub const NLE_MSG_TRUNC: i32 = 18;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// struct nl_msg being built: nlmsghdr + genlmsghdr + attributes.
pub struct Msg {
    buf: Vec<u8>,
}

impl Msg {
    /// nlmsg_alloc() + genlmsg_put(req, 0, 0, family, 0, flags, cmd, 0)
    pub fn new(family: u16, cmd: u8, flags: u16) -> Msg {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len, filled on send
        buf.extend_from_slice(&family.to_ne_bytes()); // nlmsg_type
        buf.extend_from_slice(&flags.to_ne_bytes()); // nlmsg_flags
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_seq (NL_AUTO_SEQ)
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid (NL_AUTO_PORT)
        buf.push(cmd); // genlmsghdr.cmd
        buf.push(0); // version
        buf.extend_from_slice(&0u16.to_ne_bytes()); // reserved
        Msg { buf }
    }

    fn put(&mut self, ty: u16, data: &[u8]) {
        let len = (NLA_HDRLEN + data.len()) as u16;
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(data);
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }

    /// NLA_PUT_U32
    pub fn put_u32(&mut self, ty: u16, v: u32) {
        self.put(ty, &v.to_ne_bytes());
    }

    /// NLA_PUT_STRING (NUL-terminated payload)
    pub fn put_string(&mut self, ty: u16, s: &str) {
        let mut d = s.as_bytes().to_vec();
        d.push(0);
        self.put(ty, &d);
    }

    /// NLA_PUT_FLAG
    pub fn put_flag(&mut self, ty: u16) {
        self.put(ty, &[]);
    }

    /// nl_complete_msg(): fill in length, sequence, port and force
    /// NLM_F_REQUEST | NLM_F_ACK (libnl auto-ack mode).
    fn complete(&mut self, seq: u32, pid: u32) {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        let flags = u16::from_ne_bytes([self.buf[6], self.buf[7]]) | NLM_F_REQUEST | NLM_F_ACK;
        self.buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        self.buf[12..16].copy_from_slice(&pid.to_ne_bytes());
    }
}

/// One received netlink message (header included, `data.len() == nlmsg_len`).
pub struct Nlmsg<'a> {
    pub data: &'a [u8],
}

impl<'a> Nlmsg<'a> {
    fn u16_at(&self, off: usize) -> u16 {
        match self.data.get(off..off + 2) {
            Some(b) => u16::from_ne_bytes([b[0], b[1]]),
            None => 0,
        }
    }

    fn u32_at(&self, off: usize) -> u32 {
        match self.data.get(off..off + 4) {
            Some(b) => u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
            None => 0,
        }
    }

    pub fn ty(&self) -> u16 {
        self.u16_at(4)
    }

    pub fn flags(&self) -> u16 {
        self.u16_at(6)
    }

    pub fn seq(&self) -> u32 {
        self.u32_at(8)
    }

    /// nlmsg_data()
    pub fn payload(&self) -> &'a [u8] {
        self.data.get(NLMSG_HDRLEN..).unwrap_or(&[])
    }

    /// genlmsghdr->cmd
    pub fn genl_cmd(&self) -> u8 {
        self.payload().first().copied().unwrap_or(0)
    }

    /// genlmsg_attrdata(gnlh, 0) .. genlmsg_attrlen(gnlh, 0)
    pub fn genl_attrs(&self) -> &'a [u8] {
        self.payload().get(GENL_HDRLEN..).unwrap_or(&[])
    }
}

/// struct nlattr view. `raw_type` is the on-wire nla_type field (flags
/// included) because the C code reads `band->nla_type` directly in places.
#[derive(Clone, Copy)]
pub struct Attr<'a> {
    pub raw_type: u16,
    pub data: &'a [u8],
}

impl<'a> Attr<'a> {
    /// nla_type()
    pub fn nla_type(&self) -> u16 {
        self.raw_type & NLA_TYPE_MASK
    }

    /// nla_len()
    pub fn nla_len(&self) -> usize {
        self.data.len()
    }

    // DEVIATION: libnl's nla_get_*() dereference the payload unchecked; an
    // attribute shorter than the requested width reads adjacent memory in C.
    // Here it reads as 0. With policy-validated or kernel-generated
    // attributes the two never differ.
    pub fn get_u8(&self) -> u8 {
        self.data.first().copied().unwrap_or(0)
    }

    pub fn get_u16(&self) -> u16 {
        match self.data.get(0..2) {
            Some(b) => u16::from_ne_bytes([b[0], b[1]]),
            None => 0,
        }
    }

    pub fn get_u32(&self) -> u32 {
        match self.data.get(0..4) {
            Some(b) => u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
            None => 0,
        }
    }

    pub fn get_u64(&self) -> u64 {
        match self.data.get(0..8) {
            Some(b) => u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            None => 0,
        }
    }

    /// nla_for_each_nested()
    pub fn nested(&self) -> AttrIter<'a> {
        AttrIter { buf: self.data }
    }
}

/// nla_for_each_attr(): nla_ok() / nla_next() walk.
pub struct AttrIter<'a> {
    buf: &'a [u8],
}

impl<'a> AttrIter<'a> {
    pub fn new(buf: &'a [u8]) -> AttrIter<'a> {
        AttrIter { buf }
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Attr<'a>;

    fn next(&mut self) -> Option<Attr<'a>> {
        if self.buf.len() < NLA_HDRLEN {
            return None;
        }
        let len = u16::from_ne_bytes([self.buf[0], self.buf[1]]) as usize;
        if len < NLA_HDRLEN || len > self.buf.len() {
            return None;
        }
        let attr = Attr {
            raw_type: u16::from_ne_bytes([self.buf[2], self.buf[3]]),
            data: &self.buf[NLA_HDRLEN..len],
        };
        let step = align4(len).min(self.buf.len());
        self.buf = &self.buf[step..];
        Some(attr)
    }
}

/// `struct nlattr *tb[MAX + 1]`
pub type Tb<'a> = Vec<Option<Attr<'a>>>;

/// struct nla_policy subset: (attribute type, minimum payload length). libnl
/// derives the minimum from the policy type (NLA_U8 => 1, U16 => 2, U32 => 4,
/// U64 => 8, FLAG/NESTED/UNSPEC => 0) unless `.minlen` is given.
pub type Policy = [(u16, u16)];

/// nla_parse(tb, maxtype, head, len, policy): attributes above `maxtype` are
/// skipped, later duplicates override earlier ones, a policy violation stops
/// the walk with -NLE_RANGE (the table filled so far is still returned, as
/// libnl leaves it).
pub fn nla_parse<'a>(payload: &'a [u8], maxtype: usize, policy: &Policy) -> (Tb<'a>, i32) {
    let mut tb: Tb<'a> = vec![None; maxtype + 1];
    for a in AttrIter::new(payload) {
        let t = a.nla_type() as usize;
        if t > maxtype {
            continue;
        }
        if let Some(&(_, minlen)) = policy.iter().find(|p| p.0 as usize == t) {
            if a.nla_len() < minlen as usize {
                return (tb, -NLE_RANGE);
            }
        }
        tb[t] = Some(a);
    }
    (tb, 0)
}

/// nla_parse_nested()
pub fn nla_parse_nested<'a>(attr: Attr<'a>, maxtype: usize, policy: &Policy) -> (Tb<'a>, i32) {
    nla_parse(attr.data, maxtype, policy)
}

/// struct nl80211_state: socket plus resolved family ids.
#[derive(Clone)]
pub struct Nls {
    pub fd: Rc<OwnedFd>,
    pub nl80211: u16,
    pub nlctrl: u16,
    seq: u32,
}

thread_local! {
    /// `static struct nl80211_state *nls` (per thread, as the callers are
    /// plain functions and rpcd-rs serves requests from worker threads).
    static NLS: RefCell<Option<Nls>> = const { RefCell::new(None) };
}

pub fn nls() -> Option<Nls> {
    NLS.with(|c| c.borrow().clone())
}

/// genl_ctrl_resolve(): CTRL_CMD_GETFAMILY by name -> CTRL_ATTR_FAMILY_ID.
fn genl_ctrl_resolve(st: &mut Nls, name: &str) -> Option<u16> {
    let mut msg = Msg::new(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0);
    msg.put_string(CTRL_ATTR_FAMILY_NAME, name);
    let mut id = None;
    let rc = send_on(st, msg, &mut |m: &Nlmsg| {
        for a in AttrIter::new(m.genl_attrs()) {
            if a.nla_type() == CTRL_ATTR_FAMILY_ID {
                id = Some(a.get_u16());
            }
        }
    });
    if rc != 0 {
        return None;
    }
    id
}

/// nl80211_init: allocate the socket, connect to generic netlink and resolve
/// the "nl80211" and "nlctrl" families. Returns 0 or a negative errno.
pub fn nl80211_init() -> i32 {
    if nls().is_some() {
        return 0;
    }
    let Ok(fd) = rustix::net::socket(rustix::net::AddressFamily::NETLINK,
        rustix::net::SocketType::RAW, Some(rustix::net::netlink::GENERIC)) else { return -ENOMEM; };
    if rustix::net::bind(&fd, &rustix::net::netlink::SocketAddrNetlink::new(0, 0)).is_err() {
        return -ENOLINK;
    }
    if rustix::io::fcntl_getfd(&fd).and_then(|flags| rustix::io::fcntl_setfd(&fd, flags | rustix::io::FdFlags::CLOEXEC)).is_err() {
        return -EINVAL;
    }
    let fd = Rc::new(fd);
    let mut st = Nls { fd, nl80211: 0, nlctrl: GENL_ID_CTRL, seq: 1 };
    match genl_ctrl_resolve(&mut st, "nl80211") {
        Some(id) => st.nl80211 = id,
        None => return -ENOENT,
    }
    NLS.with(|c| *c.borrow_mut() = Some(st));
    0
}

/// nl80211_close
pub fn nl80211_close() {
    NLS.with(|c| c.borrow_mut().take());
}

/// One nl_recvmsgs() pass with libnl's default handlers wired the way
/// nl80211_send()/__nl80211_wait() set them up: `err` is the conveyor the
/// error/finish/ack callbacks write to (`*ret = err->error` / `*ret = 0`),
/// `expect_seq` None disables the sequence check (nl80211_wait_seq_check).
/// Returns libnl's nl_recvmsgs() result, which the callers ignore.
pub fn recvmsgs(st: &Nls, expect_seq: Option<u32>, err: &mut i32, cb: &mut dyn FnMut(&Nlmsg)) -> i32 {
    thread_local! {
        // One receive buffer per thread, allocated once: a fresh zeroed 64 KiB
        // vector per recv() cost measurably on the router (two recvs per request).
        static RECV_BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0u8; 65536]);
    }
    RECV_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        recvmsgs_into(&mut buf, st, expect_seq, err, cb)
    })
}

fn recvmsgs_into(buf: &mut [u8], st: &Nls, expect_seq: Option<u32>, err: &mut i32, cb: &mut dyn FnMut(&Nlmsg)) -> i32 {
    let (_, n) = match rustix::net::recv(st.fd.as_ref(), &mut *buf, rustix::net::RecvFlags::empty()) {
        Ok(result) => result,
        Err(error) => return -error.raw_os_error(),
    };
    let mut off = 0;
    while off + NLMSG_HDRLEN <= n {
        let len = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
        if len < NLMSG_HDRLEN || off + len > n {
            break; // nlmsg_ok() failed
        }
        let msg = Nlmsg { data: &buf[off..off + len] };
        if let Some(seq) = expect_seq {
            if msg.seq() != seq {
                return -NLE_SEQ_MISMATCH;
            }
        }
        match msg.ty() {
            NLMSG_DONE => {
                // nl80211_msg_finish: *ret = 0, NL_SKIP
                *err = 0;
            }
            NLMSG_NOOP => {}
            NLMSG_OVERRUN => return -NLE_MSG_OVERFLOW,
            NLMSG_ERROR => {
                if len < NLMSG_HDRLEN + NLMSGERR_LEN {
                    return -NLE_MSG_TRUNC;
                }
                let e = i32::from_ne_bytes([buf[off + 16], buf[off + 17], buf[off + 18], buf[off + 19]]);
                // nl80211_msg_error: *ret = err->error, NL_STOP
                // nl80211_msg_ack:   *ret = 0,          NL_STOP
                *err = e;
                return 0;
            }
            _ => cb(&msg),
        }
        off += align4(len);
    }
    0
}

/// nl_send_auto_complete() + the `while (err > 0) nl_recvmsgs()` loop of
/// nl80211_send() on an explicit state.
fn send_on(st: &mut Nls, mut msg: Msg, cb: &mut dyn FnMut(&Nlmsg)) -> i32 {
    let seq = st.seq;
    st.seq = st.seq.wrapping_add(1);
    msg.complete(seq, 0);
    let dst = rustix::net::netlink::SocketAddrNetlink::new(0, 0);
    if let Err(error) = rustix::net::sendto(st.fd.as_ref(), &msg.buf, rustix::net::SendFlags::empty(), &dst) {
        return -error.raw_os_error();
    }
    let mut err = 1;
    while err > 0 {
        recvmsgs(st, Some(seq), &mut err, cb);
    }
    err
}

/// nl80211_send: 0 on success, the kernel's negative errno on NLMSG_ERROR,
/// a negative errno if the send itself failed.
/// Number of nl80211_send() calls in this process (profiling aid for `--iwinfo-bench`).
pub static SENDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub fn nl80211_send(msg: Msg, cb: &mut dyn FnMut(&Nlmsg)) -> i32 {
    SENDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let Some(mut st) = nls() else {
        return -ENOLINK;
    };
    let rc = send_on(&mut st, msg, cb);
    // Callbacks never touch the state, only the sequence counter moved.
    NLS.with(|c| {
        let mut current = c.borrow_mut();
        if current.as_ref().is_some_and(|cur| Rc::ptr_eq(&cur.fd, &st.fd)) {
            *current = Some(st);
        }
    });
    rc
}

/// nl_socket_add_membership(): 0 or negative errno.
pub fn nl_socket_add_membership(group: i32) -> i32 {
    let Some(st) = nls() else {
        return -ENOLINK;
    };
    match owrt_platform::rpcd::netlink_membership(st.fd.as_ref(), group) {
        Ok(()) => 0,
        Err(error) => -error.raw_os_error().unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_roundtrip() {
        let mut m = Msg::new(0x1c, 5, NLM_F_DUMP);
        m.put_u32(3, 7);
        m.put_string(4, "wlan0");
        m.put_flag(174);
        m.complete(9, 0);
        let msg = Nlmsg { data: &m.buf };
        assert_eq!(msg.ty(), 0x1c);
        assert_eq!(msg.flags(), NLM_F_DUMP | NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(msg.seq(), 9);
        assert_eq!(msg.genl_cmd(), 5);
        let (tb, rc) = nla_parse(msg.genl_attrs(), 200, &[(3, 4)]);
        assert_eq!(rc, 0);
        assert_eq!(tb[3].map(|a| a.get_u32()), Some(7));
        assert_eq!(tb[4].map(|a| a.data), Some(&b"wlan0\0"[..]));
        assert!(tb[174].is_some());
        assert_eq!(tb[174].map(|a| a.nla_len()), Some(0));
        // policy violation: 4 bytes required, string attr type 4 has 6, u32 attr shrunk below
        let (_, rc) = nla_parse(msg.genl_attrs(), 200, &[(3, 8)]);
        assert_eq!(rc, -NLE_RANGE);
        // above maxtype is skipped
        let (tb, rc) = nla_parse(msg.genl_attrs(), 100, &[]);
        assert_eq!(rc, 0);
        assert_eq!(tb.len(), 101);
    }
}
