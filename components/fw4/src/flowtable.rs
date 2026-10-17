//! Ask nf_tables directly whether flowtable `ft` exists in table `fw4`.
//!
//! firewall4 learns this one bit by spawning `sh -c "nft --terse --json list
//! flowtables inet"` and scanning the JSON (`fw4.uc` `check_flowtable`).  On the
//! AX3000T that child is about half of a whole `fw4 print`.  The kernel holds
//! the answer and gives it to one `NFT_MSG_GETFLOWTABLE` request: the object
//! comes back when it exists, `-ENOENT` when the table or the flowtable does
//! not.  Without `NLM_F_ACK` the reply is exactly one datagram either way.
//!
//! Anything the kernel does not answer cleanly (no netfilter netlink, no
//! CAP_NET_ADMIN, a truncated or unexpected reply) yields `None`, and the caller
//! falls back to the nft child, so the rendered ruleset can never differ from
//! firewall4's.

use rustix::net::{
    self, sockopt, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType,
};

const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 1;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFT_MSG_NEWFLOWTABLE: u16 = 22;
const NFT_MSG_GETFLOWTABLE: u16 = 23;
const NFTA_FLOWTABLE_TABLE: u16 = 1;
const NFTA_FLOWTABLE_NAME: u16 = 2;
const NFPROTO_INET: u8 = 1;
const ENOENT: i32 = 2;
const SEQ: u32 = 0x6677_3400;

/// `nlmsghdr` + `nfgenmsg` + two string attributes, 4-byte aligned; `None`
/// when the names do not fit the fixed request buffer.
fn request(table: &str, name: &str) -> Option<([u8; 64], usize)> {
    let mut buf = [0u8; 64];
    let mut len = 16;
    buf[len..len + 4].copy_from_slice(&[NFPROTO_INET, 0, 0, 0]); // family, version, res_id
    len += 4;
    for (kind, value) in [(NFTA_FLOWTABLE_TABLE, table), (NFTA_FLOWTABLE_NAME, name)] {
        let payload = value.len() + 1; // NUL-terminated string
        let padded = (4 + payload + 3) & !3;
        if len + padded > buf.len() {
            return None;
        }
        buf[len..len + 2].copy_from_slice(&((4 + payload) as u16).to_ne_bytes());
        buf[len + 2..len + 4].copy_from_slice(&kind.to_ne_bytes());
        buf[len + 4..len + 4 + value.len()].copy_from_slice(value.as_bytes());
        len += padded;
    }
    buf[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
    buf[4..6].copy_from_slice(&((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETFLOWTABLE).to_ne_bytes());
    buf[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    buf[8..12].copy_from_slice(&SEQ.to_ne_bytes());
    Some((buf, len))
}

/// Interpret the single reply datagram: `Some(true)` for the flowtable object,
/// `Some(false)` for `-ENOENT`, `None` for anything else.
fn interpret(reply: &[u8]) -> Option<bool> {
    if reply.len() < 16 {
        return None;
    }
    let len = u32::from_ne_bytes(reply[0..4].try_into().ok()?) as usize;
    let kind = u16::from_ne_bytes(reply[4..6].try_into().ok()?);
    let seq = u32::from_ne_bytes(reply[8..12].try_into().ok()?);
    if len > reply.len() || seq != SEQ {
        return None;
    }
    if kind == (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWFLOWTABLE {
        return Some(true);
    }
    if kind == NLMSG_ERROR && len >= 20 {
        return match i32::from_ne_bytes(reply[16..20].try_into().ok()?) {
            e if e == -ENOENT => Some(false),
            _ => None,
        };
    }
    None
}

/// `Some(exists)` when the kernel answered, `None` when it could not be asked.
pub fn exists(table: &str, name: &str) -> Option<bool> {
    let (msg, len) = request(table, name)?;
    interpret(&exchange(&msg[..len])?)
}

/// One bounded netfilter query; callers validate the response and sequence.
pub(crate) fn exchange(msg: &[u8]) -> Option<Vec<u8>> {
    let fd = net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        Some(net::netlink::NETFILTER),
    )
    .ok()?;
    sockopt::set_socket_timeout(
        &fd,
        sockopt::Timeout::Recv,
        Some(std::time::Duration::from_secs(1)),
    )
    .ok()?;
    let kernel = net::netlink::SocketAddrNetlink::new(0, 0);
    if net::sendto(&fd, msg, SendFlags::empty(), &kernel).ok()? != msg.len() {
        return None;
    }
    let mut reply = [0u8; 8192];
    let (_, n) = net::recvfrom(&fd, &mut reply[..], RecvFlags::TRUNC)
        .ok()
        .map(|(copied, size, _)| (copied, size))?;
    if n == 0 || n > reply.len() {
        return None;
    }
    Some(reply[..n].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nfnl(kind: u16) -> u16 {
        (NFNL_SUBSYS_NFTABLES << 8) | kind
    }

    #[test]
    fn request_layout_matches_nft() {
        let (buf, len) = request("fw4", "ft").unwrap();
        assert_eq!(len, 36);
        assert_eq!(u32::from_ne_bytes(buf[0..4].try_into().unwrap()), 36);
        assert_eq!(
            u16::from_ne_bytes(buf[4..6].try_into().unwrap()),
            nfnl(NFT_MSG_GETFLOWTABLE)
        );
        assert_eq!(
            u16::from_ne_bytes(buf[6..8].try_into().unwrap()),
            NLM_F_REQUEST
        );
        assert_eq!(&buf[16..20], &[NFPROTO_INET, 0, 0, 0]);
        // nla: len 8 ("fw4\0"), type TABLE, "fw4\0"
        assert_eq!(&buf[20..28], &[8, 0, 1, 0, b'f', b'w', b'4', 0]);
        // nla: len 7 ("ft\0"), type NAME, "ft\0" + 1 pad byte
        assert_eq!(&buf[28..36], &[7, 0, 2, 0, b'f', b't', 0, 0]);
        assert!(request(&"x".repeat(40), &"y".repeat(40)).is_none());
    }

    fn reply(kind: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
        v.extend_from_slice(&kind.to_ne_bytes());
        v.extend_from_slice(&0u16.to_ne_bytes());
        v.extend_from_slice(&seq.to_ne_bytes());
        v.extend_from_slice(&0u32.to_ne_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn interpret_object_error_and_noise() {
        let (req, len) = request("fw4", "ft").unwrap();
        assert_eq!(
            interpret(&reply(nfnl(NFT_MSG_NEWFLOWTABLE), SEQ, &[1, 0, 0, 0])),
            Some(true)
        );
        let mut enoent = (-ENOENT).to_ne_bytes().to_vec();
        enoent.extend_from_slice(&req[..len]);
        assert_eq!(interpret(&reply(NLMSG_ERROR, SEQ, &enoent)), Some(false));
        let mut eperm = (-1i32).to_ne_bytes().to_vec();
        eperm.extend_from_slice(&req[..len]);
        assert_eq!(interpret(&reply(NLMSG_ERROR, SEQ, &eperm)), None);
        assert_eq!(
            interpret(&reply(nfnl(NFT_MSG_NEWFLOWTABLE), SEQ + 1, &[])),
            None,
            "foreign sequence"
        );
        assert_eq!(
            interpret(&reply(3, SEQ, &[])),
            None,
            "NLMSG_DONE is not an answer"
        );
        assert_eq!(interpret(&[0; 8]), None);
        let mut short = reply(NLMSG_ERROR, SEQ, &[]);
        short.truncate(16);
        assert_eq!(interpret(&short), None, "error without a code");
    }

    /// Never panics; with the capability it agrees with itself, without it it
    /// reports `None` so the caller keeps firewall4's nft path.
    #[test]
    fn exists_is_total() {
        let a = exists("fw4", "ft");
        let b = exists("fw4", "ft");
        assert_eq!(a, b);
        assert_eq!(exists("fw4", &"n".repeat(60)), None);
    }
}
