//! Minimal rtnetlink dumps (link, address, neighbour) with the exact message
//! layouts of <linux/rtnetlink.h>, plus a musl-getifaddrs-shaped view built
//! from the link and address dumps (luci-rpc.c consumes getifaddrs()).

use std::io;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const AF_PACKET: u8 = 17;

const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x100 | 0x200;
const NLM_F_MULTI: u16 = 2;

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_GETNEIGH: u16 = 30;

pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_IFNAME: u16 = 3;
pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_LABEL: u16 = 3;
pub const IFA_BROADCAST: u16 = 4;
pub const NDA_DST: u16 = 1;
pub const NDA_LLADDR: u16 = 2;
pub const NUD_NOARP: u16 = 0x40;

pub const IFF_UP: u32 = 0x1;
pub const IFF_BROADCAST: u32 = 0x2;
pub const IFF_LOOPBACK: u32 = 0x8;
pub const IFF_POINTOPOINT: u32 = 0x10;
pub const IFF_NOARP: u32 = 0x80;
pub const IFF_PROMISC: u32 = 0x100;
pub const IFF_MULTICAST: u32 = 0x1000;

/// One netlink message of a dump: type, flags, payload after the 16-byte header.
pub struct Msg {
    pub ty: u16,
    /// nlmsg_flags, kept for completeness of the header decode
    #[allow(dead_code)]
    pub flags: u16,
    pub payload: Vec<u8>,
}

/// rtattr walk over `data`: (type, value)
pub fn attrs(data: &[u8]) -> Vec<(u16, &[u8])> {
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

/// nl_connect(NETLINK_ROUTE) + NLM_F_REQUEST|NLM_F_DUMP of `ty` with the fixed
/// header `hdr` (ifinfomsg/ifaddrmsg/ndmsg, zero-filled by the callers);
/// returns every multipart message until NLMSG_DONE.
pub fn dump(ty: u16, hdr: &[u8]) -> io::Result<Vec<Msg>> {
    let fd = rustix::net::socket_with(
        rustix::net::AddressFamily::NETLINK,
        rustix::net::SocketType::RAW,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )?;
    rustix::net::bind(&fd, &rustix::net::netlink::SocketAddrNetlink::new(0, 0))?;
    let seq: u32 = 1;
    let total = (16 + hdr.len() + 3) & !3;
    let mut req = Vec::with_capacity(total);
    req.extend_from_slice(&(total as u32).to_le_bytes());
    req.extend_from_slice(&ty.to_le_bytes());
    req.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_le_bytes());
    req.extend_from_slice(&seq.to_le_bytes());
    req.extend_from_slice(&0u32.to_le_bytes());
    req.extend_from_slice(hdr);
    req.resize(total, 0);
    rustix::net::send(&fd, &req, rustix::net::SendFlags::empty())?;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    loop {
        let (_, n) = match rustix::net::recv(&fd, &mut buf, rustix::net::RecvFlags::empty()) {
            Ok(result) => result,
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        };
        let mut off = 0;
        let mut done = false;
        while off + 16 <= n {
            let len = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            let mty = u16::from_le_bytes([buf[off + 4], buf[off + 5]]);
            let flags = u16::from_le_bytes([buf[off + 6], buf[off + 7]]);
            if len < 16 || off + len > n {
                done = true;
                break;
            }
            match mty {
                NLMSG_DONE => {
                    done = true;
                    break;
                }
                NLMSG_ERROR => {
                    done = true;
                    break;
                }
                _ => out.push(Msg {
                    ty: mty,
                    flags,
                    payload: buf[off + 16..off + len].to_vec(),
                }),
            }
            if flags & NLM_F_MULTI == 0 {
                done = true;
            }
            off += (len + 3) & !3;
        }
        if done {
            break;
        }
    }
    Ok(out)
}

/// struct ifaddrs as musl builds it: one AF_PACKET entry per link (from the
/// link dump, in dump order), then one entry per address (address dump order),
/// carrying the link's flags. `dst` is IFA_ADDRESS when IFA_LOCAL was present.
#[derive(Clone, Debug, Default)]
pub struct IfAddr {
    pub name: String,
    pub family: u8,
    pub flags: u32,
    /// AF_PACKET: sll_hatype
    pub hatype: u16,
    pub ifindex: i32,
    /// AF_PACKET: sll_addr (halen bytes), AF_INET/6: the address bytes
    pub addr: Vec<u8>,
    pub netmask: Option<Vec<u8>>,
    pub broadcast: Option<Vec<u8>>,
    pub dst: Option<Vec<u8>>,
}

fn gen_netmask(family: u8, prefix: u8) -> Vec<u8> {
    let len = if family == AF_INET { 4 } else { 16 };
    let mut m = vec![0u8; len];
    let mut p = (prefix as usize).min(len * 8);
    for b in m.iter_mut() {
        if p >= 8 {
            *b = 0xff;
            p -= 8;
        } else {
            *b = (0xffu16 << (8 - p)) as u8;
            break;
        }
    }
    m
}

/// getifaddrs()
pub fn getifaddrs() -> io::Result<Vec<IfAddr>> {
    let mut list: Vec<IfAddr> = Vec::new();
    let links = dump(RTM_GETLINK, &[0u8; 16])?;
    for m in links {
        if m.ty != RTM_NEWLINK || m.payload.len() < 16 {
            continue;
        }
        let p = &m.payload;
        let ifi_type = u16::from_le_bytes([p[2], p[3]]);
        let index = i32::from_le_bytes(p[4..8].try_into().unwrap());
        let flags = u32::from_le_bytes(p[8..12].try_into().unwrap());
        let mut e = IfAddr {
            family: AF_PACKET,
            flags,
            hatype: ifi_type,
            ifindex: index,
            ..Default::default()
        };
        for (t, v) in attrs(&p[16..]) {
            match t {
                IFLA_IFNAME => {
                    e.name = String::from_utf8_lossy(v.split(|&b| b == 0).next().unwrap_or(&[]))
                        .into_owned()
                }
                IFLA_ADDRESS => e.addr = v.to_vec(),
                _ => {}
            }
        }
        list.push(e);
    }
    let nlinks = list.len();
    let addrs = dump(RTM_GETADDR, &[0u8; 8])?;
    for m in addrs {
        if m.ty != RTM_NEWADDR || m.payload.len() < 8 {
            continue;
        }
        let p = &m.payload;
        let family = p[0];
        let prefix = p[1];
        let index = u32::from_le_bytes(p[4..8].try_into().unwrap()) as i32;
        let Some(link) = list[..nlinks].iter().find(|l| l.ifindex == index) else {
            continue;
        };
        let mut e = IfAddr {
            name: link.name.clone(),
            family,
            flags: link.flags,
            ifindex: index,
            ..Default::default()
        };
        for (t, v) in attrs(&p[8..]) {
            match t {
                IFA_ADDRESS => {
                    if !e.addr.is_empty() {
                        e.dst = Some(v.to_vec());
                    } else {
                        e.addr = v.to_vec();
                    }
                }
                IFA_LOCAL => {
                    if !e.addr.is_empty() {
                        e.dst = Some(std::mem::take(&mut e.addr));
                    }
                    e.addr = v.to_vec();
                }
                IFA_BROADCAST => e.broadcast = Some(v.to_vec()),
                IFA_LABEL => {
                    e.name = String::from_utf8_lossy(v.split(|&b| b == 0).next().unwrap_or(&[]))
                        .into_owned()
                }
                _ => {}
            }
        }
        if e.addr.is_empty() {
            continue;
        }
        e.netmask = Some(gen_netmask(family, prefix));
        list.push(e);
    }
    Ok(list)
}

/// inet_ntop for the byte forms used above.
pub fn ntop(family: u8, b: &[u8]) -> String {
    match (family, b.len()) {
        (AF_INET, 4) => std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
        (AF_INET6, 16) => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap()).to_string(),
        _ => String::new(),
    }
}

/// ea2str: "%02X:%02X:..." over the first six bytes (zero-padded when shorter).
pub fn ea2str(b: &[u8]) -> String {
    let mut o = [0u8; 6];
    for (i, v) in b.iter().take(6).enumerate() {
        o[i] = *v;
    }
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        o[0], o[1], o[2], o[3], o[4], o[5]
    )
}

pub struct Neigh {
    pub family: u8,
    pub state: u16,
    pub lladdr: Option<Vec<u8>>,
    pub dst: Option<Vec<u8>>,
}

/// RTM_GETNEIGH dump with a zeroed ndmsg.
pub fn neighbours() -> io::Result<Vec<Neigh>> {
    let msgs = dump(RTM_GETNEIGH, &[0u8; 12])?;
    let mut out = Vec::new();
    for m in msgs {
        if m.ty != RTM_NEWNEIGH || m.payload.len() < 12 {
            continue;
        }
        let p = &m.payload;
        let mut n = Neigh {
            family: p[0],
            state: u16::from_le_bytes([p[8], p[9]]),
            lladdr: None,
            dst: None,
        };
        for (t, v) in attrs(&p[12..]) {
            match t {
                NDA_LLADDR => n.lladdr = Some(v.to_vec()),
                NDA_DST => n.dst = Some(v.to_vec()),
                _ => {}
            }
        }
        out.push(n);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask() {
        assert_eq!(ntop(AF_INET, &gen_netmask(AF_INET, 24)), "255.255.255.0");
        assert_eq!(ntop(AF_INET, &gen_netmask(AF_INET, 19)), "255.255.224.0");
        assert_eq!(
            ntop(AF_INET6, &gen_netmask(AF_INET6, 64)),
            "ffff:ffff:ffff:ffff::"
        );
        assert_eq!(ea2str(&[0xde, 0xad, 0xbe, 0xef, 0, 1]), "DE:AD:BE:EF:00:01");
    }
}
