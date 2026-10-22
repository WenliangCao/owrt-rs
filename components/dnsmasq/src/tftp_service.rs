//! Socket-independent boundaries from the patched 2.93 `tftp_request()`.
//! These functions do not open files, own sockets, or claim a TFTP daemon.

use std::net::SocketAddr;

/// `dns-protocol.h:50`; `namebuff` has one additional byte for the NUL.
pub const MAX_PATH_BYTES: usize = 503;

/// tftp.c's MAXMESSAGE includes its trailing zero. The same bounded text is
/// carried by ERR and consumed by the logging owner without reformatting.
pub const MAX_ERROR_MESSAGE_BYTES: usize = 500;

/// util.c::prettyprint_addr omits the port and resolves a nonzero IPv6 scope
/// to its current interface name. No socket or interface state is changed.
pub fn peer_label(peer: SocketAddr) -> String {
    let text = peer.ip().to_string();
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if let SocketAddr::V6(peer) = peer {
        if peer.scope_id() != 0 {
            if let Ok(name) = dnsmasq_platform::interfaces::index_to_name(peer.scope_id()) {
                let name = name.split(|&byte| byte == 0).next().unwrap();
                return format!("{text}%{}", String::from_utf8_lossy(name));
            }
        }
    }
    text
}
pub fn error_packet(code: u16, message: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(MAX_ERROR_MESSAGE_BYTES + 4);
    packet.extend_from_slice(&[0, 5]);
    packet.extend_from_slice(&code.to_be_bytes());
    packet.extend(
        message
            .iter()
            .copied()
            .filter(|byte| (0x20..=0x7e).contains(byte))
            .take(MAX_ERROR_MESSAGE_BYTES - 1),
    );
    packet.push(0);
    packet
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathError {
    Empty,
    Nul,
    Traversal,
}

impl std::fmt::Display for PathError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "empty TFTP path",
            Self::Nul => "TFTP path contains a NUL byte",
            Self::Traversal => "TFTP path traverses a parent directory",
        })
    }
}

impl std::error::Error for PathError {}

fn append_bounded(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&bytes[..bytes.len().min(MAX_PATH_BYTES - output.len())]);
}

/// `tftp.c:425-507`: C-locale lowercase, Windows separators, prefix-relative
/// and absolute filenames, and the exact 503-byte concatenation limit.
/// `prefix` is the root after interface/IP/MAC root selection by the caller.
/// Paths are Unix bytes, so non-UTF-8 filenames remain supported.
///
/// This is a textual traversal guard, not symlink confinement: C follows
/// symlinks when opening the resulting path. Unlike C's first-match strstr,
/// every `/..` component is checked (see the recorded differential fixture).
pub fn resolve_path(
    prefix: Option<&[u8]>,
    lowercase: bool,
    filename: &[u8],
) -> Result<Vec<u8>, PathError> {
    let path = error_path(prefix, lowercase, filename)?;
    if prefix.is_some()
        && path
            .split(|&byte| byte == b'/')
            .any(|component| component == b"..")
    {
        return Err(PathError::Traversal);
    }
    Ok(path)
}

/// Format a rejected path for the C ERR_PERM text without opening it.
pub fn error_path(
    prefix: Option<&[u8]>,
    lowercase: bool,
    filename: &[u8],
) -> Result<Vec<u8>, PathError> {
    if filename.is_empty() || prefix == Some(b"") {
        return Err(PathError::Empty);
    }
    if filename.contains(&0) || prefix.is_some_and(|p| p.contains(&0)) {
        return Err(PathError::Nul);
    }
    let normalized: Vec<_> = filename
        .iter()
        .map(|&b| match b {
            b'\\' => b'/',
            _ if lowercase => b.to_ascii_lowercase(),
            _ => b,
        })
        .collect();
    let mut filename = normalized.as_slice();
    let mut path = vec![b'/'];
    if let Some(prefix) = prefix {
        if prefix.starts_with(b"/") {
            path.clear();
        }
        append_bounded(&mut path, prefix);
        if !prefix.ends_with(b"/") {
            append_bounded(&mut path, b"/");
        }
        if filename.starts_with(b"/") {
            if filename.starts_with(&path) {
                path.clear();
            } else {
                filename = &filename[1..];
            }
        }
    } else if filename.starts_with(b"/") {
        path.clear();
    }
    append_bounded(&mut path, filename);
    Ok(path)
}

/// Select C's optional peer directory before appending the requested file.
/// Missing directories fall back independently; when both bits are set the
/// MAC directory is looked up beneath the selected IP directory.
pub fn unique_root(
    prefix: Option<&[u8]>,
    peer: std::net::IpAddr,
    mac: Option<[u8; 6]>,
    by_ip: bool,
    by_mac: bool,
    mut is_directory: impl FnMut(&[u8]) -> bool,
) -> Option<Vec<u8>> {
    let prefix = prefix?;
    if !by_ip && !by_mac {
        return Some(prefix.to_vec());
    }
    let mut path = if prefix.starts_with(b"/") {
        Vec::new()
    } else {
        vec![b'/']
    };
    append_bounded(&mut path, prefix);
    if !prefix.ends_with(b"/") {
        append_bounded(&mut path, b"/");
    }
    if by_ip {
        let base = path.len();
        append_bounded(&mut path, peer.to_string().as_bytes());
        append_bounded(&mut path, b"/");
        if !is_directory(&path) {
            path.truncate(base);
        }
    }
    if let Some(mac) = mac.filter(|_| by_mac) {
        let base = path.len();
        let mut component = [b'-'; 18];
        const HEX: &[u8] = b"0123456789abcdef";
        for (index, byte) in mac.into_iter().enumerate() {
            component[index * 3] = HEX[usize::from(byte >> 4)];
            component[index * 3 + 1] = HEX[usize::from(byte & 15)];
        }
        component[17] = b'/';
        // C uses snprintf rather than strncat here, reserving a NUL byte.
        let available = MAX_PATH_BYTES.saturating_sub(path.len()).saturating_sub(1);
        path.extend_from_slice(&component[..component.len().min(available)]);
        if !is_directory(&path) {
            path.truncate(base);
        }
    }
    Some(path)
}

/// Additional checks after a successful `open(O_RDONLY)` followed by fstat.
/// Kernel access checks are still required; this predicate does not replace
/// opening the file under the daemon's effective identity.
pub fn permitted(mode: u32, owner_uid: u32, effective_uid: u32, secure: bool) -> bool {
    if effective_uid == 0 {
        mode & 0o004 != 0
    } else {
        !secure || owner_uid == effective_uid
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    Ignore,
    /// Source TID has matched. Caller feeds the packet to `Transfer::receive`.
    Existing(usize),
    /// Caller must release the previous file reference before admitting RRQ.
    /// Invalid RRQ/file errors still abandon the old transfer, as C does.
    Replace(usize),
    New,
}

/// The `tftp.c:242-271` single-port dispatch after interface authorization.
/// `active_peers` must use C list order (newest first). In separate-port mode,
/// listener polling/capacity belongs to the event loop; this function must
/// only be called after that poll gate, as in C.
pub fn admission(
    packet: &[u8],
    peer: SocketAddr,
    active_peers: &[SocketAddr],
    single_port: bool,
    max_transfers: usize,
) -> Admission {
    if packet.len() < 2 {
        return Admission::Ignore;
    }
    if single_port {
        if let Some(index) = active_peers.iter().position(|&active| active == peer) {
            return if packet[..2] == [0, 1] {
                Admission::Replace(index)
            } else {
                Admission::Existing(index)
            };
        }
        if active_peers.len() >= max_transfers {
            return Admission::Ignore;
        }
    }
    Admission::New
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_preserves_c_byte_and_prefix_semantics() {
        for (prefix, input, expected) in [
            (
                Some(b"/srv/tftp".as_slice()),
                b"BOOT\\X.EFI".as_slice(),
                b"/srv/tftp/boot/x.efi".as_slice(),
            ),
            (Some(b"srv/tftp"), b"a", b"/srv/tftp/a"),
            (Some(b"/srv/tftp"), b"/srv/tftp/a", b"/srv/tftp/a"),
            (Some(b"/srv/tftp"), b"/srv/tftp", b"/srv/tftp/srv/tftp"),
            (Some(b"/srv/tftp"), b"/other/a", b"/srv/tftp/other/a"),
            (None, b"../a", b"/../a"),
            (None, b"x/\xff", b"/x/\xff"),
        ] {
            assert_eq!(resolve_path(prefix, true, input).unwrap(), expected);
        }
    }

    #[test]
    fn all_parent_components_are_rejected_only_with_prefix() {
        for input in [b"../a".as_slice(), b"a/../b", b"..valid/../../escape"] {
            assert_eq!(
                resolve_path(Some(b"/srv"), false, input),
                Err(PathError::Traversal)
            );
        }
        assert_eq!(
            resolve_path(Some(b"/srv"), false, b"..valid/a").unwrap(),
            b"/srv/..valid/a"
        );
    }

    #[test]
    fn path_has_the_exact_c_truncation_limit() {
        assert_eq!(resolve_path(None, false, &[b'x'; 800]).unwrap().len(), 503);
        assert_eq!(
            resolve_path(Some(&[b'x'; 503]), false, b"a").unwrap().len(),
            503
        );
    }

    #[test]
    fn root_and_secure_checks_follow_c_branch_order() {
        assert!(!permitted(0o640, 0, 0, false));
        assert!(permitted(0o644, 2000, 0, true));
        assert!(!permitted(0o644, 2000, 1000, true));
        assert!(permitted(0o640, 1000, 1000, true));
        assert!(permitted(0o640, 2000, 1000, false));
    }

    #[test]
    fn single_port_peer_match_precedes_capacity_and_opcode_parsing() {
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let other: SocketAddr = "127.0.0.1:1235".parse().unwrap();
        assert_eq!(
            admission(&[0, 1], peer, &[peer], true, 1),
            Admission::Replace(0)
        );
        assert_eq!(
            admission(&[0, 4], peer, &[peer], true, 1),
            Admission::Existing(0)
        );
        assert_eq!(
            admission(&[0, 2], peer, &[peer], true, 1),
            Admission::Existing(0)
        );
        assert_eq!(
            admission(&[0, 1], other, &[peer], true, 1),
            Admission::Ignore
        );
        assert_eq!(admission(&[0], peer, &[peer], true, 1), Admission::Ignore);
        assert_eq!(admission(&[0, 1], peer, &[peer], false, 1), Admission::New);
    }
    #[test]
    fn unique_peer_roots_fall_back_and_preserve_combined_order() {
        let ip = "192.0.2.1".parse().unwrap();
        let mac = Some([2, 0, 0, 0, 0, 1]);
        assert_eq!(
            unique_root(Some(b"/srv"), ip, mac, true, true, |_| true).unwrap(),
            b"/srv/192.0.2.1/02-00-00-00-00-01/"
        );
        assert_eq!(
            unique_root(Some(b"/srv"), ip, mac, true, true, |p| !p
                .ends_with(b"192.0.2.1/"))
            .unwrap(),
            b"/srv/02-00-00-00-00-01/"
        );
        assert_eq!(
            unique_root(Some(b"/srv"), ip, mac, true, true, |_| false).unwrap(),
            b"/srv/"
        );
        assert_eq!(
            unique_root(None, ip, mac, true, true, |_| panic!("no root lookup")),
            None
        );
    }
}
