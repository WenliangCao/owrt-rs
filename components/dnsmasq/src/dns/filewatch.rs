//! Linux inotify boundary from the exact image's inotify.c. Resolver watches
//! attach to startup-resolved parent directories, never to an open leaf fd.

use rustix::fs::inotify::{self, CreateFlags, WatchFlags};
use rustix::net::{
    self, netlink::SocketAddrNetlink, AddressFamily, RecvFlags, SocketFlags, SocketType,
};
use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

const IN_CLOSE_WRITE: u32 = 0x8;
const IN_MOVED_TO: u32 = 0x80;
const IN_DELETE: u32 = 0x200;
// Pinned AArch64 musl sys/param.h; C allows 20 traversals, rejects the 21st.
const MAX_SYMLINKS: usize = 20;

/// C netlink.c:68–71 subscribes to route and address changes even at port=0.
/// The two event kinds stay separate: address changes never force poll_resolv.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct NetworkEvents {
    pub route: bool,
    pub address: bool,
    pub errors: Vec<i32>,
}

fn bind_groups(mut bind_group: impl FnMut(u32) -> io::Result<()>) -> io::Result<()> {
    match bind_group(0x40 | 0x10 | 0x400 | 0x100) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(1) => bind_group(0),
        Err(error) => Err(error),
    }
}

pub struct RouteWatch {
    fd: File,
    bytes: Vec<u8>,
}

impl RouteWatch {
    pub fn new() -> io::Result<Self> {
        let fd = File::from(net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )?);
        bind_groups(|groups| {
            net::bind(&fd, &SocketAddrNetlink::new(0, groups)).map_err(Into::into)
        })?;
        net::getsockname(&fd)?;
        Ok(Self {
            fd,
            bytes: vec![0; 512],
        })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn append_poll_fds(&self, fds: &mut Vec<owrt_ubus::sys::PollFd>) {
        fds.push(owrt_ubus::sys::PollFd {
            fd: self.fd.as_raw_fd(),
            events: 1,
            revents: 0,
        });
    }

    /// Read at most one datagram per owner turn. Peek its actual size first,
    /// following netlink_recv, and reject clipped/user-origin messages.
    pub fn read_events(&mut self) -> io::Result<NetworkEvents> {
        let needed = match net::recvfrom(
            &self.fd,
            self.bytes.as_mut_slice(),
            RecvFlags::PEEK | RecvFlags::TRUNC,
        ) {
            Ok((_, needed, _)) => needed,
            Err(error) => return read_error(error),
        };
        if needed > self.bytes.len() {
            self.bytes.resize(needed, 0);
        }
        let (_, length, address) =
            match net::recvfrom(&self.fd, self.bytes.as_mut_slice(), RecvFlags::TRUNC) {
                Ok(result) => result,
                Err(error) => return read_error(error),
            };
        let kernel = address
            .filter(|address| address.addr_len() >= 12)
            .and_then(|address| SocketAddrNetlink::try_from(address).ok())
            .is_some_and(|address| address.pid() == 0);
        if length > self.bytes.len() || !kernel {
            return Ok(NetworkEvents::default());
        }
        Ok(network_events(&self.bytes[..length as usize]))
    }
}

fn read_error(error: rustix::io::Errno) -> io::Result<NetworkEvents> {
    let error = io::Error::from(error);
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) {
        Ok(NetworkEvents::default())
    } else {
        Err(error)
    }
}

fn network_events(mut bytes: &[u8]) -> NetworkEvents {
    let mut events = NetworkEvents::default();
    while bytes.len() >= 16 {
        let length = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
        if length < 16 || length > bytes.len() {
            break;
        }
        let kind = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
        let pid = u32::from_ne_bytes(bytes[12..16].try_into().unwrap());
        // netlink.c::nl_async: RTM_NEWROUTE, RTN_UNICAST, RT_SCOPE_LINK,
        // RT_TABLE_MAIN or RT_TABLE_LOCAL. A delete/address message is not it.
        if kind == 24
            && pid == 0
            && length >= 28
            && bytes[23] == 1
            && bytes[22] == 253
            && matches!(bytes[20], 254 | 255)
        {
            events.route = true;
        } else if matches!(kind, 20 | 21) {
            events.address = true;
        } else if kind == 2 && length >= 20 {
            let error = i32::from_ne_bytes(bytes[16..20].try_into().unwrap());
            if error != 0 {
                events.errors.push(error.checked_neg().unwrap_or(i32::MAX));
            }
        }
        let aligned = (length + 3) & !3;
        if aligned > bytes.len() {
            break;
        }
        bytes = &bytes[aligned..];
    }
    events
}

#[cfg(test)]
fn qualifying_route(bytes: &[u8]) -> bool {
    network_events(bytes).route
}

#[derive(Debug)]
pub enum WatchError {
    Init(io::Error),
    Link { path: PathBuf, error: io::Error },
    TooManyLinks(PathBuf),
    MissingParent(PathBuf),
    Add { path: PathBuf, error: io::Error },
}

impl std::fmt::Display for WatchError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init(error) => write!(out, "failed to create inotify: {}", os_message(error)),
            Self::Link { path, error } => {
                write!(
                    out,
                    "cannot access path {}: {}",
                    path.display(),
                    os_message(error)
                )
            }
            Self::TooManyLinks(path) => {
                write!(out, "too many symlinks following {}", path.display())
            }
            Self::MissingParent(path) => write!(
                out,
                "directory {} for resolv-file is missing, cannot poll",
                path.display()
            ),
            Self::Add { path, error } => write!(
                out,
                "failed to create inotify for {}: {}",
                path.display(),
                os_message(error)
            ),
        }
    }
}

impl std::error::Error for WatchError {}

pub(super) fn os_message(error: &io::Error) -> String {
    let mut message = error.to_string();
    if let Some(code) = error.raw_os_error() {
        if let Some(text) = message.strip_suffix(&format!(" (os error {code})")) {
            message.truncate(text.len());
        }
    }
    message
}

struct WatchedFile {
    descriptor: i32,
    name: Vec<u8>,
}

pub struct FileWatch {
    fd: File,
    files: Vec<WatchedFile>,
    directories: Vec<(i32, usize)>,
    hosts_events: Vec<super::hostsdir::DirectoryEvent>,
}

impl FileWatch {
    /// Empty paths still create the descriptor when the caller enables the
    /// resolver subsystem. no-poll deliberately does not suppress watches.
    pub fn new(paths: impl IntoIterator<Item = impl AsRef<Path>>) -> Result<Self, WatchError> {
        let fd = inotify::init(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC)
            .map_err(|error| WatchError::Init(error.into()))?;
        let mut watch = Self {
            fd: File::from(fd),
            files: Vec::new(),
            directories: Vec::new(),
            hosts_events: Vec::new(),
        };
        for original in paths {
            let original = original.as_ref();
            let (path, last_error) = follow_links(original)?;
            let bytes = path.as_os_str().as_bytes();
            let Some(slash) = bytes.iter().rposition(|byte| *byte == b'/') else {
                return Err(WatchError::Add {
                    path: original.to_owned(),
                    error: last_error,
                });
            };
            let parent = CString::new(&bytes[..slash]).map_err(|_| WatchError::Add {
                path: original.to_owned(),
                error: io::Error::from_raw_os_error(22),
            })?;
            let descriptor = inotify::add_watch(
                &watch.fd,
                parent.as_c_str(),
                WatchFlags::CLOSE_WRITE | WatchFlags::MOVED_TO,
            )
            .map_err(|error| {
                let error = io::Error::from(error);
                if error.raw_os_error() == Some(2) {
                    WatchError::MissingParent(original.to_owned())
                } else {
                    WatchError::Add {
                        path: original.to_owned(),
                        error,
                    }
                }
            })?;
            watch.files.push(WatchedFile {
                descriptor,
                name: bytes[slash + 1..].to_vec(),
            });
        }
        Ok(watch)
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn add_hosts_directory(&mut self, directory: usize, path: &Path) -> io::Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::from_raw_os_error(22))?;
        let descriptor = inotify::add_watch(
            &self.fd,
            path.as_c_str(),
            WatchFlags::CLOSE_WRITE | WatchFlags::MOVED_TO | WatchFlags::DELETE,
        )?;
        self.directories.push((descriptor, directory));
        Ok(())
    }

    pub fn take_hosts_events(&mut self) -> Vec<super::hostsdir::DirectoryEvent> {
        std::mem::take(&mut self.hosts_events)
    }

    pub(super) fn pending(&self) -> io::Result<bool> {
        let mut fds = [owrt_ubus::sys::PollFd {
            fd: self.raw_fd(),
            events: 1,
            revents: 0,
        }];
        Ok(owrt_ubus::sys::poll_fds(&mut fds, 0)? != 0)
    }

    /// Consume one bounded kernel batch. Remaining events keep POLLIN set and
    /// are drained on the next owner turn; no read-to-empty busy loop.
    pub fn read_events(&mut self) -> io::Result<bool> {
        let mut bytes = [0u8; 4096];
        match self.fd.read(&mut bytes) {
            Ok(length) => Ok(self.contains_resolver_event(&bytes[..length])),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn contains_resolver_event(&mut self, mut bytes: &[u8]) -> bool {
        let mut resolver_hit = false;
        while bytes.len() >= 16 {
            let descriptor = i32::from_ne_bytes(bytes[..4].try_into().unwrap());
            let mask = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
            let length = u32::from_ne_bytes(bytes[12..16].try_into().unwrap()) as usize;
            let Some(name) = bytes.get(16..16usize.saturating_add(length)) else {
                break;
            };
            let name = name.split(|byte| *byte == 0).next().unwrap_or_default();
            if watched_name(name)
                && self
                    .files
                    .iter()
                    .any(|file| file.descriptor == descriptor && file.name == name)
            {
                resolver_hit = true;
            }
            if watched_name(name) && mask & (IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE) != 0 {
                for &(_, directory) in self.directories.iter().filter(|(wd, _)| *wd == descriptor) {
                    self.hosts_events.push(super::hostsdir::DirectoryEvent {
                        directory,
                        name: name.to_vec(),
                        deleted: mask & IN_DELETE != 0,
                    });
                }
            }
            bytes = &bytes[16 + length..];
        }
        resolver_hit
    }
}

fn watched_name(name: &[u8]) -> bool {
    super::hostsdir::watched_name(name)
}

fn follow_links(original: &Path) -> Result<(PathBuf, io::Error), WatchError> {
    let mut path = original.to_owned();
    for depth in 0.. {
        match fs::read_link(&path) {
            Ok(target) => {
                if depth >= MAX_SYMLINKS {
                    return Err(WatchError::TooManyLinks(original.to_owned()));
                }
                let mut bytes = path.as_os_str().as_bytes().to_vec();
                let target = target.as_os_str().as_bytes();
                if !target.starts_with(b"/") {
                    if let Some(slash) = bytes.iter().rposition(|byte| *byte == b'/') {
                        bytes.truncate(slash + 1);
                        bytes.extend_from_slice(target);
                        path = OsString::from_vec(bytes).into();
                        continue;
                    }
                }
                path = OsString::from_vec(target.to_vec()).into();
            }
            Err(error) if matches!(error.raw_os_error(), Some(2 | 22)) => return Ok((path, error)),
            Err(error) => return Err(WatchError::Link { path, error }),
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 16];
        bytes[..4].copy_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn address_and_route_events_have_independent_consumers() {
        for kind in [20, 21] {
            let events = network_events(&event(kind, &[0; 8]));
            assert!(events.address);
            assert!(!events.route);
        }
        for kind in [16, 25] {
            assert_eq!(
                network_events(&event(kind, &[0; 12])),
                NetworkEvents::default()
            );
        }
        let mut route = event(24, &[0; 12]);
        route[20] = 254;
        route[22] = 253;
        route[23] = 1;
        let mut mixed = event(20, &[0; 8]);
        mixed.extend(route);
        let events = network_events(&mixed);
        assert!(events.address && events.route);
        assert!(events.errors.is_empty());
    }

    #[test]
    fn kernel_errors_are_diagnostics_not_address_or_resolver_reloads() {
        let events = network_events(&event(2, &(-13i32).to_ne_bytes()));
        assert_eq!(events.errors, [13]);
        assert!(!events.address && !events.route);
        assert_eq!(
            network_events(&event(2, &0i32.to_ne_bytes())),
            NetworkEvents::default()
        );
        assert_eq!(
            network_events(&event(20, &[0; 8])[..23]),
            NetworkEvents::default()
        );
    }

    #[test]
    fn multicast_only_eperm_falls_back_once_to_ungrouped_socket() {
        let mut groups = Vec::new();
        bind_groups(|value| {
            groups.push(value);
            if value != 0 {
                Err(io::Error::from_raw_os_error(1))
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(groups, [0x550, 0]);
        let mut groups = Vec::new();
        let error = bind_groups(|value| {
            groups.push(value);
            Err(io::Error::from_raw_os_error(22))
        })
        .unwrap_err();
        assert_eq!(groups, [0x550]);
        assert_eq!(error.raw_os_error(), Some(22));
        let error = bind_groups(|value| {
            Err(io::Error::from_raw_os_error(if value == 0 {
                13
            } else {
                1
            }))
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(13));
    }

    #[test]
    fn route_predicate_requires_complete_kernel_link_scope_unicast() {
        let mut row = [0; 28];
        row[..4].copy_from_slice(&28u32.to_ne_bytes());
        row[4..6].copy_from_slice(&24u16.to_ne_bytes());
        row[20] = 254;
        row[22] = 253;
        row[23] = 1;
        assert!(qualifying_route(&row));
        for (index, value) in [(4, 25), (12, 1), (20, 100), (22, 0), (23, 2)] {
            let mut wrong = row;
            wrong[index] = value;
            assert!(!qualifying_route(&wrong));
        }
        assert!(!qualifying_route(&row[..27]));
        row[20] = 255;
        assert!(qualifying_route(&row));
    }

    #[test]
    fn event_scanner_observes_file_names_and_global_filters() {
        let mut watch = FileWatch::new(std::iter::empty::<&Path>()).unwrap();
        for name in [b"resolv".as_slice(), b".hidden", b"backup~", b"#temp#"] {
            watch.files.push(WatchedFile {
                descriptor: 7,
                name: name.to_vec(),
            });
            let mut event = Vec::new();
            event.extend_from_slice(&7i32.to_ne_bytes());
            event.extend_from_slice(&IN_CLOSE_WRITE.to_ne_bytes());
            event.extend_from_slice(&0u32.to_ne_bytes());
            event.extend_from_slice(&((name.len() + 1) as u32).to_ne_bytes());
            event.extend_from_slice(name);
            event.push(0);
            assert_eq!(watch.contains_resolver_event(&event), name == b"resolv");
            assert!(!watch.contains_resolver_event(&event[..15]));
        }
    }

    #[test]
    fn shared_directory_watch_preserves_burst_order_after_a_resolver_hit() {
        let mut watch = FileWatch::new(std::iter::empty::<&Path>()).unwrap();
        watch.files.push(WatchedFile {
            descriptor: 7,
            name: b"resolv".to_vec(),
        });
        watch.directories.extend([(7, 0), (7, 1)]);
        let mut bytes = Vec::new();
        for (mask, name) in [
            (IN_CLOSE_WRITE, b"resolv".as_slice()),
            (IN_DELETE, b"one"),
            (0x40, b"moved-from"),
            (0x100, b"create"),
            (IN_MOVED_TO, b"two"),
            (IN_DELETE, b".hidden"),
        ] {
            bytes.extend_from_slice(&7i32.to_ne_bytes());
            bytes.extend_from_slice(&mask.to_ne_bytes());
            bytes.extend_from_slice(&0u32.to_ne_bytes());
            bytes.extend_from_slice(&((name.len() + 1) as u32).to_ne_bytes());
            bytes.extend_from_slice(name);
            bytes.push(0);
        }
        assert!(watch.contains_resolver_event(&bytes));
        let events = watch.take_hosts_events();
        assert_eq!(
            events
                .iter()
                .map(|event| (event.directory, event.name.as_slice(), event.deleted))
                .collect::<Vec<_>>(),
            [
                (0, b"resolv".as_slice(), false),
                (1, b"resolv", false),
                (0, b"one", true),
                (1, b"one", true),
                (0, b"two", false),
                (1, b"two", false)
            ]
        );
        assert!(watch.take_hosts_events().is_empty());
    }
}
