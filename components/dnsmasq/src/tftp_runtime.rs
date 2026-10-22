//! Socket-independent TFTP transfer runtime.
//!
//! This is the file/open/packet boundary below the UDP listener. It
//! owns real file descriptors through `Arc`, drives the existing `tftp::Transfer`
//! state machine, and emits packets/events through a caller-owned transport.
//! Interface pktinfo, port-69 listeners, PXE helper scripts and OpenWrt reload
//! remain outside this module.

use crate::tftp::{self, Mode, ReadRequest, RequestError, Transfer};
use crate::tftp_service::{permitted, resolve_path, Admission as PeerAdmission};
use std::fs::File;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::{FileExt, MetadataExt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

pub trait FileReader: Send + Sync {
    fn size(&self) -> u64;
    fn identity(&self) -> FileIdentity;
    fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize>;
}

pub struct OpenedFile {
    pub path: Vec<u8>,
    pub identity: FileIdentity,
    pub size: u64,
    pub mode: u32,
    pub owner_uid: u32,
    pub reader: FileSource,
}

/// Real transfers own a descriptor directly. Adapters can supply a shared
/// reader without imposing an infallible heap allocation on the real opener.
pub enum FileSource {
    #[cfg(unix)]
    File(File),
    Shared(Arc<dyn FileReader>),
}

impl FileSource {
    fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::File(file) => file.read_at(output, offset),
            Self::Shared(reader) => reader.read_at(offset, output),
        }
    }
}

impl std::fmt::Debug for OpenedFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenedFile")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

pub trait FileOpener: Send + Sync {
    fn open(&self, path: &[u8]) -> io::Result<OpenedFile>;
}

#[derive(Clone, Copy, Debug)]
pub struct RealFileOpener {
    pub effective_uid: u32,
    pub secure: bool,
}

impl RealFileOpener {
    pub const fn new(effective_uid: u32, secure: bool) -> Self {
        Self {
            effective_uid,
            secure,
        }
    }
}

impl FileOpener for RealFileOpener {
    fn open(&self, path: &[u8]) -> io::Result<OpenedFile> {
        #[cfg(unix)]
        {
            let file = File::open(std::ffi::OsString::from_vec(path.to_vec()))?;
            // C reports any fstat failure as ERR_NOTDEF, independently of
            // errno. Preserve that distinction from open's ENOENT/EACCES.
            let metadata = file.metadata().map_err(io::Error::other)?;
            let identity = FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            };
            if !permitted(
                metadata.mode(),
                metadata.uid(),
                self.effective_uid,
                self.secure,
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TFTP file permission policy",
                ));
            }
            Ok(OpenedFile {
                path: path.to_vec(),
                identity,
                size: metadata.len(),
                mode: metadata.mode(),
                owner_uid: metadata.uid(),
                reader: FileSource::File(file),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TFTP real opener requires Unix metadata/read_at",
            ))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    pub path: RuntimePathPolicy,
    pub packet_buffer_size: usize,
    pub mtu: Option<u32>,
    pub ipv6: bool,
    pub no_block_size: bool,
    pub effective_uid: u32,
    pub secure: bool,
    pub max_transfers: usize,
    pub single_port: bool,
}

/// Per-request interface policy. Existing transfers retain their negotiated
/// block size and open file when interface state or root contents change.
#[derive(Clone, Debug)]
pub struct RequestPolicy {
    pub path: RuntimePathPolicy,
    pub mtu: Option<u32>,
    pub ipv6: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimePathPolicy {
    pub prefix: Option<Vec<u8>>,
    pub lowercase: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            path: RuntimePathPolicy::default(),
            // dnsmasq.c:124: EDNS_PKTSZ + MAXDNAME + RRFIXEDSZ.
            packet_buffer_size: 1232 + 255 + 10,
            mtu: None,
            ipv6: false,
            no_block_size: false,
            effective_uid: 0,
            secure: false,
            max_transfers: 50,
            single_port: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Completion {
    pub id: TransferId,
    pub peer: SocketAddr,
    pub path: Vec<u8>,
    pub size: u64,
}

/// One RRQ instance. Dedicated transfers may share a peer, but never an ID.
pub type TransferId = u64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeEvent {
    Send {
        id: Option<TransferId>,
        peer: SocketAddr,
        packet: Vec<u8>,
    },
    TidError {
        id: TransferId,
        peer: SocketAddr,
        packet: Vec<u8>,
    },
    Completed(Completion),
    /// First DATA construction failed before C links the transfer. Cleanup
    /// needs its ID, but no established-transfer "failed sending" log exists.
    Discarded {
        id: TransferId,
    },
    Failed {
        id: TransferId,
        peer: SocketAddr,
        path: Vec<u8>,
    },
    TimedOut {
        id: TransferId,
        peer: SocketAddr,
        path: Vec<u8>,
    },
    ClientError {
        peer: SocketAddr,
        code: u16,
        message: Vec<u8>,
    },
    NoFreePort,
    TransportError {
        id: Option<TransferId>,
        peer: SocketAddr,
        kind: io::ErrorKind,
    },
}

impl RuntimeEvent {
    /// tftp.c shares the bounded ERR text with its logger. Completion and
    /// abort messages retain the opened file's identity after cleanup.
    #[cfg(target_os = "linux")]
    pub fn log_event(&self, quiet_not_found: bool) -> Option<crate::logging::LogEvent> {
        use crate::logging::{LogEvent, Priority, Service};
        if let Some((code, message)) = self.error_message() {
            return (code != 1 || !quiet_not_found)
                .then(|| LogEvent::new(Service::Tftp, Priority::Error, message.to_vec()));
        }
        let (priority, message) = match self {
            Self::Completed(done) => (
                Priority::Info,
                format!(
                    "sent {} to {}",
                    sanitised_path(&done.path),
                    crate::tftp_service::peer_label(done.peer)
                ),
            ),
            Self::Failed { path, peer, .. } => (
                Priority::Error,
                format!(
                    "failed sending {} to {}",
                    sanitised_path(path),
                    crate::tftp_service::peer_label(*peer)
                ),
            ),
            Self::TimedOut { path, peer, .. } => (
                Priority::Error,
                format!(
                    "timeout sending {} to {}",
                    sanitised_path(path),
                    crate::tftp_service::peer_label(*peer)
                ),
            ),
            Self::ClientError {
                code,
                message,
                peer,
            } => (
                Priority::Error,
                format!(
                    "error {code} {} received from {}",
                    sanitised_path(message),
                    crate::tftp_service::peer_label(*peer)
                ),
            ),
            Self::NoFreePort => (
                Priority::Error,
                "unable to get free port for TFTP".to_owned(),
            ),
            _ => return None,
        };
        Some(LogEvent::new(Service::Tftp, priority, message.into_bytes()))
    }

    /// The logger consumes the exact bounded wire text. quiet-tftp may
    /// suppress ERR_FNF logging; it must not change the transmitted packet.
    pub fn error_message(&self) -> Option<(u16, &[u8])> {
        let packet = match self {
            Self::Send { packet, .. } | Self::TidError { packet, .. } => packet,
            _ => return None,
        };
        if packet.len() < 5 || packet[..2] != [0, 5] {
            return None;
        }
        let code = u16::from_be_bytes([packet[2], packet[3]]);
        let message = &packet[4..];
        Some((code, message.strip_suffix(&[0]).unwrap_or(message)))
    }
}

/// Which caller-owned UDP socket delivered a datagram.  In separate-port
/// mode dnsmasq accepts RRQ/WRQ on the port-69 listener and ACK/ERR only on
/// the transfer socket created for that RRQ.  This role gate keeps those
/// paths distinct without binding sockets or allocating transfer ports here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketRole {
    Server,
    Transfer(TransferId),
}

#[derive(Debug)]
pub enum RuntimeError {
    Request(RequestError),
    Path(crate::tftp_service::PathError),
    Open(io::Error),
    Permission,
    Capacity,
    Read(io::Error),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request(error) => error.fmt(formatter),
            Self::Path(error) => error.fmt(formatter),
            Self::Open(error) => write!(formatter, "cannot open TFTP file: {error}"),
            Self::Read(error) => write!(formatter, "cannot read TFTP file: {error}"),
            Self::Permission => formatter.write_str("TFTP file permission denied"),
            Self::Capacity => formatter.write_str("TFTP transfer capacity exhausted"),
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::Path(error) => Some(error),
            Self::Open(error) | Self::Read(error) => Some(error),
            Self::Permission | Self::Capacity => None,
        }
    }
}

impl From<RequestError> for RuntimeError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

struct SharedFile {
    path: Vec<u8>,
    identity: FileIdentity,
    size: u64,
    reader: FileSource,
}

// Every active transfer names a live file slot. Admission creates the file
// first; prune_files removes only slots with no active reference. The sole
// owner never invokes a producer while mutating these two collections.
struct Active {
    peer: SocketAddr,
    file: usize,
    transfer: Transfer,
    mode: Mode,
    /// Full block number of the last short DATA block emitted.  A transfer
    /// is complete only after that block is acknowledged; a window may have
    /// advanced `transfer.block` beyond the final block already.
    final_block: Option<u32>,
}

// ID order is retained for the single-port admission index. Reserving the
// next transfer record can fail without Rust's infallible tree-node allocator.
#[derive(Default)]
struct TransferTable(Vec<(TransferId, Active)>);

impl TransferTable {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn contains_key(&self, id: &TransferId) -> bool {
        self.get(id).is_some()
    }
    fn values(&self) -> impl Iterator<Item = &Active> {
        self.0.iter().map(|(_, active)| active)
    }
    fn keys(&self) -> impl Iterator<Item = &TransferId> {
        self.0.iter().map(|(id, _)| id)
    }
    fn get(&self, id: &TransferId) -> Option<&Active> {
        self.0
            .iter()
            .find(|(key, _)| key == id)
            .map(|(_, active)| active)
    }
    fn get_mut(&mut self, id: &TransferId) -> Option<&mut Active> {
        self.0
            .iter_mut()
            .find(|(key, _)| key == id)
            .map(|(_, active)| active)
    }
    fn remove(&mut self, id: &TransferId) -> Option<Active> {
        let index = self.0.iter().position(|(key, _)| key == id)?;
        Some(self.0.remove(index).1)
    }
    fn insert(&mut self, id: TransferId, active: Active) {
        self.0.push((id, active));
    }
    fn reserve(&mut self) -> bool {
        self.0.try_reserve_exact(1).is_ok()
    }
}

pub struct TransferRuntime<O> {
    config: RuntimeConfig,
    opener: O,
    next_id: u64,
    active: TransferTable,
    // Stable slot indices let transfers share one descriptor by path/inode.
    // Growing the file-record store is fallible, matching check_tftp_fileperm.
    files: Vec<Option<SharedFile>>,
}

impl<O: FileOpener> TransferRuntime<O> {
    pub fn new(config: RuntimeConfig, opener: O) -> Self {
        Self {
            config,
            opener,
            next_id: 1,
            active: TransferTable::default(),
            files: Vec::new(),
        }
    }

    pub fn active_len(&self) -> usize {
        self.active.len()
    }

    pub fn contains_transfer(&self, id: TransferId) -> bool {
        self.active.contains_key(&id)
    }

    /// Whether the caller should multiplex RRQ and transfer traffic on one
    /// socket. Separate-port mode owns one socket per RRQ instance.
    pub fn single_port(&self) -> bool {
        self.config.single_port
    }

    /// Dedicated listeners admit one transfer past the configured limit;
    /// single-port admission uses a strict limit instead.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub(crate) fn transfer_capacity(&self) -> usize {
        self.config
            .max_transfers
            .saturating_add(usize::from(!self.config.single_port))
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub(crate) fn has_peer(&self, peer: SocketAddr) -> bool {
        self.active.values().any(|active| active.peer == peer)
    }

    /// C set_tftp_listeners() uses <=, allowing max + 1 active transfers
    /// for one dedicated listener. The caller must stop receiving while
    /// false so pending requests remain queued until capacity returns.
    pub fn can_receive_server(&self) -> bool {
        self.config.single_port || self.active.len() <= self.config.max_transfers
    }

    /// A dedicated socket belongs to one peer, even when the actual sender
    /// owns another active transfer. C checks this before parsing any opcode
    /// (`tftp.c:647-660`); a nonempty foreign datagram receives ERR_TID.
    pub fn handle_transfer_datagram(
        &mut self,
        id: TransferId,
        peer: SocketAddr,
        packet: &[u8],
        now: u64,
    ) -> Result<Vec<RuntimeEvent>, RuntimeError> {
        if packet.is_empty() {
            return Ok(Vec::new());
        }
        let result = self.receive(id, peer, packet, now);
        self.prune_files();
        result
    }

    /// Route a datagram received from a caller-owned TFTP socket.  The caller
    /// still owns interface/pktinfo validation, socket binding and TID/port
    /// allocation; this adapter only enforces the C listener-vs-transfer
    /// opcode boundary before entering the transfer state machine.
    pub fn handle_socket_datagram(
        &mut self,
        role: SocketRole,
        peer: SocketAddr,
        packet: &[u8],
        now: u64,
    ) -> Result<Vec<RuntimeEvent>, RuntimeError> {
        match role {
            SocketRole::Server => self.handle_datagram(peer, packet, now),
            SocketRole::Transfer(id) => self.handle_transfer_datagram(id, peer, packet, now),
        }
    }

    pub fn handle_datagram(
        &mut self,
        peer: SocketAddr,
        packet: &[u8],
        now: u64,
    ) -> Result<Vec<RuntimeEvent>, RuntimeError> {
        self.handle_datagram_with_policy(peer, packet, now, None)
    }

    pub fn handle_datagram_with_policy(
        &mut self,
        peer: SocketAddr,
        packet: &[u8],
        now: u64,
        policy: Option<&RequestPolicy>,
    ) -> Result<Vec<RuntimeEvent>, RuntimeError> {
        let result = self.datagram_with_policy(peer, packet, now, policy);
        self.prune_files();
        result
    }

    fn prune_files(&mut self) {
        for (index, file) in self.files.iter_mut().enumerate() {
            if file.is_some() && !self.active.values().any(|active| active.file == index) {
                *file = None;
            }
        }
    }

    fn datagram_with_policy(
        &mut self,
        peer: SocketAddr,
        packet: &[u8],
        now: u64,
        policy: Option<&RequestPolicy>,
    ) -> Result<Vec<RuntimeEvent>, RuntimeError> {
        if packet.len() < 2 {
            return Ok(Vec::new());
        }
        if !self.config.single_port {
            return if self.can_receive_server() && matches!(opcode(packet), Some(1) | Some(2)) {
                self.start_rrq(peer, packet, now, policy)
            } else {
                Ok(Vec::new())
            };
        }
        let peers: Vec<_> = self.active.values().map(|active| active.peer).collect();
        let admission = crate::tftp_service::admission(
            packet,
            peer,
            &peers,
            self.config.single_port,
            self.config.max_transfers,
        );
        match admission {
            PeerAdmission::Existing(index) => {
                let id = self.id_at(index);
                self.receive(id, peer, packet, now)
            }
            PeerAdmission::Replace(index) => {
                let id = self.id_at(index);
                self.active.remove(&id);
                self.start_rrq(peer, packet, now, policy)
            }
            PeerAdmission::Ignore => Ok(Vec::new()),
            PeerAdmission::New => {
                if matches!(opcode(packet), Some(1) | Some(2)) {
                    self.start_rrq(peer, packet, now, policy)
                } else {
                    Ok(Vec::new())
                }
            }
        }
    }

    pub fn tick(&mut self, now: u64) -> Result<Vec<RuntimeEvent>, RuntimeError> {
        let ids: Vec<_> = self.active.keys().copied().collect();
        let mut events = Vec::new();
        for id in ids {
            let Some((peer, expired, retransmit)) = self.active.get(&id).map(|active| {
                (
                    active.peer,
                    active.transfer.expired(now),
                    active.transfer.retransmit_at <= now,
                )
            }) else {
                continue;
            };
            if expired {
                let active = self.active.remove(&id).unwrap();
                // C treats a client that omits only the final ACK as a
                // successful transfer (tftp.c check_tftp_listeners). Earlier
                // stalls and unacknowledged netascii offsets remain failures.
                events.push(
                    if active.transfer.mode == Mode::Octet && active.final_block.is_some() {
                        RuntimeEvent::Completed(Completion {
                            id,
                            peer: active.peer,
                            path: self.files[active.file].as_ref().unwrap().path.clone(),
                            size: self.files[active.file].as_ref().unwrap().size,
                        })
                    } else {
                        RuntimeEvent::TimedOut {
                            id,
                            peer: active.peer,
                            path: self.files[active.file].as_ref().unwrap().path.clone(),
                        }
                    },
                );
                continue;
            }
            if retransmit {
                match self.send_window(id, now) {
                    Ok(new_events) => events.extend(new_events),
                    Err(_) => {
                        let active = self.active.remove(&id).unwrap();
                        events.push(RuntimeEvent::Failed {
                            id,
                            peer,
                            path: self.files[active.file].as_ref().unwrap().path.clone(),
                        });
                    }
                }
            }
        }
        self.prune_files();
        Ok(events)
    }

    fn id_at(&self, index: usize) -> u64 {
        // admission() produced this index from the immediately preceding
        // active.values() snapshot; no callback or mutation occurs between.
        self.active
            .keys()
            .copied()
            .nth(index)
            .expect("admission index from active list")
    }

    fn start_rrq(
        &mut self,
        peer: SocketAddr,
        packet: &[u8],
        now: u64,
        policy: Option<&RequestPolicy>,
    ) -> Result<Vec<RuntimeEvent>, RuntimeError> {
        // tftp_request silently ignores a transfer-record allocation failure.
        if !self.active.reserve() {
            return Ok(Vec::new());
        }
        let request = match tftp::parse_request(
            packet,
            self.config.packet_buffer_size,
            policy.map_or(self.config.mtu, |policy| policy.mtu),
            policy.map_or(self.config.ipv6, |policy| policy.ipv6),
            self.config.no_block_size,
        ) {
            Ok(request) => request,
            Err(error) => {
                let label = crate::tftp_service::peer_label(peer);
                let message = match error {
                    RequestError::WriteUnsupported => {
                        format!("unsupported write request from {label}")
                    }
                    RequestError::InvalidFilename => {
                        format!("empty filename in request from {label}")
                    }
                    _ => format!("unsupported request from {label}"),
                };
                return Ok(vec![RuntimeEvent::Send {
                    id: None,
                    peer,
                    packet: error_packet(4, &message),
                }]);
            }
        };
        let request = match request {
            Some(request) => request,
            None => return Ok(Vec::new()),
        };
        let path_policy = policy.map_or(&self.config.path, |policy| &policy.path);
        let path = resolve_path(
            path_policy.prefix.as_deref(),
            path_policy.lowercase,
            request.filename,
        );
        let path = match path {
            Ok(path) => path,
            Err(_error) => {
                let rejected = crate::tftp_service::error_path(
                    path_policy.prefix.as_deref(),
                    path_policy.lowercase,
                    request.filename,
                )
                .unwrap_or_default();
                return Ok(vec![RuntimeEvent::Send {
                    id: None,
                    peer,
                    packet: access_error_packet(&rejected),
                }]);
            }
        };
        let opened = match self.opener.open(&path) {
            Ok(opened) => opened,
            Err(error) => {
                return Ok(vec![RuntimeEvent::Send {
                    id: None,
                    peer,
                    packet: open_error_packet(&error, &path, peer),
                }]);
            }
        };
        if !permitted(
            opened.mode,
            opened.owner_uid,
            self.config.effective_uid,
            self.config.secure,
        ) {
            return Ok(vec![RuntimeEvent::Send {
                id: None,
                peer,
                packet: access_error_packet(&path),
            }]);
        }
        let shared = self
            .active
            .values()
            .find(|active| {
                let file = self.files[active.file].as_ref().unwrap();
                file.path == path && file.identity == opened.identity
            })
            .map(|active| active.file);
        let file = if let Some(index) = shared {
            index
        } else {
            let index = if let Some(index) = self.files.iter().position(Option::is_none) {
                index
            } else {
                if self.files.try_reserve_exact(1).is_err() {
                    return Ok(vec![RuntimeEvent::Send {
                        id: None,
                        peer,
                        packet: open_error_packet(&io::Error::from_raw_os_error(12), &path, peer),
                    }]);
                }
                self.files.push(None);
                self.files.len() - 1
            };
            self.files[index] = Some(SharedFile {
                path,
                identity: opened.identity,
                size: opened.size,
                reader: opened.reader,
            });
            index
        };
        let transfer = Transfer::new(request.options, request.mode, now);
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.active.insert(
            id,
            Active {
                peer,
                file,
                transfer,
                mode: request.mode,
                final_block: None,
            },
        );
        let result = self.send_initial(id, request, now);
        if result.is_err() {
            // A read failure while constructing the first DATA packet must
            // release the transfer just as a later-window failure does.
            self.active.remove(&id);
        }
        result
    }

    fn send_initial(
        &mut self,
        id: u64,
        request: ReadRequest<'_>,
        now: u64,
    ) -> Result<Vec<RuntimeEvent>, RuntimeError> {
        if request.options.needs_ack() {
            let active = self.active.get(&id).unwrap();
            let mut packet = Vec::new();
            active
                .transfer
                .options
                .write_ack(self.files[active.file].as_ref().unwrap().size, &mut packet);
            let mut framed = vec![0, 6];
            framed.extend_from_slice(&packet[2..]);
            Ok(vec![RuntimeEvent::Send {
                id: Some(id),
                peer: active.peer,
                packet: framed,
            }])
        } else {
            self.send_blocks(id, 1, now, false)
        }
    }

    fn receive(
        &mut self,
        id: u64,
        peer: SocketAddr,
        packet: &[u8],
        now: u64,
    ) -> Result<Vec<RuntimeEvent>, RuntimeError> {
        let Some(active) = self.active.get_mut(&id) else {
            return Ok(vec![RuntimeEvent::TidError {
                id,
                peer,
                packet: error_packet(
                    5,
                    &format!(
                        "ignoring packet from {} (TID mismatch)",
                        crate::tftp_service::peer_label(peer)
                    ),
                ),
            }]);
        };
        if active.peer != peer {
            return Ok(vec![RuntimeEvent::TidError {
                id,
                peer,
                packet: error_packet(
                    5,
                    &format!(
                        "ignoring packet from {} (TID mismatch)",
                        crate::tftp_service::peer_label(peer)
                    ),
                ),
            }]);
        }
        // handle_tftp logs a complete client ERR string before aborting. A
        // missing, empty or unterminated string is logged as an empty string.
        if packet.len() >= 4 && opcode(packet) == Some(5) {
            let message = packet[4..]
                .iter()
                .position(|byte| *byte == 0)
                .map_or_else(Vec::new, |end| packet[4..4 + end].to_vec());
            let code = u16::from_be_bytes([packet[2], packet[3]]);
            let active = self.active.remove(&id).unwrap();
            return Ok(vec![
                RuntimeEvent::ClientError {
                    peer,
                    code,
                    message,
                },
                RuntimeEvent::Failed {
                    id,
                    peer,
                    path: self.files[active.file].as_ref().unwrap().path.clone(),
                },
            ]);
        }
        if !active.transfer.receive(packet, now) {
            if active.transfer.failed {
                let peer = active.peer;
                let active = self.active.remove(&id).unwrap();
                return Ok(vec![RuntimeEvent::Failed {
                    id,
                    peer,
                    path: self.files[active.file].as_ref().unwrap().path.clone(),
                }]);
            }
            return Ok(Vec::new());
        }
        if active.transfer.failed {
            let peer = active.peer;
            let active = self.active.remove(&id).unwrap();
            return Ok(vec![RuntimeEvent::Failed {
                id,
                peer,
                path: self.files[active.file].as_ref().unwrap().path.clone(),
            }]);
        }
        let acked_block = active.transfer.next_ack.wrapping_sub(1);
        let complete = active.final_block == Some(acked_block);
        if complete {
            let active = self.active.remove(&id).unwrap();
            return Ok(vec![RuntimeEvent::Completed(Completion {
                id,
                peer: active.peer,
                path: self.files[active.file].as_ref().unwrap().path.clone(),
                size: self.files[active.file].as_ref().unwrap().size,
            })]);
        }
        match self.send_window(id, now) {
            Ok(events) => Ok(events),
            Err(_error) => {
                let active = self.active.remove(&id);
                let path = active.as_ref().map_or_else(Vec::new, |active| {
                    self.files[active.file].as_ref().unwrap().path.clone()
                });
                let peer = active.map_or(peer, |active| active.peer);
                Ok(vec![RuntimeEvent::Failed { id, peer, path }])
            }
        }
    }

    fn send_window(&mut self, id: u64, now: u64) -> Result<Vec<RuntimeEvent>, RuntimeError> {
        // An option-bearing RRQ starts with block 0 (OACK).  It has no DATA
        // offset, so route the deadline through the same OACK framing used by
        // the initial request instead of treating block 0 as EOF.
        let oack = {
            let active = self.active.get_mut(&id).unwrap();
            if active.transfer.block == 0 && active.transfer.next_ack == 0 {
                active.transfer.begin_window(now);
                let mut packet = Vec::new();
                active
                    .transfer
                    .options
                    .write_ack(self.files[active.file].as_ref().unwrap().size, &mut packet);
                let mut framed = vec![0, 6];
                framed.extend_from_slice(&packet[2..]);
                Some((active.peer, framed))
            } else {
                None
            }
        };
        if let Some((peer, packet)) = oack {
            return Ok(vec![RuntimeEvent::Send {
                id: Some(id),
                peer,
                packet,
            }]);
        }
        let count = {
            let active = self.active.get_mut(&id).unwrap();
            active.transfer.begin_window(now).unwrap_or(0)
        };
        if count == 0 {
            return Ok(Vec::new());
        }
        self.send_blocks(id, count, now, true)
    }

    fn send_blocks(
        &mut self,
        id: u64,
        count: u32,
        _now: u64,
        established: bool,
    ) -> Result<Vec<RuntimeEvent>, RuntimeError> {
        let mut events = Vec::new();
        let mut failed = false;
        for _ in 0..count {
            let packet = match self.data_packet(id) {
                Ok(packet) => packet,
                Err(error) => {
                    let active = self.active.get_mut(&id).unwrap();
                    events.push(RuntimeEvent::Send {
                        id: Some(id),
                        peer: active.peer,
                        packet: read_error_packet(
                            &self.files[active.file].as_ref().unwrap().path,
                            &error,
                        ),
                    });
                    active.transfer.block = active.transfer.block.wrapping_add(1);
                    // C finishes the current window before error cleanup,
                    // retaining DATA/error order even on later read failures.
                    failed = true;
                    continue;
                }
            };
            if packet.is_empty() {
                break;
            }
            let peer = self.active.get(&id).unwrap().peer;
            let block = self.active.get(&id).unwrap().transfer.block;
            let block_size = self.active.get(&id).unwrap().transfer.options.block_size;
            let body_len = packet.len().saturating_sub(4);
            events.push(RuntimeEvent::Send {
                id: Some(id),
                peer,
                packet,
            });
            let active = self.active.get_mut(&id).unwrap();
            // A DATA body shorter than the negotiated block size is the C
            // get_block() end marker, including the required zero-length
            // DATA packet for empty files and exact-size multiples.
            if body_len < block_size {
                active.final_block = Some(block);
            }
            active.transfer.block = active.transfer.block.wrapping_add(1);
        }
        if failed {
            let active = self.active.remove(&id).unwrap();
            events.push(if established {
                RuntimeEvent::Failed {
                    id,
                    peer: active.peer,
                    path: self.files[active.file].as_ref().unwrap().path.clone(),
                }
            } else {
                RuntimeEvent::Discarded { id }
            });
        }
        Ok(events)
    }

    fn data_packet(&mut self, id: u64) -> Result<Vec<u8>, RuntimeError> {
        let active = self.active.get_mut(&id).unwrap();
        let file = self.files[active.file].as_ref().unwrap();
        let Some(offset) = active.transfer.file_offset(file.size) else {
            return Ok(Vec::new());
        };
        let block = active.transfer.block as u16;
        let mut raw = vec![0; active.transfer.options.block_size];
        let remaining = file.size.saturating_sub(offset);
        let to_read = remaining.min(raw.len() as u64) as usize;
        let read = if to_read == 0 {
            0
        } else {
            file.reader
                .read_at(offset, &mut raw[..to_read])
                .map_err(RuntimeError::Read)?
        };
        if read != to_read {
            return Err(RuntimeError::Read(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TFTP file changed while reading",
            )));
        }
        raw.truncate(read);
        let body = if active.mode == Mode::Netascii {
            // DATA bodies are capped at the negotiated block size.  Reading
            // one raw block and expanding into a larger buffer would emit a
            // packet larger than the peer accepted and would make the ACK
            // offset accounting diverge from `get_block()`.
            let mut output = vec![0; active.transfer.options.block_size];
            let result = tftp::encode_netascii(&raw, active.transfer.last_carry_lf, &mut output);
            active.transfer.expansion = result.expansion;
            active.transfer.carry_lf = result.carry_lf;
            output.truncate(result.len);
            output
        } else {
            active.transfer.expansion = 0;
            active.transfer.carry_lf = false;
            raw
        };
        let mut packet = Vec::with_capacity(body.len() + 4);
        packet.extend_from_slice(&[0, 3]);
        packet.extend_from_slice(&block.to_be_bytes());
        packet.extend_from_slice(&body);
        Ok(packet)
    }
}

fn opcode(packet: &[u8]) -> Option<u16> {
    (packet.len() >= 2).then(|| u16::from_be_bytes([packet[0], packet[1]]))
}

fn open_error_packet(error: &io::Error, path: &[u8], peer: SocketAddr) -> Vec<u8> {
    // tftp.c:558-570 distinguishes only ENOENT and EACCES. EPERM (which
    // Rust also calls PermissionDenied) remains the generic ERR_NOTDEF.
    let code = match error.raw_os_error() {
        Some(2) => 1,
        Some(13) => 2,
        Some(_) => 0,
        None => match error.kind() {
            io::ErrorKind::NotFound => 1,
            io::ErrorKind::PermissionDenied => 2,
            _ => 0,
        },
    };
    let path = sanitised_path(path);
    match code {
        1 => error_packet(
            1,
            &format!(
                "file {path} not found for {}",
                crate::tftp_service::peer_label(peer)
            ),
        ),
        2 => access_error_packet(path.as_bytes()),
        _ => error_packet(0, &format!("cannot read {path}: {}", error_text(error))),
    }
}

fn sanitised_path(path: &[u8]) -> String {
    path.iter()
        .copied()
        .filter(|byte| (0x20..=0x7e).contains(byte))
        .map(char::from)
        .collect()
}
fn error_text(error: &io::Error) -> String {
    let text = error.to_string();
    text.rsplit_once(" (os error ")
        .filter(|(_, suffix)| suffix.ends_with(')'))
        .map_or(text.clone(), |(message, _)| message.to_owned())
}
fn access_error_packet(path: &[u8]) -> Vec<u8> {
    error_packet(
        2,
        &format!(
            "cannot access {}: {}",
            sanitised_path(path),
            error_text(&io::Error::from_raw_os_error(13))
        ),
    )
}
fn read_error_packet(path: &[u8], error: &RuntimeError) -> Vec<u8> {
    match error {
        RuntimeError::Read(error) => error_packet(
            0,
            &format!(
                "cannot read {}: {}",
                sanitised_path(path),
                error_text(error)
            ),
        ),
        _ => error_packet(0, &format!("cannot read {}", sanitised_path(path))),
    }
}

fn error_packet(code: u16, message: &str) -> Vec<u8> {
    crate::tftp_service::error_packet(code, message.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::Mutex;

    #[test]
    fn record_allocation_layout_evidence() {
        // The AArch64 ptrace driver targets real allocator calls by size.
        println!(
            "TFTP_RECORD_LAYOUT file={} transfer={}",
            std::mem::size_of::<Option<SharedFile>>(),
            std::mem::size_of::<(TransferId, Active)>()
        );
    }

    struct MemoryReader {
        data: Vec<u8>,
        identity: FileIdentity,
    }

    impl FileReader for MemoryReader {
        fn size(&self) -> u64 {
            self.data.len() as u64
        }

        fn identity(&self) -> FileIdentity {
            self.identity
        }

        fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
            let offset = offset as usize;
            if offset >= self.data.len() {
                return Ok(0);
            }
            let length = output.len().min(self.data.len() - offset);
            output[..length].copy_from_slice(&self.data[offset..offset + length]);
            Ok(length)
        }
    }

    struct MemoryOpener {
        files: Mutex<BTreeMap<Vec<u8>, Arc<MemoryReader>>>,
        mode: u32,
        owner_uid: u32,
    }

    impl MemoryOpener {
        fn new(path: &[u8], data: &[u8]) -> Self {
            let mut files = BTreeMap::new();
            files.insert(
                path.to_vec(),
                Arc::new(MemoryReader {
                    data: data.to_vec(),
                    identity: FileIdentity {
                        device: 1,
                        inode: 2,
                    },
                }),
            );
            Self {
                files: Mutex::new(files),
                mode: 0o644,
                owner_uid: 0,
            }
        }
    }

    impl FileOpener for MemoryOpener {
        fn open(&self, path: &[u8]) -> io::Result<OpenedFile> {
            let reader = self
                .files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing"))?;
            Ok(OpenedFile {
                path: path.to_vec(),
                identity: reader.identity,
                size: reader.size(),
                mode: self.mode,
                owner_uid: self.owner_uid,
                reader: FileSource::Shared(reader),
            })
        }
    }

    fn runtime(data: &[u8]) -> TransferRuntime<MemoryOpener> {
        TransferRuntime::new(
            RuntimeConfig {
                path: RuntimePathPolicy {
                    prefix: Some(b"/srv/tftp".to_vec()),
                    lowercase: false,
                },
                ..RuntimeConfig::default()
            },
            MemoryOpener::new(b"/srv/tftp/boot.bin", data),
        )
    }

    fn rrq(name: &[u8], mode: &[u8]) -> Vec<u8> {
        let mut packet = vec![0, 1];
        packet.extend_from_slice(name);
        packet.push(0);
        packet.extend_from_slice(mode);
        packet.push(0);
        packet
    }

    fn peer(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn open_and_permission_errors_are_protocol_replies_without_active_state() {
        struct ErrorOpener(i32);
        impl FileOpener for ErrorOpener {
            fn open(&self, _path: &[u8]) -> io::Result<OpenedFile> {
                Err(io::Error::from_raw_os_error(self.0))
            }
        }
        for (errno, code) in [(2, 1), (13, 2), (1, 0), (20, 0), (24, 0)] {
            let mut runtime = TransferRuntime::new(RuntimeConfig::default(), ErrorOpener(errno));
            let events = runtime
                .handle_socket_datagram(SocketRole::Server, peer(1000), &rrq(b"boot", b"octet"), 1)
                .unwrap();
            assert!(
                matches!(events.as_slice(), [RuntimeEvent::Send { packet, .. }]
                if packet.starts_with(&[0, 5, 0, code]))
            );
            assert_eq!(runtime.active_len(), 0);
        }
        for (uid, secure, mode, owner) in [(0, false, 0o600, 0), (1000, true, 0o644, 1001)] {
            let mut opener = MemoryOpener::new(b"/boot", b"hello");
            opener.mode = mode;
            opener.owner_uid = owner;
            let mut runtime = TransferRuntime::new(
                RuntimeConfig {
                    effective_uid: uid,
                    secure,
                    ..RuntimeConfig::default()
                },
                opener,
            );
            let events = runtime
                .handle_datagram(peer(1000), &rrq(b"boot", b"octet"), 1)
                .unwrap();
            assert!(
                matches!(events.as_slice(), [RuntimeEvent::Send { packet, .. }]
                if packet.starts_with(&[0, 5, 0, 2]))
            );
            assert_eq!(runtime.active_len(), 0);
        }
    }

    #[test]
    fn read_failures_preserve_window_packets_then_error_and_release() {
        struct FaultFile {
            fail_at: u64,
        }
        impl FileReader for FaultFile {
            fn size(&self) -> u64 {
                20
            }
            fn identity(&self) -> FileIdentity {
                FileIdentity {
                    device: 1,
                    inode: 1,
                }
            }
            fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
                if offset >= self.fail_at {
                    return Err(io::Error::other("injected read failure"));
                }
                output.fill(b'x');
                Ok(output.len())
            }
        }
        impl FileOpener for FaultFile {
            fn open(&self, path: &[u8]) -> io::Result<OpenedFile> {
                Ok(OpenedFile {
                    path: path.to_vec(),
                    identity: self.identity(),
                    size: self.size(),
                    mode: 0o644,
                    owner_uid: 0,
                    reader: FileSource::Shared(Arc::new(FaultFile {
                        fail_at: self.fail_at,
                    })),
                })
            }
        }
        let mut runtime = TransferRuntime::new(RuntimeConfig::default(), FaultFile { fail_at: 0 });
        let events = runtime
            .handle_datagram(peer(1000), &rrq(b"boot", b"octet"), 1)
            .unwrap();
        assert!(matches!(events.as_slice(),
            [RuntimeEvent::Send { packet, .. }, RuntimeEvent::Discarded { .. }]
            if packet.starts_with(&[0, 5, 0, 0])));
        assert_eq!(runtime.active_len(), 0);

        let mut runtime = TransferRuntime::new(RuntimeConfig::default(), FaultFile { fail_at: 8 });
        let mut request = rrq(b"boot", b"octet");
        request.extend_from_slice(b"blksize\x004\0windowsize\x004\0");
        runtime.handle_datagram(peer(1000), &request, 1).unwrap();
        let events = runtime
            .handle_transfer_datagram(1, peer(1000), &[0, 4, 0, 0], 2)
            .unwrap();
        assert_eq!(events.len(), 5);
        for (event, header) in
            events[..4]
                .iter()
                .zip([[0, 3, 0, 1], [0, 3, 0, 2], [0, 5, 0, 0], [0, 5, 0, 0]])
        {
            assert!(
                matches!(event, RuntimeEvent::Send { packet, .. } if packet.starts_with(&header))
            );
        }
        assert!(matches!(events[4], RuntimeEvent::Failed { .. }));
        assert_eq!(runtime.active_len(), 0);
    }

    #[test]
    fn rrq_reads_real_runtime_packets_and_completes() {
        let mut runtime = runtime(b"hello");
        let first = runtime
            .handle_datagram(peer(1000), &rrq(b"boot.bin", b"octet"), 1)
            .unwrap();
        assert_eq!(first.len(), 1);
        let RuntimeEvent::Send { packet, .. } = &first[0] else {
            panic!("expected DATA")
        };
        assert_eq!(&packet[..4], &[0, 3, 0, 1]);
        assert_eq!(&packet[4..], b"hello");
        let done = runtime
            .handle_transfer_datagram(1, peer(1000), &[0, 4, 0, 1], 2)
            .unwrap();
        assert_eq!(
            done,
            vec![RuntimeEvent::Completed(Completion {
                id: 1,
                peer: peer(1000),
                path: b"/srv/tftp/boot.bin".to_vec(),
                size: 5,
            })]
        );
        assert_eq!(runtime.active_len(), 0);
    }

    #[test]
    fn timeout_after_final_data_completes_but_earlier_stall_does_not() {
        for (size, completed) in [(0, true), (511, true), (512, false), (1024, false)] {
            let mut runtime = runtime(&vec![b'x'; size]);
            runtime
                .handle_datagram(peer(1000), &rrq(b"boot.bin", b"octet"), 1)
                .unwrap();
            let events = runtime.tick(122).unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(matches!(events[0], RuntimeEvent::Completed(_)), completed);
            assert_eq!(
                matches!(events[0], RuntimeEvent::TimedOut { .. }),
                !completed
            );
            assert_eq!(runtime.active_len(), 0);
            assert!(runtime.tick(123).unwrap().is_empty());
        }
    }

    #[test]
    fn socket_roles_keep_server_rrq_and_transfer_ack_paths_distinct() {
        let mut runtime = runtime(b"hello");
        let source_peer = peer(1000);
        let request = rrq(b"boot.bin", b"octet");
        let first = runtime
            .handle_socket_datagram(SocketRole::Server, source_peer, &request, 1)
            .unwrap();
        assert!(matches!(first.first(), Some(RuntimeEvent::Send { .. })));

        // A dedicated transfer socket must not create a second transfer from
        // an RRQ, and the port-69 listener must not consume ACK state.
        assert!(runtime
            .handle_socket_datagram(SocketRole::Transfer(1), source_peer, &request, 2)
            .unwrap()
            .is_empty());
        let wrong_peer = peer(1001);
        assert!(matches!(
            runtime
                .handle_socket_datagram(SocketRole::Transfer(1), wrong_peer, &request, 2)
                .unwrap()
                .first(),
            Some(RuntimeEvent::TidError { peer, .. }) if *peer == wrong_peer
        ));
        assert!(runtime
            .handle_socket_datagram(SocketRole::Server, source_peer, &[0, 4, 0, 1], 2)
            .unwrap()
            .is_empty());
        let done = runtime
            .handle_socket_datagram(SocketRole::Transfer(1), source_peer, &[0, 4, 0, 1], 3)
            .unwrap();
        assert!(matches!(done.first(), Some(RuntimeEvent::Completed(_))));
        assert_eq!(runtime.active_len(), 0);
    }

    #[test]
    fn dedicated_socket_rejects_foreign_peer_even_with_an_active_transfer() {
        let mut runtime = runtime(b"hello");
        let request = rrq(b"boot.bin", b"octet");
        for port in [1000, 1001] {
            runtime
                .handle_socket_datagram(SocketRole::Server, peer(port), &request, 1)
                .unwrap();
        }
        for foreign in [peer(1001), peer(1002)] {
            // C checks the source before checking the payload length/opcode.
            for packet in [&[0][..], &[0, 4, 0, 1], &[0, 5, 0, 0], &request] {
                let events = runtime
                    .handle_transfer_datagram(1, foreign, packet, 2)
                    .unwrap();
                assert!(matches!(events.as_slice(),
                    [RuntimeEvent::TidError { peer, packet, .. }]
                    if *peer == foreign && packet.starts_with(&[0, 5, 0, 5])));
                assert_eq!(runtime.active_len(), 2);
            }
        }
        assert!(runtime
            .handle_transfer_datagram(1, peer(1002), &[], 2)
            .unwrap()
            .is_empty());
        for port in [1000, 1001] {
            let events = runtime
                .handle_transfer_datagram(u64::from(port - 999), peer(port), &[0, 4, 0, 1], 2)
                .unwrap();
            assert!(matches!(events.as_slice(), [RuntimeEvent::Completed(_)]));
        }
        assert_eq!(runtime.active_len(), 0);
    }

    #[test]
    fn same_peer_rrqs_have_independent_ids_and_c_capacity_boundary() {
        let mut runtime = runtime(b"hello");
        runtime.config.max_transfers = 1;
        let request = rrq(b"boot.bin", b"octet");
        for id in [1, 2] {
            assert!(runtime.can_receive_server());
            let events = runtime.handle_datagram(peer(1000), &request, 1).unwrap();
            assert!(
                matches!(events.as_slice(), [RuntimeEvent::Send { id: Some(actual), .. }] if *actual == id)
            );
        }
        assert!(!runtime.can_receive_server());
        assert!(runtime
            .handle_datagram(peer(1000), &request, 1)
            .unwrap()
            .is_empty());
        assert_eq!(runtime.active_len(), 2);
        let done = runtime
            .handle_transfer_datagram(2, peer(1000), &[0, 4, 0, 1], 1)
            .unwrap();
        assert!(matches!(
            done.as_slice(),
            [RuntimeEvent::Completed(Completion { id: 2, .. })]
        ));
        assert!(runtime.can_receive_server());
        let third = runtime.handle_datagram(peer(1000), &request, 1).unwrap();
        assert!(matches!(
            third.as_slice(),
            [RuntimeEvent::Send { id: Some(3), .. }]
        ));
        let done = runtime
            .handle_transfer_datagram(1, peer(1000), &[0, 4, 0, 1], 1)
            .unwrap();
        assert!(matches!(
            done.as_slice(),
            [RuntimeEvent::Completed(Completion { id: 1, .. })]
        ));
        let failed = runtime
            .handle_transfer_datagram(3, peer(1000), &[0, 5, 0, 0], 1)
            .unwrap();
        assert_eq!(
            failed,
            vec![
                RuntimeEvent::ClientError {
                    peer: peer(1000),
                    code: 0,
                    message: Vec::new()
                },
                RuntimeEvent::Failed {
                    id: 3,
                    peer: peer(1000),
                    path: b"/srv/tftp/boot.bin".to_vec(),
                }
            ]
        );
        assert_eq!(runtime.active_len(), 0);
    }

    #[test]
    fn single_port_replacement_reads_new_file_and_releases_the_old_reference() {
        let mut runtime = runtime(b"hello");
        runtime.config.single_port = true;
        runtime.opener.files.get_mut().unwrap().insert(
            b"/srv/tftp/alt.bin".to_vec(),
            Arc::new(MemoryReader {
                data: b"alternate".to_vec(),
                identity: FileIdentity {
                    device: 1,
                    inode: 3,
                },
            }),
        );
        runtime
            .handle_datagram(peer(1000), &rrq(b"boot.bin", b"octet"), 1)
            .unwrap();
        let replacement = runtime
            .handle_datagram(peer(1000), &rrq(b"alt.bin", b"octet"), 1)
            .unwrap();
        assert!(
            matches!(replacement.as_slice(), [RuntimeEvent::Send { packet, .. }] if packet == b"\0\x03\0\x01alternate")
        );
        assert_eq!(runtime.active_len(), 1);
        assert_eq!(
            Arc::strong_count(
                runtime
                    .opener
                    .files
                    .lock()
                    .unwrap()
                    .get(&b"/srv/tftp/boot.bin"[..])
                    .unwrap()
            ),
            1
        );
        let failed = runtime
            .handle_datagram(peer(1000), &rrq(b"missing", b"octet"), 1)
            .unwrap();
        assert!(
            matches!(failed.as_slice(), [RuntimeEvent::Send { packet, .. }] if packet.starts_with(&[0, 5, 0, 1]))
        );
        assert_eq!(runtime.active_len(), 0);
        assert_eq!(
            Arc::strong_count(
                runtime
                    .opener
                    .files
                    .lock()
                    .unwrap()
                    .get(&b"/srv/tftp/alt.bin"[..])
                    .unwrap()
            ),
            1
        );
    }

    #[test]
    fn empty_file_sends_zero_length_data_and_completes_on_ack() {
        let mut runtime = runtime(b"");
        let first = runtime
            .handle_datagram(peer(1000), &rrq(b"boot.bin", b"octet"), 1)
            .unwrap();
        assert!(matches!(
            first.first(),
            Some(RuntimeEvent::Send { packet, .. })
                if packet == &[0, 3, 0, 1]
        ));
        let done = runtime
            .handle_transfer_datagram(1, peer(1000), &[0, 4, 0, 1], 2)
            .unwrap();
        assert!(matches!(done.first(), Some(RuntimeEvent::Completed(_))));
        assert_eq!(runtime.active_len(), 0);
    }

    #[test]
    fn exact_multiple_waits_for_zero_length_final_block_ack() {
        let mut runtime = runtime(&[b'x'; 512]);
        let first = runtime
            .handle_datagram(peer(1000), &rrq(b"boot.bin", b"octet"), 1)
            .unwrap();
        assert!(matches!(
            first.first(),
            Some(RuntimeEvent::Send { packet, .. }) if packet.len() == 516
        ));
        let second = runtime
            .handle_transfer_datagram(1, peer(1000), &[0, 4, 0, 1], 2)
            .unwrap();
        assert!(matches!(
            second.first(),
            Some(RuntimeEvent::Send { packet, .. }) if packet == &[0, 3, 0, 2]
        ));
        assert_eq!(runtime.active_len(), 1);
        let done = runtime
            .handle_transfer_datagram(1, peer(1000), &[0, 4, 0, 2], 3)
            .unwrap();
        assert!(matches!(done.first(), Some(RuntimeEvent::Completed(_))));
        assert_eq!(runtime.active_len(), 0);
    }

    #[test]
    fn window_does_not_complete_on_ack_before_final_block() {
        let mut runtime = runtime(&[b'x'; 512]);
        let mut request = rrq(b"boot.bin", b"octet");
        request.extend_from_slice(b"windowsize\0");
        request.extend_from_slice(b"4\0");
        let oack = runtime.handle_datagram(peer(1000), &request, 1).unwrap();
        assert!(matches!(
            oack.first(),
            Some(RuntimeEvent::Send { packet, .. }) if packet.starts_with(&[0, 6])
        ));
        let window = runtime
            .handle_transfer_datagram(1, peer(1000), &[0, 4, 0, 0], 2)
            .unwrap();
        assert_eq!(window.len(), 2);
        assert!(matches!(
            window.last(),
            Some(RuntimeEvent::Send { packet, .. }) if packet == &[0, 3, 0, 2]
        ));
        let first_ack = runtime
            .handle_transfer_datagram(1, peer(1000), &[0, 4, 0, 1], 3)
            .unwrap();
        assert!(first_ack
            .iter()
            .all(|event| { !matches!(event, RuntimeEvent::Completed(_)) }));
        let done = runtime
            .handle_transfer_datagram(1, peer(1000), &[0, 4, 0, 2], 4)
            .unwrap();
        assert!(matches!(done.first(), Some(RuntimeEvent::Completed(_))));
        assert_eq!(runtime.active_len(), 0);
    }

    #[test]
    fn real_file_opener_fstats_and_reads_descriptor() {
        let root = std::env::temp_dir().join(format!("dnsmasq-rs-tftp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("boot"), b"real-file").unwrap();
        let mut runtime = TransferRuntime::new(
            RuntimeConfig {
                path: RuntimePathPolicy {
                    prefix: Some(root.as_os_str().as_bytes().to_vec()),
                    lowercase: false,
                },
                ..RuntimeConfig::default()
            },
            RealFileOpener::new(0, false),
        );
        let events = runtime
            .handle_datagram(peer(1000), &rrq(b"boot", b"octet"), 1)
            .unwrap();
        assert!(
            matches!(&events[0], RuntimeEvent::Send { packet, .. } if &packet[4..] == b"real-file")
        );
        assert!(runtime.active_len() == 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_peer_gets_tid_error_and_error_aborts_transfer() {
        let mut runtime = runtime(b"hello");
        runtime
            .handle_datagram(peer(1000), &rrq(b"boot.bin", b"octet"), 1)
            .unwrap();
        let wrong = runtime
            .handle_transfer_datagram(1, peer(1001), &[0, 4, 0, 1], 2)
            .unwrap();
        assert!(matches!(wrong[0], RuntimeEvent::TidError { .. }));
        let failed = runtime
            .handle_transfer_datagram(1, peer(1000), &[0, 5, 0, 1, b'x', 0], 2)
            .unwrap();
        assert_eq!(
            failed,
            vec![
                RuntimeEvent::ClientError {
                    peer: peer(1000),
                    code: 1,
                    message: b"x".to_vec()
                },
                RuntimeEvent::Failed {
                    id: 1,
                    peer: peer(1000),
                    path: b"/srv/tftp/boot.bin".to_vec(),
                }
            ]
        );
        assert_eq!(runtime.active_len(), 0);
    }

    #[test]
    fn deadline_retransmits_same_block_and_wrq_is_rejected() {
        let mut runtime = runtime(b"hello");
        let first = runtime
            .handle_datagram(peer(1000), &rrq(b"boot.bin", b"octet"), 1)
            .unwrap();
        let retry = runtime.tick(3).unwrap();
        assert_eq!(retry, first);
        let mut wrq = vec![0, 2];
        wrq.extend_from_slice(b"boot.bin\0octet\0");
        let error = runtime.handle_datagram(peer(1001), &wrq, 1).unwrap();
        assert!(matches!(error[0], RuntimeEvent::Send { .. }));
        if let RuntimeEvent::Send { packet, .. } = &error[0] {
            assert_eq!(&packet[..4], &[0, 5, 0, 4]);
        }
    }

    #[test]
    fn options_emit_oack_then_data_after_ack() {
        let mut runtime = runtime(b"abc");
        let mut request = rrq(b"boot.bin", b"octet");
        request.extend_from_slice(b"blksize\x001\0");
        let oack = runtime.handle_datagram(peer(1000), &request, 1).unwrap();
        assert!(
            matches!(oack.first(), Some(RuntimeEvent::Send { packet, .. }) if packet.starts_with(&[0, 6]))
        );
        assert_eq!(
            &match &oack[0] {
                RuntimeEvent::Send { packet, .. } => packet.clone(),
                _ => panic!("expected OACK"),
            }[..2],
            &[0, 6]
        );
        let second = runtime
            .handle_transfer_datagram(1, peer(1000), &[0, 4, 0, 0], 2)
            .unwrap();
        assert!(matches!(second[0], RuntimeEvent::Send { .. }));
    }

    #[test]
    fn option_oack_retransmits_before_block_zero_ack() {
        let mut runtime = runtime(b"abc");
        let mut request = rrq(b"boot.bin", b"octet");
        request.extend_from_slice(b"blksize\x0064\0");
        let first = runtime.handle_datagram(peer(1000), &request, 1).unwrap();
        let retry = runtime.tick(3).unwrap();
        assert_eq!(retry, first);
        assert_eq!(runtime.active_len(), 1);
    }

    #[test]
    fn netascii_expands_and_timeout_cleans_up() {
        let mut runtime = runtime(b"a\nb");
        let first = runtime
            .handle_datagram(peer(1000), &rrq(b"boot.bin", b"netascii"), 1)
            .unwrap();
        let RuntimeEvent::Send { packet, .. } = &first[0] else {
            panic!("expected DATA")
        };
        assert_eq!(&packet[4..], b"a\r\nb");
        let timeout = runtime.tick(122).unwrap();
        assert_eq!(
            timeout,
            vec![RuntimeEvent::TimedOut {
                id: 1,
                peer: peer(1000),
                path: b"/srv/tftp/boot.bin".to_vec(),
            }]
        );
        assert_eq!(runtime.active_len(), 0);
    }

    #[test]
    fn netascii_data_never_exceeds_negotiated_block_size() {
        let mut runtime = runtime(&[b'\n'; 512]);
        let mut request = rrq(b"boot.bin", b"netascii");
        request.extend_from_slice(b"blksize\x008\0");
        let oack = runtime.handle_datagram(peer(1000), &request, 1).unwrap();
        assert!(
            matches!(oack.first(), Some(RuntimeEvent::Send { packet, .. }) if packet.starts_with(&[0, 6]))
        );
        // The OACK must be acknowledged before DATA starts.
        let first = runtime
            .handle_transfer_datagram(1, peer(1000), &[0, 4, 0, 0], 2)
            .unwrap();
        let RuntimeEvent::Send { packet, .. } = &first[0] else {
            panic!("expected DATA")
        };
        assert!(packet.len() <= 4 + 8);
    }
    #[test]
    fn per_request_root_and_mtu_do_not_mutate_live_transfers() {
        let mut runtime = runtime(&[b'a'; 800]);
        runtime.opener.files.lock().unwrap().insert(
            b"/other/boot.bin".to_vec(),
            Arc::new(MemoryReader {
                data: vec![b'b'; 800],
                identity: FileIdentity {
                    device: 1,
                    inode: 3,
                },
            }),
        );
        let first = runtime
            .handle_datagram(peer(1000), &rrq(b"boot.bin", b"octet"), 1)
            .unwrap();
        assert!(matches!(&first[0],RuntimeEvent::Send{packet,..} if packet[4..]==[b'a';512]));
        let policy = RequestPolicy {
            path: RuntimePathPolicy {
                prefix: Some(b"/other".to_vec()),
                lowercase: false,
            },
            mtu: Some(600),
            ipv6: true,
        };
        let second = runtime
            .handle_datagram_with_policy(peer(1001), &rrq(b"boot.bin", b"octet"), 1, Some(&policy))
            .unwrap();
        assert!(matches!(&second[0],RuntimeEvent::Send{packet,..} if packet[4..]==[b'b';512]));
        let continued = runtime
            .handle_transfer_datagram(1, peer(1000), &[0, 4, 0, 1], 2)
            .unwrap();
        assert!(matches!(&continued[0],RuntimeEvent::Send{packet,..} if packet[4..]==[b'a';288]));
        let mut request = rrq(b"boot.bin", b"octet");
        request.extend_from_slice(b"blksize\x002000\0");
        let negotiated = runtime
            .handle_datagram_with_policy(peer(1002), &request, 1, Some(&policy))
            .unwrap();
        assert!(
            matches!(&negotiated[0],RuntimeEvent::Send{packet,..} if packet.starts_with(&[0,6]))
        );
        assert_eq!(runtime.active_len(), 3);
        assert!(runtime.config.path.prefix.as_deref() == Some(b"/srv/tftp"));
    }
}
