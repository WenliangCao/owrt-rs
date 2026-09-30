//! Socket-independent TFTP transfer runtime.
//!
//! This is the file/open/packet boundary below the eventual UDP listener. It
//! owns real file descriptors through `Arc`, drives the existing `tftp::Transfer`
//! state machine, and emits packets/events through a caller-owned transport.
//! Interface pktinfo, port-69 listeners, PXE helper scripts and OpenWrt reload
//! remain outside this module.

use crate::tftp::{self, Mode, ReadRequest, RequestError, Transfer};
use crate::tftp_service::{permitted, resolve_path, Admission as PeerAdmission};
use std::collections::BTreeMap;
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

#[derive(Clone)]
pub struct OpenedFile {
    pub path: Vec<u8>,
    pub identity: FileIdentity,
    pub size: u64,
    pub mode: u32,
    pub owner_uid: u32,
    pub reader: Arc<dyn FileReader>,
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

#[cfg(unix)]
struct RealReader {
    file: Arc<File>,
    size: u64,
    identity: FileIdentity,
}

#[cfg(unix)]
impl FileReader for RealReader {
    fn size(&self) -> u64 {
        self.size
    }

    fn identity(&self) -> FileIdentity {
        self.identity
    }

    fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        self.file.read_at(output, offset)
    }
}

impl FileOpener for RealFileOpener {
    fn open(&self, path: &[u8]) -> io::Result<OpenedFile> {
        #[cfg(unix)]
        {
            let file = Arc::new(File::open(std::ffi::OsString::from_vec(path.to_vec()))?);
            let metadata = file.metadata()?;
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
            let reader = Arc::new(RealReader {
                file,
                size: metadata.len(),
                identity,
            });
            Ok(OpenedFile {
                path: path.to_vec(),
                identity,
                size: metadata.len(),
                mode: metadata.mode(),
                owner_uid: metadata.uid(),
                reader,
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimePathPolicy {
    pub prefix: Option<Vec<u8>>,
    pub lowercase: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            path: RuntimePathPolicy::default(),
            packet_buffer_size: 8192,
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
    pub peer: SocketAddr,
    pub path: Vec<u8>,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeEvent {
    Send { peer: SocketAddr, packet: Vec<u8> },
    TidError { peer: SocketAddr, packet: Vec<u8> },
    Completed(Completion),
    Failed { peer: SocketAddr },
    TimedOut { peer: SocketAddr },
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

impl From<RequestError> for RuntimeError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

#[derive(Clone)]
struct SharedFile {
    path: Vec<u8>,
    identity: FileIdentity,
    size: u64,
    reader: Arc<dyn FileReader>,
}

struct Active {
    peer: SocketAddr,
    file: Arc<SharedFile>,
    transfer: Transfer,
    mode: Mode,
}

pub struct TransferRuntime<O> {
    config: RuntimeConfig,
    opener: O,
    next_id: u64,
    active: BTreeMap<u64, Active>,
}

impl<O: FileOpener> TransferRuntime<O> {
    pub fn new(config: RuntimeConfig, opener: O) -> Self {
        Self {
            config,
            opener,
            next_id: 1,
            active: BTreeMap::new(),
        }
    }

    pub fn active_len(&self) -> usize {
        self.active.len()
    }

    pub fn handle_datagram(
        &mut self,
        peer: SocketAddr,
        packet: &[u8],
        now: u64,
    ) -> Result<Vec<RuntimeEvent>, RuntimeError> {
        if packet.len() < 2 {
            return Ok(Vec::new());
        }
        // In separate-port mode each transfer has its own socket, but the
        // transport boundary still supplies datagrams to this runtime. Route
        // ACK/ERR from the owning peer before applying new-RRQ admission.
        if !self.config.single_port && opcode(packet) != Some(1) {
            if let Some((id, _)) = self.active.iter().find(|(_, active)| active.peer == peer) {
                return self.receive(*id, peer, packet, now);
            }
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
                self.start_rrq(peer, packet, now)
            }
            PeerAdmission::Ignore => {
                if opcode(packet) == Some(1) {
                    Ok(Vec::new())
                } else {
                    Ok(vec![RuntimeEvent::TidError {
                        peer,
                        packet: error_packet(5, "unknown transfer id"),
                    }])
                }
            }
            PeerAdmission::New => {
                if matches!(opcode(packet), Some(1) | Some(2)) {
                    self.start_rrq(peer, packet, now)
                } else if !self.active.is_empty() {
                    Ok(vec![RuntimeEvent::TidError {
                        peer,
                        packet: error_packet(5, "unknown transfer id"),
                    }])
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
            let Some(active) = self.active.get(&id) else {
                continue;
            };
            if active.transfer.expired(now) {
                let active = self.active.remove(&id).unwrap();
                events.push(RuntimeEvent::TimedOut { peer: active.peer });
                continue;
            }
            if active.transfer.retransmit_at <= now {
                events.extend(self.send_window(id, now)?);
            }
        }
        Ok(events)
    }

    fn id_at(&self, index: usize) -> u64 {
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
    ) -> Result<Vec<RuntimeEvent>, RuntimeError> {
        let request = match tftp::parse_request(
            packet,
            self.config.packet_buffer_size,
            self.config.mtu,
            self.config.ipv6,
            self.config.no_block_size,
        ) {
            Ok(request) => request,
            Err(_) => {
                return Ok(vec![RuntimeEvent::Send {
                    peer,
                    packet: error_packet(4, "illegal TFTP operation"),
                }])
            }
        };
        let request = match request {
            Some(request) => request,
            None => return Ok(Vec::new()),
        };
        if self.active.len() >= self.config.max_transfers {
            return Err(RuntimeError::Capacity);
        }
        let path = resolve_path(
            self.config.path.prefix.as_deref(),
            self.config.path.lowercase,
            request.filename,
        );
        let path = match path {
            Ok(path) => path,
            Err(_error) => {
                return Ok(vec![RuntimeEvent::Send {
                    peer,
                    packet: error_packet(2, "access violation"),
                }])
            }
        };
        let opened = self.opener.open(&path).map_err(RuntimeError::Open)?;
        if !permitted(
            opened.mode,
            opened.owner_uid,
            self.config.effective_uid,
            self.config.secure,
        ) {
            return Err(RuntimeError::Permission);
        }
        let file = self
            .active
            .values()
            .find(|active| active.file.path == path && active.file.identity == opened.identity)
            .map(|active| Arc::clone(&active.file))
            .unwrap_or_else(|| {
                Arc::new(SharedFile {
                    path,
                    identity: opened.identity,
                    size: opened.size,
                    reader: opened.reader,
                })
            });
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
            },
        );
        self.send_initial(id, request, now)
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
                .write_ack(active.file.size, &mut packet);
            let mut framed = vec![0, 6];
            framed.extend_from_slice(&packet[2..]);
            Ok(vec![RuntimeEvent::Send {
                peer: active.peer,
                packet: framed,
            }])
        } else {
            self.send_blocks(id, 1, now)
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
                peer,
                packet: error_packet(5, "unknown transfer id"),
            }]);
        };
        if active.peer != peer {
            return Ok(vec![RuntimeEvent::TidError {
                peer,
                packet: error_packet(5, "unknown transfer id"),
            }]);
        }
        if !active.transfer.receive(packet, now) {
            if active.transfer.failed {
                let peer = active.peer;
                self.active.remove(&id);
                return Ok(vec![RuntimeEvent::Failed { peer }]);
            }
            return Ok(Vec::new());
        }
        if active.transfer.failed {
            let peer = active.peer;
            self.active.remove(&id);
            return Ok(vec![RuntimeEvent::Failed { peer }]);
        }
        let complete =
            active.transfer.block != 0 && active.transfer.file_offset(active.file.size).is_none();
        if complete {
            let active = self.active.remove(&id).unwrap();
            return Ok(vec![RuntimeEvent::Completed(Completion {
                peer: active.peer,
                path: active.file.path.clone(),
                size: active.file.size,
            })]);
        }
        self.send_window(id, now)
    }

    fn send_window(&mut self, id: u64, now: u64) -> Result<Vec<RuntimeEvent>, RuntimeError> {
        let count = {
            let active = self.active.get_mut(&id).unwrap();
            active.transfer.begin_window(now).unwrap_or(0)
        };
        if count == 0 {
            return Ok(Vec::new());
        }
        self.send_blocks(id, count, now)
    }

    fn send_blocks(
        &mut self,
        id: u64,
        count: u32,
        _now: u64,
    ) -> Result<Vec<RuntimeEvent>, RuntimeError> {
        let mut events = Vec::new();
        for _ in 0..count {
            let packet = self.data_packet(id)?;
            if packet.is_empty() {
                break;
            }
            let peer = self.active.get(&id).unwrap().peer;
            events.push(RuntimeEvent::Send { peer, packet });
            let active = self.active.get_mut(&id).unwrap();
            active.transfer.block = active.transfer.block.wrapping_add(1);
        }
        Ok(events)
    }

    fn data_packet(&mut self, id: u64) -> Result<Vec<u8>, RuntimeError> {
        let active = self.active.get_mut(&id).unwrap();
        let Some(offset) = active.transfer.file_offset(active.file.size) else {
            return Ok(Vec::new());
        };
        let block = active.transfer.block as u16;
        let mut raw = vec![0; active.transfer.options.block_size];
        let remaining = active.file.size.saturating_sub(offset);
        let to_read = remaining.min(raw.len() as u64) as usize;
        let read = if to_read == 0 {
            0
        } else {
            active
                .file
                .reader
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

fn error_packet(code: u16, message: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(message.len() + 5);
    packet.extend_from_slice(&[0, 5]);
    packet.extend_from_slice(&code.to_be_bytes());
    packet.extend(
        message
            .bytes()
            .filter(|byte| byte.is_ascii() && *byte >= 0x20),
    );
    packet.push(0);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

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
                mode: 0o644,
                owner_uid: 0,
                reader,
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
            .handle_datagram(peer(1000), &[0, 4, 0, 1], 2)
            .unwrap();
        assert_eq!(
            done,
            vec![RuntimeEvent::Completed(Completion {
                peer: peer(1000),
                path: b"/srv/tftp/boot.bin".to_vec(),
                size: 5,
            })]
        );
        assert_eq!(runtime.active_len(), 0);
    }

    #[test]
    fn wrong_peer_gets_tid_error_and_error_aborts_transfer() {
        let mut runtime = runtime(b"hello");
        runtime
            .handle_datagram(peer(1000), &rrq(b"boot.bin", b"octet"), 1)
            .unwrap();
        let wrong = runtime
            .handle_datagram(peer(1001), &[0, 4, 0, 1], 2)
            .unwrap();
        assert!(matches!(wrong[0], RuntimeEvent::TidError { .. }));
        let failed = runtime
            .handle_datagram(peer(1000), &[0, 5, 0, 1, b'x', 0], 2)
            .unwrap();
        assert_eq!(failed, vec![RuntimeEvent::Failed { peer: peer(1000) }]);
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
            .handle_datagram(peer(1000), &[0, 4, 0, 0], 2)
            .unwrap();
        assert!(matches!(second[0], RuntimeEvent::Send { .. }));
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
        assert_eq!(timeout, vec![RuntimeEvent::TimedOut { peer: peer(1000) }]);
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
            .handle_datagram(peer(1000), &[0, 4, 0, 0], 2)
            .unwrap();
        let RuntimeEvent::Send { packet, .. } = &first[0] else {
            panic!("expected DATA")
        };
        assert!(packet.len() <= 4 + 8);
    }
}
