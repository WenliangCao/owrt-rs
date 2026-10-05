//! Image dump.c PCAP records. The one service owner opens, writes and logs them.
use crate::config::dump::DumpConfig;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const QUERY: i32 = 1;
pub const REPLY: i32 = 2;
pub const UP_QUERY: i32 = 4;
pub const UP_REPLY: i32 = 8;
pub const DHCP: i32 = 0x1000;
pub const TFTP: i32 = 0x8000;
const MAGIC: u32 = 0xa1b2c3d4;

#[derive(Debug)]
pub struct DumpError {
    pub message: Vec<u8>,
}
impl std::fmt::Display for DumpError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "{}", String::from_utf8_lossy(&self.message))
    }
}
impl std::error::Error for DumpError {}
fn failure(prefix: &[u8], path: &Path, error: Option<io::Error>) -> DumpError {
    let mut message = prefix.to_vec();
    message.extend_from_slice(path.as_os_str().as_bytes());
    if let Some(error) = error {
        message.extend_from_slice(b": ");
        message.extend_from_slice(crate::logging::error_text(&error).as_bytes());
    }
    DumpError { message }
}

struct Pending {
    bytes: Vec<u8>,
    position: usize,
    mask: i32,
    display_id: Option<i32>,
}
pub struct DumpWriter {
    file: File,
    mask: i32,
    count: u32,
    extra: bool,
    queue: VecDeque<Pending>,
    notices: VecDeque<(bool, Vec<u8>)>,
}

#[derive(Clone, Default)]
// The poll owner and its synchronous producers share one writer; it never
// crosses threads or calls a producer while borrowed.
pub struct DumpHandle(Option<Rc<RefCell<DumpWriter>>>);
impl DumpHandle {
    pub fn open(config: &DumpConfig, edns_max: u16) -> Result<Self, DumpError> {
        let Some(path) = &config.file else {
            return Ok(Self::default());
        };
        let existing = match std::fs::metadata(path) {
            Ok(value) => Some(value),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(failure(b"cannot create ", path, Some(error))),
        };
        let mut options = OpenOptions::new();
        options.write(true).custom_flags(0o4000);
        let file = if existing.is_none() {
            options
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .map_err(|error| failure(b"cannot create ", path, Some(error)))?
        } else {
            options
                .read(true)
                .append(true)
                .open(path)
                .map_err(|error| {
                    failure(
                        if existing.as_ref().unwrap().file_type().is_fifo() {
                            b"cannot open pipe "
                        } else {
                            b"cannot access "
                        },
                        path,
                        Some(error),
                    )
                })?
        };
        let mut writer = DumpWriter {
            file,
            mask: config.mask,
            count: 0,
            extra: false,
            queue: VecDeque::new(),
            notices: VecDeque::new(),
        };
        if existing
            .as_ref()
            .is_none_or(|meta| meta.file_type().is_fifo())
        {
            let mut header = Vec::with_capacity(24);
            header.extend_from_slice(&MAGIC.to_ne_bytes());
            header.extend_from_slice(&2u16.to_ne_bytes());
            header.extend_from_slice(&4u16.to_ne_bytes());
            for value in [0, 0, u32::from(edns_max) + 200, 101] {
                header.extend_from_slice(&value.to_ne_bytes());
            }
            writer.queue.push_back(Pending {
                bytes: header,
                position: 0,
                mask: 0,
                display_id: None,
            });
            writer.step();
            if writer.notices.iter().any(|(error, _)| *error) {
                return Err(failure(
                    b"cannot create ",
                    path,
                    Some(io::Error::last_os_error()),
                ));
            }
        } else {
            let mut header = [0; 24];
            writer.file.read_exact(&mut header).map_err(|error| {
                // C read_write leaves errno unchanged on EOF; startup's
                // last successful open has errno0 in the ordinary path.
                let error = if error.kind() == io::ErrorKind::UnexpectedEof {
                    io::Error::from_raw_os_error(0)
                } else {
                    error
                };
                failure(b"cannot access ", path, Some(error))
            })?;
            if u32::from_ne_bytes(header[..4].try_into().unwrap()) != MAGIC {
                return Err(failure(b"bad header in ", path, None));
            }
            let mut record = [0; 16];
            while writer.file.read_exact(&mut record).is_ok() {
                let length = u32::from_ne_bytes(record[8..12].try_into().unwrap());
                if writer
                    .file
                    .seek(SeekFrom::Current(i64::from(length)))
                    .is_err()
                {
                    break;
                }
                writer.count = writer.count.wrapping_add(1);
            }
        }
        Ok(Self(Some(Rc::new(RefCell::new(writer)))))
    }
    pub fn udp(&self, mask: i32, bytes: &[u8], source: SocketAddr, destination: SocketAddr) {
        self.udp_with_context(mask, bytes, source, destination, Default::default());
    }

    pub fn set_query_logging(&self, config: crate::config::logging::QueryLogging) {
        if let Some(writer) = &self.0 {
            writer.borrow_mut().extra = config.extra;
        }
    }

    pub fn udp_with_context(
        &self,
        mask: i32,
        bytes: &[u8],
        source: SocketAddr,
        destination: SocketAddr,
        context: crate::logging::query::QueryContext,
    ) {
        let Some(writer) = &self.0 else {
            return;
        };
        let mut writer = writer.borrow_mut();
        if writer.mask & mask == 0 {
            return;
        }
        if writer.queue.len() >= 256 {
            writer
                .notices
                .push_back((true, b"failed to write packet dump".to_vec()));
            return;
        }
        let Ok(time) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            writer
                .notices
                .push_back((true, b"failed to write packet dump".to_vec()));
            return;
        };
        let packet = udp_packet(bytes, source, destination);
        let mut record = Vec::with_capacity(packet.len() + 16);
        for value in [
            time.as_secs() as u32,
            time.subsec_micros(),
            packet.len() as u32,
            packet.len() as u32,
        ] {
            record.extend_from_slice(&value.to_ne_bytes());
        }
        record.extend_from_slice(&packet);
        let display_id = (writer.extra && mask & 0xff != 0).then_some(context.display_id);
        writer.queue.push_back(Pending {
            bytes: record,
            position: 0,
            mask,
            display_id,
        });
        writer.step();
    }
    pub fn step(&self) {
        if let Some(writer) = &self.0 {
            writer.borrow_mut().step();
        }
    }
    pub fn take_notices(&self) -> Vec<(bool, Vec<u8>)> {
        self.0.as_ref().map_or_else(Vec::new, |writer| {
            writer.borrow_mut().notices.drain(..).collect()
        })
    }
    pub fn poll_fd(&self) -> Option<RawFd> {
        self.0.as_ref().and_then(|writer| {
            let writer = writer.borrow_mut();
            (!writer.queue.is_empty()).then(|| writer.file.as_raw_fd())
        })
    }
}
impl DumpWriter {
    fn step(&mut self) {
        let mut budget = 16384;
        while budget != 0 {
            let Some(front) = self.queue.front_mut() else {
                break;
            };
            let end = front.bytes.len().min(front.position + budget);
            match self.file.write(&front.bytes[front.position..end]) {
                Ok(0) => break,
                Ok(count) => {
                    front.position += count;
                    budget -= count;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.queue.pop_front();
                    self.notices
                        .push_back((true, b"failed to write packet dump".to_vec()));
                    continue;
                }
            }
            if front.position == front.bytes.len() {
                let pending = self.queue.pop_front().unwrap();
                let mask = pending.mask;
                if mask != 0 {
                    self.count = self.count.wrapping_add(1);
                    let mut message = pending
                        .display_id
                        .map_or_else(String::new, |id| format!("{} ", id as u32));
                    message.push_str(&format!(
                        "dumping packet {} mask 0x{:04x}",
                        self.count, mask as u32
                    ));
                    self.notices.push_back((false, message.into_bytes()));
                }
            }
        }
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes.chunks(2).fold(0u32, |sum, bytes| {
        sum + u32::from(u16::from_be_bytes([bytes[0], *bytes.get(1).unwrap_or(&0)]))
    });
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if sum == 0xffff {
        0xffff
    } else {
        !(sum as u16)
    }
}
fn udp_packet(payload: &[u8], source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let ipv6 = source.is_ipv6();
    let mut pseudo = Vec::new();
    let mut packet = if ipv6 {
        let mut packet = vec![0; 40];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        if let IpAddr::V6(ip) = source.ip() {
            packet[8..24].copy_from_slice(&ip.octets());
        }
        if let IpAddr::V6(ip) = destination.ip() {
            packet[24..40].copy_from_slice(&ip.octets());
        }
        pseudo.extend_from_slice(&packet[8..40]);
        packet
    } else {
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((payload.len() + 28) as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        if let IpAddr::V4(ip) = source.ip() {
            packet[12..16].copy_from_slice(&ip.octets());
        }
        if let IpAddr::V4(ip) = destination.ip() {
            packet[16..20].copy_from_slice(&ip.octets());
        }
        let sum = checksum(&packet);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        pseudo.extend_from_slice(&packet[12..20]);
        packet
    };
    // Native dump.c adds the same effective pseudoheader terms in both families.
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    let start = packet.len();
    packet.extend_from_slice(&source.port().to_be_bytes());
    packet.extend_from_slice(&destination.port().to_be_bytes());
    packet.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(payload);
    pseudo.extend_from_slice(&packet[start..]);
    let sum = checksum(&pseudo);
    packet[start + 6..start + 8].copy_from_slice(&sum.to_be_bytes());
    packet
}
