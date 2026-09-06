//! Per-connection state: credentials, the incremental read state machine and
//! the bounded transmit queue.

use crate::sys;
use owrt_ubus::msg::{Header, MAX_MSGLEN};
use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

/// Header (8) plus the 4-byte blob attribute header that precedes the payload.
pub const PREFIX_LEN: usize = Header::LEN + 4;
/// `UBUS_CLIENT_MAX_TXQ_LEN`.
pub const MAX_TXQ_LEN: i64 = MAX_MSGLEN as i64;

/// A message as received: header, the whole head blob (its own 4-byte header
/// included) and at most one descriptor that rode along with it.
pub struct InMsg {
    pub header: Header,
    pub blob: Vec<u8>,
    pub fd: Option<OwnedFd>,
}

impl InMsg {
    /// Top-level attribute payload -- the blob's contents past its header.
    pub fn payload(&self) -> &[u8] {
        if self.blob.len() > 4 {
            &self.blob[4..]
        } else {
            &[]
        }
    }
}

/// A message queued for transmission.
pub struct OutMsg {
    pub header: Header,
    pub blob: Vec<u8>,
    pub fd: Option<OwnedFd>,
}

impl OutMsg {
    pub fn new(ty: u8, seq: u16, peer: u32, blob: Vec<u8>) -> Self {
        OutMsg { header: Header { ty, seq, peer }, blob, fd: None }
    }

    fn total(&self) -> usize {
        Header::LEN + self.blob.len()
    }
}

/// A LOOKUP that could not be finished because the transmit queue filled up.
/// `next` is the object to resume from, in path order.
pub struct PendingCmd {
    pub msg: InMsg,
    pub next: Option<u32>,
}

enum ReadState {
    /// Filling the 12-byte prefix.
    Prefix { got: usize },
    /// Prefix complete; filling `blob` from `got` bytes onward.
    Body { got: usize },
}

pub struct Client {
    pub sock: OwnedFd,
    pub uid: u32,
    pub gid: u32,
    pub user: String,
    pub group: String,
    pub extra_gid: Vec<u32>,
    /// Objects owned by this client, newest first (libubox list_add).
    pub objects: Vec<u32>,
    pub cmd_queue: VecDeque<PendingCmd>,
    tx: VecDeque<OutMsg>,
    /// Bytes of the head-of-queue message already written.
    txq_ofs: usize,
    /// Bytes still owed, which goes negative after a partial direct write.
    txq_len: i64,
    prefix: [u8; PREFIX_LEN],
    state: ReadState,
    blob: Vec<u8>,
    header: Header,
    pending_fd: Option<OwnedFd>,
    pub eof: bool,
}

impl Client {
    pub fn new(sock: OwnedFd, cred: sys::Ucred, user: String, group: String) -> Self {
        Client {
            sock,
            uid: cred.uid,
            gid: cred.gid,
            user,
            group,
            extra_gid: sys::extra_gids(cred.pid),
            objects: Vec::new(),
            cmd_queue: VecDeque::new(),
            tx: VecDeque::new(),
            txq_ofs: 0,
            txq_len: 0,
            prefix: [0; PREFIX_LEN],
            state: ReadState::Prefix { got: 0 },
            blob: Vec::new(),
            header: Header { ty: 0, seq: 0, peer: 0 },
            pending_fd: None,
            eof: false,
        }
    }

    pub fn fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }

    pub fn tx_empty(&self) -> bool {
        self.tx.is_empty()
    }

    /// Queue a message, dropping it silently when the client is too far behind
    /// -- exactly what `ubus_msg_enqueue` does for a slow reader.
    fn enqueue(&mut self, msg: OutMsg) {
        if self.txq_len + msg.total() as i64 > MAX_TXQ_LEN {
            return;
        }
        self.txq_len += msg.total() as i64;
        self.tx.push_back(msg);
    }

    /// Send without owning the payload. When nothing is queued the bytes go
    /// straight from the caller's buffer to the socket, and an allocation only
    /// happens for whatever the socket did not take -- which is what the C
    /// daemon gets from its shared-buffer msg_buf. Worth using wherever the
    /// payload was just assembled and would otherwise be copied, notably the
    /// lookup replies that carry a whole object signature.
    pub fn send_borrowed(&mut self, header: Header, blob: &[u8], fd: Option<OwnedFd>) -> bool {
        if self.tx.is_empty() {
            let head = header.encode();
            let total = Header::LEN + blob.len();
            let raw_fd = fd.as_ref().map(|f| f.as_raw_fd());
            let written = match sys::sendmsg_two(self.fd(), &head, blob, raw_fd) {
                Ok(n) => n,
                Err(e) if would_block(&e) => 0,
                Err(_) => 0,
            };
            if written >= total {
                return true;
            }
            self.txq_ofs = written;
            self.txq_len = -(written as i64);
        }
        self.enqueue(OutMsg { header, blob: blob.to_vec(), fd });
        true
    }

    /// Send a message: try the socket directly when nothing is queued, then
    /// queue whatever is left. Returns false when the connection is dead.
    pub fn send(&mut self, msg: OutMsg) -> bool {
        if self.tx.is_empty() {
            let head = msg.header.encode();
            let fd = msg.fd.as_ref().map(|f| f.as_raw_fd());
            let written = match sys::sendmsg_two(self.fd(), &head, &msg.blob, fd) {
                Ok(n) => n,
                Err(e) if would_block(&e) => 0,
                Err(_) => 0,
            };
            if written >= msg.total() {
                return true;
            }
            self.txq_ofs = written;
            self.txq_len = -(written as i64);
        }
        self.enqueue(msg);
        true
    }

    /// Drain as much of the queue as the socket accepts. Returns false when
    /// the connection must be torn down.
    pub fn flush(&mut self) -> bool {
        while let Some(msg) = self.tx.front() {
            let head = msg.header.encode();
            let total = msg.total();
            // A descriptor only rides on the first byte of a message; a
            // resumed write must not attach it again.
            let fd = if self.txq_ofs == 0 { msg.fd.as_ref().map(|f| f.as_raw_fd()) } else { None };
            let (a, b): (&[u8], &[u8]) = if self.txq_ofs < Header::LEN {
                (&head[self.txq_ofs..], &msg.blob)
            } else {
                (&msg.blob[self.txq_ofs - Header::LEN..], &[])
            };
            match sys::sendmsg_two(self.fd(), a, b, fd) {
                Ok(n) => {
                    self.txq_ofs += n;
                    self.txq_len -= n as i64;
                    if self.txq_ofs < total {
                        if n == 0 {
                            return true;
                        }
                        continue;
                    }
                    self.txq_ofs = 0;
                    self.tx.pop_front();
                }
                Err(e) if would_block(&e) => return true,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return false,
            }
        }
        self.txq_len = 0;
        true
    }

    /// Read one complete message, if the socket has one. `Ok(None)` means the
    /// message is still incomplete or the socket is drained; `Err` means the
    /// connection must be closed (protocol violation or socket error).
    pub fn read_message(&mut self) -> io::Result<Option<InMsg>> {
        loop {
            match self.state {
                ReadState::Prefix { got } => {
                    // Only accept a descriptor while none is held undelivered,
                    // mirroring the C control-buffer toggle.
                    let want_fd = self.pending_fd.is_none();
                    let (n, fd) = match sys::recvmsg_fd(self.fd(), &mut self.prefix[got..], want_fd)
                    {
                        Ok(v) => v,
                        Err(e) if would_block(&e) => return Ok(None),
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    };
                    if let Some(fd) = fd {
                        self.pending_fd = Some(fd);
                    }
                    if n == 0 {
                        self.eof = true;
                        return Ok(None);
                    }
                    let got = got + n;
                    if got < PREFIX_LEN {
                        self.state = ReadState::Prefix { got };
                        return Ok(None);
                    }

                    let raw_len = blob_raw_len(&self.prefix[Header::LEN..]);
                    if raw_len < 4 || pad4(raw_len) > MAX_MSGLEN {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad message length"));
                    }
                    let head: [u8; 8] = self.prefix[..Header::LEN].try_into().unwrap();
                    let Some(header) = Header::decode(&head) else {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad header"));
                    };
                    self.header = header;
                    self.blob = vec![0u8; raw_len];
                    self.blob[..4].copy_from_slice(&self.prefix[Header::LEN..]);
                    self.state = ReadState::Body { got: 4 };
                }
                ReadState::Body { got } => {
                    if got < self.blob.len() {
                        let n = match sys::read_fd(self.fd(), &mut self.blob[got..]) {
                            Ok(v) => v,
                            Err(e) if would_block(&e) => return Ok(None),
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(e) => return Err(e),
                        };
                        if n == 0 {
                            self.eof = true;
                            return Ok(None);
                        }
                        let got = got + n;
                        if got < self.blob.len() {
                            self.state = ReadState::Body { got };
                            return Ok(None);
                        }
                    }
                    self.state = ReadState::Prefix { got: 0 };
                    let blob = std::mem::take(&mut self.blob);
                    return Ok(Some(InMsg {
                        header: self.header,
                        blob,
                        fd: self.pending_fd.take(),
                    }));
                }
            }
        }
    }
}

fn would_block(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::WouldBlock
}

/// `blob_raw_len`: the low 24 bits of the big-endian id_len word, which count
/// the 4-byte header itself.
pub fn blob_raw_len(hdr: &[u8]) -> usize {
    if hdr.len() < 4 {
        return 0;
    }
    (u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) & 0x00ff_ffff) as usize
}

pub fn pad4(len: usize) -> usize {
    (len + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_len_ignores_id_and_extended_bits() {
        // extended | id 7 | len 0x14
        let hdr = 0x8700_0014u32.to_be_bytes();
        assert_eq!(blob_raw_len(&hdr), 0x14);
        assert_eq!(pad4(0x14), 0x14);
        assert_eq!(pad4(0x15), 0x18);
    }

    #[test]
    fn prefix_is_header_plus_blob_header() {
        assert_eq!(PREFIX_LEN, 12);
        assert_eq!(Header::LEN, 8);
    }
}
