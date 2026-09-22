//! Per-connection state: credentials, the incremental read state machine and
//! the bounded transmit queue.

use crate::sys;
use owrt_ubus::msg::{ty, Header, MAX_MSGLEN};
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
/// `next` is an owned path lower bound, so deleting the next object cannot
/// invalidate the cursor or restart the walk at already-delivered objects.
pub struct PendingCmd {
    pub msg: InMsg,
    pub next: Option<Vec<u8>>,
}

/// Read-ahead room per connection. A frame that does not fit is finished
/// straight into its own storage.
pub(crate) const RX_SIZE: usize = 4096;

/// A frame larger than the read-ahead buffer, being completed in place.
struct LargeFrame {
    header: Header,
    blob: Vec<u8>,
    got: usize,
    fd: Option<OwnedFd>,
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
    /// Only an incomplete tail survives a readiness round. Complete input
    /// lives in the event loop's shared stack buffer during dispatch.
    rx: Vec<u8>,
    rx_start: usize,
    rx_end: usize,
    /// Descriptors delivered with read-ahead bytes, keyed by the rx index one
    /// past the recvmsg that carried them. A peer attaches a descriptor to
    /// the sendmsg that begins its frame and the kernel ends a recvmsg after
    /// the buffer carrying ancillary data, so the frame holding that last
    /// byte owns the descriptor.
    rx_fds: VecDeque<(usize, OwnedFd)>,
    /// The last recvmsg returned less than the room offered, so the socket
    /// was drained at that moment; the next read waits for readiness
    /// instead of probing for EAGAIN.
    rx_drained: bool,
    large: Option<LargeFrame>,
    pub eof: bool,
    /// Whether the readiness set currently asks for output events on this
    /// socket. The loop keeps it equal to "something is queued".
    pub out_registered: bool,
    pub in_registered: bool,
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
            rx: Vec::new(),
            rx_start: 0,
            rx_end: 0,
            rx_fds: VecDeque::new(),
            rx_drained: false,
            large: None,
            eof: false,
            out_registered: false,
            in_registered: true,
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

    /// The final LOOKUP DATA and its successful STATUS are known together.
    /// Write both immediately, keeping their separate framing and queue caps.
    /// Neither reply carries a descriptor. Monitor users keep the per-message
    /// path so each mirror remains at its original send boundary.
    pub fn send_lookup_reply(&mut self, header: Header, blob: &[u8]) {
        let status_header = Header { ty: ty::STATUS, ..header };
        let status_blob = [0, 0, 0, 12, 1, 0, 0, 8, 0, 0, 0, 0];
        if !self.tx.is_empty() {
            self.send_borrowed(header, blob, None);
            self.send_borrowed(status_header, &status_blob, None);
            return;
        }
        let mut status_frame = [0u8; Header::LEN + 12];
        status_frame[..Header::LEN].copy_from_slice(&status_header.encode());
        status_frame[Header::LEN..].copy_from_slice(&status_blob);
        let first_len = Header::LEN + blob.len();
        let written = sys::sendmsg_three(self.fd(), [&header.encode(), blob, &status_frame])
            .unwrap_or(0);
        if written < first_len {
            self.txq_ofs = written;
            self.txq_len = -(written as i64);
            self.enqueue(OutMsg { header, blob: blob.to_vec(), fd: None });
            // If DATA was silently dropped at the cap, STATUS can still go
            // directly, exactly as on the per-message path.
            self.send_borrowed(status_header, &status_blob, None);
        } else if written < first_len + status_frame.len() {
            self.txq_ofs = written - first_len;
            self.txq_len = -(self.txq_ofs as i64);
            self.enqueue(OutMsg { header: status_header, blob: status_blob.to_vec(), fd: None });
        }
    }

    /// Submit a bounded sequence of complete descriptor-free LOOKUP frames.
    /// A short write is split back into the original per-frame queue entries,
    /// retaining their offsets and cap checks rather than queueing one giant
    /// synthetic message. `frames` is assembled by Server, never wire input.
    pub fn send_lookup_batch(&mut self, frames: &[u8]) {
        let direct = self.tx.is_empty();
        let written = if direct {
            sys::sendmsg_two(self.fd(), frames, &[], None).unwrap_or(0)
        } else {
            0
        };
        if written == frames.len() {
            return;
        }
        let mut pos = 0;
        while pos < frames.len() {
            let header = Header::decode(frames[pos..pos + Header::LEN].try_into().unwrap()).unwrap();
            let start = pos + Header::LEN;
            let end = start + blob_raw_len(&frames[start..]);
            if written < end {
                let blob = &frames[start..end];
                if direct && written >= pos {
                    self.txq_ofs = written - pos;
                    self.txq_len = -(self.txq_ofs as i64);
                    self.enqueue(OutMsg { header, blob: blob.to_vec(), fd: None });
                } else {
                    self.send_borrowed(header, blob, None);
                }
            }
            pos = end;
        }
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

    /// Begin one readiness round. The previous round saved only its unfinished
    /// tail, with FD marks relative to zero. No complete frame is retained.
    pub fn begin_read(&mut self, rx: &mut [u8; RX_SIZE]) {
        if !self.rx.is_empty() {
            rx[..self.rx.len()].copy_from_slice(&self.rx);
            self.rx = Vec::new();
        }
    }

    /// End a readiness round before the shared stack buffer serves a different
    /// client. Only incomplete bytes allocate; idle connections retain none.
    pub fn end_read(&mut self, rx: &[u8; RX_SIZE]) {
        let start = self.rx_start;
        let end = self.rx_end;
        if start != end {
            self.rx = rx[start..end].to_vec();
            while self.rx_fds.front().is_some_and(|(mark, _)| *mark <= start) {
                self.rx_fds.pop_front();
            }
            for (mark, _) in &mut self.rx_fds {
                *mark -= start;
            }
        }
        self.rx_start = 0;
        self.rx_end = end - start;
    }

    /// Read one complete message, if the socket has one. `Ok(None)` means the
    /// message is still incomplete or the socket is drained; `Err` means the
    /// connection must be closed (protocol violation or socket error).
    pub fn read_message(&mut self, rx: &mut [u8; RX_SIZE]) -> io::Result<Option<InMsg>> {
        loop {
            if let Some(large) = &mut self.large {
                let n = match sys::read_fd(self.sock.as_raw_fd(), &mut large.blob[large.got..]) {
                    Ok(v) => v,
                    Err(e) if would_block(&e) => return Ok(None),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };
                if n == 0 {
                    self.eof = true;
                    return Ok(None);
                }
                large.got += n;
                if large.got < large.blob.len() {
                    return Ok(None);
                }
                let done = self.large.take().expect("checked above");
                return Ok(Some(InMsg { header: done.header, blob: done.blob, fd: done.fd }));
            }
            let buffered = self.rx_end - self.rx_start;
            if buffered >= PREFIX_LEN {
                let s = self.rx_start;
                let raw_len = blob_raw_len(&rx[s + Header::LEN..]);
                if raw_len < 4 || pad4(raw_len) > MAX_MSGLEN {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "bad message length"));
                }
                // ubusd_main.c never looks at hdr.version: it reads the
                // prefix, checks the blob length and dispatches on the type.
                // A client sending a nonzero version is served, not dropped.
                let p = &rx[s..s + Header::LEN];
                let header = Header {
                    ty: p[1],
                    seq: u16::from_be_bytes([p[2], p[3]]),
                    peer: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
                };
                let total = Header::LEN + raw_len;
                if total > RX_SIZE {
                    let mut blob = vec![0u8; raw_len];
                    let have = buffered - Header::LEN;
                    blob[..have].copy_from_slice(&rx[s + Header::LEN..self.rx_end]);
                    let fd = self.rx_take_fd(s, s + total);
                    self.rx_reset();
                    self.large = Some(LargeFrame { header, blob, got: have, fd });
                    continue;
                }
                if buffered >= total {
                    let blob = rx[s + Header::LEN..s + total].to_vec();
                    let fd = self.rx_take_fd(s, s + total);
                    self.rx_start = s + total;
                    if self.rx_start == self.rx_end {
                        self.rx_reset();
                    }
                    return Ok(Some(InMsg { header, blob, fd }));
                }
            }
            if self.rx_drained {
                // Nothing more was available at the last read; a readiness
                // event announces the rest.
                self.rx_drained = false;
                return Ok(None);
            }
            match self.rx_fill(rx) {
                Ok(true) => {}
                Ok(false) => return Ok(None),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// One recvmsg into the read-ahead buffer. Ok(false): nothing to read
    /// now, or the peer closed (`eof` is set).
    fn rx_fill(&mut self, rx: &mut [u8; RX_SIZE]) -> io::Result<bool> {
        if self.rx_end == RX_SIZE {
            rx.copy_within(self.rx_start..self.rx_end, 0);
            for (mark, _) in &mut self.rx_fds {
                *mark -= self.rx_start;
            }
            self.rx_end -= self.rx_start;
            self.rx_start = 0;
        }
        let room = RX_SIZE - self.rx_end;
        match sys::recvmsg_fd(self.sock.as_raw_fd(), &mut rx[self.rx_end..], true) {
            Ok((0, _)) => {
                self.eof = true;
                Ok(false)
            }
            Ok((n, fd)) => {
                self.rx_end += n;
                if let Some(fd) = fd {
                    self.rx_fds.push_back((self.rx_end, fd));
                }
                self.rx_drained = n < room;
                Ok(true)
            }
            Err(e) if would_block(&e) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn rx_reset(&mut self) {
        self.rx_start = 0;
        self.rx_end = 0;
        self.rx_fds.clear();
    }

    /// The descriptor owned by the frame spanning rx indices `start..end`.
    fn rx_take_fd(&mut self, start: usize, end: usize) -> Option<OwnedFd> {
        while self.rx_fds.front().is_some_and(|(mark, _)| *mark <= start) {
            self.rx_fds.pop_front();
        }
        if self.rx_fds.front().is_some_and(|(mark, _)| *mark <= end) {
            return self.rx_fds.pop_front().map(|(_, fd)| fd);
        }
        None
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
    use owrt_ubus::blob::BlobBuf;
    use owrt_ubus::msg::attr;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

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

    fn rx_pair() -> (Client, UnixStream) {
        let (sock, peer) = UnixStream::pair().unwrap();
        sock.set_nonblocking(true).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        (Client::new(sock.into(), sys::Ucred::default(), String::new(), String::new()), peer)
    }

    fn rx_frame(seq: u16, raw_len: usize) -> Vec<u8> {
        let mut bytes = Header { ty: ty::DATA, seq, peer: 0x12345678 }.encode().to_vec();
        bytes.extend_from_slice(&(raw_len as u32).to_be_bytes());
        bytes.resize(Header::LEN + raw_len, seq as u8);
        bytes
    }

    // Drive exactly the production begin/next-until-None/end boundary, then
    // overwrite the shared storage to simulate a different ready client.
    fn rx_round(c: &mut Client, rx: &mut [u8; RX_SIZE]) -> Vec<InMsg> {
        c.begin_read(rx);
        let mut messages = Vec::new();
        while let Some(msg) = c.read_message(rx).unwrap() {
            messages.push(msg);
        }
        c.end_read(rx);
        rx.fill(0xa5);
        messages
    }

    fn assert_frame(msg: &InMsg, frame: &[u8]) {
        assert_eq!(msg.header.encode(), frame[..Header::LEN]);
        assert_eq!(msg.blob, frame[Header::LEN..]);
    }

    #[test]
    fn stack_rx_fragments_survive_other_clients_and_drop_idle_capacity() {
        let mut rx = [0u8; RX_SIZE];
        for len in [4, 64, 4088, 4089, 8192] {
            for cut in [1, 7, 8, 11, 12, 13, 27, 2048, 4096].into_iter()
                .filter(|cut| *cut < len + Header::LEN) {
                let (mut c, mut peer) = rx_pair();
                let (mut other, mut other_peer) = rx_pair();
                let frame = rx_frame(17, len);
                peer.write_all(&frame[..cut]).unwrap();
                assert!(rx_round(&mut c, &mut rx).is_empty());
                let expected = if len + Header::LEN > RX_SIZE && cut >= PREFIX_LEN { 0 } else { cut };
                assert_eq!(c.rx.len(), expected);
                assert_eq!(c.rx.capacity(), expected);
                let other_frame = rx_frame(29, 36);
                other_peer.write_all(&other_frame).unwrap();
                let got = rx_round(&mut other, &mut rx);
                assert_eq!(got.len(), 1);
                assert_frame(&got[0], &other_frame);
                let tail = frame[cut..].to_vec();
                let writer = std::thread::spawn(move || peer.write_all(&tail).unwrap());
                let mut got = Vec::new();
                let deadline = Instant::now() + Duration::from_secs(3);
                while !c.eof {
                    got.extend(rx_round(&mut c, &mut rx));
                    assert!(Instant::now() < deadline);
                    std::thread::yield_now();
                }
                writer.join().unwrap();
                assert_eq!(got.len(), 1, "len={len} cut={cut}");
                assert_frame(&got[0], &frame);
                assert_eq!(c.rx.capacity(), 0);
                assert!(c.large.is_none());
            }
        }
    }

    #[test]
    fn stack_rx_batches_cross_buffer_boundaries_and_eof() {
        let mut rx = [0u8; RX_SIZE];
        for lengths in [vec![4; 700], vec![4088, 4089, 4, 8192, 28], vec![4000, 192, 4]] {
            let (mut c, mut peer) = rx_pair();
            let frames: Vec<_> = lengths.into_iter().enumerate().map(|(i, n)| rx_frame(i as u16, n)).collect();
            let stream = frames.concat();
            let writer = std::thread::spawn(move || {
                peer.write_all(&stream).unwrap();
                peer.shutdown(std::net::Shutdown::Write).unwrap();
            });
            let mut got = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(3);
            while !c.eof {
                got.extend(rx_round(&mut c, &mut rx));
                assert!(Instant::now() < deadline);
            }
            writer.join().unwrap();
            assert_eq!(got.len(), frames.len());
            for (msg, frame) in got.iter().zip(&frames) { assert_frame(msg, frame); }
            assert_eq!(c.rx.capacity(), 0);
        }
    }

    #[test]
    fn stack_rx_complete_short_read_preserves_drained_boundary() {
        let (mut c, mut peer) = rx_pair();
        let mut rx = [0u8; RX_SIZE];
        for seq in 0..20 {
            let frame = rx_frame(seq, 16);
            peer.write_all(&frame).unwrap();
            c.begin_read(&mut rx);
            assert_frame(&c.read_message(&mut rx).unwrap().unwrap(), &frame);
            assert!(c.rx_drained, "retain short-read marker until end of round");
            assert!(c.read_message(&mut rx).unwrap().is_none());
            assert!(!c.rx_drained);
            c.end_read(&rx);
            assert_eq!(c.rx.capacity(), 0);
        }
    }

    #[test]
    fn stack_rx_rejects_bad_lengths_after_fragmented_prefix() {
        for raw_len in [0, 1, 3, MAX_MSGLEN + 1] {
            let (mut c, mut peer) = rx_pair();
            let mut frame = Header { ty: ty::DATA, seq: 0, peer: 0 }.encode().to_vec();
            frame.extend_from_slice(&(raw_len as u32).to_be_bytes());
            let mut rx = [0u8; RX_SIZE];
            peer.write_all(&frame[..7]).unwrap();
            assert!(rx_round(&mut c, &mut rx).is_empty());
            peer.write_all(&frame[7..]).unwrap();
            c.begin_read(&mut rx);
            assert!(matches!(c.read_message(&mut rx), Err(e) if e.kind() == io::ErrorKind::InvalidData));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stack_rx_rebases_fd_marks_after_complete_frames_and_partial_tail() {
        let mut rx = [0u8; RX_SIZE];
        for cut in [1, 7, 11, 12, 23] {
            let (mut c, mut peer) = rx_pair();
            let prefix = rx_frame(1, 28);
            let tail = rx_frame(2, 64);
            peer.write_all(&prefix).unwrap();
            let (sent, mut witness) = UnixStream::pair().unwrap();
            assert_eq!(sys::sendmsg_two(peer.as_raw_fd(), &tail[..cut], &[], Some(sent.as_raw_fd())).unwrap(), cut);
            drop(sent);
            let got = rx_round(&mut c, &mut rx);
            assert_eq!(got.len(), 1);
            assert_frame(&got[0], &prefix);
            assert!(got[0].fd.is_none());
            assert_eq!(c.rx, tail[..cut]);
            assert_eq!(c.rx_fds.front().unwrap().0, cut);
            peer.write_all(&tail[cut..]).unwrap();
            let mut got = rx_round(&mut c, &mut rx);
            assert_eq!(got.len(), 1);
            assert_frame(&got[0], &tail);
            let mut received = UnixStream::from(got[0].fd.take().unwrap());
            witness.write_all(b"x").unwrap();
            received.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut byte = [0];
            received.read_exact(&mut byte).unwrap();
            assert_eq!(byte, *b"x");
            drop(received);
            witness.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            assert_eq!(witness.read(&mut byte).unwrap(), 0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stack_rx_fragmented_large_fd_and_disconnect_close_once() {
        let mut rx = [0u8; RX_SIZE];
        for cut in [7, 24, 4096] {
            for finish in [false, true] {
                let (mut c, mut peer) = rx_pair();
                let frame = rx_frame(8, 8192);
                let (sent, mut witness) = UnixStream::pair().unwrap();
                assert_eq!(sys::sendmsg_two(peer.as_raw_fd(), &frame[..cut], &[], Some(sent.as_raw_fd())).unwrap(), cut);
                drop(sent);
                assert!(rx_round(&mut c, &mut rx).is_empty());
                if finish { peer.write_all(&frame[cut..]).unwrap(); }
                drop(peer);
                let mut got = Vec::new();
                for _ in 0..5 { if !c.eof { got.extend(rx_round(&mut c, &mut rx)); } }
                assert!(c.eof);
                assert_eq!(got.len(), usize::from(finish));
                if finish {
                    assert_frame(&got[0], &frame);
                    assert!(got[0].fd.is_some());
                }
                drop(got);
                drop(c);
                witness.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                assert_eq!(witness.read(&mut [0]).unwrap(), 0);
            }
        }
    }

    #[test]
    fn combined_lookup_preserves_bytes_through_partial_and_queued_writes() {
        for size in [4, 28, 65536, MAX_MSGLEN] {
            let (sock, mut peer) = UnixStream::pair().unwrap();
            sock.set_nonblocking(true).unwrap();
            peer.set_nonblocking(true).unwrap();
            let mut c = Client::new(sock.into(), sys::Ucred::default(), String::new(), String::new());
            let mut expected = Vec::new();
            for (seq, len) in [(0xfffe, size), (0xffff, 28)] {
                let header = Header { ty: ty::DATA, seq, peer: 0x87654321 };
                let mut blob = vec![0x5a; len];
                blob[..4].copy_from_slice(&(len as u32).to_be_bytes());
                expected.extend_from_slice(&header.encode());
                expected.extend_from_slice(&blob);
                expected.extend_from_slice(&Header { ty: ty::STATUS, ..header }.encode());
                let mut status = BlobBuf::new();
                status.put_u32(attr::STATUS, 0);
                expected.extend_from_slice(status.as_bytes());
                c.send_lookup_reply(header, &blob);
                // Reusing the caller's storage must not corrupt queued output.
                blob.fill(0xa5);
            }
            if size == MAX_MSGLEN {
                assert!(!c.tx_empty(), "the fixture must force a partial write");
                assert!(c.txq_ofs > 0);
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut got = Vec::new();
            let mut buf = [0u8; 8192];
            while got.len() < expected.len() || !c.tx_empty() {
                assert!(Instant::now() < deadline, "queue did not drain");
                match peer.read(&mut buf) {
                    Ok(0) => panic!("unexpected EOF"),
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(e) if would_block(&e) => {}
                    Err(e) => panic!("read: {e}"),
                }
                assert!(c.flush());
            }
            assert_eq!(got, expected, "DATA followed by STATUS, then the next reply");
            assert_eq!(c.txq_len, 0);
            assert_eq!(c.txq_ofs, 0);
            assert!(matches!(peer.read(&mut buf), Err(e) if would_block(&e)));
        }
    }

    #[test]
    fn lookup_batch_keeps_frames_when_blocked_or_already_queued() {
        for mode in 0..3 {
            let (sock, mut peer) = UnixStream::pair().unwrap();
            sock.set_nonblocking(true).unwrap();
            peer.set_nonblocking(true).unwrap();
            let mut c = Client::new(sock.into(), sys::Ucred::default(), String::new(), String::new());
            let mut expected = Vec::new();
            let mut got = Vec::new();
            if mode == 1 {
                // Fill the kernel buffer without a user-space queue, then free
                // some space so the batch meets a partially writable socket.
                let fill = [0x77; 4096];
                loop {
                    match sys::sendmsg_two(c.fd(), &fill, &[], None) {
                        Ok(n) => expected.extend_from_slice(&fill[..n]),
                        Err(e) if would_block(&e) => break,
                        Err(e) => panic!("fill: {e}"),
                    }
                    assert!(expected.len() < 8 * MAX_MSGLEN);
                }
                let mut buf = [0u8; 8192];
                let n = peer.read(&mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
            } else if mode == 2 {
                let header = Header { ty: ty::DATA, seq: 9, peer: 0 };
                let mut blob = vec![0x33; MAX_MSGLEN];
                blob[..4].copy_from_slice(&(MAX_MSGLEN as u32).to_be_bytes());
                expected.extend_from_slice(&header.encode());
                expected.extend_from_slice(&blob);
                c.send_borrowed(header, &blob, None);
                assert!(!c.tx_empty());
            }
            let mut batch = Vec::new();
            for i in 0..128 {
                let header = Header { ty: ty::DATA, seq: 10, peer: 0 };
                let mut blob = BlobBuf::new();
                blob.put_string(attr::OBJPATH, &format!("object{i:04}"));
                blob.put_u32(attr::OBJID, i);
                batch.extend_from_slice(&header.encode());
                batch.extend_from_slice(blob.as_bytes());
            }
            let mut status = BlobBuf::new();
            status.put_u32(attr::STATUS, 0);
            batch.extend_from_slice(&Header { ty: ty::STATUS, seq: 10, peer: 0 }.encode());
            batch.extend_from_slice(status.as_bytes());
            expected.extend_from_slice(&batch);
            c.send_lookup_batch(&batch);
            batch.fill(0xaa);
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut buf = [0u8; 8192];
            while got.len() < expected.len() || !c.tx_empty() {
                assert!(Instant::now() < deadline, "batch queue did not drain");
                match peer.read(&mut buf) {
                    Ok(0) => panic!("unexpected EOF"),
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(e) if would_block(&e) => {}
                    Err(e) => panic!("read: {e}"),
                }
                assert!(c.flush());
            }
            assert_eq!(got, expected);
            assert_eq!((c.txq_len, c.txq_ofs), (0, 0));
        }
    }
}
