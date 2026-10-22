//! Per-connection state: credentials, the incremental read state machine and
//! the bounded transmit queue.

use crate::sys;
use owrt_ubus::msg::{ty, Header, MAX_MSGLEN};
use std::borrow::Cow;
use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

/// Header (8) plus the 4-byte blob attribute header that precedes the payload.
pub const PREFIX_LEN: usize = Header::LEN + 4;
/// `UBUS_CLIENT_MAX_TXQ_LEN`.
pub const MAX_TXQ_LEN: i64 = MAX_MSGLEN as i64;
/// A slow reader may pipeline LOOKUPs, but cannot retain arbitrary input.
const MAX_PENDING_COMMANDS: usize = 64;
const MAX_PENDING_BYTES: usize = 2 * MAX_MSGLEN;

/// A message as received: header, the whole head blob (its own 4-byte header
/// included) and at most one descriptor that rode along with it.
pub struct InMsg<'a> {
    pub header: Header,
    pub blob: Cow<'a, [u8]>,
    pub fd: Option<OwnedFd>,
}

impl InMsg<'_> {
    /// Only a parked command must outlive the current shared receive buffer.
    /// Large frames already own their bytes and move them without a copy.
    pub fn into_owned(self) -> InMsg<'static> {
        InMsg {
            header: self.header,
            blob: Cow::Owned(self.blob.into_owned()),
            fd: self.fd,
        }
    }

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
        OutMsg {
            header: Header { ty, seq, peer },
            blob,
            fd: None,
        }
    }

    fn total(&self) -> usize {
        Header::LEN + self.blob.len()
    }
}

/// A LOOKUP that could not be finished because the transmit queue filled up.
/// `next` is an owned path lower bound, so deleting the next object cannot
/// invalidate the cursor or restart the walk at already-delivered objects.
pub struct PendingCmd {
    pub msg: InMsg<'static>,
    pub next: Option<Vec<u8>>,
}

/// Shared read-ahead space in the event loop. One recvmsg takes whatever the
/// socket holds up to this size and complete frames are dispatched straight
/// from it; a frame larger than this is completed in its own storage.
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
    /// Only an incomplete frame survives a readiness round. Complete input
    /// lives in the event loop's shared buffer during dispatch.
    rx: Vec<u8>,
    /// Unconsumed input in the shared buffer during a round: rx_start is the
    /// first byte of the next frame.
    rx_start: usize,
    rx_end: usize,
    /// A descriptor from the last recvmsg, with the buffer index one past the
    /// last byte that read delivered and the index where the read began. The
    /// kernel ends a read after the buffer carrying ancillary data, so the
    /// frame holding that last byte owns the descriptor.
    rx_fd: Option<(usize, usize, OwnedFd)>,
    /// The descriptor owned by the frame at rx_start.
    pending_fd: Option<OwnedFd>,
    /// The last recvmsg returned less than it was offered and carried no
    /// descriptor; yield instead of probing for EAGAIN. If input remains,
    /// level-triggered readiness schedules another round.
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
            rx_fd: None,
            pending_fd: None,
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

    /// Include the owned continuation path as well as the original frame.
    /// Recompute over at most 64 commands so popping/requeueing needs no
    /// separate accounting state that could drift on an error path.
    pub fn can_queue_command(&self, msg: &InMsg<'_>, next: Option<&[u8]>) -> bool {
        if self.cmd_queue.len() >= MAX_PENDING_COMMANDS {
            return false;
        }
        let queued: usize = self
            .cmd_queue
            .iter()
            .map(|cmd| Header::LEN + cmd.msg.blob.len() + cmd.next.as_ref().map_or(0, Vec::len))
            .sum();
        let needed = Header::LEN + msg.blob.len() + next.map_or(0, |path| path.len());
        needed <= MAX_PENDING_BYTES.saturating_sub(queued)
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
        self.enqueue(OutMsg {
            header,
            blob: blob.to_vec(),
            fd,
        });
        true
    }

    /// A DATA reply and its immediately following successful STATUS are known together.
    /// Write both immediately, keeping their separate framing and queue caps.
    /// Neither reply carries a descriptor. Monitor users keep the per-message
    /// path so each mirror remains at its original send boundary.
    pub fn send_data_status_reply(&mut self, header: Header, blob: &[u8]) {
        let status_header = Header {
            ty: ty::STATUS,
            ..header
        };
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
        let written =
            sys::sendmsg_three(self.fd(), [&header.encode(), blob, &status_frame]).unwrap_or(0);
        if written < first_len {
            self.txq_ofs = written;
            self.txq_len = -(written as i64);
            self.enqueue(OutMsg {
                header,
                blob: blob.to_vec(),
                fd: None,
            });
            // If DATA was silently dropped at the cap, STATUS can still go
            // directly, exactly as on the per-message path.
            self.send_borrowed(status_header, &status_blob, None);
        } else if written < first_len + status_frame.len() {
            self.txq_ofs = written - first_len;
            self.txq_len = -(self.txq_ofs as i64);
            self.enqueue(OutMsg {
                header: status_header,
                blob: status_blob.to_vec(),
                fd: None,
            });
        }
    }

    /// Submit a bounded sequence of complete descriptor-free frames.
    /// A short write is split back into the original per-frame queue entries,
    /// retaining their offsets and cap checks rather than queueing one giant
    /// synthetic message. `frames` is assembled by Server, never wire input.
    ///
    /// The first frame that a direct write did not finish establishes the
    /// queue offset exactly once. Every later frame is enqueued directly;
    /// calling `send_borrowed` for those frames would retry a direct write if
    /// the first frame was dropped by the queue cap, which could move later
    /// bytes ahead of it.
    pub fn send_borrowed_batch(&mut self, frames: &[u8]) {
        if frames.is_empty() {
            return;
        }
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
        let mut first_unsent = true;
        while pos < frames.len() {
            let header =
                Header::decode(frames[pos..pos + Header::LEN].try_into().unwrap()).unwrap();
            let start = pos + Header::LEN;
            let end = start + blob_raw_len(&frames[start..]);
            if written < end {
                let blob = &frames[start..end];
                if direct && first_unsent && written >= pos {
                    self.txq_ofs = written - pos;
                    self.txq_len = -(self.txq_ofs as i64);
                    first_unsent = false;
                } else {
                    // Either the client already had a queue, or an earlier
                    // frame in this direct batch is now the queue head.
                    // Do not retry direct I/O here: preserve stream order if
                    // the earlier frame was rejected by the cap.
                    first_unsent = false;
                }
                self.enqueue(OutMsg {
                    header,
                    blob: blob.to_vec(),
                    fd: None,
                });
            }
            pos = end;
        }
    }

    /// Compatibility name for the existing lookup batching call site.
    pub fn send_lookup_batch(&mut self, frames: &[u8]) {
        self.send_borrowed_batch(frames);
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
            let fd = if self.txq_ofs == 0 {
                msg.fd.as_ref().map(|f| f.as_raw_fd())
            } else {
                None
            };
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

    /// Begin one readiness round, restoring only its unfinished frame.
    pub fn begin_read(&mut self, rx: &mut [u8; RX_SIZE]) {
        self.rx_start = 0;
        self.rx_end = self.rx.len();
        self.rx_drained = false;
        if !self.rx.is_empty() {
            rx[..self.rx.len()].copy_from_slice(&self.rx);
            self.rx = Vec::new();
        }
    }

    /// End a readiness round before the shared buffer serves a different
    /// client. Only incomplete bytes allocate; idle connections retain none.
    pub fn end_read(&mut self, rx: &[u8; RX_SIZE]) {
        self.settle_fd();
        if self.rx_start < self.rx_end {
            self.rx = rx[self.rx_start..self.rx_end].to_vec();
        }
        self.rx_start = 0;
        self.rx_end = 0;
    }

    /// Give the last read's descriptor to the frame at rx_start, which holds
    /// its last byte once every complete frame before it has been cut.
    fn settle_fd(&mut self) {
        if let Some((_, began, fd)) = self.rx_fd.take() {
            self.adopt_fd(began, fd);
        }
    }

    /// The frame at rx_start receives a descriptor that arrived in a read
    /// beginning at `began`. C takes descriptors only while reading a prefix
    /// and keeps the first: a frame whose prefix was already complete before
    /// that read (C would be in its body read) or that has one closes it.
    fn adopt_fd(&mut self, began: usize, fd: OwnedFd) {
        if began < self.rx_start + PREFIX_LEN && self.pending_fd.is_none() {
            self.pending_fd = Some(fd);
        }
    }

    /// Read one complete message, if the socket has one. `Ok(None)` means the
    /// message is still incomplete or the socket is drained; `Err` means the
    /// connection must be closed (protocol violation or socket error).
    pub fn read_message<'a>(&mut self, rx: &'a mut [u8; RX_SIZE]) -> io::Result<Option<InMsg<'a>>> {
        loop {
            if let Some(large) = &mut self.large {
                // Like C's body read: never past this frame, and ancillary
                // data arriving here is discarded by the kernel.
                let n = match owrt_platform::unix::read_fd(
                    self.sock.as_raw_fd(),
                    &mut large.blob[large.got..],
                ) {
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
                return Ok(Some(InMsg {
                    header: done.header,
                    blob: Cow::Owned(done.blob),
                    fd: done.fd,
                }));
            }
            let s = self.rx_start;
            if self.rx_end - s >= PREFIX_LEN {
                let raw_len = blob_raw_len(&rx[s + Header::LEN..s + PREFIX_LEN]);
                if raw_len < 4 || pad4(raw_len) > MAX_MSGLEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "bad message length",
                    ));
                }
                // The matching C daemon ignores hdr.version.
                let header = Header {
                    ty: rx[s + 1],
                    seq: u16::from_be_bytes([rx[s + 2], rx[s + 3]]),
                    peer: u32::from_be_bytes([rx[s + 4], rx[s + 5], rx[s + 6], rx[s + 7]]),
                };
                let total = Header::LEN + raw_len;
                if total > RX_SIZE {
                    // Every buffered byte from s belongs to this frame.
                    self.settle_fd();
                    let have = self.rx_end - s - Header::LEN;
                    let mut blob = vec![0u8; raw_len];
                    blob[..have].copy_from_slice(&rx[s + Header::LEN..self.rx_end]);
                    self.rx_start = 0;
                    self.rx_end = 0;
                    self.large = Some(LargeFrame {
                        header,
                        blob,
                        got: have,
                        fd: self.pending_fd.take(),
                    });
                    continue;
                }
                let e = s + total;
                if e <= self.rx_end {
                    if self.rx_fd.as_ref().is_some_and(|(last, _, _)| *last <= e) {
                        self.settle_fd();
                    }
                    let fd = self.pending_fd.take();
                    if e == self.rx_end {
                        self.rx_start = 0;
                        self.rx_end = 0;
                    } else {
                        self.rx_start = e;
                    }
                    return Ok(Some(InMsg {
                        header,
                        blob: Cow::Borrowed(&rx[s + Header::LEN..e]),
                        fd,
                    }));
                }
            }
            if self.rx_drained {
                return Ok(None);
            }
            // Only the frame at rx_start is buffered now; it owns any
            // descriptor still unassigned. Move it to the front if its
            // remaining bytes would not fit.
            self.settle_fd();
            if self.rx_start == self.rx_end {
                self.rx_start = 0;
                self.rx_end = 0;
            } else if self.rx_start > 0 {
                rx.copy_within(self.rx_start..self.rx_end, 0);
                self.rx_end -= self.rx_start;
                self.rx_start = 0;
            }
            let began = self.rx_end;
            let (n, fd) = match sys::recvmsg_fd(self.fd(), &mut rx[began..], true) {
                Ok(v) => v,
                Err(e) if would_block(&e) => return Ok(None),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if n == 0 {
                self.eof = true;
                return Ok(None);
            }
            self.rx_end += n;
            self.rx_drained = n < RX_SIZE - began && fd.is_none();
            if let Some(fd) = fd {
                self.rx_fd = Some((self.rx_end, began, fd));
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

    fn rx_pair() -> (Client, UnixStream) {
        let (sock, peer) = UnixStream::pair().unwrap();
        sock.set_nonblocking(true).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        (
            Client::new(
                sock.into(),
                sys::Ucred::default(),
                String::new(),
                String::new(),
            ),
            peer,
        )
    }

    fn rx_frame(seq: u16, raw_len: usize) -> Vec<u8> {
        let mut bytes = Header {
            ty: ty::DATA,
            seq,
            peer: 0x12345678,
        }
        .encode()
        .to_vec();
        bytes.extend_from_slice(&(raw_len as u32).to_be_bytes());
        bytes.resize(Header::LEN + raw_len, seq as u8);
        bytes
    }

    // Drive exactly the production begin/next-until-None/end boundary, then
    // overwrite the shared storage to simulate a different ready client.
    fn rx_round(c: &mut Client, rx: &mut [u8; RX_SIZE]) -> Vec<InMsg<'static>> {
        c.begin_read(rx);
        let mut messages = Vec::new();
        while let Some(msg) = c.read_message(rx).unwrap() {
            messages.push(msg.into_owned());
        }
        c.end_read(rx);
        rx.fill(0xa5);
        messages
    }

    fn assert_frame(msg: &InMsg, frame: &[u8]) {
        assert_eq!(msg.header.encode(), frame[..Header::LEN]);
        assert_eq!(msg.blob.as_ref(), &frame[Header::LEN..]);
    }

    #[test]
    fn stack_rx_fragments_survive_other_clients_and_drop_idle_capacity() {
        let mut rx = [0u8; RX_SIZE];
        for len in [4, 64, 4088, 4089, 8192] {
            for cut in [1, 7, 8, 11, 12, 13, 27, 2048, 4096]
                .into_iter()
                .filter(|cut| *cut < len + Header::LEN)
            {
                let (mut c, mut peer) = rx_pair();
                let (mut other, mut other_peer) = rx_pair();
                let frame = rx_frame(17, len);
                peer.write_all(&frame[..cut]).unwrap();
                assert!(rx_round(&mut c, &mut rx).is_empty());
                let expected = if len + Header::LEN > RX_SIZE && cut >= PREFIX_LEN {
                    0
                } else {
                    cut
                };
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
        for lengths in [
            vec![4; 700],
            vec![4088, 4089, 4, 8192, 28],
            vec![4000, 192, 4],
        ] {
            let (mut c, mut peer) = rx_pair();
            let frames: Vec<_> = lengths
                .into_iter()
                .enumerate()
                .map(|(i, n)| rx_frame(i as u16, n))
                .collect();
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
            for (msg, frame) in got.iter().zip(&frames) {
                assert_frame(msg, frame);
            }
            assert_eq!(c.rx.capacity(), 0);
        }
    }

    #[test]
    fn stack_rx_complete_frame_clears_partial_state() {
        let (mut c, mut peer) = rx_pair();
        let mut rx = [0u8; RX_SIZE];
        for seq in 0..20 {
            let frame = rx_frame(seq, 16);
            peer.write_all(&frame).unwrap();
            c.begin_read(&mut rx);
            assert_frame(&c.read_message(&mut rx).unwrap().unwrap(), &frame);
            assert_eq!((c.rx_start, c.rx_end), (0, 0));
            assert!(c.pending_fd.is_none() && c.rx_fd.is_none());
            assert!(c.read_message(&mut rx).unwrap().is_none());
            c.end_read(&rx);
            assert_eq!(c.rx.capacity(), 0);
        }
    }

    #[test]
    fn stack_rx_rejects_bad_lengths_after_fragmented_prefix() {
        for raw_len in [0, 1, 3, MAX_MSGLEN + 1] {
            let (mut c, mut peer) = rx_pair();
            let mut frame = Header {
                ty: ty::DATA,
                seq: 0,
                peer: 0,
            }
            .encode()
            .to_vec();
            frame.extend_from_slice(&(raw_len as u32).to_be_bytes());
            let mut rx = [0u8; RX_SIZE];
            peer.write_all(&frame[..7]).unwrap();
            assert!(rx_round(&mut c, &mut rx).is_empty());
            peer.write_all(&frame[7..]).unwrap();
            c.begin_read(&mut rx);
            assert!(
                matches!(c.read_message(&mut rx), Err(e) if e.kind() == io::ErrorKind::InvalidData)
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fd_goes_to_the_frame_holding_the_last_byte_of_its_read() {
        // Separate sendmsgs (every libubus/ubusd/owrt-ubus sender) match C.
        // One sendmsg carrying two frames plus a descriptor is the documented
        // difference: C gives it to the first frame, read-ahead to the second.
        for fd_on_second in [false, true] {
            let (mut c, mut peer) = rx_pair();
            let first = rx_frame(101, 24);
            let second = rx_frame(102, 24);
            let (sent, mut witness) = UnixStream::pair().unwrap();
            if fd_on_second {
                peer.write_all(&first).unwrap();
                assert_eq!(
                    sys::sendmsg_two(peer.as_raw_fd(), &second, &[], Some(sent.as_raw_fd()))
                        .unwrap(),
                    second.len()
                );
            } else {
                assert_eq!(
                    sys::sendmsg_two(peer.as_raw_fd(), &first, &second, Some(sent.as_raw_fd()))
                        .unwrap(),
                    first.len() + second.len()
                );
            }
            drop(sent);
            let mut rx = [0; RX_SIZE];
            let mut got = rx_round(&mut c, &mut rx);
            assert_eq!(got.len(), 2);
            assert_frame(&got[0], &first);
            assert_frame(&got[1], &second);
            assert_eq!([got[0].fd.is_some(), got[1].fd.is_some()], [false, true]);
            let mut received = UnixStream::from(got[1].fd.take().unwrap());
            witness.write_all(b"x").unwrap();
            received
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut byte = [0];
            received.read_exact(&mut byte).unwrap();
            assert_eq!(byte, *b"x");
            drop(received);
            witness
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            assert_eq!(witness.read(&mut byte).unwrap(), 0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fd_attached_to_body_is_discarded_once_the_prefix_was_read() {
        // C reads a body with read(2), which drops ancillary data. A read
        // that begins after the frame's prefix therefore closes its
        // descriptor. If the prefix and a descriptor-carrying body arrive in
        // one read, read-ahead cannot see where that body began and delivers
        // the descriptor with the frame holding the read's last byte -- the
        // documented difference for descriptors not riding on a frame's
        // first sendmsg, which no libubus/ubusd/owrt-ubus sender produces.
        for prefix_read_first in [true, false] {
            for bundle_next in [false, true] {
                let (mut c, mut peer) = rx_pair();
                let first = rx_frame(101, 24);
                let second = rx_frame(102, 24);
                let mut rx = [0; RX_SIZE];
                let mut got = Vec::new();
                peer.write_all(&first[..PREFIX_LEN]).unwrap();
                if prefix_read_first {
                    got.extend(rx_round(&mut c, &mut rx));
                }
                let (sent, mut witness) = UnixStream::pair().unwrap();
                let tail = if bundle_next { second.as_slice() } else { &[] };
                assert_eq!(
                    sys::sendmsg_two(
                        peer.as_raw_fd(),
                        &first[PREFIX_LEN..],
                        tail,
                        Some(sent.as_raw_fd())
                    )
                    .unwrap(),
                    first.len() - PREFIX_LEN + tail.len()
                );
                drop(sent);
                if !bundle_next {
                    peer.write_all(&second).unwrap();
                }
                got.extend(rx_round(&mut c, &mut rx));
                assert_eq!(got.len(), 2);
                assert_frame(&got[0], &first);
                assert_frame(&got[1], &second);
                // Only a body-only read that ends inside the same frame is
                // known to be C's body read; otherwise the last-byte frame
                // owns the descriptor (the documented difference).
                let owner = match (prefix_read_first, bundle_next) {
                    (true, false) => None,
                    (_, true) => Some(1),
                    (false, false) => Some(0),
                };
                for (i, msg) in got.iter().enumerate() {
                    assert_eq!(msg.fd.is_some(), owner == Some(i));
                }
                drop(got);
                witness
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                assert_eq!(witness.read(&mut [0]).unwrap(), 0);
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fd_first_prefix_fragment_wins_and_later_descriptor_is_closed() {
        let (mut c, peer) = rx_pair();
        let frame = rx_frame(103, 24);
        let (first, mut first_witness) = UnixStream::pair().unwrap();
        let (second, mut second_witness) = UnixStream::pair().unwrap();
        assert_eq!(
            sys::sendmsg_two(peer.as_raw_fd(), &frame[..7], &[], Some(first.as_raw_fd())).unwrap(),
            7
        );
        assert_eq!(
            sys::sendmsg_two(
                peer.as_raw_fd(),
                &frame[7..11],
                &[],
                Some(second.as_raw_fd())
            )
            .unwrap(),
            4
        );
        assert_eq!(
            sys::sendmsg_two(peer.as_raw_fd(), &frame[11..], &[], None).unwrap(),
            frame.len() - 11
        );
        drop(first);
        drop(second);
        let mut rx = [0; RX_SIZE];
        let mut got = Vec::new();
        for _ in 0..4 {
            got.extend(rx_round(&mut c, &mut rx));
        }
        assert_eq!(got.len(), 1);
        assert_frame(&got[0], &frame);
        let mut received = UnixStream::from(got[0].fd.take().unwrap());
        first_witness.write_all(b"y").unwrap();
        received
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut byte = [0];
        received.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"y");
        drop(received);
        for witness in [&mut first_witness, &mut second_witness] {
            witness
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            assert_eq!(witness.read(&mut byte).unwrap(), 0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stack_rx_preserves_fd_after_complete_frames_and_partial_prefix() {
        let mut rx = [0u8; RX_SIZE];
        for cut in [1, 7, 11, 12, 23] {
            let (mut c, mut peer) = rx_pair();
            let prefix = rx_frame(1, 28);
            let tail = rx_frame(2, 64);
            peer.write_all(&prefix).unwrap();
            let (sent, mut witness) = UnixStream::pair().unwrap();
            assert_eq!(
                sys::sendmsg_two(peer.as_raw_fd(), &tail[..cut], &[], Some(sent.as_raw_fd()))
                    .unwrap(),
                cut
            );
            drop(sent);
            let got = rx_round(&mut c, &mut rx);
            assert_eq!(got.len(), 1);
            assert_frame(&got[0], &prefix);
            assert!(got[0].fd.is_none());
            assert_eq!(c.rx, tail[..cut]);
            assert!(c.pending_fd.is_some());
            peer.write_all(&tail[cut..]).unwrap();
            let mut got = rx_round(&mut c, &mut rx);
            assert_eq!(got.len(), 1);
            assert_frame(&got[0], &tail);
            let mut received = UnixStream::from(got[0].fd.take().unwrap());
            witness.write_all(b"x").unwrap();
            received
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut byte = [0];
            received.read_exact(&mut byte).unwrap();
            assert_eq!(byte, *b"x");
            drop(received);
            witness
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
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
                assert_eq!(
                    sys::sendmsg_two(peer.as_raw_fd(), &frame[..cut], &[], Some(sent.as_raw_fd()))
                        .unwrap(),
                    cut
                );
                drop(sent);
                assert!(rx_round(&mut c, &mut rx).is_empty());
                if finish {
                    peer.write_all(&frame[cut..]).unwrap();
                }
                drop(peer);
                let mut got = Vec::new();
                for _ in 0..5 {
                    if !c.eof {
                        got.extend(rx_round(&mut c, &mut rx));
                    }
                }
                assert!(c.eof);
                assert_eq!(got.len(), usize::from(finish));
                if finish {
                    assert_frame(&got[0], &frame);
                    assert!(got[0].fd.is_some());
                }
                drop(got);
                drop(c);
                witness
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                assert_eq!(witness.read(&mut [0]).unwrap(), 0);
            }
        }
    }

    #[test]
    fn combined_reply_keeps_each_frame_cap_when_already_queued() {
        for blob_len in [12, 20] {
            for room in [0, 19, 20, 27, 28, 39, 40, 47, 48] {
                let (mut combined, _combined_peer) = rx_pair();
                let (mut separate, _separate_peer) = rx_pair();
                for client in [&mut combined, &mut separate] {
                    client.enqueue(OutMsg::new(
                        ty::DATA,
                        10,
                        20,
                        vec![0; MAX_MSGLEN - room - Header::LEN],
                    ));
                }
                let header = Header {
                    ty: ty::DATA,
                    seq: 11,
                    peer: 21,
                };
                let mut blob = vec![0x5a; blob_len];
                blob[..4].copy_from_slice(&(blob_len as u32).to_be_bytes());
                combined.send_data_status_reply(header, &blob);
                separate.send_borrowed(header, &blob, None);
                separate.send_borrowed(
                    Header {
                        ty: ty::STATUS,
                        ..header
                    },
                    &[0, 0, 0, 12, 1, 0, 0, 8, 0, 0, 0, 0],
                    None,
                );
                assert_eq!(
                    (combined.txq_len, combined.txq_ofs, combined.tx.len()),
                    (separate.txq_len, separate.txq_ofs, separate.tx.len())
                );
                for (actual, wanted) in combined.tx.iter().zip(&separate.tx) {
                    assert_eq!(actual.header.encode(), wanted.header.encode());
                    assert_eq!(actual.blob, wanted.blob);
                    assert!(actual.fd.is_none() && wanted.fd.is_none());
                }
            }
        }
    }

    #[test]
    fn combined_lookup_preserves_bytes_through_partial_and_queued_writes() {
        for size in [4, 28, 65536, MAX_MSGLEN] {
            let (sock, mut peer) = UnixStream::pair().unwrap();
            sock.set_nonblocking(true).unwrap();
            peer.set_nonblocking(true).unwrap();
            let mut c = Client::new(
                sock.into(),
                sys::Ucred::default(),
                String::new(),
                String::new(),
            );
            let mut expected = Vec::new();
            for (seq, len) in [(0xfffe, size), (0xffff, 28)] {
                let header = Header {
                    ty: ty::DATA,
                    seq,
                    peer: 0x87654321,
                };
                let mut blob = vec![0x5a; len];
                blob[..4].copy_from_slice(&(len as u32).to_be_bytes());
                expected.extend_from_slice(&header.encode());
                expected.extend_from_slice(&blob);
                expected.extend_from_slice(
                    &Header {
                        ty: ty::STATUS,
                        ..header
                    }
                    .encode(),
                );
                let mut status = BlobBuf::new();
                status.put_u32(attr::STATUS, 0);
                expected.extend_from_slice(status.as_bytes());
                c.send_data_status_reply(header, &blob);
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
            assert_eq!(
                got, expected,
                "DATA followed by STATUS, then the next reply"
            );
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
            let mut c = Client::new(
                sock.into(),
                sys::Ucred::default(),
                String::new(),
                String::new(),
            );
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
                let header = Header {
                    ty: ty::DATA,
                    seq: 9,
                    peer: 0,
                };
                let mut blob = vec![0x33; MAX_MSGLEN];
                blob[..4].copy_from_slice(&(MAX_MSGLEN as u32).to_be_bytes());
                expected.extend_from_slice(&header.encode());
                expected.extend_from_slice(&blob);
                c.send_borrowed(header, &blob, None);
                assert!(!c.tx_empty());
            }
            let mut batch = Vec::new();
            for i in 0..128 {
                let header = Header {
                    ty: ty::DATA,
                    seq: 10,
                    peer: 0,
                };
                let mut blob = BlobBuf::new();
                blob.put_string(attr::OBJPATH, &format!("object{i:04}"));
                blob.put_u32(attr::OBJID, i);
                batch.extend_from_slice(&header.encode());
                batch.extend_from_slice(blob.as_bytes());
            }
            let mut status = BlobBuf::new();
            status.put_u32(attr::STATUS, 0);
            batch.extend_from_slice(
                &Header {
                    ty: ty::STATUS,
                    seq: 10,
                    peer: 0,
                }
                .encode(),
            );
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

    #[cfg(target_os = "linux")]
    fn set_send_buffer(fd: impl std::os::fd::AsFd, bytes: i32) -> i32 {
        rustix::net::sockopt::set_socket_send_buffer_size(&fd, bytes as usize).unwrap();
        rustix::net::sockopt::socket_send_buffer_size(fd).unwrap() as i32
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lookup_batch_preserves_frames_when_direct_write_stops_in_frame_two() {
        assert_direct_batch_short_write(1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lookup_batch_preserves_frames_when_direct_write_stops_in_frame_three() {
        assert_direct_batch_short_write(2);
    }

    #[cfg(target_os = "linux")]
    fn assert_direct_batch_short_write(complete_frames: usize) {
        let (sock, mut peer) = UnixStream::pair().unwrap();
        sock.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let actual_buf = set_send_buffer(&sock, 4096) as usize;
        assert!(
            actual_buf >= 1024,
            "unexpectedly small send buffer: {actual_buf}"
        );

        // Put one or two complete frames before the partial frame, followed
        // by another queued frame. Both cases must preserve the partial
        // frame's offset while the next frame is added to the queue.
        let first_total = (actual_buf / (3 * complete_frames)) & !3;
        let partial_total = (actual_buf - complete_frames * first_total + 128) & !3;
        let frame = |seq: u16, total: usize| {
            assert!(total >= Header::LEN + 4 && total.is_multiple_of(4));
            let blob_len = total - Header::LEN;
            let mut blob = vec![seq as u8; blob_len];
            blob[..4].copy_from_slice(&(blob_len as u32).to_be_bytes());
            let mut out = Header {
                ty: ty::DATA,
                seq,
                peer: 0xfeed_beef,
            }
            .encode()
            .to_vec();
            out.extend_from_slice(&blob);
            out
        };
        let mut batch = Vec::new();
        for i in 0..complete_frames {
            batch.extend_from_slice(&frame(101 + i as u16, first_total));
        }
        let partial_seq = 101 + complete_frames as u16;
        batch.extend_from_slice(&frame(partial_seq, partial_total));
        batch.extend_from_slice(&frame(partial_seq + 1, partial_total));
        let expected = batch.clone();

        let mut c = Client::new(
            sock.into(),
            sys::Ucred::default(),
            String::new(),
            String::new(),
        );
        c.send_borrowed_batch(&batch);
        assert_eq!(
            c.tx.len(),
            2,
            "the direct write must queue one partial frame and the next frame"
        );
        assert!(
            c.txq_ofs > 0 && c.txq_ofs < partial_total,
            "offset must point inside frame {}: {}",
            complete_frames + 1,
            c.txq_ofs
        );
        assert_eq!(c.tx.front().unwrap().header.seq, partial_seq);
        assert_eq!(c.tx.back().unwrap().header.seq, partial_seq + 1);
        // Queued bytes must be owned even if the batch scratch is reused.
        batch.fill(0xa5);

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut got = Vec::new();
        let mut buf = [0u8; 8192];
        while got.len() < expected.len() || !c.tx_empty() {
            assert!(Instant::now() < deadline, "cross-frame batch did not drain");
            match peer.read(&mut buf) {
                Ok(0) => panic!("unexpected EOF"),
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) if would_block(&e) => std::thread::yield_now(),
                Err(e) => panic!("read: {e}"),
            }
            assert!(c.flush());
        }
        assert_eq!(
            got, expected,
            "partial frame must precede the following queued frame"
        );
        assert_eq!((c.txq_len, c.txq_ofs), (0, 0));
    }
}
