use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use owrt_ubus::{sys,BlobBuf};
mod ring;
use ring::{Ring, Entry, normalize,SOURCE_SYSLOG};
fn now_ms()->u64 {0}
struct Dummy;
impl Dummy {fn notify(&self,_:u32,_:&str,_:&[u8])->Result<(),()> {Ok(())}}
fn entry_fields(b: &mut BlobBuf, entry: &Entry) {
    b.msg_string_bytes("msg", &entry.msg)
        .msg_u32("id", entry.id)
        .msg_u32("priority", entry.priority)
        .msg_u32("source", entry.source)
        .msg_u64("time", entry.time_ms);
}

/// One frame as logd writes it to a stream client: a head blob with the fields.
fn frame(entry: &Entry) -> Vec<u8> {
    let mut b = BlobBuf::new();
    entry_fields(&mut b, entry);
    b.as_bytes().to_vec()
}

struct Client {
    fd: OwnedFd,
    pending: Vec<u8>,
    oneshot: bool,
}

// The original ustream write queue is unbounded. Disconnect a lagging
// stream instead of letting it exhaust the daemon.
const MAX_STREAM_PENDING: usize = 1024 * 1024;
const MAX_TOTAL_PENDING: usize = 4 * 1024 * 1024;
const MAX_STREAM_CLIENTS: usize = 64;

impl Client {
    /// Write what we can; Ok(false) when the client must be dropped.
    fn flush(&mut self) -> bool {
        while !self.pending.is_empty() {
            // SAFETY: borrowing our own still-open descriptor to get at
            // File's write(). ManuallyDrop keeps the File from closing it --
            // self.fd remains the owner.
            let mut file =
                std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(self.fd.as_raw_fd()) });
            match file.write(&self.pending) {
                Ok(0) => return false,
                Ok(n) => {
                    self.pending.drain(..n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return true,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return false,
            }
        }
        !self.oneshot
    }
}

struct Daemon {ring:Ring,clients:Vec<Client>,has_subscribers:bool,conn:Dummy,objid:u32}
impl Daemon {
    fn add(&mut self, raw: &[u8], source: u32) {
        let Some((priority, msg)) = normalize(raw, source) else {
            return;
        };
        let entry = self.ring.add(msg, priority, source, now_ms());
        if self.clients.is_empty() && !self.has_subscribers {
            return;
        }
        let bytes = frame(&entry);
        if self.has_subscribers {
            let _ = self.conn.notify(self.objid, "message", &bytes[4..]);
        }
        let mut total: usize = self.clients.iter().map(|c| c.pending.len()).sum();
        self.clients.retain_mut(|client| {
            total -= client.pending.len();
            let size = client.pending.len() + bytes.len();
            if size > MAX_STREAM_PENDING || total + size > MAX_TOTAL_PENDING {
                return false;
            }
            client.pending.extend_from_slice(&bytes);
            let keep = client.flush();
            if keep { total += client.pending.len(); }
            keep
        });
    }

}
fn main() {
 let (a, aw)=UnixStream::pair().unwrap();
 let (mut b,bw)=UnixStream::pair().unwrap();
 aw.set_nonblocking(true).unwrap();bw.set_nonblocking(true).unwrap();
 let mut d=Daemon{ring:Ring::new(16384), clients:vec![Client{fd:aw.into(),pending:vec![1],oneshot:false},Client{fd:bw.into(),pending:vec![],oneshot:false}],has_subscribers:false,conn:Dummy,objid:0};
 let mut fds:Vec<_>=d.clients.iter().map(|c|sys::PollFd{fd:c.fd.as_raw_fd(),events:if c.pending.is_empty() {0} else {sys::POLLOUT},revents:0}).collect();
 drop(a);sys::poll_fds(&mut fds,0).unwrap();
 assert_ne!(fds[0].revents & sys::POLLHUP,0);assert_eq!(fds[1].revents,0);
 d.add(b"simultaneous log event",SOURCE_SYSLOG);
 assert_eq!(d.clients.len(),1);println!("after log dispatch: healthy B still present; stale A revents = {}",fds[0].revents);
 let client_base=0;let polled_clients=2;
            // Clients added while handling this iteration were not polled.
            let mut position = 0;
            d.clients.retain_mut(|client| {
                let current = position;
                position += 1;
                if current >= polled_clients {
                    return true;
                }
                let revents = fds[client_base + current].revents;
                if revents & (sys::POLLERR | sys::POLLHUP) != 0 {
                    return false;
                }
                if revents & sys::POLLOUT != 0 {
                    return client.flush();
                }
                true
            });

 assert_eq!(d.clients.len(),0);println!("after exact run_connected retention: healthy B incorrectly removed");
 let mut bytes=vec![]; b.read_to_end(&mut bytes).unwrap();println!("B received {} frame bytes and then EOF",bytes.len());
}
