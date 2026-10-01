//! PRIVATE TCP cache pipe reference. Uses the kernel's byte backpressure;
//! there is no message-count queue and no parent acknowledgement cycle.
//! Begin clears prior pending state; each complete record is applied before
//! End commits. EOF leaves the applied prefix in the parent. This typed wire
//! is not C's native ABI; allocation and byte-saturation costs are unqualified.

#[cfg(all(test, target_os = "linux"))]
#[path = "tcp_partial_eof_tests.rs"]
mod partial_eof_tests;

use super::cache::{CacheTransaction, Kind, Record, TransferredRecord};
use super::wire::{decode_name, Name};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Instant;

const BEGIN: u8 = 1;
const END: u32 = u32::MAX;
const MIN_RECORD: usize = 21;

pub struct Sender(File);
pub struct Receiver {
    pipe: File,
    bytes: Vec<u8>,
    state: State,
}

#[derive(Clone, Copy)]
enum State {
    Operation,
    Length,
    Record(usize),
}

pub enum Received {
    Begin,
    Record(TransferredRecord),
    End,
    Pending,
    Eof,
}

pub fn pipe() -> io::Result<(Receiver, Sender)> {
    let (read, write) = owrt_ubus::sys::pipe()?;
    owrt_ubus::sys::set_nonblocking(read.as_raw_fd())?;
    owrt_ubus::sys::set_nonblocking(write.as_raw_fd())?;
    Ok((
        Receiver {
            pipe: read.into(),
            bytes: Vec::new(),
            state: State::Operation,
        },
        Sender(write.into()),
    ))
}

impl Sender {
    pub fn send(
        &mut self,
        transaction: CacheTransaction,
        deadline: Instant,
        stopped: fn() -> bool,
    ) -> io::Result<()> {
        let bytes = encode(transaction)?;
        let mut offset = 0;
        while offset < bytes.len() {
            if stopped() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            match self.0.write(&bytes[offset..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => offset += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let mut fd = [owrt_ubus::sys::PollFd {
                        fd: self.0.as_raw_fd(),
                        events: owrt_ubus::sys::POLLOUT,
                        revents: 0,
                    }];
                    owrt_ubus::sys::poll_fds(&mut fd, 10)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

impl Receiver {
    pub fn as_raw_fd(&self) -> RawFd {
        self.pipe.as_raw_fd()
    }
    pub fn ready(&self) -> io::Result<bool> {
        owrt_ubus::sys::wait_readable(self.pipe.as_raw_fd(), 0)
    }

    /// Return one complete semantic event without reading its successor.
    /// The caller pins one parent event/clock from Begin through End or EOF.
    pub fn receive(&mut self) -> io::Result<Received> {
        loop {
            let needed = match self.state {
                State::Operation => 1,
                State::Length => 4,
                State::Record(length) => length,
            };
            if self.bytes.len() == needed {
                match self.state {
                    State::Operation => {
                        if self.bytes[0] != BEGIN {
                            return Err(invalid());
                        }
                        self.bytes.clear();
                        self.state = State::Length;
                        return Ok(Received::Begin);
                    }
                    State::Length => {
                        let length = u32::from_be_bytes(self.bytes[..4].try_into().unwrap());
                        self.bytes.clear();
                        if length == END {
                            self.state = State::Operation;
                            return Ok(Received::End);
                        }
                        if (length as usize) < MIN_RECORD {
                            return Err(invalid());
                        }
                        self.state = State::Record(length as usize);
                        continue;
                    }
                    State::Record(_) => {
                        let record = decode_record(&self.bytes)?;
                        self.bytes.clear();
                        self.state = State::Length;
                        return Ok(Received::Record(record));
                    }
                }
            }
            let mut chunk = [0; 4096];
            let length = chunk.len().min(needed - self.bytes.len());
            match self.pipe.read(&mut chunk[..length]) {
                Ok(0) if matches!(self.state, State::Operation) && self.bytes.is_empty() => {
                    return Ok(Received::Eof)
                }
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(count) => self.bytes.extend_from_slice(&chunk[..count]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(Received::Pending)
                }
                Err(error) => return Err(error),
            }
        }
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "private TCP cache transaction")
}

fn encode(transaction: CacheTransaction) -> io::Result<Vec<u8>> {
    let mut bytes = vec![BEGIN];
    for transferred in transaction.records {
        let length_at = bytes.len();
        bytes.extend_from_slice(&[0; 4]);
        let record = transferred.record;
        let (tag, rrtype) = match record.kind {
            Kind::Ipv4 => (0, 0),
            Kind::Ipv6 => (1, 0),
            Kind::Generic(rrtype) => (2, rrtype),
            Kind::Cname => (3, 0),
            Kind::NxDomain => (4, 0),
        };
        bytes.push(tag);
        bytes.extend_from_slice(&rrtype.to_be_bytes());
        bytes.push(u8::from(record.negative));
        bytes.extend_from_slice(&transferred.expires.to_be_bytes());
        put_name(&mut bytes, Some(&record.name))?;
        bytes.extend_from_slice(
            &u32::try_from(record.data.len())
                .map_err(|_| invalid())?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&record.data);
        put_name(&mut bytes, transferred.authority_name.as_ref())?;
        let length = u32::try_from(bytes.len() - length_at - 4).map_err(|_| invalid())?;
        if length == END {
            return Err(invalid());
        }
        bytes[length_at..length_at + 4].copy_from_slice(&length.to_be_bytes());
    }
    bytes.extend_from_slice(&END.to_be_bytes());
    Ok(bytes)
}

fn put_name(bytes: &mut Vec<u8>, name: Option<&Name>) -> io::Result<()> {
    let data = name.map_or(&[][..], Name::as_wire);
    bytes.extend_from_slice(
        &u16::try_from(data.len())
            .map_err(|_| invalid())?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(data);
    Ok(())
}

fn take<'a>(bytes: &mut &'a [u8], length: usize) -> io::Result<&'a [u8]> {
    let (head, tail) = bytes.split_at_checked(length).ok_or_else(invalid)?;
    *bytes = tail;
    Ok(head)
}

fn get_name(bytes: &mut &[u8]) -> io::Result<Option<Name>> {
    let length = u16::from_be_bytes(take(bytes, 2)?.try_into().unwrap()) as usize;
    if length == 0 {
        return Ok(None);
    }
    let wire = take(bytes, length)?;
    let (name, end) = decode_name(wire, 0, 0).map_err(|_| invalid())?;
    if end != wire.len() || name.as_wire() != wire {
        return Err(invalid());
    }
    Ok(Some(name))
}

fn decode_record(mut bytes: &[u8]) -> io::Result<TransferredRecord> {
    let tag = take(&mut bytes, 1)?[0];
    let rrtype = u16::from_be_bytes(take(&mut bytes, 2)?.try_into().unwrap());
    let negative = match take(&mut bytes, 1)?[0] {
        0 => false,
        1 => true,
        _ => return Err(invalid()),
    };
    let kind = match (tag, rrtype) {
        (0, 0) => Kind::Ipv4,
        (1, 0) => Kind::Ipv6,
        (2, rrtype) => Kind::Generic(rrtype),
        (3, 0) => Kind::Cname,
        (4, 0) => Kind::NxDomain,
        _ => return Err(invalid()),
    };
    let expires = i64::from_be_bytes(take(&mut bytes, 8)?.try_into().unwrap());
    let name = get_name(&mut bytes)?.ok_or_else(invalid)?;
    let length = u32::from_be_bytes(take(&mut bytes, 4)?.try_into().unwrap()) as usize;
    let data = take(&mut bytes, length)?.to_vec();
    let authority_name = get_name(&mut bytes)?;
    if !bytes.is_empty() {
        return Err(invalid());
    }
    Ok(TransferredRecord {
        record: Record {
            name,
            kind,
            negative,
            data,
        },
        expires,
        authority_name,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::dns::cache::{Cache, CacheCounters, Policy};
    use std::time::Duration;

    fn transaction() -> CacheTransaction {
        let mut cache = Cache::new(10, Policy::default());
        cache.start_insert();
        cache
            .insert(
                Record {
                    name: Name::from_ascii("pipe.test").unwrap(),
                    kind: Kind::Ipv4,
                    negative: false,
                    data: vec![192, 0, 2, 7],
                },
                100,
                120,
            )
            .unwrap();
        cache
            .capture_commit_counted(&mut CacheCounters::default())
            .unwrap()
    }

    #[test]
    fn two_transactions_buffer_without_parent_ack_and_eof_follows_both() {
        let (mut receiver, mut sender) = pipe().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        sender.send(transaction(), deadline, || false).unwrap();
        sender.send(transaction(), deadline, || false).unwrap();
        drop(sender);
        let mut parent = Cache::new(10, Policy::default());
        let mut counters = CacheCounters::default();
        for expected in 1..=2 {
            assert!(receiver.ready().unwrap());
            assert!(matches!(receiver.receive().unwrap(), Received::Begin));
            let mut cursor = parent.start_import();
            let Received::Record(record) = receiver.receive().unwrap() else {
                panic!("record")
            };
            parent.import_record_counted(record, 110, &mut counters, &mut cursor, |_| None);
            assert_eq!(counters.inserted, expected - 1);
            assert!(matches!(receiver.receive().unwrap(), Received::End));
            assert!(parent.commit_counted(&mut counters));
            assert_eq!(counters.inserted, expected);
        }
        assert!(matches!(receiver.receive().unwrap(), Received::Eof));
        let ids = parent.lookup(
            &Name::from_ascii("pipe.test").unwrap(),
            &[Kind::Ipv4],
            110,
            false,
        );
        assert_eq!(parent.get(ids[0]).unwrap().expires, 220);
    }

    #[test]
    fn complete_prefix_remains_pending_after_partial_end_and_eof() {
        let (mut receiver, mut sender) = pipe().unwrap();
        let bytes = encode(transaction()).unwrap();
        sender.0.write_all(&bytes[..bytes.len() - 1]).unwrap();
        let mut parent = Cache::new(10, Policy::default());
        let mut counters = CacheCounters::default();
        assert!(matches!(receiver.receive().unwrap(), Received::Begin));
        let mut cursor = parent.start_import();
        let Received::Record(record) = receiver.receive().unwrap() else {
            panic!("record")
        };
        parent.import_record_counted(record, 110, &mut counters, &mut cursor, |_| None);
        assert_eq!(parent.insertion_test_state(), (1, false));
        assert_eq!(counters.inserted, 0);
        assert!(matches!(receiver.receive().unwrap(), Received::Pending));
        drop(sender);
        assert_eq!(
            receiver.receive().err().unwrap().kind(),
            io::ErrorKind::UnexpectedEof
        );
        drop(cursor);
        assert_eq!(parent.insertion_test_state(), (1, false));
        parent.start_insert();
        assert_eq!(parent.insertion_test_state(), (0, false));
    }

    #[test]
    fn invalid_record_length_and_compressed_ipc_name_fail_closed() {
        let (mut receiver, mut sender) = pipe().unwrap();
        sender.0.write_all(&[BEGIN, 0, 0, 0, 0]).unwrap();
        assert!(matches!(receiver.receive().unwrap(), Received::Begin));
        assert_eq!(
            receiver.receive().err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        let mut name = &[0, 4, 1, 0, 0xc0, 1][..];
        assert!(get_name(&mut name).is_err());
        let wire = encode(transaction()).unwrap();
        let length = u32::from_be_bytes(wire[1..5].try_into().unwrap()) as usize;
        let payload = &wire[5..5 + length];
        for end in 0..payload.len() {
            assert!(decode_record(&payload[..end]).is_err());
        }
        assert!(decode_record(payload).is_ok());
    }

    #[test]
    fn full_pipe_write_cancels_without_parent_event_or_ack() {
        let (_receiver, mut sender) = pipe().unwrap();
        let fill = [0; 4096];
        while sender.0.write(&fill).is_ok() {}
        assert_eq!(
            sender
                .send(
                    transaction(),
                    Instant::now() + Duration::from_secs(2),
                    || true
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
    }
}
