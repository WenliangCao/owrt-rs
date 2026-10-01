//! PRIVATE TCP cache pipe reference. Uses the kernel's byte backpressure;
//! there is no message-count queue and no parent acknowledgement cycle.
//! This typed codec is not C's native ABI. Whole-transaction decoding and
//! allocation failure/partial EOF behavior remain explicitly unqualified.

use super::cache::{CacheTransaction, Kind, Record, TransferredRecord};
use super::wire::{decode_name, Name};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Instant;

pub struct Sender(File);
pub struct Receiver {
    pipe: File,
    bytes: Vec<u8>,
    end: usize,
}

pub enum Received {
    Pending,
    Transaction(CacheTransaction),
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
            end: 4,
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
    pub fn duplicate_reader(&self) -> io::Result<OwnedFd> {
        Ok(self.pipe.try_clone()?.into())
    }
    pub fn ready(&self) -> io::Result<bool> {
        owrt_ubus::sys::wait_readable(self.pipe.as_raw_fd(), 0)
    }

    /// Read exactly one transaction. Do not consume bytes from its successor.
    pub fn receive(&mut self) -> io::Result<Received> {
        loop {
            if self.bytes.len() == self.end {
                if self.end == 4 {
                    self.end = 4usize
                        .checked_add(
                            u32::from_be_bytes(self.bytes[..4].try_into().unwrap()) as usize
                        )
                        .ok_or_else(invalid)?;
                    if self.end == 4 {
                        return Err(invalid());
                    }
                } else {
                    let transaction = decode(&self.bytes[4..])?;
                    self.bytes.clear();
                    self.end = 4;
                    return Ok(Received::Transaction(transaction));
                }
            }
            let mut chunk = [0; 4096];
            let length = chunk.len().min(self.end - self.bytes.len());
            match self.pipe.read(&mut chunk[..length]) {
                Ok(0) if self.bytes.is_empty() => return Ok(Received::Eof),
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
    let mut bytes = vec![0; 4];
    bytes.extend_from_slice(
        &u32::try_from(transaction.records.len())
            .map_err(|_| invalid())?
            .to_be_bytes(),
    );
    for transferred in transaction.records {
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
    }
    let length = u32::try_from(bytes.len() - 4).map_err(|_| invalid())?;
    bytes[..4].copy_from_slice(&length.to_be_bytes());
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
    if end != wire.len() {
        return Err(invalid());
    }
    Ok(Some(name))
}

fn decode(mut bytes: &[u8]) -> io::Result<CacheTransaction> {
    let count = u32::from_be_bytes(take(&mut bytes, 4)?.try_into().unwrap());
    let mut records = Vec::new();
    for _ in 0..count {
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
        records.push(TransferredRecord {
            record: Record {
                name,
                kind,
                negative,
                data,
            },
            expires,
            authority_name,
        });
    }
    if !bytes.is_empty() {
        return Err(invalid());
    }
    Ok(CacheTransaction { records })
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
            let Received::Transaction(transaction) = receiver.receive().unwrap() else {
                panic!("transaction")
            };
            assert!(parent.import_counted(transaction, 110, &mut counters, |_| None));
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
    fn partial_transaction_does_not_import_or_hide_truncated_eof() {
        let (mut receiver, mut sender) = pipe().unwrap();
        let bytes = encode(transaction()).unwrap();
        sender.0.write_all(&bytes[..bytes.len() - 1]).unwrap();
        assert!(matches!(receiver.receive().unwrap(), Received::Pending));
        drop(sender);
        assert_eq!(
            receiver.receive().err().unwrap().kind(),
            io::ErrorKind::UnexpectedEof
        );
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
