//! One bounded hosts-file read and parse step per owner turn. FIFO and device
//! readiness comes from the existing poll owner, without a reader thread.

use super::HostSource;
use crate::config::dns::DnsConfig;
use crate::hosts::{Hosts, HostsParser, ReadStats};
use owrt_ubus::sys::PollFd;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

pub struct HostsLoad {
    pub source: HostSource,
    /// Accepted names retain their source order and duplicates. Publication
    /// applies duplicate/PTR rules against the actual remaining host records.
    pub records: Vec<(Vec<u8>, IpAddr)>,
    pub ttl: u32,
    pub stats: ReadStats,
    /// (line number, bad-address count, bad-name count), for exact diagnostics.
    pub bad_lines: Vec<(usize, usize, usize)>,
}

impl HostsLoad {
    pub fn apply(self, hosts: &mut Hosts) -> usize {
        let removed = hosts.remove_uid(self.source.uid);
        for (name, address) in self.records {
            hosts.insert(name, address, self.ttl, self.source.uid);
        }
        removed
    }
}

pub struct HostsRead {
    file: File,
    wait_readiness: bool,
    config: DnsConfig,
    loaded: HostsLoad,
    parser: HostsParser,
}

impl HostsRead {
    pub fn open(source: HostSource, config: &DnsConfig, ttl: u32) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(0o4000 | 0o2000000)
            .open(&source.path)?;
        let wait_readiness = !file.metadata().is_ok_and(|metadata| metadata.is_file());
        Ok(Self {
            file,
            wait_readiness,
            config: config.clone(),
            loaded: HostsLoad {
                source,
                records: Vec::new(),
                ttl,
                stats: ReadStats::default(),
                bad_lines: Vec::new(),
            },
            parser: HostsParser::default(),
        })
    }

    pub fn append_poll_fds(&self, fds: &mut Vec<PollFd>) {
        if self.wait_readiness {
            fds.push(PollFd {
                fd: self.file.as_raw_fd(),
                events: 1,
                revents: 0,
            });
        }
    }

    pub fn runnable(&self) -> bool {
        !self.wait_readiness
    }

    fn consume(&mut self, bytes: &[u8]) {
        self.parser.feed(
            bytes,
            self.config.expand_hosts,
            |address| {
                self.config
                    .domain_for_address(address)
                    .ok()
                    .flatten()
                    .map(ToOwned::to_owned)
            },
            |name, address| self.loaded.records.push((name, address)),
            |line, address| {
                if self
                    .loaded
                    .bad_lines
                    .last()
                    .is_none_or(|entry| entry.0 != line)
                {
                    self.loaded.bad_lines.push((line, 0, 0));
                }
                let entry = self.loaded.bad_lines.last_mut().unwrap();
                if address {
                    entry.1 += 1;
                } else {
                    entry.2 += 1;
                }
            },
        );
        self.loaded.stats = self.parser.stats;
    }

    /// EOF and read errors complete the received prefix, including a partial
    /// last line, as read_hostsfile/gettok does. Only open errors are fatal to
    /// this source read; the daemon keeps serving its other sources.
    pub fn step(&mut self) -> io::Result<bool> {
        if self.wait_readiness {
            let mut fds = Vec::new();
            self.append_poll_fds(&mut fds);
            if owrt_ubus::sys::poll_fds(&mut fds, 0)? == 0 {
                return Ok(false);
            }
        }
        let mut bytes = [0; 4096];
        let length = match self.file.read(&mut bytes) {
            Ok(length) => length,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(false)
            }
            Err(_) => 0,
        };
        self.consume(&bytes[..length]);
        if length == 0 {
            self.consume(b"\n");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn finish(self) -> HostsLoad {
        self.loaded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn staged_reader_retains_duplicates_and_partial_final_line() {
        let directory =
            std::env::temp_dir().join(format!("dnsmasq-hostsdir-read-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("hosts");
        std::fs::write(&path, b"192.0.2.7 one.test one.test\n192.0.2.8 two.test").unwrap();
        let source = HostSource { path, uid: 100 };
        let mut reader = HostsRead::open(source, &DnsConfig::default(), 77).unwrap();
        assert!(!reader.step().unwrap());
        assert!(reader.step().unwrap());
        let loaded = reader.finish();
        assert_eq!(
            loaded
                .records
                .iter()
                .map(|record| record.0.as_slice())
                .collect::<Vec<_>>(),
            [b"one.test".as_slice(), b"one.test", b"two.test"]
        );
        assert_eq!(loaded.stats.accepted, 3);
        let mut hosts = Hosts::new();
        loaded.apply(&mut hosts);
        assert_eq!(hosts.len(), 2);
        assert!(hosts
            .entries()
            .iter()
            .all(|host| host.ttl == 77 && host.source == 100));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
