//! One bounded hosts-file read and parse step per owner turn. FIFO and device
//! readiness comes from the existing poll owner, without a reader thread.

use super::HostSource;
use crate::config::dns::DnsConfig;
use crate::hosts::{Hosts, HostsParser, ReadStats};
use dnsmasq_platform::poll::PollFd;
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
    /// Cumulative accepted-record offsets at nonempty source-line ends.
    /// A staged bulk publication must rehash between lines, not between aliases.
    pub line_ends: Vec<usize>,
    pub ttl: u32,
    pub stats: ReadStats,
    /// (line number, bad-address count, bad-name count), for exact diagnostics.
    pub bad_lines: Vec<(usize, usize, usize)>,
    /// An incomplete staged source must not replace its last published view.
    pub allocation_failed: bool,
}

impl HostsLoad {
    pub fn apply(self, hosts: &mut Hosts) -> usize {
        if self.allocation_failed {
            return 0;
        }
        let Ok(removed) = hosts.try_remove_uid(self.source.uid) else {
            return 0;
        };
        for (name, address) in self.records {
            hosts.insert(name, address, self.ttl, self.source.uid);
        }
        removed
    }
}

pub struct HostsRead {
    file: File,
    wait_readiness: bool,
    loaded: HostsLoad,
    parser: HostsParser,
}

impl HostsRead {
    pub fn open(source: HostSource, ttl: u32) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(0o4000 | 0o2000000)
            .open(&source.path)?;
        let wait_readiness = !file.metadata().is_ok_and(|metadata| metadata.is_file());
        Ok(Self {
            file,
            wait_readiness,
            loaded: HostsLoad {
                source,
                records: Vec::new(),
                line_ends: Vec::new(),
                ttl,
                stats: ReadStats::default(),
                bad_lines: Vec::new(),
                allocation_failed: false,
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

    fn consume(&mut self, bytes: &[u8], config: &DnsConfig) {
        let mut allocation_failed = false;
        let mut diagnostics_failed = false;
        let mut line_metadata_failed = false;
        self.parser.feed_with_line_end(
            bytes,
            config.expand_hosts,
            |address| {
                config
                    .domain_for_address(address)
                    .ok()
                    .flatten()
                    .and_then(|name| crate::hosts::try_copy(name).ok())
            },
            |name, address| {
                if self.loaded.records.try_reserve(1).is_ok() {
                    self.loaded.records.push((name, address));
                } else {
                    allocation_failed = true;
                }
            },
            |line, address| {
                if self
                    .loaded
                    .bad_lines
                    .last()
                    .is_none_or(|entry| entry.0 != line)
                {
                    if self.loaded.bad_lines.try_reserve(1).is_err() {
                        diagnostics_failed = true;
                        return;
                    }
                    self.loaded.bad_lines.push((line, 0, 0));
                }
                let entry = self.loaded.bad_lines.last_mut().unwrap();
                if address {
                    entry.1 += 1;
                } else {
                    entry.2 += 1;
                }
            },
            |accepted| {
                if accepted == self.loaded.line_ends.last().copied().unwrap_or(0) {
                    return;
                }
                if self.loaded.line_ends.try_reserve(1).is_err() {
                    line_metadata_failed = true;
                } else {
                    self.loaded.line_ends.push(accepted);
                }
            },
        );
        self.loaded.stats = self.parser.stats;
        self.loaded.allocation_failed |= allocation_failed
            || diagnostics_failed
            || line_metadata_failed
            || self.parser.allocation_failed;
        if self.loaded.allocation_failed {
            // The owner polls and serves other work between chunks. Release
            // incomplete staging now, before that work needs memory too.
            self.loaded.records = Vec::new();
            self.loaded.bad_lines = Vec::new();
            self.loaded.line_ends = Vec::new();
        }
    }

    /// EOF and read errors complete the received prefix, including a partial
    /// last line, as read_hostsfile/gettok does. Only open errors are fatal to
    /// this source read; the daemon keeps serving its other sources.
    pub fn step(&mut self, config: &DnsConfig) -> io::Result<bool> {
        if self.wait_readiness {
            let mut fds = [PollFd {
                fd: self.file.as_raw_fd(),
                events: 1,
                revents: 0,
            }];
            if dnsmasq_platform::poll::poll_fds(&mut fds, 0)? == 0 {
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
        self.consume(&bytes[..length], config);
        if self.loaded.allocation_failed {
            return Ok(true);
        }
        if length == 0 {
            self.consume(b"\n", config);
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
        let mut reader = HostsRead::open(source, 77).unwrap();
        assert!(!reader.step(&DnsConfig::default()).unwrap());
        assert!(reader.step(&DnsConfig::default()).unwrap());
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
        assert_eq!(loaded.line_ends, [2, 3]);
        let mut hosts = Hosts::new();
        loaded.apply(&mut hosts);
        assert_eq!(hosts.len(), 2);
        assert!(hosts
            .entries()
            .iter()
            .all(|host| host.ttl == 77 && host.source == 100));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn staged_line_ends_survive_chunk_boundaries_and_count_expanded_duplicates() {
        use crate::config::lex_line;
        use std::io::Write;
        let directory =
            std::env::temp_dir().join(format!("dnsmasq-hostsdir-lines-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("hosts");
        let mut input = b"\n# ignored\nbad ignored\n192.0.2.1 ".to_vec();
        for i in 0..1002 {
            write!(input, "name{i}.test ").unwrap();
        }
        input.extend_from_slice(b"\n192.0.2.2 short short");
        std::fs::write(&path, &input).unwrap();
        let mut config = DnsConfig::default();
        config.expand_hosts = true;
        config
            .apply(&lex_line(b"domain=example.test").unwrap().unwrap())
            .unwrap();
        let mut reader = HostsRead::open(HostSource { path, uid: 100 }, 37).unwrap();
        assert!(!reader.step(&config).unwrap());
        assert!(!reader.loaded.records.is_empty());
        assert!(
            reader.loaded.line_ends.is_empty(),
            "a read chunk is not a source-line boundary"
        );
        while !reader.step(&config).unwrap() {}
        let loaded = reader.finish();
        assert!(!loaded.allocation_failed);
        assert_eq!(loaded.stats.bad_addresses, 1);
        assert_eq!(loaded.records.len(), 1006);
        assert_eq!(loaded.line_ends, [1002, 1006]);
        assert_eq!(
            loaded.records[1002..]
                .iter()
                .map(|(name, _)| name.as_slice())
                .collect::<Vec<_>>(),
            [
                b"short.example.test".as_slice(),
                b"short",
                b"short.example.test",
                b"short"
            ]
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
