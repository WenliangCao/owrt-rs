//! dhcp.c::dhcp_read_ethers: /etc/ethers augments the configured host list.
// Standalone configuration parsing is portable; staged file reloads are used
// by the Linux 64-bit DHCP daemon.
#![cfg_attr(
    not(all(target_os = "linux", target_pointer_width = "64")),
    allow(dead_code)
)]

use super::dhcp::{HardwareAddress, HostConfig, HostFiles, HostReload};
use std::io::{self, BufRead};
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Clone)]
pub struct Ethers {
    hosts: Vec<HostConfig>,
    origins: Vec<Origin>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Source {
    Main,
    HostFile,
    Ethers,
}

#[derive(Clone, Copy)]
struct Origin {
    source: Source,
    previous: Option<usize>,
    inferred_address: bool,
}

impl Ethers {
    pub fn new(hosts: &[HostConfig]) -> Self {
        Self {
            hosts: hosts.to_vec(),
            origins: vec![
                Origin {
                    source: Source::Main,
                    previous: None,
                    inferred_address: false,
                };
                hosts.len()
            ],
        }
    }
    pub fn hosts(&self) -> &[HostConfig] {
        &self.hosts
    }

    /// A full DHCP data reload drops every CONFIG_BANK row, including rows
    /// appended by a directory notification. Old ethers/inferred addresses
    /// remain visible to the parser's duplicate-address check at this stage.
    pub(crate) fn file_bank_base(&self, current: &[HostConfig]) -> Vec<HostConfig> {
        self.origins
            .iter()
            .enumerate()
            .filter_map(|(index, origin)| {
                (origin.source != Source::HostFile).then(|| current[index].clone())
            })
            .collect()
    }

    /// Install already parsed bank rows in their newest-first order. The live
    /// directory path appends without retiring any older file's rows.
    pub(crate) fn append_file_bank(&mut self, bank: Vec<HostConfig>, current: &[HostConfig]) {
        self.install_file_bank(bank, current, false);
    }

    /// Full reload replaces the file bank while retaining inline/ethers rows.
    pub(crate) fn replace_file_bank(&mut self, bank: Vec<HostConfig>, current: &[HostConfig]) {
        self.install_file_bank(bank, current, true);
    }

    fn install_file_bank(
        &mut self,
        mut bank: Vec<HostConfig>,
        current: &[HostConfig],
        replace: bool,
    ) {
        let mut origins = vec![
            Origin {
                source: Source::HostFile,
                previous: None,
                inferred_address: false,
            };
            bank.len()
        ];
        for (index, origin) in self.origins.iter().enumerate() {
            if replace && origin.source == Source::HostFile {
                continue;
            }
            bank.push(current[index].clone());
            origins.push(Origin {
                source: origin.source,
                previous: Some(index),
                inferred_address: origin.inferred_address
                    || (self.hosts[index].address.is_none() && current[index].address.is_some()),
            });
        }
        self.hosts = bank;
        self.origins = origins;
    }

    pub(crate) fn reload_host_files(
        &mut self,
        files: &mut HostFiles,
        current: &[HostConfig],
    ) -> HostReload {
        let base = self.file_bank_base(current);
        let report = files.reload(&base);
        if report.ready() {
            let file_count = report.hosts.len() - base.len();
            self.replace_file_bank(report.hosts[..file_count].to_vec(), current);
        }
        report
    }

    /// Clear CONFIG_ADDR_HOSTS only after ethers has matched the old addresses.
    pub(crate) fn clear_inferred_addresses(&mut self) {
        for (host, origin) in self.hosts.iter_mut().zip(&mut self.origins) {
            if origin.inferred_address {
                host.address = None;
                origin.inferred_address = false;
            }
        }
    }

    /// Surviving rows retain DECLINE state; fresh file/ethers rows do not.
    pub(crate) fn previous_indices(&self) -> impl Iterator<Item = Option<usize>> + '_ {
        self.origins.iter().map(|origin| origin.previous)
    }

    /// An open failure preserves the previous generation. Once opened, remove
    /// only entries created by ethers; mutations to explicit rules survive HUP.
    pub fn reload(&mut self, path: &Path) -> io::Result<Vec<usize>> {
        let file = std::fs::File::open(path)?;
        Ok(self.read(io::BufReader::new(file)))
    }

    fn read(&mut self, mut reader: impl BufRead) -> Vec<usize> {
        let mut index = 0;
        self.hosts.retain(|_| {
            let keep = self.origins[index].source != Source::Ethers;
            index += 1;
            keep
        });
        self.origins
            .retain(|origin| origin.source != Source::Ethers);
        let mut bad = Vec::new();
        let mut line = Vec::new();
        let mut number = 0;
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line).unwrap_or(line.len()) == 0 {
                break;
            }
            number += 1;
            if !self.read_line(&mut line) {
                bad.push(number);
            }
        }
        bad
    }

    fn read_line(&mut self, line: &mut Vec<u8>) -> bool {
        line.truncate(
            line.iter()
                .position(|byte| *byte == 0)
                .unwrap_or(line.len()),
        );
        while line.last().is_some_and(u8::is_ascii_whitespace) {
            line.pop();
        }
        line.is_empty() || matches!(line[0], b'#' | b'+') || self.add(line).is_some()
    }

    /// A nonblocking draft read. The old generation remains available to the
    /// owner until the returned reader completes. Open failure changes nothing.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub(crate) fn begin_read(&self, path: &Path) -> io::Result<EthersRead> {
        use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0o4000)
            .open(path)?;
        let wait_readiness = file.metadata().is_ok_and(|metadata| {
            metadata.file_type().is_fifo() || metadata.file_type().is_char_device()
        });
        let mut draft = self.clone();
        let mut index = 0;
        draft.hosts.retain(|_| {
            let keep = draft.origins[index].source != Source::Ethers;
            index += 1;
            keep
        });
        draft
            .origins
            .retain(|origin| origin.source != Source::Ethers);
        Ok(EthersRead {
            draft,
            file,
            wait_readiness,
            line: Vec::new(),
            number: 0,
            bad: Vec::new(),
            done: false,
        })
    }

    fn add(&mut self, line: &[u8]) -> Option<()> {
        let at = line.iter().position(u8::is_ascii_whitespace)?;
        let target = &line[at..];
        let target = &target[target.iter().position(|byte| !byte.is_ascii_whitespace())?..];
        let hardware = mac(&line[..at])?;
        let (address, name) = if target
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b'.')
        {
            (
                Some(std::str::from_utf8(target).ok()?.parse::<Ipv4Addr>().ok()?),
                None,
            )
        } else {
            let name = crate::hosts::canonicalise(target)?;
            let first = name.split(|byte| *byte == b'.').next()?;
            if !first.first().is_some_and(u8::is_ascii_alphanumeric)
                || !first
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return None;
            }
            (None, Some(name))
        };
        let named = self.hosts.iter().position(|host| {
            address.is_some_and(|address| host.address == Some(address))
                || name.as_ref().is_some_and(|name| {
                    host.hostname
                        .as_ref()
                        .is_some_and(|host| host.eq_ignore_ascii_case(name))
                })
        });
        if named.is_some_and(|index| self.origins[index].source == Source::Ethers) {
            return None;
        }
        let index = if let Some(index) = named {
            index
        } else {
            let by_mac = self.hosts.iter().position(|host| {
                host.hardware.len() == 1
                    && matches!(host.hardware[0].kind, 0 | 1)
                    && host.hardware[0].address == hardware
            });
            let index = by_mac.unwrap_or_else(|| {
                self.hosts.insert(0, HostConfig::default());
                self.origins.insert(
                    0,
                    Origin {
                        source: Source::Ethers,
                        previous: None,
                        inferred_address: false,
                    },
                );
                0
            });
            if let Some(address) = address {
                self.hosts[index].address = Some(address);
            }
            if let Some(name) = name {
                self.hosts[index].hostname = Some(name);
            }
            index
        };
        let host = &mut self.hosts[index];
        host.ignore_client_id = true;
        host.hardware = vec![HardwareAddress {
            wildcard_mask: 0,
            kind: 1,
            address: hardware,
        }];
        Some(())
    }
}

/// Owner-driven /etc/ethers reader. Completion transfers the full draft, with
/// inline/file provenance and previous-index mappings preserved.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) struct EthersRead {
    draft: Ethers,
    file: std::fs::File,
    wait_readiness: bool,
    line: Vec<u8>,
    number: usize,
    bad: Vec<usize>,
    done: bool,
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
impl EthersRead {
    pub(crate) fn append_poll_fds(&self, fds: &mut Vec<dnsmasq_platform::poll::PollFd>) {
        use std::os::fd::AsRawFd;
        if self.wait_readiness && !self.done {
            fds.push(dnsmasq_platform::poll::PollFd {
                fd: self.file.as_raw_fd(),
                events: 1,
                revents: 0,
            });
        }
    }

    pub(crate) fn runnable(&self) -> bool {
        !self.wait_readiness && !self.done
    }

    fn line(&mut self) {
        self.number += 1;
        if !self.draft.read_line(&mut self.line) {
            self.bad.push(self.number);
        }
        self.line.clear();
    }

    pub(crate) fn step(&mut self) -> bool {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        if self.done {
            return true;
        }
        if self.wait_readiness {
            let mut fds = [dnsmasq_platform::poll::PollFd {
                fd: self.file.as_raw_fd(),
                events: 1,
                revents: 0,
            }];
            match dnsmasq_platform::poll::poll_fds(&mut fds, 0) {
                Ok(0) => return false,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => return false,
                Err(_) => {
                    if !self.line.is_empty() {
                        self.line();
                    }
                    self.done = true;
                    return true;
                }
                Ok(_) => {}
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
                return false
            }
            Err(_) => 0,
        };
        for byte in &bytes[..length] {
            if *byte == b'\n' {
                self.line();
            } else {
                self.line.push(*byte);
            }
        }
        if length == 0 {
            if !self.line.is_empty() {
                self.line();
            }
            self.done = true;
        }
        self.done
    }

    pub(crate) fn into_result(self) -> (Ethers, Vec<usize>) {
        assert!(self.done, "ethers draft must complete before publication");
        (self.draft, self.bad)
    }
}

// util.c::parse_hex accepts compact and odd-sized groups, stopping at six
// output octets. Validate the current entire group before taking that prefix.
fn mac(input: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(6);
    for group in input.split(|byte| matches!(byte, b':' | b'-' | b' ')) {
        if output.len() == 6 {
            break;
        }
        if !group.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        // Entire group was validated as ASCII hex. Chunks contain one or
        // two digits, bounding the fold to u8 and proving to_digit succeeds.
        for pair in group.chunks(2).take(6 - output.len()) {
            output.push(pair.iter().fold(0u8, |value, byte| {
                value * 16 + (*byte as char).to_digit(16).unwrap() as u8
            }));
        }
    }
    (output.len() == 6).then_some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_append_keeps_old_file_rows_until_full_bank_reload() {
        let host = |last| HostConfig {
            address: Some(Ipv4Addr::new(192, 0, 2, last)),
            ..Default::default()
        };
        let mut ethers = Ethers::new(&[host(10)]);
        assert!(ethers
            .read(&b"02:00:00:00:00:02 192.0.2.11\n"[..])
            .is_empty());
        let current = ethers.hosts().to_vec();
        ethers.replace_file_bank(vec![host(12)], &current);
        let current = ethers.hosts().to_vec();
        ethers.append_file_bank(vec![host(13)], &current);
        assert_eq!(
            ethers
                .hosts()
                .iter()
                .map(|h| h.address.unwrap().octets()[3])
                .collect::<Vec<_>>(),
            [13, 12, 11, 10]
        );
        // Old bank policies keep their DECLINE identity on a live append.
        assert_eq!(
            ethers.previous_indices().collect::<Vec<_>>(),
            [None, Some(0), Some(1), Some(2)]
        );
        let current = ethers.hosts().to_vec();
        assert_eq!(ethers.file_bank_base(&current), current[2..]);
        ethers.replace_file_bank(vec![host(14)], &current);
        assert_eq!(
            ethers
                .hosts()
                .iter()
                .map(|h| h.address.unwrap().octets()[3])
                .collect::<Vec<_>>(),
            [14, 11, 10]
        );
        // A full reload retires file rows, but preserves ethers/main policies.
        assert_eq!(
            ethers.previous_indices().collect::<Vec<_>>(),
            [None, Some(2), Some(3)]
        );
    }

    #[test]
    fn inferred_address_provenance_survives_append_and_is_consumed_on_refresh() {
        let configured = HostConfig {
            hostname: Some(b"inferred".to_vec()),
            hardware: vec![HardwareAddress {
                kind: 1,
                address: vec![0, 1, 2, 3, 4, 5],
                wildcard_mask: 0,
            }],
            ..Default::default()
        };
        let mut ethers = Ethers::new(&[configured]);
        let mut current = ethers.hosts().to_vec();
        current[0].address = Some(Ipv4Addr::new(192, 0, 2, 10));
        ethers.append_file_bank(Vec::new(), &current);
        ethers.append_file_bank(Vec::new(), &current);
        ethers.clear_inferred_addresses();
        assert!(ethers.hosts()[0].address.is_none());
        // dhcp_update_configs clears CONFIG_ADDR_HOSTS too. A later explicit
        // ethers mutation must not inherit the retired inference marker.
        assert!(ethers
            .read(&b"00:01:02:03:04:05 192.0.2.20\n"[..])
            .is_empty());
        ethers.clear_inferred_addresses();
        assert_eq!(
            ethers.hosts()[0].address,
            Some(Ipv4Addr::new(192, 0, 2, 20))
        );
    }

    #[test]
    fn ordered_duplicates_merge_by_address_then_mac_and_survive_reload() {
        let explicit = HostConfig {
            address: Some("192.0.2.10".parse().unwrap()),
            hostname: Some(b"fixed".to_vec()),
            ..Default::default()
        };
        let mut ethers = Ethers::new(&[explicit]);
        assert_eq!(ethers.read(&b"00:11:22:33:44:55 192.0.2.10\n00:11:22:33:44:66 mixed.Test\n00:11:22:33:44:77 MIXED.test\n"[..]), [3]);
        assert_eq!(ethers.hosts.len(), 2);
        assert_eq!(
            ethers.hosts[0].hostname.as_deref(),
            Some(b"mixed.Test".as_slice())
        );
        assert_eq!(
            ethers.hosts[1].hostname.as_deref(),
            Some(b"fixed".as_slice())
        );
        assert!(ethers.hosts[1].ignore_client_id);
        ethers.read(&b"00:11:22:33:44:55 renamed\n"[..]);
        assert_eq!(ethers.hosts.len(), 1);
        assert_eq!(
            ethers.hosts[0].hostname.as_deref(),
            Some(b"renamed".as_slice())
        );
        assert_eq!(
            ethers.hosts[0].address.unwrap(),
            "192.0.2.10".parse::<Ipv4Addr>().unwrap()
        );
        ethers.read(&b""[..]);
        assert_eq!(
            ethers.hosts[0].hostname.as_deref(),
            Some(b"renamed".as_slice())
        );
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn staged_ethers_read_keeps_previous_generation_until_complete() {
        let path = std::env::temp_dir().join(format!(
            "ethers-stage-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut original = Ethers::new(&[]);
        original.read(&b"00:11:22:33:44:55 old\n"[..]);
        let mut data = vec![b'#'; 5000];
        data.extend_from_slice(b"\nbad-row\n00:11:22:33:44:66 new");
        std::fs::write(&path, data).unwrap();
        let mut staged = original.begin_read(&path).unwrap();
        assert!(!staged.step());
        assert_eq!(original.hosts()[0].hostname.as_deref(), Some(&b"old"[..]));
        assert!(!staged.step());
        assert!(staged.step());
        let (published, bad) = staged.into_result();
        assert_eq!(bad, [2]);
        assert_eq!(published.hosts().len(), 1);
        assert_eq!(published.hosts()[0].hostname.as_deref(), Some(&b"new"[..]));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn malformed_rows_and_missing_file_preserve_the_c_boundaries() {
        let mut ethers = Ethers::new(&[]);
        assert_eq!(ethers.read(&b"#comment\n+nis\n 00:11:22:33:44:55 host\n00:11:22:33:44:55 999.2.3.4\n00:11:22:33:44:55 bad name\n001122334455 good.\n"[..]), [3, 4, 5]);
        assert_eq!(
            ethers.hosts[0].hostname.as_deref(),
            Some(b"good".as_slice())
        );
        assert!(ethers
            .reload(Path::new("/no/such/dnsmasq-ethers-fixture"))
            .is_err());
        assert_eq!(ethers.hosts.len(), 1);
        assert_eq!(mac(b"0:1:2:3:4:5"), Some(vec![0, 1, 2, 3, 4, 5]));
    }
}
