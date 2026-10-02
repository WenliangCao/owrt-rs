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

    /// C drops CONFIG_BANK rows before parsing host files, while previous
    /// ethers rows and hosts-inferred addresses still participate in conflicts.
    pub(crate) fn reload_host_files(
        &mut self,
        files: &mut HostFiles,
        current: &[HostConfig],
    ) -> HostReload {
        let retained: Vec<_> = self
            .origins
            .iter()
            .enumerate()
            .filter_map(|(index, origin)| (origin.source != Source::HostFile).then_some(index))
            .collect();
        let base: Vec<_> = retained
            .iter()
            .map(|&index| current[index].clone())
            .collect();
        let report = files.reload(&base);
        if report.ready() {
            let file_count = report.hosts.len() - base.len();
            let mut origins = vec![
                Origin {
                    source: Source::HostFile,
                    previous: None,
                    inferred_address: false,
                };
                file_count
            ];
            origins.extend(retained.iter().map(|&index| Origin {
                source: self.origins[index].source,
                previous: Some(index),
                inferred_address: self.hosts[index].address.is_none()
                    && current[index].address.is_some(),
            }));
            self.hosts = report.hosts.clone();
            self.origins = origins;
        }
        report
    }

    /// Clear CONFIG_ADDR_HOSTS only after ethers has matched the old addresses.
    pub(crate) fn clear_inferred_addresses(&mut self) {
        for (host, origin) in self.hosts.iter_mut().zip(&self.origins) {
            if origin.inferred_address {
                host.address = None;
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
            line.truncate(
                line.iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(line.len()),
            );
            while line.last().is_some_and(u8::is_ascii_whitespace) {
                line.pop();
            }
            if line.is_empty() || matches!(line[0], b'#' | b'+') {
                continue;
            }
            if self.add(&line).is_none() {
                bad.push(number);
            }
        }
        bad
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
            kind: 1,
            address: hardware,
        }];
        Some(())
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
