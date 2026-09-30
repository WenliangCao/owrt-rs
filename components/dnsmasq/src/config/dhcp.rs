//! Minimal typed DHCPv4 configuration for the local listener.
//!
//! The parser keeps the byte-oriented option boundary separate from the
//! state/runtime modules. Unsupported context selectors remain explicit
//! errors instead of silently producing a pool with different semantics.

use super::{validate_directive, Directive, Error};
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeConfig {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub router: Ipv4Addr,
    pub lease_time: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhcpConfig {
    pub ranges: Vec<RangeConfig>,
    pub authoritative: bool,
    pub bootp_dynamic: bool,
    pub sequential: bool,
    pub ignore_client_id: bool,
    pub lease_max: usize,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            ranges: Vec::new(),
            authoritative: false,
            bootp_dynamic: false,
            sequential: false,
            ignore_client_id: false,
            lease_max: 150,
        }
    }
}

fn integer(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(Error("bad DHCP integer"));
    }
    bytes.iter().try_fold(0u32, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(byte - b'0')))
            .filter(|value| *value <= i32::MAX as u32)
            .ok_or(Error("DHCP integer exceeds defined C int range"))
    })
}

fn lease_time(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.is_empty() {
        return Err(Error("empty DHCP lease time"));
    }
    let (digits, multiplier) = match bytes.last().copied() {
        Some(b's') => (&bytes[..bytes.len() - 1], 1),
        Some(b'm') => (&bytes[..bytes.len() - 1], 60),
        Some(b'h') => (&bytes[..bytes.len() - 1], 3600),
        Some(b'd') => (&bytes[..bytes.len() - 1], 86_400),
        Some(b'w') => (&bytes[..bytes.len() - 1], 604_800),
        _ => (bytes, 1),
    };
    integer(digits)?
        .checked_mul(multiplier)
        .ok_or(Error("DHCP lease time overflow"))
}

fn ip(bytes: &[u8]) -> Result<Ipv4Addr, Error> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(Error("bad DHCP IPv4 address"))
}

impl DhcpConfig {
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        validate_directive(directive)?;
        let argument = directive.argument.as_ref();
        match directive.name.as_slice() {
            b"dhcp-authoritative" => self.authoritative = true,
            b"bootp-dynamic" => self.bootp_dynamic = true,
            b"dhcp-sequential-ip" => self.sequential = true,
            b"dhcp-ignore-clid" => self.ignore_client_id = true,
            b"dhcp-lease-max" => {
                self.lease_max =
                    integer(&argument.ok_or(Error("missing parameter"))?.decoded())? as usize
            }
            b"dhcp-range" => {
                let argument = argument.ok_or(Error("missing parameter"))?;
                let parts = argument.split(b',');
                if parts.len() < 2 || parts.len() > 4 {
                    return Err(Error("bad DHCP range"));
                }
                let start = ip(&parts[0].decoded())?;
                let end = ip(&parts[1].decoded())?;
                if start > end {
                    return Err(Error("DHCP range start after end"));
                }
                let mut netmask = Ipv4Addr::new(255, 255, 255, 0);
                let mut router = Ipv4Addr::UNSPECIFIED;
                let mut duration = 43_200;
                for part in &parts[2..] {
                    let value = part.decoded();
                    if let Ok(address) = std::str::from_utf8(&value)
                        .ok()
                        .and_then(|value| value.parse().ok())
                        .ok_or(())
                    {
                        if netmask == Ipv4Addr::new(255, 255, 255, 0) {
                            netmask = address;
                        } else {
                            router = address;
                        }
                    } else {
                        duration = lease_time(&value)?;
                    }
                }
                self.ranges.push(RangeConfig {
                    start,
                    end,
                    netmask,
                    router,
                    lease_time: duration,
                });
            }
            b"dhcp-host"
            | b"dhcp-option"
            | b"dhcp-option-force"
            | b"dhcp-boot"
            | b"dhcp-vendorclass"
            | b"dhcp-userclass"
            | b"dhcp-match"
            | b"dhcp-name-match"
            | b"dhcp-ignore"
            | b"dhcp-hostsfile"
            | b"dhcp-hostsdir"
            | b"dhcp-optsfile"
            | b"dhcp-optsdir"
            | b"dhcp-script"
            | b"dhcp-scriptuser"
            | b"dhcp-fqdn"
            | b"dhcp-client-update"
            | b"dhcp-rapid-commit"
            | b"dhcp-reply-delay"
            | b"leasefile-ro"
            | b"dhcp-leasefile"
            | b"dhcp-lease" => {
                return Err(Error(
                    "DHCP option is parsed but runtime wiring is not complete",
                ));
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub fn validate_ready(&self) -> Result<(), Error> {
        if self.ranges.is_empty() {
            return Ok(());
        }
        if self
            .ranges
            .iter()
            .any(|range| range.router.is_unspecified())
        {
            return Ok(());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lex_line;

    #[test]
    fn parses_basic_ipv4_range_and_duration() {
        let directive = lex_line(b"dhcp-range=192.0.2.10,192.0.2.20,12h")
            .unwrap()
            .unwrap();
        let mut config = DhcpConfig::default();
        assert!(config.apply(&directive).unwrap());
        assert_eq!(config.ranges[0].lease_time, 43_200);
        assert_eq!(config.ranges[0].start, Ipv4Addr::new(192, 0, 2, 10));
    }
}
