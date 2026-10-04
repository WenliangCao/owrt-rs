//! DHCPv4 relay and port grammar from option.c:4644-4658,4731-4807.

use super::{EncodedArg, Error};
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayRule {
    pub local: Ipv4Addr,
    pub server: Ipv4Addr,
    /// Ordinary mode: allowed reply interface. Split mode: uplink interface.
    pub interface: Option<Vec<u8>>,
    pub port: u16,
    pub split: bool,
    /// Used only for a split rule with a literal third address.
    pub uplink: Ipv4Addr,
}

impl RelayRule {
    pub fn parse(argument: &EncodedArg, split: bool) -> Result<Self, Error> {
        let bad = Error("Bad dhcp-relay");
        let (local, rest) = argument.split_once(b',');
        let (server, third) = rest.ok_or_else(|| bad.clone())?.split_once(b',');
        if split
            && third
                .as_ref()
                .is_none_or(|value| value.encoded().contains(&b'*'))
        {
            return Err(bad);
        }
        // C inet_pton operates before unhide_metas for relay addresses.
        let local = address(local.encoded()).ok_or_else(|| bad.clone())?;
        let (server, port) = server.split_once(b'#');
        let port = port
            .as_ref()
            .and_then(|value| number(&value.decoded()))
            .unwrap_or(67);
        let (server, third) = match address(server.encoded()) {
            Some(server) => (server, third),
            None if third.is_none() && !server.encoded().contains(&b'*') => {
                (Ipv4Addr::UNSPECIFIED, Some(server))
            }
            None => return Err(bad),
        };
        let mut uplink = Ipv4Addr::UNSPECIFIED;
        let interface = match third {
            Some(value) if split && address(value.encoded()).is_some() => {
                uplink = address(value.encoded()).unwrap();
                None
            }
            Some(value) => {
                let bytes = value.decoded();
                (!bytes.is_empty()).then_some(bytes)
            }
            None => None,
        };
        Ok(Self {
            local,
            server,
            interface,
            port,
            split,
            uplink,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DhcpPorts {
    pub server: u16,
    pub client: u16,
}

impl Default for DhcpPorts {
    fn default() -> Self {
        Self {
            server: 67,
            client: 68,
        }
    }
}

impl DhcpPorts {
    pub fn parse(argument: Option<&EncodedArg>) -> Result<Self, Error> {
        let Some(argument) = argument else {
            return Ok(Self {
                server: 1067,
                client: 1068,
            });
        };
        let (server, client) = argument.split_once(b',');
        let bad = Error("invalid port number");
        let server = number(&server.decoded()).ok_or_else(|| bad.clone())?;
        let client = match client {
            Some(value) => number(&value.decoded()).ok_or(bad)?,
            // C keeps an int until htons, so 65535+1 becomes port zero.
            None => server.wrapping_add(1),
        };
        Ok(Self { server, client })
    }
}

fn address(bytes: &[u8]) -> Option<Ipv4Addr> {
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

fn number(bytes: &[u8]) -> Option<u16> {
    // numeric_check accepts an empty string, and atoi("") is zero.
    bytes.iter().try_fold(0u16, |value, digit| {
        digit
            .is_ascii_digit()
            .then_some(())
            .and_then(|()| value.checked_mul(10))
            .and_then(|value| value.checked_add(u16::from(*digit - b'0')))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(value: &[u8], split: bool) -> Result<RelayRule, Error> {
        RelayRule::parse(&EncodedArg::command_line(value), split)
    }

    #[test]
    fn ordinary_forms_and_c_port_fallback() {
        let rule = relay(b"192.0.2.1,198.51.100.1#1067,wan*", false).unwrap();
        assert_eq!(rule.port, 1067);
        assert_eq!(rule.interface.as_deref(), Some(&b"wan*"[..]));
        for port in ["bad", "-1", "65536"] {
            assert_eq!(
                relay(format!("192.0.2.1,198.51.100.1#{port}").as_bytes(), false)
                    .unwrap()
                    .port,
                67
            );
        }
        assert_eq!(relay(b"192.0.2.1,198.51.100.1#", false).unwrap().port, 0);
        let broadcast = relay(b"192.0.2.1,wan0", false).unwrap();
        assert!(broadcast.server.is_unspecified());
        assert_eq!(broadcast.interface.as_deref(), Some(&b"wan0"[..]));
        for invalid in [
            b"192.0.2.1,wan*".as_slice(),
            b"192.0.2.1,wan0,extra",
            b"::1,::2",
            b"192.0.2.1",
        ] {
            assert!(relay(invalid, false).is_err());
        }
    }

    #[test]
    fn split_requires_exact_interface_or_literal_uplink() {
        let rule = relay(b"192.0.2.1,198.51.100.2,198.51.100.1", true).unwrap();
        assert_eq!(rule.uplink, Ipv4Addr::new(198, 51, 100, 1));
        assert!(rule.interface.is_none());
        assert!(relay(b"192.0.2.1,198.51.100.2,wan0", true).is_ok());
        assert!(relay(b"192.0.2.1,198.51.100.2,wan*", true).is_err());
        assert!(relay(b"192.0.2.1,198.51.100.2", true).is_err());
    }

    #[test]
    fn alternate_ports_keep_c_empty_and_overflow_boundaries() {
        assert_eq!(
            DhcpPorts::parse(None).unwrap(),
            DhcpPorts {
                server: 1067,
                client: 1068
            }
        );
        for (input, expected) in [
            ("", (0, 1)),
            ("65535", (65535, 0)),
            ("1067,1069", (1067, 1069)),
            (",", (0, 0)),
        ] {
            let ports =
                DhcpPorts::parse(Some(&EncodedArg::command_line(input.as_bytes()))).unwrap();
            assert_eq!((ports.server, ports.client), expected);
        }
        for input in ["-1", "65536", "1,2,3", "x", "1,-2"] {
            assert!(DhcpPorts::parse(Some(&EncodedArg::command_line(input.as_bytes()))).is_err());
        }
    }
}
