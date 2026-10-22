//! Options accepted by option.c even in the exact image's NO_AUTH build.
//! Authoritative answers are absent, but auth-server still affects interface
//! selection and disables local-service. Keep only that live state.

use super::{Directive, EncodedArg, Error};
use std::net::IpAddr;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Interface {
    Address(IpAddr),
    Name { name: Vec<u8>, ipv6: Option<bool> },
}

#[derive(Clone, Debug, Default)]
pub struct AuthConfig {
    pub server_present: bool,
    interfaces: Vec<Interface>,
}

impl AuthConfig {
    pub fn has_interfaces(&self) -> bool {
        !self.interfaces.is_empty()
    }

    pub fn selected(&self, address: IpAddr, name: &[u8]) -> bool {
        self.interfaces.iter().any(|interface| match interface {
            Interface::Address(selected) => *selected == address,
            Interface::Name {
                name: selected,
                ipv6,
            } => selected == name && ipv6.is_none_or(|ipv6| ipv6 == address.is_ipv6()),
        })
    }

    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        let argument = directive.argument.as_ref();
        match directive.name.as_slice() {
            b"auth-server" => {
                let (server, tail) = argument.ok_or(Error("missing parameter"))?.split_once(b',');
                self.server_present = !server.decoded().is_empty();
                if let Some(tail) = tail {
                    for interface in tail.split(b',') {
                        // option.c unhides this field before splitting its /4 or /6 suffix.
                        let decoded = interface.decoded();
                        let interface = if let Some(address) = address(&decoded) {
                            Interface::Address(address)
                        } else {
                            let (name, family) =
                                EncodedArg::command_line(&decoded).split_once(b'/');
                            let ipv6 = match family.as_ref().map(EncodedArg::encoded) {
                                None => None,
                                Some(b"4") => Some(false),
                                Some(b"6") => Some(true),
                                _ => return Err(Error("error")),
                            };
                            Interface::Name {
                                name: name.encoded().to_vec(),
                                ipv6,
                            }
                        };
                        self.interfaces.insert(0, interface);
                    }
                }
            }
            b"auth-ttl" => {
                // atoi_check accepts any all-decimal argument, including empty
                // and values which wrap musl's int. The result is only used by auth.c.
                if !argument
                    .ok_or(Error("missing parameter"))?
                    .decoded()
                    .iter()
                    .all(u8::is_ascii_digit)
                {
                    return Err(Error("error"));
                }
            }
            b"auth-peer" => {
                for peer in argument.ok_or(Error("missing parameter"))?.split(b',') {
                    if address(&peer.decoded()).is_none() {
                        return Err(Error("error"));
                    }
                }
            }
            // C accepts arbitrary strings here. auth-soa uses unchecked atoi
            // for its numeric fields; neither option has effects without AUTH.
            b"auth-soa" | b"auth-sec-servers" => {
                argument.ok_or(Error("missing parameter"))?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

fn address(bytes: &[u8]) -> Option<IpAddr> {
    std::str::from_utf8(bytes).ok()?.parse().ok()
}
