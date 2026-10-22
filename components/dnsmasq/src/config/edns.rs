//! EDNS configuration from the exact image's option.c. Parsing is pure; the
//! caller supplies client identity and owns all neighbor I/O.
use super::{validate_directive, Directive, EncodedArg, Error};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MacModes {
    pub raw: bool,
    pub base64: bool,
    pub text: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Subnet {
    /// calc_subnet_opt narrows the C int to an unsigned byte before use.
    pub mask: u8,
    /// A fixed address may have a different family from its positional slot.
    pub address: Option<IpAddr>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Umbrella {
    pub organization: u32,
    pub asset: u32,
    pub device: Option<[u8; 8]>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EdnsConfig {
    pub mac: MacModes,
    pub strip_mac: bool,
    pub add_subnet: bool,
    pub subnet4: Option<Subnet>,
    pub subnet6: Option<Subnet>,
    pub strip_subnet: bool,
    pub cpe_id: Option<Vec<u8>>,
    pub umbrella: Option<Umbrella>,
}

fn mask(argument: &EncodedArg) -> Result<u8, Error> {
    let bytes = argument.decoded();
    if !bytes.iter().all(u8::is_ascii_digit) {
        return Err(Error("error"));
    }
    // musl atoi wraps to a C int; only its low byte reaches the wire.
    Ok(bytes.iter().fold(0u8, |value, byte| {
        value.wrapping_mul(10).wrapping_add(byte - b'0')
    }))
}

fn subnet(argument: &EncodedArg) -> Result<Subnet, Error> {
    let (head, tail) = argument.split_once(b'/');
    let Some(tail) = tail else {
        return Ok(Subnet {
            mask: mask(&head)?,
            address: None,
        });
    };
    // parse_mysockaddr does not unhide quoted address metacharacters.
    let address = std::str::from_utf8(head.encoded())
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(Error("bad address"))?;
    Ok(Subnet {
        mask: mask(&tail)?,
        address: Some(address),
    })
}

fn unsigned(bytes: &[u8]) -> Result<u32, Error> {
    // The image's musl strtoul sets EINVAL when there is no subject sequence.
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(Error("error"));
    }
    bytes.iter().try_fold(0u32, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(byte - b'0')))
            .ok_or(Error("error"))
    })
}

fn contains(bytes: &[u8], marker: &[u8]) -> bool {
    bytes.windows(marker.len()).any(|word| word == marker)
}

impl EdnsConfig {
    pub fn needs_mac(&self) -> bool {
        self.mac.raw || self.mac.base64 || self.mac.text
    }

    pub fn active(&self) -> bool {
        self.needs_mac()
            || self.strip_mac
            || self.add_subnet
            || self.strip_subnet
            || self.cpe_id.is_some()
            || self.umbrella.is_some()
    }

    /// Loader repeat/origin rules remain at their existing common boundary.
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        validate_directive(directive)?;
        let argument = directive.argument.as_ref();
        match directive.name.as_slice() {
            b"add-mac" => match argument.map(EncodedArg::decoded).as_deref() {
                None => self.mac.raw = true,
                Some(b"base64") => self.mac.base64 = true,
                Some(b"text") => self.mac.text = true,
                _ => return Err(Error("error")),
            },
            b"strip-mac" => self.strip_mac = true,
            b"strip-subnet" => self.strip_subnet = true,
            b"add-subnet" => {
                self.add_subnet = true;
                if let Some(argument) = argument {
                    let (v4, v6) = argument.split_once(b',');
                    self.subnet4 = Some(subnet(&v4)?);
                    if let Some(v6) = v6 {
                        self.subnet6 = Some(subnet(&v6)?);
                    }
                }
            }
            b"add-cpe-id" => {
                self.cpe_id = argument
                    .map(EncodedArg::decoded)
                    .filter(|value| !value.is_empty());
            }
            b"umbrella" => {
                let umbrella = self.umbrella.get_or_insert_with(Umbrella::default);
                if let Some(argument) = argument {
                    for field in argument.split(b',') {
                        let bytes = field.encoded();
                        // Retain C's strstr selector and fixed skip offset.
                        // A misplaced marker therefore still normally fails.
                        if contains(bytes, b"deviceid:") {
                            let value = bytes.get(9..).ok_or(Error("error"))?;
                            if value.len() != 16 || !value.iter().all(u8::is_ascii_hexdigit) {
                                return Err(Error("error"));
                            }
                            let mut device = [0; 8];
                            // The preceding ASCII-hex guard also proves UTF-8;
                            // each fixed two-byte chunk is a valid hexadecimal word.
                            for (out, word) in device.iter_mut().zip(value.as_chunks::<2>().0) {
                                *out = u8::from_str_radix(std::str::from_utf8(word).unwrap(), 16)
                                    .map_err(|_| Error("error"))?;
                            }
                            umbrella.device = Some(device);
                        } else if contains(bytes, b"orgid:") {
                            let value =
                                EncodedArg::command_line(bytes.get(6..).ok_or(Error("error"))?)
                                    .decoded();
                            umbrella.organization = unsigned(&value)?;
                        } else if contains(bytes, b"assetid:") {
                            let value =
                                EncodedArg::command_line(bytes.get(8..).ok_or(Error("error"))?)
                                    .decoded();
                            umbrella.asset = unsigned(&value)?;
                        } else {
                            return Err(Error("error"));
                        }
                    }
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lex_line;
    fn apply(config: &mut EdnsConfig, line: &str) -> Result<bool, Error> {
        config.apply(&lex_line(line.as_bytes())?.unwrap())
    }
    #[test]
    fn independent_mac_modes_and_strip_accumulate() {
        let mut config = EdnsConfig::default();
        for line in ["add-mac", "add-mac=base64", "add-mac=text", "strip-mac"] {
            assert!(apply(&mut config, line).unwrap());
        }
        assert_eq!(
            config.mac,
            MacModes {
                raw: true,
                base64: true,
                text: true
            }
        );
        assert!(config.strip_mac && config.needs_mac());
        assert_eq!(apply(&mut config, "add-mac="), Err(Error("error")));
    }
    #[test]
    fn positional_cross_family_masks_and_wrap_are_explicit() {
        let mut config = EdnsConfig::default();
        apply(
            &mut config,
            "add-subnet=2001:db8::ffff/65,198.51.100.255/25",
        )
        .unwrap();
        assert!(config.subnet4.unwrap().address.unwrap().is_ipv6());
        assert!(config.subnet6.unwrap().address.unwrap().is_ipv4());
        apply(&mut config, "add-subnet=4294967296,257").unwrap();
        assert_eq!(config.subnet4.unwrap().mask, 0);
        assert_eq!(config.subnet6.unwrap().mask, 1);
        assert_eq!(
            apply(&mut config, "add-subnet=24,56,32"),
            Err(Error("error"))
        );
    }
    #[test]
    fn cpe_bytes_and_umbrella_full_width_fields() {
        let mut config = EdnsConfig::default();
        apply(&mut config, "add-cpe-id=\"one,two:three four\"").unwrap();
        assert_eq!(config.cpe_id.as_deref(), Some(&b"one,two:three four"[..]));
        apply(&mut config, "add-cpe-id=").unwrap();
        assert_eq!(config.cpe_id, None);
        apply(
            &mut config,
            "umbrella=orgid:4294967295,deviceid:001122aabbccddff,assetid:0",
        )
        .unwrap();
        assert_eq!(config.umbrella.as_ref().unwrap().organization, u32::MAX);
        assert_eq!(
            config.umbrella.as_ref().unwrap().device,
            Some([0, 17, 34, 170, 187, 204, 221, 255])
        );
        assert_eq!(apply(&mut config, "umbrella=orgid:"), Err(Error("error")));
        assert_eq!(
            apply(&mut config, "umbrella=orgid:4294967296"),
            Err(Error("error"))
        );
    }
}
