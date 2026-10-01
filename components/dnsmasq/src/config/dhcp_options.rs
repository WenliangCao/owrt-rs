//! Ordinary untagged option subset from option.c parse_dhcp_opt.
//! Unsupported option codes/encodings remain errors at the configuration gate.

use super::{integer, ip};
use crate::config::{EncodedArg, Error};
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OptionValue {
    Empty,
    Addresses(Vec<Ipv4Addr>),
    String(Vec<u8>),
    Time(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhcpOption {
    pub code: u8,
    pub force: bool,
    pub value: OptionValue,
}

impl DhcpOption {
    pub fn parse(argument: &EncodedArg, force: bool) -> Result<Self, Error> {
        let (selector, value) = argument.split_once(b',');
        let code = match selector.encoded() {
            b"option:netmask" => 1,
            b"option:router" => 3,
            b"option:dns-server" => 6,
            b"option:domain-name" => 15,
            b"option:T1" => 58,
            b"option:T2" => 59,
            b"option:tftp-server" => 66,
            b"option:bootfile-name" => 67,
            // C permits the numeric forms, but named OT_INTERNAL entries
            // such as hostname and broadcast are configuration errors.
            b"option:hostname" | b"option:broadcast" => {
                return Err(Error("internal DHCP option requires its numeric code"));
            }
            bytes if !bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit) => {
                u8::try_from(integer(bytes)?)
                    .map_err(|_| Error("DHCP option code is not implemented"))?
            }
            _ => {
                return Err(Error(
                    "DHCP option name, tag or encapsulation is not implemented",
                ))
            }
        };
        if !matches!(code, 1 | 3 | 6 | 12 | 15 | 28 | 58 | 59 | 66 | 67) {
            return Err(Error("DHCP option code is not implemented"));
        }
        let value = match (code, value) {
            (58 | 59, Some(value)) => OptionValue::Time(duration(value.encoded())?),
            (58 | 59, None) => return Err(Error("DHCP timer requires a bounded numeric duration")),
            (_, None) => OptionValue::Empty,
            (1 | 3 | 6 | 28, Some(value)) => {
                let addresses = value
                    .split(b',')
                    .iter()
                    .map(|part| ip(part.encoded()))
                    .collect::<Result<Vec<_>, _>>()?;
                if addresses.len() > 63 {
                    return Err(Error("DHCP option exceeds one-byte length"));
                }
                OptionValue::Addresses(addresses)
            }
            (12 | 15 | 66 | 67, Some(value)) => {
                let value = value.decoded();
                if value.len() > 255 {
                    return Err(Error("DHCP option exceeds one-byte length"));
                }
                // With 66/67 C distinguishes no argument (no string flag)
                // from an explicit empty string, which becomes a NUL TLV.
                if value.is_empty() && !matches!(code, 66 | 67) {
                    OptionValue::Empty
                } else {
                    OptionValue::String(value)
                }
            }
            _ => unreachable!("supported option code was checked"),
        };
        Ok(Self { code, force, value })
    }
}

fn duration(bytes: &[u8]) -> Result<u32, Error> {
    let (digits, multiplier) = match bytes.last() {
        Some(b's' | b'S') => (&bytes[..bytes.len() - 1], 1),
        Some(b'm' | b'M') => (&bytes[..bytes.len() - 1], 60),
        Some(b'h' | b'H') => (&bytes[..bytes.len() - 1], 3600),
        Some(b'd' | b'D') => (&bytes[..bytes.len() - 1], 86_400),
        Some(b'w' | b'W') => (&bytes[..bytes.len() - 1], 604_800),
        _ => (bytes, 1),
    };
    if digits.is_empty() {
        return Err(Error("DHCP timer requires a bounded numeric duration"));
    }
    integer(digits)?
        .checked_mul(multiplier)
        .filter(|value| *value <= i32::MAX as u32)
        .ok_or(Error("DHCP timer exceeds defined C int range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lex_line;

    fn parse(line: &[u8]) -> Result<DhcpOption, Error> {
        let directive = lex_line(line)?.unwrap();
        DhcpOption::parse(directive.argument.as_ref().unwrap(), false)
    }

    #[test]
    fn boot_options_preserve_empty_argument_string_flag() {
        assert_eq!(parse(b"dhcp-option=66").unwrap().value, OptionValue::Empty);
        assert_eq!(
            parse(b"dhcp-option=66,").unwrap().value,
            OptionValue::String(Vec::new())
        );
        assert_eq!(
            parse(b"dhcp-option=option:tftp-server,boot.test")
                .unwrap()
                .code,
            66
        );
        assert_eq!(
            parse(b"dhcp-option=option:bootfile-name,boot.img")
                .unwrap()
                .code,
            67
        );
    }

    #[test]
    fn supported_encodings_preserve_empty_self_string_and_duration() {
        assert_eq!(parse(b"dhcp-option=3").unwrap().value, OptionValue::Empty);
        assert_eq!(
            parse(b"dhcp-option=3,0.0.0.0,192.0.2.1").unwrap().value,
            OptionValue::Addresses(vec![Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(192, 0, 2, 1)])
        );
        assert_eq!(
            parse(b"dhcp-option=15,\"quoted,domain\"").unwrap().value,
            OptionValue::String(b"quoted,domain".to_vec())
        );
        assert_eq!(
            parse(b"dhcp-option=option:T1,3m").unwrap().value,
            OptionValue::Time(180)
        );
        assert_eq!(
            parse(b"dhcp-option=58,0").unwrap().value,
            OptionValue::Time(0)
        );
        for line in [
            b"dhcp-option=3,".as_slice(),
            b"dhcp-option=3,\"192.0.2.1\"",
            b"dhcp-option=option:hostname,name",
            b"dhcp-option=option:broadcast,192.0.2.255",
            b"dhcp-option=58",
            b"dhcp-option=58,",
            b"dhcp-option=58,2147483647w",
            b"dhcp-option=tag:known,3,192.0.2.1",
            b"dhcp-option=vendor:test,3,192.0.2.1",
            b"dhcp-option=119,example.test",
            b"dhcp-option=3,192.0.2.1/24",
        ] {
            assert!(parse(line).is_err(), "{line:?}");
        }
    }
}
