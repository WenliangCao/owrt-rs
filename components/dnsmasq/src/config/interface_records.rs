//! option.c's shared interface-name/dynamic-host parser.
use super::{validate_directive, Directive, EncodedArg, Error};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceRule {
    pub name: Vec<u8>,
    pub interface: Vec<u8>,
    pub family4: bool,
    pub family6: bool,
    pub prototype4: Option<Ipv4Addr>,
    pub prototype6: Option<Ipv6Addr>,
}

#[derive(Clone, Debug, Default)]
pub struct InterfaceRecordConfig {
    /// C appends rules; order also controls reverse ownership and skip groups.
    pub rules: Vec<InterfaceRule>,
}

fn address(argument: &EncodedArg) -> Option<IpAddr> {
    std::str::from_utf8(argument.encoded()).ok()?.parse().ok()
}

pub fn parse_rule(argument: &EncodedArg, dynamic: bool) -> Result<InterfaceRule, Error> {
    let parts = argument.split(b',');
    let mut prototype4 = None;
    let mut prototype6 = None;
    let mut index = 1;
    // C attempts an address only when a following comma exists. Once a token
    // is not an address it becomes the interface; remaining tokens are ignored.
    while index + 1 < parts.len() {
        match address(&parts[index]) {
            Some(IpAddr::V4(value)) => prototype4 = Some(value),
            Some(IpAddr::V6(value)) => prototype6 = Some(value),
            None => break,
        }
        index += 1;
    }
    let mut family4 = true;
    let mut family6 = true;
    let interface = match parts.get(index) {
        Some(value) => {
            let (name, suffix) = value.split_once(b'/');
            match suffix.as_ref().map(EncodedArg::encoded) {
                None => {}
                Some(b"4") => family6 = false,
                Some(b"6") => family4 = false,
                Some(_) => return Err(Error("error")),
            }
            name.decoded()
        }
        None => Vec::new(),
    };
    let bad = if dynamic {
        Error("bad dynamic host")
    } else {
        Error("bad interface name")
    };
    if dynamic {
        if prototype4.is_none() && prototype6.is_none() {
            return Err(Error("missing address in dynamic host"));
        }
        if !family4 || !family6 {
            return Err(bad);
        }
        family4 = false;
        family6 = false;
    } else if prototype4.is_some() || prototype6.is_some() {
        return Err(bad);
    }
    if interface.is_empty() {
        return Err(bad);
    }
    let name = crate::hosts::canonicalise(&parts[0].decoded()).ok_or(bad)?;
    Ok(InterfaceRule {
        name,
        interface,
        family4,
        family6,
        prototype4,
        prototype6,
    })
}

impl InterfaceRecordConfig {
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        let dynamic = match directive.name.as_slice() {
            b"interface-name" => false,
            b"dynamic-host" => true,
            _ => return Ok(false),
        };
        validate_directive(directive)?;
        self.rules
            .push(parse_rule(directive.argument.as_ref().unwrap(), dynamic)?);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(value: &str, dynamic: bool) -> Result<InterfaceRule, Error> {
        parse_rule(&EncodedArg::command_line(value.as_bytes()), dynamic)
    }
    #[test]
    fn source_parser_priority_and_discarded_tail_match_image_calibration() {
        let rule = parse("name.test,m5ir0,ignored", false).unwrap();
        assert_eq!(rule.interface, b"m5ir0");
        assert_eq!(
            parse("name.test,192.0.2.7", true),
            Err(Error("missing address in dynamic host"))
        );
        assert_eq!(
            parse("name.test,192.0.2.7,m5ir0/4", true),
            Err(Error("bad dynamic host"))
        );
        assert_eq!(parse("name.test,m5ir0/0", false), Err(Error("error")));
        assert_eq!(
            parse("name.test,192.0.2.7,m5ir0", false),
            Err(Error("bad interface name"))
        );
    }
    #[test]
    fn latest_prototype_and_original_case_are_retained() {
        let rule = parse("NAME.TEST.,192.0.2.7,192.0.2.8,2001:db8::7,m5ir0", true).unwrap();
        assert_eq!(rule.name, b"NAME.TEST");
        assert_eq!(rule.prototype4, Some("192.0.2.8".parse().unwrap()));
        assert_eq!(rule.prototype6, Some("2001:db8::7".parse().unwrap()));
        assert!(!rule.family4 && !rule.family6);
    }
}
