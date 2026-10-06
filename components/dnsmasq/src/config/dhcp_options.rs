//! DHCPv4 option grammar and tag priority, from option.c::parse_dhcp_opt
//! and dhcp-common.c::option_filter. Values own configuration bytes only.
use super::{
    ip,
    tags::{TagIf, TagPredicate},
};
use crate::config::{EncodedArg, Error};
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum OptionValue {
    #[default]
    Empty,
    Addresses(Vec<Ipv4Addr>),
    String(Vec<u8>),
    Time(u32),
    Raw(Vec<u8>),
}
impl OptionValue {
    pub fn bytes(&self, local: Option<Ipv4Addr>, null_term: bool) -> Vec<u8> {
        match self {
            Self::Empty => Vec::new(),
            Self::Addresses(addresses) => addresses
                .iter()
                .flat_map(|address| {
                    if address.is_unspecified() {
                        local.unwrap_or(*address)
                    } else {
                        *address
                    }
                    .octets()
                })
                .collect(),
            Self::Time(value) => value.to_be_bytes().to_vec(),
            Self::Raw(value) => value.clone(),
            Self::String(value) => {
                let mut bytes = value.clone();
                if null_term && bytes.len() != 255 {
                    bytes.push(0);
                }
                bytes
            }
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Encapsulation {
    #[default]
    None,
    Vendor(Vec<u8>),
    /// pxe-prompt shares the ordered option bank and matches any configured
    /// PXE vendor by substring. Distinct from the dhcp-option-pxe mode bit.
    PxeVendor,
    Option(u8),
    Enterprise(u32),
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DhcpOption {
    pub code: u8,
    pub force: bool,
    pub value: OptionValue,
    pub tags: TagPredicate,
    pub encapsulation: Encapsulation,
    pub pxe_only: bool,
}

// dhcp-common.c::opttab, nodhcpv6. Numeric codes use the same type hints;
// OT_INTERNAL forbids named configuration, but not dhcp-match selectors.
const ADDR: u16 = 0x8000;
const DOMAIN: u16 = 0x4000;
const INTERNAL: u16 = 0x2000;
const NAME: u16 = 0x1000;
const TIME: u16 = 0x0200;
const OPTIONS: &[(&[u8], u8, u16)] = &[
    (b"netmask", 1, ADDR),
    (b"time-offset", 2, 4),
    (b"router", 3, ADDR),
    (b"dns-server", 6, ADDR),
    (b"log-server", 7, ADDR),
    (b"lpr-server", 9, ADDR),
    (b"hostname", 12, INTERNAL | NAME),
    (b"boot-file-size", 13, 2),
    (b"domain-name", 15, NAME),
    (b"swap-server", 16, ADDR),
    (b"root-path", 17, NAME),
    (b"extension-path", 18, NAME),
    (b"ip-forward-enable", 19, 1),
    (b"non-local-source-routing", 20, 1),
    (b"policy-filter", 21, ADDR),
    (b"max-datagram-reassembly", 22, 2),
    (b"default-ttl", 23, 1),
    (b"mtu", 26, 2),
    (b"all-subnets-local", 27, 1),
    (b"broadcast", 28, INTERNAL | ADDR),
    (b"router-discovery", 31, 1),
    (b"router-solicitation", 32, ADDR),
    (b"static-route", 33, ADDR),
    (b"trailer-encapsulation", 34, 1),
    (b"arp-timeout", 35, 4),
    (b"ethernet-encap", 36, 1),
    (b"tcp-ttl", 37, 1),
    (b"tcp-keepalive", 38, 4),
    (b"nis-domain", 40, NAME),
    (b"nis-server", 41, ADDR),
    (b"ntp-server", 42, ADDR),
    (b"vendor-encap", 43, INTERNAL),
    (b"netbios-ns", 44, ADDR),
    (b"netbios-dd", 45, ADDR),
    (b"netbios-nodetype", 46, 1),
    (b"netbios-scope", 47, 0),
    (b"x-windows-fs", 48, ADDR),
    (b"x-windows-dm", 49, ADDR),
    (b"requested-address", 50, INTERNAL | ADDR),
    (b"lease-time", 51, INTERNAL | TIME),
    (b"option-overload", 52, INTERNAL),
    (b"message-type", 53, INTERNAL),
    (b"server-identifier", 54, INTERNAL | ADDR),
    (b"parameter-request", 55, INTERNAL),
    (b"message", 56, INTERNAL),
    (b"max-message-size", 57, INTERNAL),
    (b"T1", 58, TIME),
    (b"T2", 59, TIME),
    (b"vendor-class", 60, 0),
    (b"client-id", 61, INTERNAL),
    (b"nis+-domain", 64, NAME),
    (b"nis+-server", 65, ADDR),
    (b"tftp-server", 66, NAME),
    (b"bootfile-name", 67, NAME),
    (b"mobile-ip-home", 68, ADDR),
    (b"smtp-server", 69, ADDR),
    (b"pop3-server", 70, ADDR),
    (b"nntp-server", 71, ADDR),
    (b"irc-server", 74, ADDR),
    (b"user-class", 77, 0),
    (b"rapid-commit", 80, 0),
    (b"FQDN", 81, INTERNAL),
    (b"agent-info", 82, INTERNAL),
    (b"last-transaction", 91, 4 | TIME),
    (b"associated-ip", 92, ADDR),
    (b"client-arch", 93, 2),
    (b"client-interface-id", 94, 0),
    (b"client-machine-id", 97, 0),
    (b"posix-timezone", 100, NAME),
    (b"tzdb-timezone", 101, NAME),
    (b"ipv6-only", 108, 4),
    (b"captive-portal", 114, NAME),
    (b"subnet-select", 118, INTERNAL),
    (b"domain-search", 119, DOMAIN),
    (b"sip-server", 120, 0),
    (b"classless-static-route", 121, 0),
    (b"vendor-id-encap", 125, 0),
    (b"tftp-server-address", 150, ADDR),
    (b"server-ip-address", 255, ADDR),
];

impl DhcpOption {
    pub fn parse(argument: &EncodedArg, force: bool) -> Result<Self, Error> {
        Self::parse_mode(argument, force, false)
    }
    pub fn parse_mode(argument: &EncodedArg, force: bool, pxe_only: bool) -> Result<Self, Error> {
        let (mut option, _) = parse(argument, false)?;
        if pxe_only && matches!(option.encapsulation, Encapsulation::Vendor(_)) {
            return Err(Error("No vendor-encap options allowed in dhcp-option-pxe"));
        }
        option.force = force;
        option.pxe_only = pxe_only;
        Ok(option)
    }
    pub fn pxe_ok(&self, mode: u8) -> bool {
        if self.pxe_only {
            mode != 0
        } else {
            mode != 2
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhcpMatch {
    pub set_tag: Vec<u8>,
    pub code: u8,
    pub enterprise: Option<u32>,
    value: Vec<u8>,
    wildcard: Vec<bool>,
    hex: bool,
    string: bool,
}
impl DhcpMatch {
    pub fn parse(argument: &EncodedArg) -> Result<Self, Error> {
        let (option, wildcard) = parse(argument, true)?;
        if option.tags.tags().len() != 1 {
            return Err(Error("illegal dhcp-match"));
        }
        let enterprise = match option.encapsulation {
            // C stores enterprise and wildcard mask in the same union. Its
            // hex parser overwrites the enterprise even without wildcards.
            // Use explicit unsigned arithmetic, not C's signed mask shifts.
            Encapsulation::Enterprise(_) if !wildcard.is_empty() => Some(
                wildcard
                    .iter()
                    .fold(0u32, |mask, bit| (mask << 1) | u32::from(*bit)),
            ),
            Encapsulation::Enterprise(value) => Some(value),
            _ => None,
        };
        Ok(Self {
            set_tag: option.tags.tags()[0].clone(),
            code: option.code,
            enterprise,
            hex: !wildcard.is_empty(),
            string: matches!(option.value, OptionValue::String(_)),
            value: option.value.bytes(None, false),
            wildcard,
        })
    }
    pub fn matches_value(&self, bytes: &[u8]) -> bool {
        if bytes.len() < self.value.len() {
            return false;
        }
        if self.value.is_empty() {
            return true;
        }
        if self.hex {
            return self
                .value
                .iter()
                .zip(bytes)
                .zip(&self.wildcard)
                .all(|((left, right), wildcard)| *wildcard || left == right);
        }
        let step = if self.string { 1 } else { self.value.len() };
        (0..=bytes.len() - self.value.len())
            .step_by(step)
            .any(|offset| bytes[offset..offset + self.value.len()] == self.value)
    }
    pub fn matches_packet(&self, packet: crate::dhcp::packet::Packet<'_>) -> bool {
        if let Some(enterprise) = self.enterprise {
            let Some(bytes) = packet.option(124, 5) else {
                return false;
            };
            let mut at = 0;
            // Exact C loop excludes a final empty enterprise block.
            while at + 5 < bytes.len() {
                let length = usize::from(bytes[at + 4]);
                let end = at + 5 + length;
                if end > bytes.len() {
                    return false;
                }
                if bytes[at..at + 4] == enterprise.to_be_bytes() {
                    let mut item = at + 5;
                    while item < end {
                        let last = item + 1 + usize::from(bytes[item]);
                        // C bounds class data by the entire option, not by
                        // its enterprise block. Preserve that defined wire
                        // behavior while keeping the slice inside the option.
                        if last > bytes.len() {
                            break;
                        }
                        if self.matches_value(&bytes[item + 1..last]) {
                            return true;
                        }
                        item = last;
                    }
                }
                at = end;
            }
            false
        } else {
            packet
                .option(self.code, 1)
                .is_some_and(|value| self.matches_value(value))
        }
    }
}

impl DhcpOption {
    pub(crate) fn log_descriptor(
        code: u8,
    ) -> Option<(&'static [u8], crate::dhcp::logging::OptionLogKind)> {
        let (name, _, hint) = OPTIONS.iter().find(|(_, number, _)| *number == code)?;
        let kind = if hint & ADDR != 0 {
            crate::dhcp::logging::OptionLogKind::Address
        } else if hint & NAME != 0 {
            crate::dhcp::logging::OptionLogKind::Name
        } else if hint & TIME != 0 {
            crate::dhcp::logging::OptionLogKind::Time
        } else if matches!(code, 13 | 22 | 23 | 26 | 35 | 38 | 53 | 93 | 108) {
            crate::dhcp::logging::OptionLogKind::Decimal
        } else {
            crate::dhcp::logging::OptionLogKind::Raw
        };
        Some((name, kind))
    }
}

fn parse(argument: &EncodedArg, matching: bool) -> Result<(DhcpOption, Vec<bool>), Error> {
    let mut rest = argument.clone();
    let mut tags = Vec::new();
    let mut encapsulation = Encapsulation::None;
    let (code, mut hint, tail) = loop {
        let (head, tail) = rest.split_once(b',');
        let bytes = head.encoded();
        if bytes.iter().all(u8::is_ascii_digit) {
            let code = match u8::try_from(super::integer(bytes)?) {
                Ok(code) => code,
                // C accepts a full int matcher which cannot equal a wire
                // byte. PAD is likewise never returned by option_find, so
                // it represents this inert selector without widening output.
                Err(_) if matching => 0,
                Err(_) => return Err(Error("bad DHCP option code")),
            };
            break (code, 0, tail);
        }
        if let Some(name) = bytes.strip_prefix(b"option:") {
            let (_, code, hint) = OPTIONS
                .iter()
                // lookup_dhcp_opt() uses strcasecmp(), so named options are
                // case-insensitive while retaining the original value bytes.
                .find(|(n, _, _)| n.eq_ignore_ascii_case(name))
                .ok_or(Error("bad dhcp-option"))?;
            if hint & INTERNAL != 0 && !matching {
                return Err(Error("bad dhcp-option"));
            }
            break (*code, *hint, tail);
        }
        if let Some(vendor) = bytes.strip_prefix(b"vendor:") {
            if matching
                || !matches!(
                    encapsulation,
                    Encapsulation::None | Encapsulation::Vendor(_)
                )
            {
                return Err(Error("inappropriate vendor:"));
            }
            encapsulation = Encapsulation::Vendor(EncodedArg::command_line(vendor).decoded());
        } else if let Some(number) = bytes.strip_prefix(b"encap:") {
            if matching
                || !matches!(
                    encapsulation,
                    Encapsulation::None | Encapsulation::Option(_)
                )
            {
                return Err(Error("inappropriate encap:"));
            }
            encapsulation = Encapsulation::Option(
                u8::try_from(c_atoi(number)?).map_err(|_| Error("bad DHCP encapsulation code"))?,
            );
        } else if let Some(number) = bytes.strip_prefix(b"vi-encap:") {
            if !matches!(
                encapsulation,
                Encapsulation::None | Encapsulation::Enterprise(_)
            ) {
                return Err(Error("conflicting DHCP encapsulations"));
            }
            encapsulation = Encapsulation::Enterprise(c_atoi(number)? as u32);
            if matching {
                break (0, 0, tail);
            }
        } else {
            let value = head.decoded();
            let tag = [b"tag:".as_slice(), b"net:", b"set:"]
                .iter()
                .find_map(|prefix| value.strip_prefix(*prefix))
                .unwrap_or(&value);
            tags.insert(0, tag.to_vec());
        }
        rest = tail.ok_or(Error("bad dhcp-option"))?;
    };
    if hint == 0 && encapsulation == Encapsulation::None {
        hint = OPTIONS
            .iter()
            .find(|(_, number, _)| *number == code)
            .map_or(0, |(_, _, kind)| *kind);
    }
    let (value, wildcard) = match tail {
        None => (OptionValue::Empty, Vec::new()),
        Some(tail) => encode(
            code,
            hint,
            &tail,
            encapsulation == Encapsulation::None,
            matching,
        )?,
    };
    let length = value.bytes(None, false).len();
    let maximum = match encapsulation {
        Encapsulation::None => 255,
        Encapsulation::Enterprise(_) => 250,
        _ => 253,
    };
    if length > maximum {
        return Err(Error("dhcp-option too long"));
    }
    // C dereferences timer storage as a u32 even for a raw/empty value.
    // Preserve only its defined four-byte behavior, never that unsafe read.
    if !matching
        && encapsulation == Encapsulation::None
        && matches!(code, 58 | 59 | 255)
        && length < 4
    {
        return Err(Error(
            "DHCP timer or server address requires at least four bytes",
        ));
    }
    Ok((
        DhcpOption {
            code,
            value,
            tags: TagPredicate::from_tags(tags),
            encapsulation,
            ..DhcpOption::default()
        },
        wildcard,
    ))
}

fn c_atoi(input: &[u8]) -> Result<i32, Error> {
    let mut bytes = input
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .peekable();
    let negative = match bytes.peek() {
        Some(b'-') => {
            bytes.next();
            true
        }
        Some(b'+') => {
            bytes.next();
            false
        }
        _ => false,
    };
    let mut value = 0i64;
    for byte in bytes.take_while(u8::is_ascii_digit) {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(i64::from(byte - b'0')))
            .ok_or(Error("DHCP number outside defined C int range"))?;
    }
    i32::try_from(if negative { -value } else { value })
        .map_err(|_| Error("DHCP number outside defined C int range"))
}

fn encode(
    code: u8,
    hint: u16,
    argument: &EncodedArg,
    ordinary: bool,
    matching: bool,
) -> Result<(OptionValue, Vec<bool>), Error> {
    let raw = argument.encoded();
    let mut address = true;
    let mut hex = true;
    let mut decimal = true;
    let mut digit = false;
    let mut colons = 0;
    let mut dots = 0;
    let mut width = None;
    for (index, byte) in raw.iter().copied().enumerate() {
        match byte {
            b',' => {
                decimal = false;
                hex = false;
            }
            b':' => {
                colons += 1;
                decimal = false;
                address = false;
            }
            b'/' => {
                decimal = false;
                hex = false;
                if index == 0 {
                    address = false;
                }
            }
            b'.' => {
                decimal = false;
                hex = false;
                dots += 1;
            }
            b'-' => {
                hex = false;
                address = false;
            }
            b' ' => {
                decimal = false;
                hex = false;
            }
            b'0'..=b'9' => digit = true,
            _ => {
                address = false;
                if index + 1 == raw.len() && decimal && matches!(byte, b'b' | b's' | b'i') {
                    width = Some(match byte {
                        b'b' => 1,
                        b's' => 2,
                        _ => 4,
                    });
                } else {
                    decimal = false;
                }
                if !byte.is_ascii_hexdigit() && !(matching && byte == b'*') {
                    hex = false;
                }
            }
        }
    }
    if !digit {
        decimal = false;
        address = false;
    }
    if hint & ADDR != 0 {
        decimal = false;
        hex = false;
        if !address || dots == 0 {
            return Err(Error("bad IP address"));
        }
    } else if hint & (NAME | DOMAIN) != 0 {
        address = false;
        decimal = false;
        hex = false;
    }
    let encoded = if digit && hint & TIME != 0 && !raw.is_empty() {
        let factor = match raw.last() {
            Some(b'w' | b'W') => 604800,
            Some(b'd' | b'D') => 86400,
            Some(b'h' | b'H') => 3600,
            Some(b'm' | b'M') => 60,
            _ => 1,
        };
        let value = c_atoi(raw)?
            .checked_mul(factor)
            .ok_or(Error("DHCP time outside defined C int range"))?;
        OptionValue::Time(value as u32)
    } else if hex && colons > 0 {
        let mut bytes = Vec::new();
        let mut wildcard = Vec::new();
        for group in raw.split(|b| *b == b':') {
            if group.is_empty() {
                continue;
            }
            if group == b"*" && matching {
                bytes.push(0);
                wildcard.push(true);
            } else {
                if !group.iter().all(u8::is_ascii_hexdigit) {
                    return Err(Error("bad DHCP hex value"));
                }
                for pair in group.chunks(2) {
                    bytes.push(pair.iter().fold(0u8, |value, byte| {
                        value * 16 + (*byte as char).to_digit(16).unwrap() as u8
                    }));
                    wildcard.push(false);
                }
            }
        }
        // parse_hex's allocated size comes from ':' count. Reject forms
        // where C would leave bytes uninitialised or write past that buffer.
        if bytes.len() > colons + 1 {
            return Err(Error("ambiguous DHCP hex width"));
        }
        let padding = colons + 1 - bytes.len();
        bytes.resize(colons + 1, 0); // C opt_malloc zero-initializes storage.
        wildcard.splice(0..0, std::iter::repeat_n(false, padding));
        return Ok((OptionValue::Raw(bytes), wildcard));
    } else if decimal {
        let value = c_atoi(raw)?;
        let length = width.unwrap_or_else(|| {
            if hint != 0 {
                usize::from(hint)
            } else if value as u32 & 0xffff0000 != 0 {
                4
            } else if value & 0xff00 != 0 {
                2
            } else {
                1
            }
        });
        if !matches!(length, 1 | 2 | 4) {
            return Err(Error("unsafe DHCP numeric width"));
        }
        OptionValue::Raw(value.to_be_bytes()[4 - length..].to_vec())
    } else if address {
        let mut bytes = Vec::new();
        let mut addresses = Vec::new();
        let mut descriptors = false;
        if code == 120 && ordinary {
            bytes.push(1);
            descriptors = true;
        }
        for part in argument.split(b',') {
            let (address, prefix) = part.split_once(b'/');
            let address = ip(address.encoded())?;
            if let Some(prefix) = prefix {
                descriptors = true;
                let bits = c_atoi(prefix.encoded())?;
                bytes.push(bits as u8);
                for (index, byte) in address.octets().iter().enumerate() {
                    if bits > index as i32 * 8 {
                        bytes.push(*byte);
                    }
                }
            } else {
                bytes.extend_from_slice(&address.octets());
            }
            addresses.push(address);
        }
        if descriptors {
            OptionValue::Raw(bytes)
        } else {
            OptionValue::Addresses(addresses)
        }
    } else if ordinary && matches!(code, 119 | 120) {
        OptionValue::Raw(encode_domains(argument, code == 120)?)
    } else {
        OptionValue::String(argument.decoded())
    };
    Ok((encoded, Vec::new()))
}

fn encode_domains(argument: &EncodedArg, sip: bool) -> Result<Vec<u8>, Error> {
    let mut names = Vec::new();
    for domain in argument.split(b',') {
        if domain.encoded().is_empty() {
            break;
        }
        let domain = domain.decoded();
        let previous = names.len();
        if domain == b"." {
            names.push(0);
            continue;
        }
        let name = crate::hosts::canonicalise(&domain).ok_or(Error("bad domain in dhcp-option"))?;
        for label in name.split(|b| *b == b'.') {
            if label.len() > 63 {
                return Err(Error("bad domain in dhcp-option"));
            }
            names.push(label.len() as u8);
            names.extend_from_slice(label);
        }
        names.push(0);
        let mut tail = previous;
        'compression: while names[tail] != 0 {
            let mut earlier = 0;
            while earlier < previous {
                // C strcmp compares encoded tails, including any previous
                // pointer bytes, not expanded DNS names.
                let left_end = names[earlier..]
                    .iter()
                    .position(|b| *b == 0)
                    .map(|n| earlier + n);
                if left_end.is_some_and(|end| names[earlier..=end] == names[tail..]) {
                    let pointer = 0xc000 | earlier as u16;
                    names.truncate(tail);
                    names.extend_from_slice(&pointer.to_be_bytes());
                    break 'compression;
                }
                earlier += usize::from(names[earlier]) + 1;
            }
            tail += usize::from(names[tail]) + 1;
        }
    }
    if sip {
        names.insert(0, 0);
    }
    Ok(names)
}

#[derive(Debug)]
pub struct FilteredOptions<'a> {
    pub selected: Vec<usize>,
    pub tags: Vec<&'a [u8]>,
    pub duplicate_warnings: usize,
    pub duplicate_codes: Vec<u8>,
}

/// Options are in reverse declaration order; tag-if rules are in declaration
/// order. Request-derived tags outrank context-only tags, then untagged rules.
pub fn option_filter<'a>(
    options: &[DhcpOption],
    request_tags: &[&'a [u8]],
    context_tags: &[&'a [u8]],
    rules: &'a [TagIf],
    pxe_mode: u8,
) -> FilteredOptions<'a> {
    let mut tags = request_tags.to_vec();
    TagIf::apply_all(rules, &mut tags);
    let eligible = |option: &DhcpOption| {
        option.encapsulation == Encapsulation::None && option.pxe_ok(pxe_mode)
    };
    let mut selected: Vec<bool> = options
        .iter()
        .map(|option| eligible(option) && option.tags.matches_with(&tags, false))
        .collect();
    if !context_tags.is_empty() {
        tags = context_tags.iter().chain(request_tags).copied().collect();
        TagIf::apply_all(rules, &mut tags);
        for (option, selected) in options.iter().zip(&mut selected) {
            if *selected && !option.tags.matches_with(&tags, false) {
                *selected = false;
            }
        }
        for (index, option) in options.iter().enumerate() {
            if eligible(option)
                && !selected[index]
                && option.tags.matches_with(&tags, false)
                && !options
                    .iter()
                    .enumerate()
                    .any(|(other, candidate)| candidate.code == option.code && selected[other])
            {
                selected[index] = true;
            }
        }
    }
    let mut duplicate_warnings = 0;
    let mut duplicate_codes = Vec::new();
    for (index, option) in options.iter().enumerate() {
        if eligible(option) && !selected[index] && option.tags.is_unconditional() {
            if let Some((_, other)) = options
                .iter()
                .enumerate()
                .find(|(at, candidate)| candidate.code == option.code && selected[*at])
            {
                if other.tags.is_unconditional() {
                    duplicate_warnings += 1;
                    duplicate_codes.push(option.code);
                }
            } else {
                selected[index] = true;
            }
        }
    }
    for index in 0..options.len() {
        if selected[index] {
            for other in index + 1..options.len() {
                if options[index].code == options[other].code {
                    selected[other] = false;
                }
            }
        }
    }
    FilteredOptions {
        selected: selected
            .iter()
            .enumerate()
            .filter_map(|(at, yes)| yes.then_some(at))
            .collect(),
        tags,
        duplicate_warnings,
        duplicate_codes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn option(line: &[u8]) -> DhcpOption {
        let directive = crate::config::lex_line(line).unwrap().unwrap();
        DhcpOption::parse(directive.argument.as_ref().unwrap(), false).unwrap()
    }
    #[test]
    fn option_encodings_cover_widths_strings_addresses_and_descriptors() {
        assert_eq!(option(b"dhcp-option=option:ROUTER,192.0.2.1").code, 3);
        assert_eq!(
            option(b"dhcp-option=option:mtu,1500")
                .value
                .bytes(None, false),
            [5, 220]
        );
        assert_eq!(
            option(b"dhcp-option=224,1025b").value.bytes(None, false),
            [1]
        );
        assert_eq!(
            option(b"dhcp-option=224,-1i").value.bytes(None, false),
            [255; 4]
        );
        assert_eq!(
            option(b"dhcp-option=224,01:02:0f").value.bytes(None, false),
            [1, 2, 15]
        );
        assert_eq!(
            option(b"dhcp-option=224,\"01:02\"")
                .value
                .bytes(None, false),
            b"01:02"
        );
        assert_eq!(
            option(b"dhcp-option=3,0.0.0.0,192.0.2.1")
                .value
                .bytes(Some(Ipv4Addr::LOCALHOST), false),
            [127, 0, 0, 1, 192, 0, 2, 1]
        );
        assert_eq!(
            option(b"dhcp-option=121,192.0.2.0/24,192.0.2.1")
                .value
                .bytes(None, false),
            [24, 192, 0, 2, 192, 0, 2, 1]
        );
        assert_eq!(
            option(b"dhcp-option=120,192.0.2.1")
                .value
                .bytes(None, false),
            [1, 192, 0, 2, 1]
        );
        assert_eq!(option(b"dhcp-option=58,3m").value, OptionValue::Time(180));
    }
    #[test]
    fn domain_search_compression_and_sip_encoding_are_distinct() {
        assert_eq!(
            option(b"dhcp-option=119,a.example,b.example")
                .value
                .bytes(None, false),
            b"\x01a\x07example\0\x01b\xc0\x02"
        );
        assert_eq!(
            option(b"dhcp-option=120,a.example")
                .value
                .bytes(None, false),
            b"\0\x01a\x07example\0"
        );
        assert_eq!(option(b"dhcp-option=119,.").value.bytes(None, false), [0]);
    }
    #[test]
    fn null_termination_and_encapsulation_limits_are_preserved() {
        assert_eq!(option(b"dhcp-option=66").value.bytes(None, true), b"");
        assert_eq!(option(b"dhcp-option=66,").value.bytes(None, true), b"\0");
        let long = vec![b'x'; 255];
        assert_eq!(OptionValue::String(long.clone()).bytes(None, true), long);
        let opt = option(b"dhcp-option=tag:desk,vendor:client,1,0.0.0.0");
        assert_eq!(opt.encapsulation, Encapsulation::Vendor(b"client".to_vec()));
        assert!(opt.tags.matches_with(&[b"desk"], false));
        let mut input = b"vendor:client,1,".to_vec();
        input.extend(vec![b'x'; 254]);
        assert!(DhcpOption::parse(&EncodedArg::command_line(&input), false).is_err());
        assert!(
            DhcpOption::parse(&EncodedArg::command_line(b"option:hostname,host"), false).is_err()
        );
        assert!(
            DhcpMatch::parse(&EncodedArg::command_line(b"set:host,option:hostname,host")).is_ok()
        );
    }
    #[test]
    fn match_uses_presence_element_alignment_or_prefix_mask() {
        let presence = DhcpMatch::parse(&EncodedArg::command_line(b"set:yes,224")).unwrap();
        assert!(presence.matches_value(&[]));
        let numeric =
            DhcpMatch::parse(&EncodedArg::command_line(b"set:arch,option:client-arch,7")).unwrap();
        assert!(numeric.matches_value(&[0, 0, 0, 7]));
        assert!(!numeric.matches_value(&[1, 0, 7, 0]));
        let masked = DhcpMatch::parse(&EncodedArg::command_line(b"set:yes,224,01:*:03")).unwrap();
        assert!(masked.matches_value(&[1, 2, 3, 4]));
        assert!(!masked.matches_value(&[0, 1, 2, 3]));
        let text = DhcpMatch::parse(&EncodedArg::command_line(b"set:yes,224,text")).unwrap();
        assert!(text.matches_value(b"prefix-text-suffix"));
    }

    #[test]
    fn enterprise_class_is_bounded_by_whole_option_like_c() {
        let rule = DhcpMatch::parse(&EncodedArg::command_line(b"set:a,vi-encap:1234,abc")).unwrap();
        let mut bytes = vec![0; 240];
        bytes[..3].copy_from_slice(&[1, 1, 6]);
        bytes[236..240].copy_from_slice(&crate::dhcp::packet::COOKIE);
        // Class 'abc' extends two bytes beyond its enterprise data but stays
        // inside option124. C accepts this safe, noncanonical layout.
        bytes.extend_from_slice(&[53, 1, 1, 124, 9, 0, 0, 4, 210, 2, 3, b'a', b'b', b'c', 255]);
        assert!(rule.matches_packet(crate::dhcp::packet::Packet::parse(&bytes).unwrap()));
        bytes[250] = 4; // Class would cross the whole option: must not match.
        assert!(!rule.matches_packet(crate::dhcp::packet::Packet::parse(&bytes).unwrap()));
    }

    #[test]
    fn enterprise_hex_uses_the_c_union_mask_value() {
        let hex =
            DhcpMatch::parse(&EncodedArg::command_line(b"set:a,vi-encap:1234,01:02")).unwrap();
        let wildcard =
            DhcpMatch::parse(&EncodedArg::command_line(b"set:a,vi-encap:1234,01:*:03")).unwrap();
        assert_eq!(hex.enterprise, Some(0));
        assert_eq!(wildcard.enterprise, Some(2));
    }

    #[test]
    fn non_wire_match_codes_are_accepted_but_never_match_a_packet() {
        let mut bytes = vec![0; 240];
        bytes[..3].copy_from_slice(&[1, 1, 6]);
        bytes[236..240].copy_from_slice(&crate::dhcp::packet::COOKIE);
        bytes.extend_from_slice(b"\x35\x01\x01\xe0\x06needle\xff");
        let packet = crate::dhcp::packet::Packet::parse(&bytes).unwrap();
        for code in [224, 256, 65535] {
            let input = format!("set:hit,{code},needle");
            let rule = DhcpMatch::parse(&EncodedArg::command_line(input.as_bytes())).unwrap();
            assert_eq!(rule.matches_packet(packet), code == 224);
        }
        assert!(DhcpOption::parse(&EncodedArg::command_line(b"256,needle"), false).is_err());
    }
    #[test]
    fn request_tag_priority_beats_later_context_and_untagged_rules() {
        let opts = [
            option(b"dhcp-option=tag:lan,224,1"),
            option(b"dhcp-option=tag:client,224,2"),
            option(b"dhcp-option=224,3"),
        ];
        assert_eq!(
            option_filter(&opts, &[b"client"], &[b"lan"], &[], 0).selected,
            [1]
        );
        assert_eq!(option_filter(&opts, &[], &[b"lan"], &[], 0).selected, [0]);
        assert_eq!(option_filter(&opts, &[], &[], &[], 0).selected, [2]);
        let negated = [
            option(b"dhcp-option=tag:!lan,224,1"),
            option(b"dhcp-option=tag:lan,224,2"),
        ];
        assert_eq!(
            option_filter(&negated, &[], &[b"lan"], &[], 0).selected,
            [1]
        );
    }
    #[test]
    fn duplicate_warnings_and_pxe_option_scope_match_filter_stages() {
        let opts = [option(b"dhcp-option=224,1"), option(b"dhcp-option=224,2")];
        let selected = option_filter(&opts, &[], &[], &[], 0);
        assert_eq!(selected.selected, [0]);
        assert_eq!(selected.duplicate_warnings, 1);
        let pxe = DhcpOption::parse_mode(&EncodedArg::command_line(b"224,1"), false, true).unwrap();
        assert!(option_filter(std::slice::from_ref(&pxe), &[], &[], &[], 0)
            .selected
            .is_empty());
        assert_eq!(option_filter(&[pxe], &[], &[], &[], 2).selected, [0]);
    }
    #[test]
    fn malformed_input_and_unsafe_c_widths_are_bounded_errors() {
        for value in [
            b"3,invalid".as_slice(),
            b"3,",
            b"option:no-such-option,1",
            b"58",
            b"58,",
            b"255",
            b"224,010203:04",
            b"224,999999999999999999999999999999",
        ] {
            assert!(
                DhcpOption::parse(&EncodedArg::command_line(value), false).is_err(),
                "{value:?}"
            );
        }
    }
}
