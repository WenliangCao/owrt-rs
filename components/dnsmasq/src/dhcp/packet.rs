//! Borrowed DHCP/BOOTP packet access. Reference: dhcp.c:173-177 and
//! rfc2131.c:117-156,1976-2024. All offsets are wire offsets, never native structs.

use std::net::Ipv4Addr;

pub const FIXED_LEN: usize = 236;
pub const OPTIONS_OFFSET: usize = 240;
pub const DEFAULT_PACKET_LEN: usize = 548;
pub const MAX_PACKET_LEN: usize = 16384;
pub const COOKIE: [u8; 4] = [99, 130, 83, 99];
/// The BOOTP `vend` field is four bytes of RFC 1048 cookie followed by at
/// most sixty bytes of options.  dnsmasq keeps two bytes for an option header
/// and one byte for `END` when deciding whether an option fits.
pub const BOOTP_VENDOR_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VendorOption<'a> {
    pub code: u8,
    pub value: &'a [u8],
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VendorEncoding {
    /// Number of bytes through the terminating `END`, including the cookie.
    pub len: usize,
    /// Options that did not fit.  C logs and skips these, then continues with
    /// later options, so an oversized option must not abort the whole reply.
    pub omitted: usize,
    /// Actual codes in serializer omission order; empty does not allocate.
    pub omitted_options: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VendorError {
    OutputTooSmall,
    ValueTooLong,
    PadHasValue,
    EndHasValue,
    MalformedOptions,
}

impl std::fmt::Display for VendorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::OutputTooSmall => "BOOTP vendor output buffer is too small",
            Self::ValueTooLong => "BOOTP vendor option exceeds its wire length",
            Self::PadHasValue => "BOOTP PAD option must not have a value",
            Self::EndHasValue => "BOOTP END option must not have a value",
            Self::MalformedOptions => "malformed BOOTP vendor options",
        })
    }
}

impl std::error::Error for VendorError {}

/// Encode the RFC 1048 BOOTP vendor field used by `rfc2131.c`'s BOOTP path.
///
/// The caller supplies already-selected options; policy, option ordering and
/// value construction remain outside this wire primitive.  The output starts
/// with the four-byte cookie and always ends with `END`.  `PAD` is accepted as
/// a one-byte option, while `END` terminates the supplied sequence and ignores
/// anything after it, matching the C option scanner.  An option that cannot
/// fit in the 64-byte vend field is skipped and counted, as `free_space()`
/// does, while later options still get a chance to fit.
pub fn encode_bootp_vendor(
    options: &[VendorOption<'_>],
    output: &mut [u8],
) -> Result<VendorEncoding, VendorError> {
    validate_vendor_output(output)?;
    for option in options {
        match option.code {
            0 if !option.value.is_empty() => return Err(VendorError::PadHasValue),
            255 => {
                if !option.value.is_empty() {
                    return Err(VendorError::EndHasValue);
                }
                break;
            }
            _ if option.value.len() > u8::MAX as usize => return Err(VendorError::ValueTooLong),
            _ => {}
        }
    }
    let mut state = VendorEncoder::new(output)?;
    for option in options {
        if !state.append(*option)? {
            break;
        }
    }
    Ok(state.finish())
}

/// Encode an already wire-formatted option region. This adapter is useful at
/// the boundary where options are copied from a DHCP option builder: a
/// truncated TLV is rejected before it can cause an out-of-bounds read, while
/// `PAD`/`END` retain the scanner semantics of `find_option`.
pub fn encode_bootp_vendor_raw(
    options: &[u8],
    output: &mut [u8],
) -> Result<VendorEncoding, VendorError> {
    validate_vendor_output(output)?;
    let mut validation_position = 0;
    while validation_position < options.len() {
        let code = options[validation_position];
        validation_position += 1;
        if code == 0 {
            continue;
        }
        if code == 255 {
            break;
        }
        let len = *options
            .get(validation_position)
            .ok_or(VendorError::MalformedOptions)? as usize;
        validation_position += 1;
        validation_position = validation_position
            .checked_add(len)
            .filter(|&end| end <= options.len())
            .ok_or(VendorError::MalformedOptions)?;
    }
    let mut state = VendorEncoder::new(output)?;
    let mut position = 0;
    while position < options.len() {
        let code = options[position];
        position += 1;
        if code == 0 {
            if !state.append(VendorOption { code, value: &[] })? {
                break;
            }
            continue;
        }
        if code == 255 {
            break;
        }
        let len = *options.get(position).ok_or(VendorError::MalformedOptions)? as usize;
        position += 1;
        let end = position
            .checked_add(len)
            .ok_or(VendorError::MalformedOptions)?;
        let value = options
            .get(position..end)
            .ok_or(VendorError::MalformedOptions)?;
        position = end;
        if !state.append(VendorOption { code, value })? {
            break;
        }
    }
    Ok(state.finish())
}

fn validate_vendor_output(output: &[u8]) -> Result<(), VendorError> {
    if output.len() < BOOTP_VENDOR_LEN {
        Err(VendorError::OutputTooSmall)
    } else {
        Ok(())
    }
}

struct VendorEncoder<'a> {
    output: &'a mut [u8],
    position: usize,
    omitted: usize,
    omitted_options: Vec<u8>,
}

impl<'a> VendorEncoder<'a> {
    fn new(output: &'a mut [u8]) -> Result<Self, VendorError> {
        validate_vendor_output(output)?;
        output[..BOOTP_VENDOR_LEN].fill(0);
        output[..COOKIE.len()].copy_from_slice(&COOKIE);
        Ok(Self {
            output,
            position: COOKIE.len(),
            omitted: 0,
            omitted_options: Vec::new(),
        })
    }

    /// Returns false for END, which terminates an input option sequence.
    fn append(&mut self, option: VendorOption<'_>) -> Result<bool, VendorError> {
        match option.code {
            0 => {
                if !option.value.is_empty() {
                    return Err(VendorError::PadHasValue);
                }
                // Keep one byte for END, as the C free-space check does.
                if self.position + 2 < BOOTP_VENDOR_LEN {
                    self.output[self.position] = 0;
                    self.position += 1;
                } else {
                    self.omitted += 1;
                    self.omitted_options.push(option.code);
                }
            }
            255 => {
                if !option.value.is_empty() {
                    return Err(VendorError::EndHasValue);
                }
                return Ok(false);
            }
            code => {
                if option.value.len() > u8::MAX as usize {
                    return Err(VendorError::ValueTooLong);
                }
                let needed = option.value.len() + 2;
                // `free_space()` uses `p + len + 3 < end`, reserving END and
                // preserving the historical exact-boundary behavior.
                if self.position + needed + 1 < BOOTP_VENDOR_LEN {
                    self.output[self.position] = code;
                    self.output[self.position + 1] = option.value.len() as u8;
                    self.output[self.position + 2..self.position + needed]
                        .copy_from_slice(option.value);
                    self.position += needed;
                } else {
                    self.omitted += 1;
                    self.omitted_options.push(option.code);
                }
            }
        }
        Ok(true)
    }

    fn finish(self) -> VendorEncoding {
        // Every successful append reserved one byte for END.
        self.output[self.position] = 255;
        VendorEncoding {
            len: self.position + 1,
            omitted: self.omitted,
            omitted_options: self.omitted_options,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    TruncatedHeader,
    NotRequest,
    HardwareAddressTooLong,
    HardwareTypeMissing,
    BadCookie,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::TruncatedHeader => "truncated DHCP packet header",
            Self::NotRequest => "DHCP packet is not a request",
            Self::HardwareAddressTooLong => "DHCP hardware address exceeds its header field",
            Self::HardwareTypeMissing => "DHCP hardware address has no hardware type",
            Self::BadCookie => "invalid DHCP magic cookie",
        })
    }
}

impl std::error::Error for ParseError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptionValue<'a> {
    /// Offset of the option tag within the supplied region.
    pub offset: usize,
    pub value: &'a [u8],
}

/// Exactly the scan semantics of option_find1: the first *sufficiently long*
/// instance wins, PAD is ignored, END or a malformed TLV ends this region.
/// A malformed suffix does not invalidate an earlier matching option.
pub fn find_option(region: &[u8], code: u8, min_len: usize) -> Option<OptionValue<'_>> {
    let mut pos = 0;
    while let Some(&tag) = region.get(pos) {
        match tag {
            0 => pos += 1,
            255 => {
                return (code == 255).then_some(OptionValue {
                    offset: pos,
                    value: &region[pos + 1..pos + 1],
                });
            }
            _ => {
                let len = *region.get(pos + 1)? as usize;
                let end = pos + 2 + len;
                let value = region.get(pos + 2..end)?;
                if tag == code && len >= min_len {
                    return Some(OptionValue { offset: pos, value });
                }
                pos = end;
            }
        }
    }
    None
}

#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    bytes: &'a [u8],
}

impl<'a> Packet<'a> {
    /// Parse either a BOOTP or DHCP request, preserving dnsmasq's cookie rule:
    /// require the cookie only when option 53 with at least one byte is present.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() < FIXED_LEN {
            return Err(ParseError::TruncatedHeader);
        }
        if bytes[0] != 1 {
            return Err(ParseError::NotRequest);
        }
        if bytes[2] > 16 {
            return Err(ParseError::HardwareAddressTooLong);
        }
        if bytes[1] == 0 && bytes[2] != 0 {
            return Err(ParseError::HardwareTypeMissing);
        }
        let packet = Self { bytes };
        if packet.option(53, 1).is_some() && bytes.get(236..240) != Some(&COOKIE) {
            return Err(ParseError::BadCookie);
        }
        Ok(packet)
    }

    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    pub fn option(self, code: u8, min_len: usize) -> Option<&'a [u8]> {
        let primary = self.bytes.get(OPTIONS_OFFSET..).unwrap_or_default();
        if let Some(found) = find_option(primary, code, min_len) {
            return Some(found.value);
        }
        // Only the primary region can enable overload. Nested overload options
        // in sname/file do not cause further recursion.
        let overload = *find_option(primary, 52, 1)?.value.first()?;
        if overload & 1 != 0 {
            if let Some(found) = find_option(&self.bytes[108..236], code, min_len) {
                return Some(found.value);
            }
        }
        if overload & 2 != 0 {
            return find_option(&self.bytes[44..108], code, min_len).map(|v| v.value);
        }
        None
    }

    pub fn message_type(self) -> u8 {
        self.option(53, 1).map_or(0, |v| v[0])
    }

    pub fn transaction_id(self) -> u32 {
        u32::from_be_bytes([self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]])
    }

    pub fn flags(self) -> u16 {
        u16::from_be_bytes([self.bytes[10], self.bytes[11]])
    }

    pub fn hardware_type(self) -> u8 {
        self.bytes[1]
    }

    pub fn hardware_address(self) -> &'a [u8] {
        &self.bytes[28..28 + self.bytes[2] as usize]
    }

    pub fn client_id(self) -> Option<&'a [u8]> {
        self.option(61, 1)
    }

    pub fn ciaddr(self) -> Ipv4Addr {
        ipv4(&self.bytes[12..16])
    }

    /// rfc2131.c clears buggy ciaddr values before context selection.
    pub fn effective_ciaddr(self) -> Ipv4Addr {
        if self.option(53, 1).is_some()
            && (self.message_type() == 1 || self.option(50, 4).is_some())
        {
            Ipv4Addr::UNSPECIFIED
        } else {
            self.ciaddr()
        }
    }

    pub fn giaddr(self) -> Ipv4Addr {
        ipv4(&self.bytes[24..28])
    }

    pub fn requested_address(self) -> Option<Ipv4Addr> {
        self.option(50, 4).map(ipv4)
    }

    pub fn server_identifier(self) -> Option<Ipv4Addr> {
        self.option(54, 4).map(ipv4)
    }

    pub fn requested_lease_time(self) -> Option<u32> {
        self.option(51, 4)
            .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    }

    /// rfc2131.c:700-765,799-816: option 81 takes precedence over option 12,
    /// even when it has no usable name. Client domains are not configuration
    /// domains; this adapter returns only the validated short hostname.
    pub fn client_hostname(self) -> Option<Vec<u8>> {
        let mut name = self.client_hostname_full()?;
        if let Some(dot) = name.iter().position(|byte| *byte == b'.') {
            name.truncate(dot);
        }
        (!name.is_empty()).then_some(name)
    }

    /// The unstripped name is needed for the configured OFFER-name comparison.
    pub fn client_hostname_full(self) -> Option<Vec<u8>> {
        if self.message_type() == 0 {
            return None;
        } // BOOTP returns before this parsing.
        let candidate = if let Some(fqdn) = self.option(81, 3) {
            if fqdn[0] & 4 == 0 {
                fqdn[3..].to_vec()
            } else {
                let mut rest = &fqdn[3..];
                let mut name = Vec::new();
                while let Some(&length) = rest.first() {
                    if length == 0 || usize::from(length) >= rest.len() {
                        break;
                    }
                    name.extend_from_slice(&rest[1..=usize::from(length)]);
                    name.push(b'.');
                    rest = &rest[usize::from(length) + 1..];
                }
                if name.last() == Some(&b'.') {
                    name.pop();
                }
                name
            }
        } else {
            self.option(12, 1)?.to_vec()
        };
        let name = crate::hosts::canonicalise(&candidate)?;
        // legal_hostname checks only the first label. A leading dot is legal
        // here; strip_hostname later turns it into an absent lease name, but
        // C retains the empty string for a FQDN OFFER.
        if !name
            .split(|byte| *byte == b'.')
            .next()
            .unwrap()
            .iter()
            .enumerate()
            .all(|(index, byte)| {
                byte.is_ascii_alphanumeric() || (index != 0 && matches!(byte, b'-' | b'_'))
            })
        {
            return None;
        }
        Some(name)
    }

    /// rfc2131.c:2247-2260. An absent PRL means "send everything";
    /// an explicitly empty PRL means no requested options. END inside the
    /// client's list terminates it, just like the copied C list.
    pub fn requests(self, code: u8) -> bool {
        self.option(55, 0).is_none_or(|list| {
            list.iter()
                .take_while(|&&option| option != 255)
                .any(|&option| option == code)
        })
    }

    /// Preserve the reference's unsigned underflow behavior for option 57 < 28:
    /// it requests the hard maximum, not a tiny response buffer.
    pub fn response_capacity(self) -> usize {
        if self.option(53, 1).is_none() {
            return DEFAULT_PACKET_LEN;
        }
        self.option(57, 2).map_or(DEFAULT_PACKET_LEN, |v| {
            let advertised = u16::from_be_bytes([v[0], v[1]]) as usize;
            advertised
                .wrapping_sub(28)
                .clamp(DEFAULT_PACKET_LEN, MAX_PACKET_LEN)
        })
    }

    /// rfc2131.c:189-205: preserve the first relay-agent option only when
    /// there is room to copy it beyond the incoming primary END marker.
    /// The same reservation controls reply echo and leasequery retention.
    pub fn echo_agent_id(self) -> Option<&'a [u8]> {
        if matches!(self.message_type(), 0 | 10) {
            return None;
        }
        let agent = self.option(82, 1)?;
        let end = find_option(self.bytes.get(240..)?, 255, 0)?.offset + 240;
        (end + agent.len() + 2 < self.response_capacity()).then_some(agent)
    }

    /// RFC3527 link selection takes precedence over RFC3011 option118.
    /// Both are echoed as option118, independently of the request list.
    pub fn subnet_selector(self) -> Option<Ipv4Addr> {
        if matches!(self.message_type(), 0 | 10) {
            return None;
        }
        self.option(82, 1)
            .and_then(|agent| find_option(agent, 5, 4))
            .map(|option| ipv4(&option.value[..4]))
            .filter(|address| !address.is_unspecified())
            .or_else(|| {
                self.option(118, 4)
                    .map(|value| ipv4(&value[..4]))
                    .filter(|address| !address.is_unspecified())
            })
    }

    /// PXE vendor matching is a configured-prefix match, not exact equality.
    /// The returned slice refers to the configured prefix, as in is_pxe_client.
    pub fn pxe_vendor<'b>(self, prefixes: &'b [&'b [u8]]) -> Option<&'b [u8]> {
        let vendor = self.option(60, 0)?;
        prefixes
            .iter()
            .copied()
            .find(|prefix| vendor.starts_with(prefix))
    }
}

/// util.c::legal_hostname plus dhcp-common.c::strip_hostname for the target
/// no-IDN variant. check_name is shared with hosts parsing, not its storage.
pub fn client_hostname_value(value: &[u8]) -> Option<Vec<u8>> {
    let mut name = crate::hosts::canonicalise(value)?;
    if let Some(dot) = name.iter().position(|byte| *byte == b'.') {
        name.truncate(dot);
    }
    if !name.first().is_some_and(u8::is_ascii_alphanumeric)
        || !name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return None;
    }
    Some(name)
}

fn ipv4(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(options: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; OPTIONS_OFFSET];
        bytes[0] = 1;
        bytes[1] = 1;
        bytes[2] = 6;
        bytes[236..240].copy_from_slice(&COOKIE);
        bytes.extend_from_slice(options);
        bytes
    }

    #[test]
    fn duplicate_short_options_do_not_hide_later_valid_values() {
        assert_eq!(
            find_option(&[53, 0, 0, 53, 1, 3, 255], 53, 1)
                .unwrap()
                .value,
            &[3]
        );
        assert_eq!(
            find_option(&[53, 1, 3, 53, 4, 1], 53, 1).unwrap().value,
            &[3]
        );
        assert!(find_option(&[53, 4, 1, 54, 1, 9], 54, 1).is_none());
    }

    #[test]
    fn overload_order_and_malformed_region_match_c() {
        let mut bytes = request(&[52, 1, 3, 53, 0, 254]);
        bytes[108..112].copy_from_slice(&[53, 1, 3, 255]);
        bytes[44..48].copy_from_slice(&[53, 1, 8, 255]);
        assert_eq!(Packet::parse(&bytes).unwrap().message_type(), 3);
        bytes[108..112].copy_from_slice(&[53, 128, 3, 255]);
        assert_eq!(Packet::parse(&bytes).unwrap().message_type(), 8);
    }

    #[test]
    fn client_names_follow_fqdn_precedence_and_short_name_policy() {
        let mut options = vec![53, 1, 3, 12, 13];
        options.extend_from_slice(b"node.example.");
        options.push(255);
        assert_eq!(
            Packet::parse(&request(&options)).unwrap().client_hostname(),
            Some(b"node".to_vec())
        );
        let mut options = vec![53, 1, 3, 12, 8];
        options.extend_from_slice(b"fallback");
        options.extend_from_slice(&[81, 3, 0, 0, 0, 255]);
        assert_eq!(
            Packet::parse(&request(&options)).unwrap().client_hostname(),
            None
        );
        options.truncate(13);
        options.extend_from_slice(&[81, 17, 4, 0, 0, 4]);
        options.extend_from_slice(b"node");
        options.push(7);
        options.extend_from_slice(b"example");
        options.extend_from_slice(&[0, 255]);
        assert_eq!(
            Packet::parse(&request(&options)).unwrap().client_hostname(),
            Some(b"node".to_vec())
        );
        assert_eq!(client_hostname_value(b"bad name"), None);
        assert_eq!(
            Packet::parse(&request(&[12, 4, b'n', b'o', b'd', b'e', 255]))
                .unwrap()
                .client_hostname(),
            None
        );
    }

    #[test]
    fn bootp_needs_neither_cookie_nor_options() {
        let mut bytes = request(&[]);
        bytes.truncate(FIXED_LEN);
        assert_eq!(Packet::parse(&bytes).unwrap().message_type(), 0);
        bytes.resize(240, 0);
        bytes.extend_from_slice(&[53, 1, 1]);
        assert_eq!(Packet::parse(&bytes).unwrap_err(), ParseError::BadCookie);
    }

    #[test]
    fn malformed_headers_are_rejected_without_panics() {
        for length in 0..FIXED_LEN {
            assert!(Packet::parse(&vec![0; length]).is_err());
        }
        let mut bytes = request(&[53, 1, 1]);
        bytes[2] = 17;
        assert_eq!(
            Packet::parse(&bytes).unwrap_err(),
            ParseError::HardwareAddressTooLong
        );
        bytes[2] = 6;
        bytes[1] = 0;
        assert_eq!(
            Packet::parse(&bytes).unwrap_err(),
            ParseError::HardwareTypeMissing
        );
    }

    #[test]
    fn maximum_message_size_preserves_wire_quirks() {
        for (advertised, expected) in [
            (0u16, 16384),
            (27, 16384),
            (28, 548),
            (576, 548),
            (1500, 1472),
            (65535, 16384),
        ] {
            let [a, b] = advertised.to_be_bytes();
            let bytes = request(&[53, 1, 1, 57, 2, a, b, 255]);
            assert_eq!(Packet::parse(&bytes).unwrap().response_capacity(), expected);
        }
    }

    #[test]
    fn discover_clears_ciaddr_and_pxe_uses_configured_prefix() {
        let mut bytes = request(&[
            53, 1, 1, 60, 9, b'P', b'X', b'E', b'C', b'l', b'i', b'e', b'n', b't',
        ]);
        bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
        let packet = Packet::parse(&bytes).unwrap();
        assert_eq!(packet.effective_ciaddr(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(packet.pxe_vendor(&[b"PXEClient"]), Some(&b"PXEClient"[..]));
    }

    #[test]
    fn bootp_vendor_exact_boundary_keeps_cookie_and_end() {
        let mut output = [0xaa; BOOTP_VENDOR_LEN];
        let value = [0x5a; 56];
        let result = encode_bootp_vendor(
            &[VendorOption {
                code: 1,
                value: &value,
            }],
            &mut output,
        )
        .unwrap();
        assert_eq!(
            result,
            VendorEncoding {
                len: 63,
                omitted: 0,
                omitted_options: Vec::new()
            }
        );
        assert_eq!(&output[..4], &COOKIE);
        assert_eq!(output[4], 1);
        assert_eq!(output[5], 56);
        assert_eq!(&output[6..62], &value);
        assert_eq!(output[62], 255);
        // C leaves the final spare byte zeroed after the END marker.
        assert_eq!(output[63], 0);
    }

    #[test]
    fn bootp_vendor_full_field_skips_only_options_that_do_not_fit() {
        let mut output = [0xaa; BOOTP_VENDOR_LEN];
        let first = [1; 27];
        let second = [2; 27];
        let result = encode_bootp_vendor(
            &[
                VendorOption {
                    code: 1,
                    value: &first,
                },
                VendorOption {
                    code: 2,
                    value: &second,
                },
            ],
            &mut output,
        )
        .unwrap();
        assert_eq!(
            result,
            VendorEncoding {
                len: 63,
                omitted: 0,
                omitted_options: Vec::new()
            }
        );
        assert_eq!(&output[4..33], &[&[1, 27][..], &first[..]].concat());
        assert_eq!(output[33], 2);
        assert_eq!(output[34], 27);
        assert_eq!(&output[35..62], &second);
        assert_eq!(output[62], 255);
    }

    #[test]
    fn bootp_vendor_truncation_is_bounded_and_continues_after_omission() {
        let mut output = [0xaa; BOOTP_VENDOR_LEN];
        let oversized = [7; 60];
        let result = encode_bootp_vendor(
            &[
                VendorOption {
                    code: 1,
                    value: &oversized,
                },
                VendorOption {
                    code: 2,
                    value: b"ok",
                },
            ],
            &mut output,
        )
        .unwrap();
        assert_eq!(
            result,
            VendorEncoding {
                len: 9,
                omitted: 1,
                omitted_options: vec![1]
            }
        );
        assert_eq!(&output[4..9], &[2, 2, b'o', b'k', 255]);
        assert!(output[9..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn bootp_vendor_rejects_malformed_tlvs_and_honors_end() {
        let mut output = [0; BOOTP_VENDOR_LEN];
        assert_eq!(
            encode_bootp_vendor(
                &[VendorOption {
                    code: 0,
                    value: b"pad",
                }],
                &mut output,
            ),
            Err(VendorError::PadHasValue)
        );
        assert_eq!(
            encode_bootp_vendor(
                &[VendorOption {
                    code: 255,
                    value: b"end",
                }],
                &mut output,
            ),
            Err(VendorError::EndHasValue)
        );
        let value = [0; 256];
        assert_eq!(
            encode_bootp_vendor(
                &[VendorOption {
                    code: 1,
                    value: &value,
                }],
                &mut output,
            ),
            Err(VendorError::ValueTooLong)
        );
        let mut unchanged = [0xa5; BOOTP_VENDOR_LEN];
        assert_eq!(
            encode_bootp_vendor(
                &[
                    VendorOption {
                        code: 1,
                        value: b"ok",
                    },
                    VendorOption {
                        code: 0,
                        value: b"invalid",
                    },
                ],
                &mut unchanged,
            ),
            Err(VendorError::PadHasValue)
        );
        assert!(unchanged.iter().all(|&byte| byte == 0xa5));
        assert_eq!(
            encode_bootp_vendor_raw(&[1, 2, 7], &mut unchanged),
            Err(VendorError::MalformedOptions)
        );
        assert!(unchanged.iter().all(|&byte| byte == 0xa5));
        assert_eq!(
            encode_bootp_vendor(
                &[
                    VendorOption {
                        code: 1,
                        value: b"ok",
                    },
                    VendorOption {
                        code: 255,
                        value: &[],
                    },
                    VendorOption {
                        code: 2,
                        value: b"ignored",
                    },
                ],
                &mut output,
            )
            .unwrap()
            .len,
            9
        );
        assert_eq!(&output[8..9], &[255]);
        assert_eq!(
            encode_bootp_vendor_raw(&[1, 4, 1, 2], &mut output),
            Err(VendorError::MalformedOptions)
        );
        assert_eq!(
            encode_bootp_vendor_raw(&[1], &mut output),
            Err(VendorError::MalformedOptions)
        );
        let raw = encode_bootp_vendor_raw(&[0, 1, 2, 9, 8, 255, 1, 1, 7], &mut output).unwrap();
        assert_eq!(raw.omitted, 0);
        assert_eq!(&output[4..11], &[0, 1, 2, 9, 8, 255, 0]);
        assert_eq!(
            encode_bootp_vendor(&[], &mut [0; 4]),
            Err(VendorError::OutputTooSmall)
        );
    }
}
