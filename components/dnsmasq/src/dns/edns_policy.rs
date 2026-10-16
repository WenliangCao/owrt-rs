//! Exact edns0.c option decoration. The owner supplies a completed MAC lookup;
//! this module performs no I/O and never waits. Capacity failures preserve the
//! C routine's already-written fields and its returned packet length.
use super::reply::strip_opt;
use super::wire::{find_pseudoheader, Header, Message, WireError};
use crate::config::edns::{EdnsConfig, Subnet, Umbrella};
use std::net::IpAddr;

pub const OPTION_MAC: u16 = 65001;
pub const OPTION_DEVICE: u16 = 65073;
pub const OPTION_CPE: u16 = 65074;
pub const OPTION_SUBNET: u16 = 8;
pub const OPTION_UMBRELLA: u16 = 20292;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Replace {
    Keep,
    Replace,
    Strip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decoration {
    pub cacheable: bool,
    /// C reads beyond its address for oversized masks. Rust zero-fills those
    /// bytes rather than disclosing memory; the driver preserves that case.
    pub padded_subnet: bool,
}

fn put(packet: &mut Vec<u8>, at: usize, data: &[u8]) {
    if packet.len() < at + data.len() {
        packet.resize(at + data.len(), 0);
    }
    packet[at..at + data.len()].copy_from_slice(data);
}

fn finish(packet: &mut Vec<u8>, length: usize) {
    packet.truncate(length);
}

/// add_pseudoheader's three replacement modes and strict `i + 4 < rdlen`
/// option loop. `None` only advertises the daemon maximum (or sets DO).
pub fn add_pseudoheader(
    packet: &mut Vec<u8>,
    maximum: u16,
    limit: usize,
    code: Option<u16>,
    data: &[u8],
    set_do: bool,
    replace: Replace,
) -> Result<(), WireError> {
    let original_len = packet.len();
    let Ok(scan) = find_pseudoheader(packet, true) else {
        return Ok(());
    };
    if scan.signed {
        return Ok(());
    }
    let opt = scan
        .opt
        .map(|opt| (opt.record.fixed, opt.record.end, opt.is_last));
    let mut ttl = if set_do { 0x8000 } else { 0 };
    let mut copied = Vec::new();
    let mut position = None;
    let mut length_field = 0;
    let mut data_start = 0;
    if let Some((fixed, end, is_last)) = opt {
        put(packet, fixed + 2, &maximum.to_be_bytes());
        ttl |= u32::from_be_bytes(packet[fixed + 4..fixed + 8].try_into().unwrap());
        put(packet, fixed + 4, &ttl.to_be_bytes());
        if code.is_none() {
            return Ok(());
        }
        length_field = fixed + 8;
        data_start = fixed + 10;
        let mut rdlen = end - data_start;
        let mut at = 0;
        let mut malformed = false;
        while at + 4 < rdlen {
            let found = u16::from_be_bytes(
                packet[data_start + at..data_start + at + 2]
                    .try_into()
                    .unwrap(),
            );
            let size = usize::from(u16::from_be_bytes(
                packet[data_start + at + 2..data_start + at + 4]
                    .try_into()
                    .unwrap(),
            ));
            if at + 4 + size > rdlen {
                rdlen = 0;
                malformed = true;
                break;
            }
            if Some(found) == code {
                if replace == Replace::Keep {
                    return Ok(());
                }
                packet.copy_within(
                    data_start + at + 4 + size..data_start + rdlen,
                    data_start + at,
                );
                rdlen -= 4 + size;
                put(packet, length_field, &(rdlen as u16).to_be_bytes());
            } else {
                at += 4 + size;
            }
        }
        if is_last && !malformed {
            position = Some(data_start + at);
        } else {
            copied.extend_from_slice(&packet[data_start..data_start + rdlen]);
            // C also filters after an in-place option deletion; malformed
            // record layout may make rrfilter leave the packet untouched.
            strip_opt(packet)?;
        }
    }
    let retained_len = packet.len();
    let mut at = if let Some(at) = position {
        at
    } else {
        let Ok(message) = Message::parse(packet) else {
            return Ok(());
        };
        let end = message.end;
        if end.checked_add(11).is_none_or(|value| value > limit) {
            return Ok(());
        }
        data_start = end + 11;
        length_field = end + 9;
        let mut header_bytes = [0u8; 11];
        header_bytes[1..3].copy_from_slice(&41u16.to_be_bytes());
        header_bytes[3..5].copy_from_slice(&maximum.to_be_bytes());
        header_bytes[5..9].copy_from_slice(&ttl.to_be_bytes());
        header_bytes[9..11].copy_from_slice(&(copied.len() as u16).to_be_bytes());
        put(packet, end, &header_bytes);
        if data_start + copied.len() > limit {
            finish(packet, retained_len);
            return Ok(());
        }
        put(packet, data_start, &copied);
        let at = data_start + copied.len();
        // The C capacity guard reserves four bytes even for an empty OPT
        // and Strip. arcount changes only once that guard succeeds.
        if at
            .checked_add(4 + data.len())
            .is_some_and(|end| end <= limit)
        {
            let mut header = Header::parse(packet)?;
            header.additionals = header.additionals.wrapping_add(1);
            header.write(packet)?;
        }
        at
    };
    if at.checked_add(4 + data.len()).is_none_or(|end| end > limit) {
        // Use the post-rrfilter length if non-final OPT removal took place.
        finish(
            packet,
            if position.is_some() {
                original_len
            } else {
                retained_len
            },
        );
        return Ok(());
    }
    if let Some(code) = code.filter(|_| replace != Replace::Strip) {
        put(packet, at, &code.to_be_bytes());
        put(packet, at + 2, &(data.len() as u16).to_be_bytes());
        put(packet, at + 4, data);
        at += 4 + data.len();
        put(
            packet,
            length_field,
            &((at - data_start) as u16).to_be_bytes(),
        );
    }
    finish(packet, at);
    Ok(())
}

/// calc_subnet_opt, including positional family selection, zero-mask behavior
/// and its assignment (not AND) to the caller's cacheable flag.
pub fn source_subnet(config: &EdnsConfig, source: IpAddr) -> (Vec<u8>, bool, bool) {
    let selected: Option<Subnet> = if source.is_ipv4() {
        config.subnet4
    } else {
        config.subnet6
    };
    let mask = selected.map_or(0, |selected| selected.mask);
    let address = selected
        .and_then(|selected| selected.address)
        .unwrap_or(source);
    let fixed = selected.is_some_and(|selected| selected.address.is_some());
    let (family, address) = match address {
        IpAddr::V4(address) => (1u16, address.octets().to_vec()),
        IpAddr::V6(address) => (2u16, address.octets().to_vec()),
    };
    let size = usize::from(mask).div_ceil(8);
    let mut output = Vec::with_capacity(4 + size);
    output.extend_from_slice(&family.to_be_bytes());
    output.extend_from_slice(&[mask, 0]);
    output.extend_from_slice(&address[..size.min(address.len())]);
    output.resize(4 + size, 0);
    if mask & 7 != 0 {
        *output.last_mut().unwrap() &= 0xff << (8 - (mask & 7));
    }
    (output, fixed || mask == 0, size > address.len())
}

/// check_source's existence form. Malformed/trailing options stop its strict
/// loop, and a client ECS with source mask zero remains globally cacheable.
pub fn client_subnet_cacheable(packet: &[u8]) -> bool {
    // Without Additional records there cannot be a client ECS option. This
    // predicate already accepts malformed questions; leave their validation
    // to the query owner instead of walking them again to find an absent OPT.
    let Ok(header) = Header::parse(packet) else { return true };
    if header.additionals == 0 {
        return true;
    }
    let Ok(scan) = find_pseudoheader(packet, false) else {
        return true;
    };
    let Some(opt) = scan.opt else { return true };
    let bytes = opt.record.rdata;
    let mut at = 0;
    while at + 4 < bytes.len() {
        let code = u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap());
        let size = usize::from(u16::from_be_bytes(
            bytes[at + 2..at + 4].try_into().unwrap(),
        ));
        if at + 4 + size > bytes.len() {
            break;
        }
        // C reads an absent mask from its zeroed packet padding. Never read
        // unrelated memory when the option is shorter than the ECS header.
        if code == OPTION_SUBNET && bytes.get(at + 6).copied().unwrap_or(0) != 0 {
            return false;
        }
        at += 4 + size;
    }
    true
}

/// process_reply checks this before signed-packet/OPT stripping decisions.
/// Absence and malformed TLVs are accepted. Any complete mismatching ECS is
/// rejected, while the returned scope prefix is deliberately unconstrained.
pub fn check_reply_source(packet: &[u8], config: &EdnsConfig, source: IpAddr) -> bool {
    if !config.add_subnet {
        return true;
    }
    let Ok(scan) = find_pseudoheader(packet, true) else {
        return true;
    };
    let Some(opt) = scan.opt else { return true };
    let (mut expected, _, _) = source_subnet(config, source);
    let bytes = opt.record.rdata;
    let mut at = 0;
    while at + 4 < bytes.len() {
        let code = u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap());
        let size = usize::from(u16::from_be_bytes(
            bytes[at + 2..at + 4].try_into().unwrap(),
        ));
        if at + 4 + size > bytes.len() {
            break;
        }
        if code == OPTION_SUBNET {
            let value = &bytes[at + 4..at + 4 + size];
            if value.len() != expected.len() {
                return false;
            }
            expected[3] = value[3];
            if value != expected {
                return false;
            }
        }
        at += 4 + size;
    }
    true
}

fn encoded_mac(mac: &[u8], text: bool) -> Vec<u8> {
    if text {
        const HEX: &[u8] = b"0123456789abcdef";
        let mut output = Vec::with_capacity(17);
        for (at, byte) in mac.iter().enumerate() {
            if at != 0 {
                output.push(b':')
            }
            output.extend_from_slice(&[HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]]);
        }
        output
    } else {
        const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = Vec::with_capacity(8);
        for word in mac.chunks_exact(3) {
            for index in [
                word[0] >> 2,
                (word[0] << 4 | word[1] >> 4) & 63,
                (word[1] << 2 | word[2] >> 6) & 63,
                word[2] & 63,
            ] {
                output.push(BASE64[index as usize]);
            }
        }
        output
    }
}

fn umbrella_bytes(umbrella: &Umbrella, source: IpAddr) -> Vec<u8> {
    let mut output = b"ODNS\x01\x00".to_vec();
    if umbrella.organization != 0 {
        output.extend_from_slice(&8u16.to_be_bytes());
        output.extend_from_slice(&umbrella.organization.to_be_bytes());
    }
    match source {
        IpAddr::V4(address) => {
            output.extend_from_slice(&16u16.to_be_bytes());
            output.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            output.extend_from_slice(&32u16.to_be_bytes());
            output.extend_from_slice(&address.octets());
        }
    }
    if let Some(device) = umbrella.device {
        output.extend_from_slice(&64u16.to_be_bytes());
        output.extend_from_slice(&device);
    }
    if umbrella.asset != 0 {
        output.extend_from_slice(&4u16.to_be_bytes());
        output.extend_from_slice(&umbrella.asset.to_be_bytes());
    }
    output
}

/// add_edns0_config's exact order: raw MAC, encoded MAC, CPE, Umbrella, ECS.
/// `mac` is a raw 1..16-byte neighbor identity from the owner's snapshot.
pub fn decorate(
    packet: &mut Vec<u8>,
    config: &EdnsConfig,
    source: IpAddr,
    mac: Option<&[u8]>,
    maximum: u16,
    limit: usize,
) -> Result<Decoration, WireError> {
    let mut result = Decoration {
        cacheable: true,
        padded_subnet: false,
    };
    let mac = mac.filter(|value| !value.is_empty() && value.len() <= 16);
    if let Some(mac) = mac.filter(|_| config.mac.raw) {
        result.cacheable = false;
        add_pseudoheader(
            packet,
            maximum,
            limit,
            Some(OPTION_MAC),
            mac,
            false,
            if config.strip_mac {
                Replace::Replace
            } else {
                Replace::Keep
            },
        )?;
    } else if config.strip_mac {
        add_pseudoheader(
            packet,
            maximum,
            limit,
            Some(OPTION_MAC),
            &[],
            false,
            Replace::Strip,
        )?;
    }
    if let Some(mac) =
        mac.filter(|value| value.len() == 6 && (config.mac.base64 || config.mac.text))
    {
        result.cacheable = false;
        add_pseudoheader(
            packet,
            maximum,
            limit,
            Some(OPTION_DEVICE),
            &encoded_mac(mac, config.mac.text),
            false,
            if config.strip_mac {
                Replace::Replace
            } else {
                Replace::Keep
            },
        )?;
    } else if config.strip_mac {
        add_pseudoheader(
            packet,
            maximum,
            limit,
            Some(OPTION_DEVICE),
            &[],
            false,
            Replace::Strip,
        )?;
    }
    if let Some(cpe) = &config.cpe_id {
        add_pseudoheader(
            packet,
            maximum,
            limit,
            Some(OPTION_CPE),
            cpe,
            false,
            Replace::Replace,
        )?;
    }
    if let Some(umbrella) = &config.umbrella {
        result.cacheable = false;
        add_pseudoheader(
            packet,
            maximum,
            limit,
            Some(OPTION_UMBRELLA),
            &umbrella_bytes(umbrella, source),
            false,
            Replace::Replace,
        )?;
    }
    if config.add_subnet {
        let (data, cacheable, padded) = source_subnet(config, source);
        result.cacheable = cacheable;
        result.padded_subnet = padded;
        add_pseudoheader(
            packet,
            maximum,
            limit,
            Some(OPTION_SUBNET),
            &data,
            false,
            if config.strip_subnet {
                Replace::Replace
            } else {
                Replace::Keep
            },
        )?;
    } else if config.strip_subnet {
        add_pseudoheader(
            packet,
            maximum,
            limit,
            Some(OPTION_SUBNET),
            &[],
            false,
            Replace::Strip,
        )?;
    } else if result.cacheable && !client_subnet_cacheable(packet) {
        result.cacheable = false;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::edns::{MacModes, Subnet};
    use crate::dns::wire::{Name, PacketWriter, Section};
    fn query(data: Option<&[u8]>) -> Vec<u8> {
        let mut writer = PacketWriter::new(0x6200, 0x100, 1232).unwrap();
        writer
            .question(&Name::from_ascii("remote.edns.test").unwrap(), 1, 1)
            .unwrap();
        if let Some(data) = data {
            writer
                .record(Section::Additional, &Name::root(), 41, 1232, 0, data)
                .unwrap()
        }
        writer.finish()
    }
    #[test]
    fn ecs_absence_uses_declared_additional_count_and_accepts_bad_questions() {
        let mut packet = query(Some(b"\0\x08\0\x07\0\x01\x18\0\xc0\0\x02"));
        assert!(!client_subnet_cacheable(&packet));
        packet[10..12].copy_from_slice(&0u16.to_be_bytes());
        assert!(client_subnet_cacheable(&packet), "undeclared trailing OPT is ignored");
        for questions in [0u16, 1, 2, u16::MAX] {
            packet[4..6].copy_from_slice(&questions.to_be_bytes());
            for end in 0..=packet.len() {
                assert!(client_subnet_cacheable(&packet[..end]));
            }
        }
        packet[4..6].copy_from_slice(&1u16.to_be_bytes());
        packet[12] = 0xff;
        assert!(client_subnet_cacheable(&packet));
    }
    #[test]
    fn exact_image_calibration_mac_and_ecs_bytes() {
        let source = "192.0.2.17".parse().unwrap();
        let mac = [2, 17, 34, 170, 187, 204];
        let mut config = EdnsConfig {
            mac: MacModes {
                raw: true,
                base64: true,
                text: true,
            },
            ..EdnsConfig::default()
        };
        let mut packet = query(Some(&[]));
        assert!(
            !decorate(&mut packet, &config, source, Some(&mac), 1232, 1232)
                .unwrap()
                .cacheable
        );
        assert_eq!(
            find_pseudoheader(&packet, false)
                .unwrap()
                .opt
                .unwrap()
                .record
                .rdata,
            b"\xfd\xe9\0\x06\x02\x11\x22\xaa\xbb\xcc\xfe\x31\0\x1102:11:22:aa:bb:cc"
        );
        config.add_subnet = true;
        config.subnet4 = Some(Subnet {
            mask: 25,
            address: None,
        });
        assert_eq!(
            source_subnet(&config, source).0,
            b"\0\x01\x19\0\xc0\0\x02\0"
        );
    }
    #[test]
    fn ecs_assignment_restores_cacheability_after_mac_and_umbrella() {
        let source = "192.0.2.17".parse().unwrap();
        let config = EdnsConfig {
            mac: MacModes {
                raw: true,
                ..MacModes::default()
            },
            umbrella: Some(Umbrella::default()),
            add_subnet: true,
            subnet4: Some(Subnet {
                mask: 0,
                address: None,
            }),
            ..EdnsConfig::default()
        };
        assert!(
            decorate(
                &mut query(None),
                &config,
                source,
                Some(&[2, 17, 34, 170, 187, 204]),
                1232,
                1232
            )
            .unwrap()
            .cacheable
        );
    }
    #[test]
    fn strict_terminal_empty_option_is_not_matched() {
        let mut packet = query(Some(b"\xfe\x32\0\0"));
        add_pseudoheader(
            &mut packet,
            1232,
            1232,
            Some(OPTION_CPE),
            b"router",
            false,
            Replace::Replace,
        )
        .unwrap();
        assert_eq!(
            find_pseudoheader(&packet, false)
                .unwrap()
                .opt
                .unwrap()
                .record
                .rdata,
            b"\xfe\x32\0\x06router"
        );
    }
    #[test]
    fn reply_ecs_requires_source_but_accepts_any_scope_and_absence() {
        let source = "192.0.2.17".parse().unwrap();
        let config = EdnsConfig {
            add_subnet: true,
            subnet4: Some(Subnet {
                mask: 24,
                address: None,
            }),
            ..EdnsConfig::default()
        };
        let mut data = source_subnet(&config, source).0;
        data[3] = 255;
        let mut option = vec![0, 8, 0, data.len() as u8];
        option.extend_from_slice(&data);
        assert!(check_reply_source(&query(Some(&option)), &config, source));
        *option.last_mut().unwrap() ^= 1;
        assert!(!check_reply_source(&query(Some(&option)), &config, source));
        assert!(check_reply_source(&query(None), &config, source));
    }
    #[test]
    fn insufficient_new_opt_keeps_partial_tail_without_count_increment() {
        let mut packet = query(None);
        let length = packet.len();
        packet.extend_from_slice(&[0xbb; 11]);
        add_pseudoheader(
            &mut packet,
            512,
            length + 11,
            None,
            &[],
            false,
            Replace::Keep,
        )
        .unwrap();
        assert_eq!(Header::parse(&packet).unwrap().additionals, 0);
        assert_eq!(packet.len(), length + 11);
        assert_eq!(&packet[length..], &[0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 0]);
    }
    #[test]
    fn signed_tkey_keeps_bytes_but_policy_still_sets_no_cache() {
        let mut packet = query(None);
        let end = packet.len();
        packet[end - 4..end - 2].copy_from_slice(&249u16.to_be_bytes());
        let before = packet.clone();
        let config = EdnsConfig {
            mac: MacModes {
                raw: true,
                ..MacModes::default()
            },
            ..EdnsConfig::default()
        };
        assert!(
            !decorate(
                &mut packet,
                &config,
                "192.0.2.17".parse().unwrap(),
                Some(&[1]),
                1232,
                1232
            )
            .unwrap()
            .cacheable
        );
        assert_eq!(packet, before);
    }
}
