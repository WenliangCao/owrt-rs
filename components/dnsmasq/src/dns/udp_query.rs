//! UDP receive/query-error boundary from forward.c:1658-1661,1880-1904,
//! 329-345,365-376,590-605 and rfc1035.c::setup_reply.
//! OPT discovery precedes extract_request failure in UDP. TCP has a different
//! ordering and deliberately does not call this admission helper.

use super::wire::{find_pseudoheader, skip_questions, validate_name, Header, HEADER_LEN};

#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    /// Continue through local lookup and forwarding admission.
    Continue,
    /// No UDP response: short/QR/truncated receive or unskippable questions.
    Drop,
    Reply(Vec<u8>),
}

/// `edns_packet_max` is the daemon's configured receive/advertised maximum.
/// A caller with recvmsg metadata must also discard MSG_TRUNC before this.
pub fn inspect(query: &[u8], edns_packet_max: u16) -> Admission {
    let maximum = edns_packet_max.max(512);
    let Ok(header) = Header::parse(query) else {
        return Admission::Drop;
    };
    if query.len() > usize::from(maximum) || header.flags & 0x8000 != 0 {
        return Admission::Drop;
    }
    let error = if header.opcode() != 0 {
        Some((4, None)) // F_RCODE / NOTIMP, EDE_UNSET
    } else if header.questions != 1
        || header.answers != 0
        || header.authorities != 0
        || validate_name(query, HEADER_LEN, 4).is_err()
    {
        Some((5, Some(24))) // extract_request failure / EDE_INVALID_DATA
    } else {
        None
    };
    match error {
        None => Admission::Continue,
        Some((rcode, ede)) => error_reply(query, header, maximum, rcode, ede)
            .map_or(Admission::Drop, Admission::Reply),
    }
}

/// Refuse a new query when the forwarding table cannot admit it. This does
/// not cancel or mutate any already pending request or coalesced recipient.
/// Malformed/opcode errors retain their earlier, more specific precedence.
pub fn table_full(query: &[u8], edns_packet_max: u16) -> Option<Vec<u8>> {
    match inspect(query, edns_packet_max) {
        Admission::Drop => None,
        Admission::Reply(reply) => Some(reply),
        Admission::Continue => error_reply(
            query,
            Header::parse(query).ok()?,
            edns_packet_max.max(512),
            5,
            None,
        ),
    }
}

fn error_reply(
    query: &[u8],
    mut header: Header,
    advertised: u16,
    rcode: u16,
    ede: Option<u16>,
) -> Option<Vec<u8>> {
    let end = skip_questions(query).ok()?;
    // receive_query passes is_sign=NULL: always skip questions, including
    // non-QUERY opcodes, before looking through answer/additional sections.
    let opt = find_pseudoheader(query, false).ok()?.opt;
    let limit = opt
        .as_ref()
        .map_or(512, |opt| usize::from(opt.udp_size(advertised)));
    header.flags = (header.flags & !0x062f) | 0x8080 | rcode;
    header.answers = 0;
    header.authorities = 0;
    header.additionals = 0;
    let mut packet = query[..end].to_vec();
    header.write(&mut packet).ok()?;
    // add_pseudoheader detects signing after setup_reply discarded all
    // original RRs. A TKEY question still suppresses OPT; an old TSIG RR
    // no longer does. Never infer this from the original signed-query flag.
    let signed = find_pseudoheader(&packet, true).ok()?.signed;
    let required = if ede.is_some() { 17 } else { 15 };
    if opt.is_some()
        && !signed
        && packet
            .len()
            .checked_add(required)
            .is_some_and(|end| end <= limit)
    {
        packet.extend_from_slice(&[0, 0, 41]);
        packet.extend_from_slice(&advertised.to_be_bytes());
        packet.extend_from_slice(&[0; 4]); // reset extended RCODE/version/DO
        if let Some(ede) = ede {
            packet.extend_from_slice(&[0, 6, 0, 15, 0, 2]);
            packet.extend_from_slice(&ede.to_be_bytes());
        } else {
            packet.extend_from_slice(&[0, 0]);
        }
        header.additionals = 1;
        header.write(&mut packet).ok()?;
    }
    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{Name, PacketWriter};

    fn query(flags: u16, kind: u16) -> Vec<u8> {
        let mut writer = PacketWriter::new(7, flags, 1232).unwrap();
        writer
            .question(&Name::from_ascii("remote.test").unwrap(), kind, 1)
            .unwrap();
        let mut packet = writer.finish();
        let mut header = Header::parse(&packet).unwrap();
        header.additionals = 1;
        header.write(&mut packet).unwrap();
        packet.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0]);
        packet
    }

    #[test]
    fn opcode_keeps_opcode_rd_cd_z_but_clears_do_aa_tc_ad() {
        let Admission::Reply(reply) = inspect(&query(0xf70, 1), 1232) else {
            panic!("expected NOTIMP")
        };
        assert_eq!(Header::parse(&reply).unwrap().flags, 0x89d4); // real C baseline
        let opt = find_pseudoheader(&reply, false).unwrap().opt.unwrap();
        assert_eq!(opt.record.class, 1232);
        assert_eq!(opt.record.ttl, 0);
        assert!(opt.record.rdata.is_empty());
    }

    #[test]
    fn invalid_but_skippable_pointer_is_echoed_with_invalid_data_ede() {
        let mut query = vec![0; 12];
        Header {
            id: 7,
            flags: 0x100,
            questions: 1,
            additionals: 1,
            ..Header::default()
        }
        .write(&mut query)
        .unwrap();
        query.extend_from_slice(&[0xc0, 0xff, 0, 1, 0, 1]);
        query.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0]);
        let Admission::Reply(reply) = inspect(&query, 1232) else {
            panic!("expected REFUSED")
        };
        assert_eq!(Header::parse(&reply).unwrap().flags, 0x8185);
        assert_eq!(&reply[12..18], &query[12..18]);
        assert_eq!(
            find_pseudoheader(&reply, false)
                .unwrap()
                .opt
                .unwrap()
                .record
                .rdata,
            &[0, 15, 0, 2, 0, 24]
        );
    }

    #[test]
    fn table_full_has_empty_opt_and_tkey_suppresses_it() {
        let plain = table_full(&query(0x100, 1), 1232).unwrap();
        assert_eq!(Header::parse(&plain).unwrap().flags, 0x8185);
        assert!(find_pseudoheader(&plain, false)
            .unwrap()
            .opt
            .unwrap()
            .record
            .rdata
            .is_empty());
        let signed = table_full(&query(0x100, 249), 1232).unwrap();
        assert_eq!(Header::parse(&signed).unwrap().additionals, 0);
    }

    #[test]
    fn qr_short_oversize_and_unskippable_questions_do_not_reply() {
        assert_eq!(inspect(&[0; 11], 1232), Admission::Drop);
        assert_eq!(inspect(&query(0x8100, 1), 1232), Admission::Drop);
        let mut packet = query(0x100, 1);
        packet.resize(1233, 0);
        assert_eq!(inspect(&packet, 1232), Admission::Drop);
        let mut packet = query(0x100, 1);
        packet.truncate(14);
        assert_eq!(inspect(&packet, 1232), Admission::Drop);
    }

    #[test]
    fn admission_preserves_binary_pointer_and_expanded_name_boundaries() {
        let packet = |name: &[u8]| {
            let mut bytes = vec![0; HEADER_LEN];
            Header {
                id: 7,
                flags: 0x100,
                questions: 1,
                ..Default::default()
            }
            .write(&mut bytes)
            .unwrap();
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(&[0, 1, 0, 1]);
            bytes
        };
        assert_eq!(inspect(&packet(&[0]), 1232), Admission::Continue);
        assert_eq!(
            inspect(&packet(&[5, 0, 1, b'.', 255, b'A', 0]), 1232),
            Admission::Continue
        );
        let mut forward = packet(&[0xc0, 18]);
        forward.extend_from_slice(&[1, b'x', 0]);
        assert_eq!(
            inspect(&forward, 1232),
            Admission::Continue,
            "the question cursor follows its encoded pointer, not its target"
        );

        let mut maximum = Vec::new();
        for length in [63, 63, 63, 61] {
            maximum.push(length);
            maximum.extend(std::iter::repeat_n(b'x', usize::from(length)));
        }
        maximum.push(0);
        assert_eq!(inspect(&packet(&maximum), 1232), Admission::Continue);
        maximum[192] = 62;
        maximum.insert(maximum.len() - 1, b'x');
        for invalid in [
            packet(&maximum),
            packet(&[0xc0, 12]),
            packet(&[65, 8, 255, 0]),
        ] {
            let Admission::Reply(reply) = inspect(&invalid, 1232) else {
                panic!("invalid but skippable questions must retain REFUSED");
            };
            assert_eq!(Header::parse(&reply).unwrap().flags, 0x8185);
        }
        let mut truncated = packet(&[3, b'x', b'y', b'z', 0]);
        truncated.truncate(14);
        assert_eq!(inspect(&truncated, 1232), Admission::Drop);
    }
}
