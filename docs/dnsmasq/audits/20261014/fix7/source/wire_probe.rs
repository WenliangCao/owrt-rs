//! Audit-only probe of the unmodified production wire writer.
#![allow(dead_code)]
#[path = __WIRE_PATH__]
mod wire;

use wire::{Header, Name, PacketWriter, Section, WireError};

fn prefix(target: usize, limit: usize) -> PacketWriter {
    let mut writer = PacketWriter::new(0x1234, 0x8580, limit).unwrap();
    writer.question(&Name::from_ascii("alias.example").unwrap(), 255, 1).unwrap();
    let mut opaque = vec![0; target - writer.position() - 12];
    opaque.extend_from_slice(Name::from_ascii("example").unwrap().as_wire());
    writer.record_at(Section::Answer, 12, 65401, 1, 60, &opaque).unwrap();
    writer
}

fn main() {
    let owner = Name::from_ascii("example").unwrap();
    let data = [192, 0, 2, 20];
    let mut cases = 0;
    for target in [0x3fff, 0x4000, 0x4012, 0x7fff, 0xc000] {
        let mut writer = prefix(target, 65535);
        let before = prefix(target, 65535).finish();
        let result = writer.record_at(Section::Additional, target as u16, 1, 1, 60, &data);
        if target < 0x4000 {
            assert_eq!(result, Ok(()));
            let packet = writer.finish();
            assert_eq!(&packet[before.len()..before.len() + 2], &[0xff, 0xff]);
            assert_eq!(Header::parse(&packet).unwrap().additionals, 1);
            assert_eq!(wire::decode_name(&packet, before.len(), 0).unwrap().0, owner);
        } else {
            assert_eq!(result, Err(WireError::InvalidName));
            assert_eq!(writer.position(), before.len());
            // The failed append preserves every byte and every count/flag.
            assert_eq!(writer.finish(), before);
            let mut writer = prefix(target, 65535);
            assert_eq!(writer.record_at(Section::Additional, target as u16, 1, 1, 60, &data), Err(WireError::InvalidName));
            writer.record(Section::Additional, &owner, 1, 1, 60, &data).unwrap();
            let packet = writer.finish();
            assert_eq!(packet.len(), before.len() + owner.as_wire().len() + 14);
            assert_eq!(Header::parse(&packet).unwrap().additionals, 1);
            assert_eq!(wire::decode_name(&packet, before.len(), 0).unwrap().0, owner);
            let mut direct = prefix(target, 65535);
            direct.record(Section::Additional, &owner, 1, 1, 60, &data).unwrap();
            assert_eq!(packet, direct.finish());
        }
        cases += 1;
    }
    // An in-range but out-of-packet offset is also an atomic InvalidName.
    let mut writer = prefix(80, 65535);
    let before = prefix(80, 65535).finish();
    assert_eq!(writer.record_at(Section::Additional, 500, 1, 1, 60, &data), Err(WireError::InvalidName));
    assert_eq!(writer.finish(), before);
    cases += 1;

    // Section ordering can produce InvalidName, again before any write.
    let section_prefix = || {
        let mut writer = prefix(80, 65535);
        writer.record_at(Section::Additional, 80, 1, 1, 60, &data).unwrap();
        writer
    };
    let mut writer = section_prefix();
    assert_eq!(writer.record_at(Section::Answer, 80, 1, 1, 60, &data), Err(WireError::InvalidName));
    assert_eq!(writer.finish(), section_prefix().finish());
    cases += 1;

    // Other malformed-name errors are distinct from InvalidName.
    let malformed_prefix = || {
        let mut writer = prefix(80, 65535);
        writer.record_at(Section::Answer, 12, 65401, 1, 60, &[0x40]).unwrap();
        writer
    };
    let mut writer = malformed_prefix();
    let offset = writer.position() - 1;
    assert_eq!(writer.record_at(Section::Additional, offset as u16, 1, 1, 60, &data), Err(WireError::LabelType));
    assert_eq!(writer.finish(), malformed_prefix().finish());
    cases += 1;

    // Full-owner overflow is atomic in bytes/counts, with intentional TC.
    let mut writer = prefix(0x4012, 0x4012 + owner.as_wire().len() + 16);
    let before_len = writer.position();
    assert_eq!(writer.record_at(Section::Additional, 0x4012, 1, 1, 60, &data), Err(WireError::InvalidName));
    assert_eq!(writer.record(Section::Additional, &owner, 1, 1, 60, &data), Err(WireError::Full));
    assert_eq!(writer.position(), before_len);
    let packet = writer.finish();
    assert_eq!(Header::parse(&packet).unwrap().additionals, 0);
    assert_eq!(Header::parse(&packet).unwrap().flags & 0x200, 0x200);
    cases += 1;
    println!("{{\"passed_cases\":{cases},\"wire_source_unmodified\":true}}");
}
