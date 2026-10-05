//! Internal typed framing. All allocation lengths are checked before allocation.
use super::*;

pub(super) const MAX_FRAME: usize = 65_536;
// Exact image script_data occupies104B on its AArch64 helper command pipe.
// Preserve that logical capacity because pressure changes the TERM prefix.
const ARP_COMMAND_BYTES: usize = 104;

fn bytes(out: &mut Vec<u8>, value: &[u8]) -> io::Result<()> {
    if value.len() > MAX_FRAME || out.len().saturating_add(value.len() + 4) > MAX_FRAME {
        return Err(invalid());
    }
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
}
fn ip(out: &mut Vec<u8>, address: IpAddr) {
    match address {
        IpAddr::V4(address) => {
            out.push(4);
            out.extend(address.octets());
        }
        IpAddr::V6(address) => {
            out.push(6);
            out.extend(address.octets());
        }
    }
}

pub(super) fn encode(event: &Event) -> io::Result<Vec<u8>> {
    let mut out = vec![1];
    match event {
        Event::Lease(lease) => {
            out.extend([
                0,
                match lease.action {
                    LeaseAction::Add => 0,
                    LeaseAction::Old => 1,
                    LeaseAction::Delete => 2,
                    LeaseAction::OldHostname => 3,
                },
            ]);
            out.extend(lease.hardware_type.to_le_bytes());
            bytes(&mut out, &lease.hardware_address)?;
            out.extend(lease.address.octets());
            out.push(u8::from(lease.hostname.is_some()));
            if let Some(name) = &lease.hostname {
                bytes(&mut out, name)?;
            }
            bytes(&mut out, &lease.client_id)?;
            bytes(&mut out, &lease.interface)?;
            out.extend(lease.expires.to_le_bytes());
            out.extend(lease.now.to_le_bytes());
            out.extend(
                lease
                    .relay_address
                    .unwrap_or(Ipv4Addr::UNSPECIFIED)
                    .octets(),
            );
            out.push(u8::from(lease.log_dhcp));
            out.push(u8::from(lease.extra.is_some()));
            if let Some(extra) = &lease.extra {
                for value in [
                    &extra.vendor_class,
                    &extra.supplied_hostname,
                    &extra.cpewan_oui,
                    &extra.cpewan_serial,
                    &extra.cpewan_class,
                    &extra.circuit_id,
                    &extra.subscriber_id,
                    &extra.remote_id,
                    &extra.requested_options,
                    &extra.mud_url,
                    &extra.tags,
                ] {
                    bytes(&mut out, value)?;
                }
                if extra.user_classes.len() > 255 {
                    return Err(invalid());
                }
                out.push(extra.user_classes.len() as u8);
                for value in &extra.user_classes {
                    bytes(&mut out, value)?;
                }
            }
        }
        Event::Arp {
            added,
            hardware_address,
            address,
        } => {
            out.extend([1, u8::from(*added)]);
            bytes(&mut out, hardware_address)?;
            ip(&mut out, *address);
        }
        Event::Tftp {
            size,
            address,
            filename,
        } => {
            out.push(2);
            out.extend(size.to_le_bytes());
            ip(&mut out, *address);
            bytes(&mut out, filename)?;
        }
    }
    if out.len() > MAX_FRAME {
        return Err(invalid());
    }
    // Validate semantic bounds too; the child independently repeats this check.
    let _ = invocation(event)?;
    Ok(out)
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> io::Result<&'a [u8]> {
        let result = self.0.get(..count).ok_or_else(invalid)?;
        self.0 = &self.0[count..];
        Ok(result)
    }
    fn byte(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn boolean(&mut self) -> io::Result<bool> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid()),
        }
    }
    fn number(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let count = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
        Ok(self.take(count)?.to_vec())
    }
    fn ipv4(&mut self) -> io::Result<Ipv4Addr> {
        Ok(Ipv4Addr::from(<[u8; 4]>::try_from(self.take(4)?).unwrap()))
    }
    fn ip(&mut self) -> io::Result<IpAddr> {
        match self.byte()? {
            4 => self.ipv4().map(IpAddr::V4),
            6 => Ok(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(self.take(16)?).unwrap()).into()),
            _ => Err(invalid()),
        }
    }
}

pub(super) fn decode(payload: &[u8]) -> io::Result<Event> {
    if payload.len() > MAX_FRAME {
        return Err(invalid());
    }
    let mut input = Reader(payload);
    if input.byte()? != 1 {
        return Err(invalid());
    }
    let event = match input.byte()? {
        0 => {
            let action = match input.byte()? {
                0 => LeaseAction::Add,
                1 => LeaseAction::Old,
                2 => LeaseAction::Delete,
                3 => LeaseAction::OldHostname,
                _ => return Err(invalid()),
            };
            let hardware_type = u32::from_le_bytes(input.take(4)?.try_into().unwrap());
            let hardware_address = input.bytes()?;
            let address = input.ipv4()?;
            let hostname = if input.boolean()? {
                Some(input.bytes()?)
            } else {
                None
            };
            let client_id = input.bytes()?;
            let interface = input.bytes()?;
            let expires = input.number()? as i64;
            let now = input.number()? as i64;
            let relay = input.ipv4()?;
            let relay_address = (!relay.is_unspecified()).then_some(relay);
            let log_dhcp = input.boolean()?;
            let extra = if input.boolean()? {
                let mut extra = ExtraData {
                    vendor_class: input.bytes()?,
                    supplied_hostname: input.bytes()?,
                    cpewan_oui: input.bytes()?,
                    cpewan_serial: input.bytes()?,
                    cpewan_class: input.bytes()?,
                    circuit_id: input.bytes()?,
                    subscriber_id: input.bytes()?,
                    remote_id: input.bytes()?,
                    requested_options: input.bytes()?,
                    mud_url: input.bytes()?,
                    tags: input.bytes()?,
                    user_classes: Vec::new(),
                };
                for _ in 0..input.byte()? {
                    extra.user_classes.push(input.bytes()?);
                }
                Some(Box::new(extra))
            } else {
                None
            };
            Event::Lease(LeaseEvent {
                action,
                hardware_type,
                hardware_address,
                address,
                hostname,
                client_id,
                interface,
                expires,
                now,
                relay_address,
                extra,
                log_dhcp,
            })
        }
        1 => Event::Arp {
            added: input.boolean()?,
            hardware_address: input.bytes()?,
            address: input.ip()?,
        },
        2 => Event::Tftp {
            size: input.number()?,
            address: input.ip()?,
            filename: input.bytes()?,
        },
        _ => return Err(invalid()),
    };
    if !input.0.is_empty()
        && !(matches!(event, Event::Arp { .. })
            && payload.len() == ARP_COMMAND_BYTES - 4
            && input.0.iter().all(|&byte| byte == 0))
    {
        return Err(invalid());
    }
    let _ = invocation(&event)?;
    Ok(event)
}

/// Init records use independent bounded frames; the owner never receives the
/// raw script output or one frame proportional to the whole lease database.
pub(super) fn encode_init(record: &crate::dhcp::lease_file::LeaseRecord) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend(record.address.octets());
    out.extend(record.expires.to_le_bytes());
    out.extend(record.hardware_type.to_le_bytes());
    bytes(&mut out, &record.hardware_address)?;
    for value in [
        &record.client_id,
        &record.hostname,
        &record.agent_id,
        &record.vendor_class,
    ] {
        out.push(u8::from(value.is_some()));
        if let Some(value) = value {
            bytes(&mut out, value)?;
        }
    }
    Ok(out)
}

pub(super) fn decode_init(payload: &[u8]) -> io::Result<crate::dhcp::lease_file::LeaseRecord> {
    if payload.len() > MAX_FRAME {
        return Err(invalid());
    }
    let mut input = Reader(payload);
    let address = input.ipv4()?;
    let expires = input.number()? as i64;
    let hardware_type = u32::from_le_bytes(input.take(4)?.try_into().unwrap());
    let hardware_address = input.bytes()?;
    let mut field = || -> io::Result<Option<Vec<u8>>> {
        if input.boolean()? {
            let bytes = input.bytes()?;
            if bytes.len() > 255 {
                return Err(invalid());
            }
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    };
    let record = crate::dhcp::lease_file::LeaseRecord {
        address,
        expires,
        hardware_type,
        hardware_address,
        client_id: field()?,
        hostname: field()?,
        agent_id: field()?,
        vendor_class: field()?,
    };
    if !input.0.is_empty() || record.hardware_address.len() > 16 {
        return Err(invalid());
    }
    Ok(record)
}

pub(super) fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend((payload.len() as u32).to_le_bytes());
    out.extend(payload);
    out
}

/// ARP commands have a fixed bounded layout. Construct their complete frame
/// with one checked allocation so the owner can retain the record on ENOMEM.
pub(super) fn arp_frame(added: bool, hardware: &[u8], address: IpAddr) -> io::Result<Vec<u8>> {
    if hardware.len() > 16 {
        return Err(invalid());
    }
    let mut out = Vec::new();
    out.try_reserve_exact(ARP_COMMAND_BYTES)
        .map_err(|_| io::Error::from_raw_os_error(12))?;
    out.extend(((ARP_COMMAND_BYTES - 4) as u32).to_le_bytes());
    out.extend([1, 1, u8::from(added)]);
    bytes(&mut out, hardware)?;
    ip(&mut out, address);
    out.resize(ARP_COMMAND_BYTES, 0);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    #[test]
    fn checked_arp_frame_preserves_c_pipe_capacity_and_rejects_noncanonical_padding() {
        for address in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            for length in [0, 1, 6, 16] {
                let event = Event::Arp {
                    added: true,
                    hardware_address: vec![2; length],
                    address,
                };
                let framed = arp_frame(true, &vec![2; length], address).unwrap();
                let payload = encode(&event).unwrap();
                assert_eq!(framed.len(), ARP_COMMAND_BYTES);
                assert_eq!(&framed[4..4 + payload.len()], payload);
                assert_eq!(decode(&framed[4..]).unwrap(), event);
                let mut invalid_padding = framed.clone();
                *invalid_padding.last_mut().unwrap() = 1;
                assert!(decode(&invalid_padding[4..]).is_err());
                assert!(decode(&framed[4..framed.len() - 1]).is_err());
            }
        }
        assert!(arp_frame(true, &[0; 17], Ipv4Addr::LOCALHOST.into()).is_err());
    }
    #[test]
    fn init_record_roundtrip_rejects_truncation_and_oversized_fields() {
        let mut record = crate::dhcp::lease_file::parse(
            b"0 02:00:00:00:00:01 127.0.0.11 one 01:02\nagent-info 127.0.0.11 61:62\n",
        )
        .records
        .remove(0);
        let encoded = encode_init(&record).unwrap();
        assert_eq!(decode_init(&encoded).unwrap(), record);
        for length in 0..encoded.len() {
            assert!(decode_init(&encoded[..length]).is_err());
        }
        record.hostname = Some(vec![b'x'; 256]);
        assert!(decode_init(&encode_init(&record).unwrap()).is_err());
    }

    #[test]
    fn typed_roundtrip_and_each_truncated_boundary() {
        let event = Event::Lease(super::super::tests::lease());
        let payload = encode(&event).unwrap();
        assert_eq!(decode(&payload).unwrap(), event);
        for length in 0..payload.len() {
            assert!(decode(&payload[..length]).is_err(), "length {length}");
        }
        let mut extra = payload.clone();
        extra.push(0);
        assert!(decode(&extra).is_err());
    }
    #[test]
    fn malformed_typed_frames_are_bounded() {
        for data in [
            vec![255],
            vec![1, 255],
            vec![1, 0, 255],
            vec![1, 1, 3],
            vec![1, 1, 1, 255, 255, 255, 255],
            vec![0; MAX_FRAME + 1],
        ] {
            assert!(decode(&data).is_err());
        }
        let event = Event::Tftp {
            size: 0,
            address: Ipv4Addr::LOCALHOST.into(),
            filename: vec![b'a'; MAX_FRAME],
        };
        assert!(encode(&event).is_err());
        let mut event = super::super::tests::lease();
        event.interface = vec![b'a'; 16];
        assert!(encode(&Event::Lease(event)).is_err());
    }
    #[test]
    fn mutation_corpus_never_panics_or_accepts_unknown_events() {
        let seed = encode(&Event::Lease(super::super::tests::lease())).unwrap();
        for i in 0..seed.len() {
            for byte in [0, 1, 2, 15, 16, 127, 255] {
                let mut value = seed.clone();
                value[i] = byte;
                if let Ok(event) = decode(&value) {
                    assert!(encode(&event).is_ok());
                }
            }
        }
    }
}
