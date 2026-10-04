//! Transient DHCP packet fields in the exact rfc2131.c helper field order.

use super::ExtraData;
use crate::dhcp::packet::{find_option, Packet};

pub fn cpe_data(packet: Packet<'_>) -> [Option<&[u8]>; 3] {
    let Some(mut value) = packet.option(125, 5) else {
        return [None; 3];
    };
    while value.len() > 5 {
        let length = usize::from(value[4]);
        let Some(block) = value.get(5..5 + length) else {
            break;
        };
        if u32::from_be_bytes(value[..4].try_into().unwrap()) == 3561 {
            return [1, 2, 3].map(|code| find_option(block, code, 1).map(|option| option.value));
        }
        value = &value[5 + length..];
    }
    [None; 3]
}

pub fn extra_data(packet: Packet<'_>, tags: &[&[u8]]) -> ExtraData {
    let [oui, serial, class] = cpe_data(packet);
    let mut extra = ExtraData {
        cpewan_oui: oui.unwrap_or_default().to_vec(),
        cpewan_serial: serial.unwrap_or_default().to_vec(),
        cpewan_class: class.unwrap_or_default().to_vec(),
        ..Default::default()
    };
    if let Some(value) = packet.option(60, 0) {
        extra.vendor_class = value.to_vec();
    }
    if let Some(value) = packet.option(12, 1) {
        extra.supplied_hostname = value.to_vec();
    }
    if let Some(value) = relay_suboption(packet, 1) {
        extra.circuit_id = value.to_vec();
    }
    if let Some(value) = relay_suboption(packet, 6) {
        extra.subscriber_id = value.to_vec();
    }
    if let Some(value) = relay_suboption(packet, 2) {
        extra.remote_id = value.to_vec();
    }
    if let Some(value) = packet.option(55, 0) {
        let mut first = true;
        for code in value {
            if !first {
                extra.requested_options.push(b',');
            }
            first = false;
            extra.requested_options.extend(code.to_string().bytes());
        }
    }
    if let Some(value) = packet.option(161, 0) {
        extra.mud_url = value.to_vec();
    }
    // Request tags are appended in reverse C linked-list order. Keep the
    // oldest duplicate, as C scans each node's tail before serializing it.
    for (index, tag) in tags.iter().enumerate().rev() {
        if !tag.is_empty() && !tags[..index].contains(tag) {
            if !extra.tags.is_empty() {
                extra.tags.push(b' ');
            }
            extra.tags.extend_from_slice(tag);
        }
    }
    if let Some(value) = packet.option(77, 0) {
        if !value.is_empty() {
            extra.user_classes = helper_user_classes(value);
        }
    }
    extra
}

fn helper_user_classes(value: &[u8]) -> Vec<Vec<u8>> {
    let mut classes = Vec::new();
    let mut cursor = 0;
    while cursor < value.len() {
        let length = usize::from(value[cursor]);
        let start = cursor + 1;
        let end = start.saturating_add(length);
        if end > value.len() {
            let raw = value.strip_prefix(&[0]).unwrap_or(value);
            return raw.split(|&byte| byte == 0).map(<[u8]>::to_vec).collect();
        }
        classes.extend(
            value[start..end]
                .split(|&byte| byte == 0)
                .map(<[u8]>::to_vec),
        );
        cursor = end;
    }
    if classes.is_empty() {
        vec![value.to_vec()]
    } else {
        classes
    }
}

fn relay_suboption(packet: Packet<'_>, code: u8) -> Option<&[u8]> {
    find_option(packet.option(82, 1)?, code, 1).map(|option| option.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userclass_counted_strings_and_raw_nul_fields_follow_c() {
        assert_eq!(
            helper_user_classes(b"\x03one\x03two"),
            [b"one".to_vec(), b"two".to_vec()]
        );
        assert_eq!(
            helper_user_classes(b"raw\0next"),
            [b"raw".to_vec(), b"next".to_vec()]
        );
        assert_eq!(helper_user_classes(b"\x07short"), [b"\x07short".to_vec()]);
        assert_eq!(
            helper_user_classes(b"\x07one\0two"),
            [b"one".to_vec(), b"two".to_vec()]
        );
    }
}
