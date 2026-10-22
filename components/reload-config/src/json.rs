//! Byte-preserving JSON string escaping for configuration payloads and diagnostics.

/// Shared JSON string escaping for payloads and traces: the shell does no escaping at all, but a
/// quote or a control byte in a filename would otherwise break the payload
/// before ubus ever sees it. Bytes >= 0x20 other than `"` and `\` pass through
/// unchanged, so a name that is not UTF-8 is forwarded verbatim.
pub fn escape_bytes(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    for &byte in value {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x00..=0x1f => out.extend_from_slice(format!("\\u{byte:04x}").as_bytes()),
            _ => out.push(byte),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn control_bytes_are_json_escaped_and_non_ascii_bytes_are_preserved() {
        let bytes: Vec<u8> = (0..=31).chain([b'"', b'\\', b' ', 0x7f, 0x80, 0xff]).collect();
        assert_eq!(super::escape_bytes(&bytes), concat!(
            "\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007",
            "\\u0008\\t\\n\\u000b\\u000c\\r\\u000e\\u000f",
            "\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017",
            "\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f",
            "\\\"\\\\ "
        ).as_bytes().iter().copied().chain([0x7f, 0x80, 0xff]).collect::<Vec<_>>());
    }
}
