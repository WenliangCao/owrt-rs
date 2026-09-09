//! R81 audit (owrt-ubus client library): integration tests for F7, F9, F10.
//!
//! `owrt-ubus` is a library crate, so these run as an external test:
//!     cp tools/audit/r81_ubus_lib_fidelity.rs components/ubus/tests/
//!     cargo test -p owrt-ubus --test r81_ubus_lib_fidelity
//! Each test is expected to FAIL on the current tree and PASS once the
//! finding is fixed. (Not run by the auditor: no cargo on the audit host.)

use owrt_ubus::blob::{self, BlobBuf, MsgType};
use owrt_ubus::convert::field_to_json;
use owrt_ubus::json::Json;

/// F7: libubox's blob_for_each_attr() stops when blob_pad_len(pos) > rem
/// (blob.h:251-256). blob::attr_at() only requires the *raw* length to fit,
/// so a trailing attribute whose padding bytes are missing is yielded by
/// blob::iter() but skipped by C. attrs_of() in ubusd patches this for the
/// top level only; SIGNATURE methods and blobmsg fields go through iter().
#[test]
fn r81_f7_iter_requires_padded_length_like_blob_for_each_attr() {
    // one INT32-typed blobmsg field "a" (namelen 1 -> hdr pad4(2+1+1)=4) plus
    // a 2-byte payload: raw_len = 4 + 4 + 2 = 10, pad_len = 12.
    let mut v = vec![0u8; 0];
    let id_len: u32 = 0x8000_0000 | (MsgType::Int16 as u32) << 24 | 10;
    v.extend_from_slice(&id_len.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes()); // namelen
    v.extend_from_slice(b"a\0");
    v.extend_from_slice(&7u16.to_be_bytes()); // INT16 payload
    assert_eq!(v.len(), 10, "exactly raw_len bytes, no padding");
    let n = blob::iter(&v).count();
    assert_eq!(n, 0, "C sees rem=10 < pad_len=12 and yields nothing");
    // with the padding present both agree
    v.extend_from_slice(&[0, 0]);
    assert_eq!(blob::iter(&v).count(), 1);
}

/// F9: blobmsg_format_json prints doubles with "%.17g" (blobmsg_json.c:275).
#[test]
fn r81_f9_double_formatting_matches_printf_17g() {
    assert_eq!(Json::Float(0.1).to_compact(), "0.10000000000000001");
    assert_eq!(Json::Float(1.1).to_compact(), "1.1000000000000001");
    assert_eq!(Json::Float(1e21).to_compact(), "1e+21");
    assert_eq!(Json::Float(100.0).to_compact(), "100");
    assert_eq!(Json::Float(0.5).to_compact(), "0.5");
}

/// F10: blobmsg_format_string copies the bytes of a STRING verbatim
/// (blobmsg_json.c:176-229); field_to_json turns any non-UTF-8 string into
/// "" because Field::as_str() requires str::from_utf8 to succeed.
#[test]
fn r81_f10_non_utf8_string_is_not_silently_emptied() {
    // a Latin-1 "caf\xe9" as a provider (C hostapd/dnsmasq/uci) would emit it
    let mut b = BlobBuf::new();
    let off = b.msg_open_table("");
    b.msg_field(MsgType::String as u32, "ssid", b"caf\xe9\0");
    b.msg_close(off);
    let payload = b.into_payload();
    let table = blob::fields(&payload).next().unwrap();
    let ssid = table.children().next().unwrap();
    let j = field_to_json(&ssid);
    // any representation that preserves the information is acceptable
    // (lossy U+FFFD like a browser would render the C output, or raw bytes);
    // an empty string is not.
    assert_ne!(j, Json::Str(String::new()), "non-UTF-8 string value must not become \"\"");
}
