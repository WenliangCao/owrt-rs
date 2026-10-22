//! blobmsg <-> JSON conversion shared by the HTTP bridge and by tools that
//! call ubus and want plain JSON values (fw4, rpcd).

use crate::blob::{self, BlobBuf, Field, MsgType};
use crate::json::Json;

/// Maximum nested TABLE/ARRAY fields; the implicit top-level object and scalar
/// leaves do not count. Unlike libubox, reject deeper input before stack overflow.
pub const MAX_CONTAINER_DEPTH: usize = 64;

fn check_container_depth(depth: usize) -> Result<(), String> {
    if depth >= MAX_CONTAINER_DEPTH {
        Err("blobmsg nesting exceeds 64 containers".into())
    } else {
        Ok(())
    }
}

/// Convert a blobmsg payload (sequence of named fields) into a JSON object.
pub fn fields_to_json(payload: &[u8]) -> Result<Json, String> {
    fields_to_json_at(payload, 0)
}

fn fields_to_json_at(payload: &[u8], depth: usize) -> Result<Json, String> {
    Ok(Json::Object(
        blob::fields(payload)
            .map(|f| Ok((f.name.to_owned(), field_to_json_at(&f, depth)?)))
            .collect::<Result<_, String>>()?,
    ))
}

/// Serialize blobmsg fields with the same byte semantics as `fields_to_json`,
/// without allocating an intermediate tree of owned names and strings.
/// On a depth error, leave `out` unchanged so callers cannot send partial JSON.
pub fn append_fields_json(payload: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
    let start = out.len();
    let result = append_container(payload, out, true, 0);
    if result.is_err() { out.truncate(start); }
    result
}

fn append_container(payload: &[u8], out: &mut Vec<u8>, object: bool, depth: usize) -> Result<(), String> {
    out.push(if object { b'{' } else { b'[' });
    for (index, field) in blob::fields(payload).enumerate() {
        if index != 0 { out.push(b','); }
        if object {
            crate::json::write_string(out, field.name.as_bytes());
            out.push(b':');
        }
        match field.ty {
            t if t == MsgType::Table as u32 || t == MsgType::Array as u32 => {
                check_container_depth(depth)?;
                append_container(field.data, out, t == MsgType::Table as u32, depth + 1)?;
            }
            t if t == MsgType::String as u32 => crate::json::write_string(out, field.as_bytes().unwrap_or(b"")),
            _ => field_to_json_at(&field, depth)?.append_to(out),
        }
    }
    out.push(if object { b'}' } else { b']' });
    Ok(())
}

pub fn field_to_json(field: &Field) -> Result<Json, String> {
    field_to_json_at(field, 0)
}

fn field_to_json_at(field: &Field, depth: usize) -> Result<Json, String> {
    Ok(match field.ty {
        t if t == MsgType::Table as u32 => {
            check_container_depth(depth)?;
            return fields_to_json_at(field.data, depth + 1);
        }
        t if t == MsgType::Array as u32 => {
            check_container_depth(depth)?;
            Json::Array(field.children().map(|f| field_to_json_at(&f, depth + 1))
                .collect::<Result<_, _>>()?)
        }
        t if t == MsgType::String as u32 => {
            Json::from_string_bytes(field.as_bytes().unwrap_or(b"").to_vec())
        }
        t if t == MsgType::Int8 as u32 => Json::Bool(field.as_bool().unwrap_or(false)),
        t if t == MsgType::Int16 as u32 => {
            // libubox blobmsg_format_json casts INT16 through (int16_t): signed.
            Json::Int(field.as_u32().unwrap_or(0) as u16 as i16 as i64)
        }
        t if t == MsgType::Int32 as u32 => {
            // ...and INT32 through (int32_t): signed (e.g. iwinfo signal/noise).
            Json::Int(field.as_u32().unwrap_or(0) as i32 as i64)
        }
        t if t == MsgType::Int64 as u32 => Json::Int(field.as_u64().unwrap_or(0) as i64),
        t if t == MsgType::Double as u32 => Json::Float(field.as_f64().unwrap_or(0.0)),
        _ => Json::Null,
    })
}

/// Append one JSON value as a named blobmsg field.
pub fn json_to_fields(b: &mut BlobBuf, name: &str, value: &Json) {
    match value {
        Json::Null => {
            b.msg_null(name);
        }
        Json::Bool(v) => {
            b.msg_bool(name, *v);
        }
        Json::Int(v) => {
            // libubox blobmsg_json: INT32 for the signed 32-bit range, else INT64.
            if (i32::MIN as i64..=i32::MAX as i64).contains(v) {
                b.msg_u32(name, *v as i32 as u32);
            } else {
                b.msg_i64(name, *v);
            }
        }
        Json::Float(v) => {
            b.msg_double(name, *v);
        }
        Json::Str(v) => {
            b.msg_string(name, v);
        }
        Json::Bytes(v) => {
            b.msg_string_bytes(name, v);
        }
        Json::Array(items) => {
            let cookie = b.msg_open_array(name);
            for item in items {
                json_to_fields(b, "", item);
            }
            b.msg_close(cookie);
        }
        Json::Object(items) => {
            let cookie = b.msg_open_table(name);
            for (k, v) in items {
                json_to_fields(b, k, v);
            }
            b.msg_close(cookie);
        }
    }
}

/// Convert a JSON object into a blobmsg payload (top-level fields only;
/// non-objects produce an empty payload).
pub fn object_to_payload(value: &Json) -> Vec<u8> {
    let mut b = BlobBuf::new();
    if let Json::Object(items) = value {
        for (k, v) in items {
            json_to_fields(&mut b, k, v);
        }
    }
    b.into_payload()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_serialization_preserves_nested_and_malformed_field_bytes() {
        let nested = Json::Object(vec![
            ("quoted\"key".into(), Json::Array(vec![Json::Int(-55), Json::Bool(true),
                Json::Null, Json::Float(1.25), Json::Bytes(b"raw\xff\n\t\\\"".to_vec())])),
            ("table".into(), Json::Object(vec![("empty".into(), Json::Array(vec![]))])),
        ]);
        let check = |payload: &[u8]| {
            let mut direct = b"prefix".to_vec();
            append_fields_json(payload, &mut direct).unwrap();
            let mut expected = b"prefix".to_vec();
            fields_to_json(payload).unwrap().append_to(&mut expected);
            assert_eq!(direct, expected);
        };
        check(&object_to_payload(&nested));
        // Preserve existing defaults for truncated numeric/string payloads,
        // unknown types, invalid UTF-8 and malformed nested containers.
        for ty in 0..=12 {
            for len in 0..=32 {
                let mut b = BlobBuf::new();
                let mut bytes = (0..len).map(|i| (i * 37) as u8).collect::<Vec<_>>();
                b.msg_field(ty, "control\nkey", &bytes);
                bytes.reverse();
                b.msg_field(ty, "control\nkey", &bytes);
                check(b.payload());
            }
        }
    }

    // libubox blobmsg_json: signed 32-bit range -> INT32, else INT64.
    #[test]
    fn json_int_uses_signed_i32_range() {
        for (v, ty) in [
            (0i64, MsgType::Int32),
            (-1, MsgType::Int32),
            (i32::MIN as i64, MsgType::Int32),
            (i32::MAX as i64, MsgType::Int32),
            (i32::MAX as i64 + 1, MsgType::Int64),
            (3_000_000_000, MsgType::Int64),
            (-(i32::MIN as i64) , MsgType::Int64),
        ] {
            let payload = object_to_payload(&Json::Object(vec![("n".into(), Json::Int(v))]));
            let f = blob::fields(&payload).next().unwrap();
            assert_eq!(f.ty, ty as u32, "value {v}");
            // round-trips to the same integer
            assert_eq!(field_to_json(&f).unwrap(), Json::Int(v), "value {v}");
        }
    }

    // Both directions must preserve the bytes, including across JSON output.
    #[test]
    fn non_utf8_string_is_not_silently_emptied() {
        let mut b = BlobBuf::new();
        let off = b.msg_open_table("");
        b.msg_field(MsgType::String as u32, "ssid", b"caf\xe9\0");
        b.msg_close(off);
        let payload = b.into_payload();
        let table = blob::fields(&payload).next().unwrap();
        let ssid = table.children().next().unwrap();
        let json = field_to_json(&ssid).unwrap();
        assert_eq!(json.as_bytes(), Some(&b"caf\xe9"[..]));
        assert_eq!(json.to_bytes(), b"\"caf\xe9\"");
        assert_eq!(crate::json::parse_bytes(&json.to_bytes()).unwrap(), json);
        let payload = object_to_payload(&Json::Object(vec![("ssid".into(), json)]));
        assert_eq!(blob::fields(&payload).next().unwrap().as_bytes(), Some(&b"caf\xe9"[..]));
        // and valid UTF-8 still comes through untouched
        let mut b = BlobBuf::new();
        b.msg_string("ssid", "caf\u{e9}");
        let payload = b.into_payload();
        let f = blob::fields(&payload).next().unwrap();
        assert_eq!(field_to_json(&f).unwrap(), Json::Str("caf\u{e9}".to_owned()));
    }

    // INT16/INT32 decode is signed (iwinfo signal/noise are negative dBm).
    #[test]
    fn signed_int_fields_decode_negative() {
        let mut b = BlobBuf::new();
        b.msg_u32("signal", (-55i32) as u32); // INT32 0xffffffc9
        let payload = b.into_payload();
        let f = blob::fields(&payload).next().unwrap();
        assert_eq!(field_to_json(&f).unwrap(), Json::Int(-55));
    }

    #[test]
    fn nested_blob_depth_is_bounded_without_partial_output() {
        for array in [false, true] {
            for depth in [63, 64, 65, 100_000] {
                let mut blob = BlobBuf::new();
                let mut cookies = Vec::new();
                for _ in 0..depth {
                    cookies.push(if array { blob.msg_open_array("a") } else { blob.msg_open_table("a") });
                }
                blob.msg_u32("value", 7);
                for cookie in cookies.into_iter().rev() { blob.msg_close(cookie); }
                let payload = blob.payload();
                let field = blob::fields(payload).next().unwrap();
                let tree = fields_to_json(payload);
                let single = field_to_json(&field);
                let mut direct = b"prefix".to_vec();
                let result = append_fields_json(payload, &mut direct);
                // Independent protocol boundary: changing the implementation
                // constant must not silently change this test's oracle.
                if depth <= 64 {
                    result.unwrap();
                    assert!(single.is_ok());
                    assert_eq!(&direct[6..], tree.unwrap().to_bytes());
                } else {
                    assert_eq!(tree.unwrap_err(), "blobmsg nesting exceeds 64 containers");
                    assert!(single.is_err());
                    assert!(result.is_err());
                    assert_eq!(direct, b"prefix");
                }
            }
        }
    }
}
