//! blobmsg <-> JSON conversion shared by the HTTP bridge and by tools that
//! call ubus and want plain JSON values (fw4, rpcd).

use crate::blob::{self, BlobBuf, Field, MsgType};
use crate::json::Json;

/// Convert a blobmsg payload (sequence of named fields) into a JSON object.
pub fn fields_to_json(payload: &[u8]) -> Json {
    Json::Object(
        blob::fields(payload)
            .map(|f| (f.name.to_owned(), field_to_json(&f)))
            .collect(),
    )
}

pub fn field_to_json(field: &Field) -> Json {
    match field.ty {
        t if t == MsgType::Table as u32 => Json::Object(
            field
                .children()
                .map(|f| (f.name.to_owned(), field_to_json(&f)))
                .collect(),
        ),
        t if t == MsgType::Array as u32 => {
            Json::Array(field.children().map(|f| field_to_json(&f)).collect())
        }
        t if t == MsgType::String as u32 => Json::Str(field.as_str().unwrap_or("").to_owned()),
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
    }
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
            assert_eq!(field_to_json(&f), Json::Int(v), "value {v}");
        }
    }

    // INT16/INT32 decode is signed (iwinfo signal/noise are negative dBm).
    #[test]
    fn signed_int_fields_decode_negative() {
        let mut b = BlobBuf::new();
        b.msg_u32("signal", (-55i32) as u32); // INT32 0xffffffc9
        let payload = b.into_payload();
        let f = blob::fields(&payload).next().unwrap();
        assert_eq!(field_to_json(&f), Json::Int(-55));
    }
}
