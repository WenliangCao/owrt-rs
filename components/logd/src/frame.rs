//! Wire encoding of log records: the blobmsg frame logd writes to a stream
//! client and the `{"log":[{...}]}` reply of a non-stream `read`, emitted
//! from fixed byte templates. Output is byte-identical to what the generic
//! `BlobBuf` field builder (and libubox) produces; the tests compare them.
//!
//! Layout (libubox blob): a 4-byte big-endian `id_len` -- bit 31 extended,
//! bits 24..30 blobmsg type, bits 0..23 raw length including this header --
//! then for blobmsg fields `namelen(be16) name NUL` padded to 4, then the
//! value, the whole attr padded to 4.

use crate::ring::{pad4, Record};

const EXTENDED: u32 = 0x8000_0000;
const ARRAY: u32 = 1;
const TABLE: u32 = 2;
const STRING: u32 = 3;

// Header of the "msg" string field is followed by the raw text and its
// padding; the four fixed-size fields carry their whole header verbatim.
const MSG_NAME: [u8; 8] = [0, 3, b'm', b's', b'g', 0, 0, 0];
const ID_FIELD: [u8; 12] = [0x85, 0, 0, 16, 0, 2, b'i', b'd', 0, 0, 0, 0];
const PRIORITY_FIELD: [u8; 16] = [
    0x85, 0, 0, 20, 0, 8, b'p', b'r', b'i', b'o', b'r', b'i', b't', b'y', 0, 0,
];
const SOURCE_FIELD: [u8; 16] = [
    0x85, 0, 0, 20, 0, 6, b's', b'o', b'u', b'r', b'c', b'e', 0, 0, 0, 0,
];
const TIME_FIELD: [u8; 12] = [0x84, 0, 0, 20, 0, 4, b't', b'i', b'm', b'e', 0, 0];
const TABLE_NAME: [u8; 4] = [0, 0, 0, 0];
const ARRAY_NAME: [u8; 8] = [0, 3, b'l', b'o', b'g', 0, 0, 0];

/// Bytes of the five fields for a record whose text (with NUL) is `size`.
pub const fn fields_len(size: usize) -> usize {
    (4 + MSG_NAME.len() + pad4(size)) + 16 + 20 + 20 + 20
}

/// Bytes of one stream frame (head attr around the fields).
pub const fn frame_len(size: usize) -> usize {
    4 + fields_len(size)
}

/// Bytes of one unnamed table entry in a `read` reply.
pub const fn table_len(size: usize) -> usize {
    4 + TABLE_NAME.len() + fields_len(size)
}

/// Bytes of the "log" array header; a reply is this plus its tables.
pub const REPLY_HEADER_LEN: usize = 4 + ARRAY_NAME.len();

fn push_fields(out: &mut Vec<u8>, record: &Record) {
    let size = record.size();
    out.extend_from_slice(
        &(EXTENDED | STRING << 24 | (4 + MSG_NAME.len() + size) as u32).to_be_bytes(),
    );
    out.extend_from_slice(&MSG_NAME);
    out.extend_from_slice(record.text);
    out.resize(out.len() + pad4(size) - size, 0);
    out.extend_from_slice(&ID_FIELD);
    out.extend_from_slice(&record.id.to_be_bytes());
    out.extend_from_slice(&PRIORITY_FIELD);
    out.extend_from_slice(&record.priority.to_be_bytes());
    out.extend_from_slice(&SOURCE_FIELD);
    out.extend_from_slice(&record.source.to_be_bytes());
    out.extend_from_slice(&TIME_FIELD);
    out.extend_from_slice(&record.time_ms.to_be_bytes());
}

/// Append one stream frame: the head attr logd hands to `ustream_write`.
pub fn push_frame(out: &mut Vec<u8>, record: &Record) {
    out.extend_from_slice(&(frame_len(record.size()) as u32).to_be_bytes());
    push_fields(out, record);
}

/// Append the `{"log": [` array header for a reply of `total` bytes.
pub fn push_reply_header(out: &mut Vec<u8>, total: usize) {
    out.extend_from_slice(&(EXTENDED | ARRAY << 24 | total as u32).to_be_bytes());
    out.extend_from_slice(&ARRAY_NAME);
}

/// Append one `{...}` table entry of a reply.
pub fn push_table(out: &mut Vec<u8>, record: &Record) {
    out.extend_from_slice(
        &(EXTENDED | TABLE << 24 | table_len(record.size()) as u32).to_be_bytes(),
    );
    out.extend_from_slice(&TABLE_NAME);
    push_fields(out, record);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ring::Ring;
    use owrt_ubus::{blob, BlobBuf, MsgType};

    /// The generic builder, as the daemon encoded records before R94.
    fn entry_fields(b: &mut BlobBuf, record: &Record) {
        b.msg_string_bytes("msg", record.msg())
            .msg_u32("id", record.id)
            .msg_u32("priority", record.priority)
            .msg_u32("source", record.source)
            .msg_u64("time", record.time_ms);
    }

    fn sample(len: usize, seed: u8) -> Vec<u8> {
        // arbitrary bytes, no NUL, no LF (normalize/ring handle those)
        (0..len)
            .map(|i| match (i as u8).wrapping_mul(31).wrapping_add(seed) {
                0 | b'\n' => 0xff,
                b => b,
            })
            .collect()
    }

    #[test]
    fn frames_match_the_generic_builder_for_every_text_length() {
        let mut ring = Ring::new(1 << 20);
        let mut out = Vec::new();
        let lengths = (0..=1100).chain([1500, 4095, 4096, 4097, 65_000]);
        for (i, len) in lengths.enumerate() {
            let text = sample(len, i as u8);
            let record = ring.add(
                &text,
                u32::MAX - i as u32,
                i as u32 % 3,
                u64::MAX - i as u64,
            );
            let mut b = BlobBuf::new();
            entry_fields(&mut b, &record);
            let expected = b.as_bytes().to_vec();
            out.clear();
            push_frame(&mut out, &record);
            assert_eq!(out, expected, "frame bytes differ for text length {len}");
            assert_eq!(out.len(), frame_len(record.size()), "frame_len for {len}");
            // and the frame parses back to the same five fields
            let fields: Vec<_> = blob::fields(&out[4..]).collect();
            assert_eq!(
                fields.iter().map(|f| f.name).collect::<Vec<_>>(),
                ["msg", "id", "priority", "source", "time"]
            );
            assert_eq!(fields[0].as_bytes(), Some(record.msg()));
            assert_eq!(fields[1].as_u32(), Some(record.id));
            assert_eq!(fields[2].as_u32(), Some(record.priority));
            assert_eq!(fields[3].as_u32(), Some(record.source));
            assert_eq!(fields[4].as_u64(), Some(record.time_ms));
            assert_eq!(fields[4].ty, MsgType::Int64 as u32);
        }
    }

    #[test]
    fn reply_matches_the_generic_builder_and_its_declared_length() {
        let mut ring = Ring::new(65_536);
        for i in 0..250usize {
            let text = sample(i % 130, i as u8);
            ring.add(&text, i as u32, 1, 1_700_000_000_000 + i as u64);
        }
        for count in [0i64, 1, 2, 100, 249, 10_000] {
            let mut b = BlobBuf::new();
            let array = b.msg_open_array("log");
            for record in ring.list(count) {
                let table = b.msg_open_table("");
                entry_fields(&mut b, &record);
                b.msg_close(table);
            }
            b.msg_close(array);
            let expected = b.payload().to_vec();

            let total =
                REPLY_HEADER_LEN + ring.list(count).map(|r| table_len(r.size())).sum::<usize>();
            let mut out = Vec::with_capacity(total);
            push_reply_header(&mut out, total);
            for record in ring.list(count) {
                push_table(&mut out, &record);
            }
            assert_eq!(out.len(), total, "count {count}");
            assert_eq!(out, expected, "reply bytes differ for count {count}");
            let log = blob::fields(&out).next().unwrap();
            assert_eq!(log.name, "log");
            assert_eq!(log.ty, MsgType::Array as u32);
            assert_eq!(log.children().count(), ring.list(count).count());
        }
    }
}
