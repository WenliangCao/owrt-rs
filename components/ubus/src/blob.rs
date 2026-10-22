//! libubox blob / blobmsg codec.
//!
//! blob attr: 4-byte big-endian `id_len` (bit 31 extended, bits 24..30 id,
//! bits 0..23 raw length including the 4-byte header) followed by the payload,
//! padded to 4 bytes. blobmsg fields are extended attrs whose id is the field
//! type and whose payload starts with `namelen(be16) name NUL pad4`.

pub const EXTENDED: u32 = 0x8000_0000;
const ID_MASK: u32 = 0x7f00_0000;
const LEN_MASK: u32 = 0x00ff_ffff;

pub fn pad4(len: usize) -> usize {
    (len + 3) & !3
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attr<'a> {
    pub id: u32,
    pub extended: bool,
    pub payload: &'a [u8],
}

impl<'a> Attr<'a> {
    pub fn as_u32(&self) -> Option<u32> {
        match self.payload.len() {
            4 => Some(u32::from_be_bytes(self.payload.try_into().unwrap())),
            2 => Some(u16::from_be_bytes(self.payload.try_into().unwrap()) as u32),
            1 => Some(self.payload[0] as u32),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&'a str> {
        let end = self.payload.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&self.payload[..end]).ok()
    }

    /// Interpret this attr as a blobmsg field.
    pub fn field(&self) -> Option<Field<'a>> {
        if !self.extended || self.payload.len() < 2 {
            return None;
        }
        let namelen = u16::from_be_bytes([self.payload[0], self.payload[1]]) as usize;
        let hdrlen = pad4(2 + namelen + 1);
        if self.payload.len() < hdrlen {
            return None;
        }
        let name = std::str::from_utf8(&self.payload[2..2 + namelen]).ok()?;
        Some(Field {
            name,
            ty: self.id,
            data: &self.payload[hdrlen..],
        })
    }
}

/// Parse the attr starting at `offset`; returns the attr and the next offset.
///
/// Stops where libubox's `blob_for_each_attr` stops: the attribute's *padded*
/// length must fit in what remains (`blob_pad_len(pos) <= rem`), so a trailing
/// attribute whose padding bytes are missing is not yielded.
pub fn attr_at(buf: &[u8], offset: usize) -> Option<(Attr<'_>, usize)> {
    let remaining = buf.get(offset..)?;
    let id_len = u32::from_be_bytes(remaining.get(..4)?.try_into().unwrap());
    let raw_len = (id_len & LEN_MASK) as usize;
    if raw_len < 4 || remaining.len() < pad4(raw_len) {
        return None;
    }
    Some((
        Attr {
            id: (id_len & ID_MASK) >> 24,
            extended: id_len & EXTENDED != 0,
            payload: &buf[offset + 4..offset + raw_len],
        },
        offset + pad4(raw_len),
    ))
}

pub struct AttrIter<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl std::fmt::Debug for AttrIter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttrIter")
            .field("bytes", &self.buf.len())
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Attr<'a>;
    fn next(&mut self) -> Option<Attr<'a>> {
        let (attr, next) = attr_at(self.buf, self.offset)?;
        self.offset = next;
        Some(attr)
    }
}

/// Iterate the attrs packed in `payload`.
pub fn iter(payload: &[u8]) -> AttrIter<'_> {
    AttrIter {
        buf: payload,
        offset: 0,
    }
}

/// Iterate blobmsg fields packed in `payload` (skips non-field attrs).
pub fn fields(payload: &[u8]) -> impl Iterator<Item = Field<'_>> {
    iter(payload).filter_map(|attr| attr.field())
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgType {
    Unspec = 0,
    Array = 1,
    Table = 2,
    String = 3,
    Int64 = 4,
    Int32 = 5,
    Int16 = 6,
    Int8 = 7,
    Double = 8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field<'a> {
    pub name: &'a str,
    pub ty: u32,
    pub data: &'a [u8],
}

impl<'a> Field<'a> {
    /// The bytes of a STRING field up to its NUL terminator, whatever they
    /// are: libubox never validates string contents, so a provider can and
    /// does put non-UTF-8 bytes (a Latin-1 or GBK SSID) on the bus.
    pub fn as_bytes(&self) -> Option<&'a [u8]> {
        if self.ty != MsgType::String as u32 {
            return None;
        }
        let end = self.data.iter().position(|&b| b == 0)?;
        Some(&self.data[..end])
    }

    pub fn as_str(&self) -> Option<&'a str> {
        std::str::from_utf8(self.as_bytes()?).ok()
    }

    pub fn as_u32(&self) -> Option<u32> {
        match (self.ty, self.data.len()) {
            (t, 4) if t == MsgType::Int32 as u32 => {
                Some(u32::from_be_bytes(self.data.try_into().unwrap()))
            }
            (t, 2) if t == MsgType::Int16 as u32 => {
                Some(u16::from_be_bytes(self.data.try_into().unwrap()) as u32)
            }
            (t, 1) if t == MsgType::Int8 as u32 => Some(self.data[0] as u32),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        if self.ty == MsgType::Int64 as u32 && self.data.len() == 8 {
            return Some(u64::from_be_bytes(self.data.try_into().unwrap()));
        }
        self.as_u32().map(u64::from)
    }

    pub fn as_bool(&self) -> Option<bool> {
        self.as_u32().map(|v| v != 0)
    }

    pub fn as_f64(&self) -> Option<f64> {
        if self.ty == MsgType::Double as u32 && self.data.len() == 8 {
            return Some(f64::from_bits(u64::from_be_bytes(
                self.data.try_into().unwrap(),
            )));
        }
        None
    }

    /// Nested table/array contents.
    pub fn children(&self) -> impl Iterator<Item = Field<'a>> + 'a {
        fields(self.data)
    }
}

/// Builder for a blob head attr containing raw ubus attrs and/or blobmsg fields.
pub struct BlobBuf {
    data: Vec<u8>,
}

impl std::fmt::Debug for BlobBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobBuf")
            .field("bytes", &self.data.len())
            .finish_non_exhaustive()
    }
}

impl Default for BlobBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl BlobBuf {
    /// Head attr with id 0 and (for now) empty payload.
    pub fn new() -> Self {
        Self::with_capacity(4)
    }

    /// Reserve storage for a known common reply size; larger values still grow.
    pub fn with_capacity(capacity: usize) -> Self {
        let mut data = Vec::with_capacity(capacity.max(4));
        data.extend_from_slice(&[0, 0, 0, 4]);
        Self { data }
    }

    /// blob_buf_init(): drop everything but the empty head, keeping the allocation.
    pub fn reset(&mut self) {
        self.data.clear();
        self.data.extend_from_slice(&[0, 0, 0, 4]);
    }

    /// Reset, discarding backing storage that exceeds `limit` bytes.
    /// A large one-off reply must not set a daemon's permanent footprint.
    pub fn reset_bounded(&mut self, limit: usize) {
        if self.data.capacity() > limit {
            *self = Self::new();
        } else {
            self.reset();
        }
    }

    #[inline]
    fn set_raw_len(&mut self, offset: usize, raw_len: usize) {
        let id_len = u32::from_be_bytes(self.data[offset..offset + 4].try_into().unwrap());
        let value = (id_len & !LEN_MASK) | (raw_len as u32 & LEN_MASK);
        self.data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    #[inline]
    fn open(&mut self, id: u32, extended: bool) -> usize {
        let offset = self.data.len();
        let mut id_len = (id << 24) & ID_MASK;
        if extended {
            id_len |= EXTENDED;
        }
        self.data.extend_from_slice(&(id_len | 4).to_be_bytes());
        offset
    }

    #[inline]
    fn close(&mut self, offset: usize) {
        let raw_len = self.data.len() - offset;
        self.set_raw_len(offset, raw_len);
        let padded = pad4(self.data.len());
        self.data.resize(padded, 0);
    }

    pub fn put(&mut self, id: u32, payload: &[u8]) -> &mut Self {
        let offset = self.open(id, false);
        self.data.extend_from_slice(payload);
        self.close(offset);
        self
    }

    pub fn put_u32(&mut self, id: u32, value: u32) -> &mut Self {
        self.put(id, &value.to_be_bytes())
    }

    pub fn put_u8(&mut self, id: u32, value: u8) -> &mut Self {
        self.put(id, &[value])
    }

    pub fn put_string(&mut self, id: u32, value: &str) -> &mut Self {
        self.put_string_bytes(id, value.as_bytes())
    }

    /// Append the supplied bytes and a terminating NUL, without a temporary
    /// allocation or UTF-8 conversion. Callers choose their C-string length.
    pub fn put_string_bytes(&mut self, id: u32, value: &[u8]) -> &mut Self {
        let offset = self.open(id, false);
        self.data.extend_from_slice(value);
        self.data.push(0);
        self.close(offset);
        self
    }

    /// Start a nested raw attr; finish with `nest_end`.
    pub fn nest_start(&mut self, id: u32) -> usize {
        self.open(id, false)
    }

    pub fn nest_end(&mut self, cookie: usize) {
        self.close(cookie);
    }

    fn msg_open(&mut self, ty: MsgType, name: &str) -> usize {
        self.msg_open_bytes(ty, name.as_bytes())
    }

    #[inline]
    fn msg_open_bytes(&mut self, ty: MsgType, name: &[u8]) -> usize {
        // One reservation for the whole header; the resize supplies the NUL
        // terminator and the padding together.
        let header = 4 + pad4(2 + name.len() + 1);
        self.data.reserve(header);
        let offset = self.open(ty as u32, true);
        self.data
            .extend_from_slice(&(name.len() as u16).to_be_bytes());
        self.data.extend_from_slice(name);
        self.data.resize(offset + header, 0);
        offset
    }

    pub fn msg_string(&mut self, name: &str, value: &str) -> &mut Self {
        self.msg_string_bytes(name, value.as_bytes())
    }

    pub fn msg_string_bytes(&mut self, name: &str, value: &[u8]) -> &mut Self {
        let offset = self.msg_open(MsgType::String, name);
        let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
        self.data.extend_from_slice(&value[..end]);
        self.data.push(0);
        self.close(offset);
        self
    }

    pub fn msg_u32(&mut self, name: &str, value: u32) -> &mut Self {
        let offset = self.msg_open(MsgType::Int32, name);
        self.data.extend_from_slice(&value.to_be_bytes());
        self.close(offset);
        self
    }

    pub fn msg_u16(&mut self, name: &str, value: u16) -> &mut Self {
        let offset = self.msg_open(MsgType::Int16, name);
        self.data.extend_from_slice(&value.to_be_bytes());
        self.close(offset);
        self
    }

    pub fn msg_u64(&mut self, name: &str, value: u64) -> &mut Self {
        let offset = self.msg_open(MsgType::Int64, name);
        self.data.extend_from_slice(&value.to_be_bytes());
        self.close(offset);
        self
    }

    pub fn msg_i64(&mut self, name: &str, value: i64) -> &mut Self {
        let offset = self.msg_open(MsgType::Int64, name);
        self.data.extend_from_slice(&value.to_be_bytes());
        self.close(offset);
        self
    }

    pub fn msg_double(&mut self, name: &str, value: f64) -> &mut Self {
        let offset = self.msg_open(MsgType::Double, name);
        self.data.extend_from_slice(&value.to_bits().to_be_bytes());
        self.close(offset);
        self
    }

    /// Null field (BLOBMSG_TYPE_UNSPEC, empty payload), as libubox emits for
    /// JSON null.
    pub fn msg_null(&mut self, name: &str) -> &mut Self {
        let offset = self.msg_open(MsgType::Unspec, name);
        self.close(offset);
        self
    }

    pub fn msg_bool(&mut self, name: &str, value: bool) -> &mut Self {
        let offset = self.msg_open(MsgType::Int8, name);
        self.data.push(value as u8);
        self.close(offset);
        self
    }

    /// blobmsg_add_field(ty, name, data): append a field with an arbitrary
    /// blobmsg type and already-encoded payload (used to re-emit stored
    /// session data with its original type).
    pub fn msg_field(&mut self, ty: u32, name: &str, data: &[u8]) -> &mut Self {
        let header = 4 + pad4(2 + name.len() + 1);
        self.data.reserve(header + data.len() + 3);
        let offset = self.open(ty, true);
        self.data
            .extend_from_slice(&(name.len() as u16).to_be_bytes());
        self.data.extend_from_slice(name.as_bytes());
        self.data.resize(offset + header, 0);
        self.data.extend_from_slice(data);
        self.close(offset);
        self
    }

    pub fn msg_open_table(&mut self, name: &str) -> usize {
        self.msg_open(MsgType::Table, name)
    }

    pub fn msg_open_array(&mut self, name: &str) -> usize {
        self.msg_open(MsgType::Array, name)
    }

    /// Session ACLs use filesystem paths as object keys, including byte paths.
    pub fn msg_open_array_bytes(&mut self, name: &[u8]) -> usize {
        self.msg_open_bytes(MsgType::Array, name)
    }

    pub fn msg_close(&mut self, cookie: usize) {
        self.close(cookie);
    }

    /// Append already-encoded attrs/fields verbatim.
    pub fn put_raw_fields(&mut self, encoded: &[u8]) -> &mut Self {
        self.data.extend_from_slice(encoded);
        let padded = pad4(self.data.len());
        self.data.resize(padded, 0);
        self
    }

    /// Whole head attr (header + payload), length patched.
    pub fn as_bytes(&mut self) -> &[u8] {
        let raw_len = self.data.len();
        self.set_raw_len(0, raw_len);
        &self.data
    }

    /// Whole head attr, finalized as above, for in-place payload updates.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.as_bytes();
        &mut self.data
    }

    /// Payload of the head attr: the packed attrs/fields only.
    pub fn payload(&self) -> &[u8] {
        &self.data[4..]
    }

    pub fn into_payload(mut self) -> Vec<u8> {
        self.data.drain(..4);
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_offsets_do_not_overflow_or_read_outside_the_packet() {
        let bytes = [0, 0, 0, 4];
        assert!(attr_at(&bytes, 0).is_some());
        for offset in [1, 4, 5, usize::MAX - 3, usize::MAX] {
            assert!(attr_at(&bytes, offset).is_none(), "offset {offset}");
        }
        let truncated = [0, 0, 0, 5, 42];
        assert!(attr_at(&truncated, 0).is_none());
    }

    #[test]
    fn builder_debug_does_not_disclose_encoded_credentials() {
        let mut buffer = BlobBuf::new();
        buffer.msg_string("password", "unlogged-secret");
        assert_eq!(format!("{buffer:?}"), "BlobBuf { bytes: 36, .. }");
    }

    #[test]
    fn mutable_bytes_finalize_head_and_preserve_nested_padding() {
        let mut b = BlobBuf::with_capacity(128);
        b.put_u32(3, 0x11223344);
        let data = b.nest_start(7);
        let array = b.msg_open_array("a");
        let table = b.msg_open_table("");
        b.msg_u16("v", 0x1234).msg_string("s", "xy");
        b.msg_close(table);
        b.msg_close(array);
        b.nest_end(data);
        let storage = b.data.as_ptr();
        // Do not finalize through as_bytes before testing the mutable API.
        let bytes = b.as_mut_bytes();
        assert_eq!(bytes.as_ptr(), storage);
        assert_eq!(
            bytes,
            &[
                0x00, 0x00, 0x00, 0x38, // whole blob: 56 bytes
                0x03, 0x00, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x07, 0x00, 0x00,
                0x2c, // DATA: 44 bytes
                0x81, 0x00, 0x00, 0x28, 0x00, 0x01, b'a', 0x00, 0x82, 0x00, 0x00, 0x20, 0x00, 0x00,
                0x00, 0x00, 0x86, 0x00, 0x00, 0x0a, 0x00, 0x01, b'v', 0x00, 0x12, 0x34, 0x00,
                0x00, // INT16 raw length 10, padded to 12
                0x83, 0x00, 0x00, 0x0b, 0x00, 0x01, b's', 0x00, b'x', b'y', 0x00,
                0x00, // STRING raw length 11, padded to 12
            ]
        );
        bytes[8..12].copy_from_slice(&0xaabbccddu32.to_be_bytes());
        let (head, next) = attr_at(b.as_bytes(), 0).unwrap();
        assert_eq!(next, 56);
        let attrs: Vec<_> = iter(head.payload).collect();
        assert_eq!(attrs[0].as_u32(), Some(0xaabbccdd));
        let array = fields(attrs[1].payload).next().unwrap();
        assert_eq!((array.name, array.ty), ("a", MsgType::Array as u32));
        let table = array.children().next().unwrap();
        assert_eq!(table.ty, MsgType::Table as u32);
        let values: Vec<_> = table.children().collect();
        assert_eq!(values.len(), 2);
        assert_eq!((values[0].name, values[0].as_u32()), ("v", Some(0x1234)));
        assert_eq!(
            (values[1].name, values[1].as_bytes()),
            ("s", Some(&b"xy"[..]))
        );
    }

    #[test]
    fn bounded_reset_clears_old_fields_and_releases_large_storage() {
        let mut b = BlobBuf::with_capacity(128);
        b.msg_string("old", "value");
        let storage = b.data.as_ptr();
        b.reset_bounded(128);
        assert_eq!(b.data.as_ptr(), storage);
        assert!(b.payload().is_empty());
        b.msg_string("large", &"x".repeat(4096));
        b.reset_bounded(128);
        assert!(b.data.capacity() <= 128);
        b.msg_u32("new", 42);
        let fields: Vec<_> = fields(b.payload()).collect();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "new");
        assert_eq!(fields[0].as_u32(), Some(42));
    }

    #[test]
    fn raw_attr_roundtrip() {
        let mut b = BlobBuf::new();
        b.put_u32(3, 0x11223344).put_string(4, "read").put_u8(10, 1);
        let bytes = b.as_bytes().to_vec();
        assert_eq!(bytes.len() % 4, 0);
        let (head, _) = attr_at(&bytes, 0).unwrap();
        assert_eq!(head.id, 0);
        let attrs: Vec<Attr> = iter(head.payload).collect();
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0].id, 3);
        assert_eq!(attrs[0].as_u32(), Some(0x11223344));
        assert_eq!(attrs[1].as_str(), Some("read"));
        assert_eq!(attrs[2].as_u32(), Some(1));
    }

    #[test]
    fn raw_string_bytes_preserve_non_utf8_and_caller_supplied_nuls() {
        let mut b = BlobBuf::new();
        b.put_string_bytes(4, b"caf\xff\0tail").put_u32(3, 7);
        let attrs: Vec<_> = iter(b.payload()).collect();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].payload, b"caf\xff\0tail\0");
        assert_eq!(attrs[0].as_str(), None);
        assert_eq!(attrs[1].as_u32(), Some(7));
    }

    #[test]
    fn blobmsg_field_layout_matches_libubox() {
        // blobmsg_add_u32(&b, "lines", 5): extended attr, type INT32, name "lines"
        let mut b = BlobBuf::new();
        b.msg_u32("lines", 5);
        let bytes = b.as_bytes().to_vec();
        // head(4) + attr hdr(4) + namelen(2) + "lines"(5) + NUL(1) -> pad to 8 + value 4 = 20
        assert_eq!(bytes.len(), 20);
        assert_eq!(&bytes[4..8], &[0x85, 0x00, 0x00, 0x10]);
        let field = fields(&bytes[4..]).next().unwrap();
        assert_eq!(field.name, "lines");
        assert_eq!(field.as_u32(), Some(5));
    }

    // libubox blob_for_each_attr() stops when blob_pad_len(pos) > rem
    // (blob.h:254-256): a trailing attribute whose padding is missing is
    // skipped by C, so it must be skipped here too, at every nesting level.
    #[test]
    fn iter_requires_the_padded_length_to_fit() {
        // one INT16-typed blobmsg field "a": hdr pad4(2+1+1)=4, payload 2:
        // raw_len = 4 + 4 + 2 = 10, pad_len = 12
        let mut v = Vec::new();
        let id_len: u32 = EXTENDED | (MsgType::Int16 as u32) << 24 | 10;
        v.extend_from_slice(&id_len.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(b"a\0");
        v.extend_from_slice(&7u16.to_be_bytes());
        assert_eq!(v.len(), 10, "exactly raw_len bytes, no padding");
        assert_eq!(
            iter(&v).count(),
            0,
            "C sees rem=10 < pad_len=12 and yields nothing"
        );
        assert_eq!(fields(&v).count(), 0);
        // with the padding present both agree
        v.extend_from_slice(&[0, 0]);
        assert_eq!(iter(&v).count(), 1);
        assert_eq!(fields(&v).next().unwrap().as_u32(), Some(7));
    }

    #[test]
    fn string_field_bytes_are_not_validated() {
        let mut b = BlobBuf::new();
        b.msg_field(MsgType::String as u32, "ssid", b"caf\xe9\0");
        let payload = b.into_payload();
        let f = fields(&payload).next().unwrap();
        assert_eq!(f.as_bytes(), Some(&b"caf\xe9"[..]));
        assert_eq!(f.as_str(), None);
    }

    #[test]
    fn nested_table_and_array() {
        let mut b = BlobBuf::new();
        let arr = b.msg_open_array("log");
        let t = b.msg_open_table("");
        b.msg_string("msg", "hello")
            .msg_u32("id", 7)
            .msg_u64("time", 1_700_000_000_123);
        b.msg_close(t);
        b.msg_close(arr);
        let bytes = b.as_bytes().to_vec();
        let log = fields(&bytes[4..]).next().unwrap();
        assert_eq!(log.name, "log");
        assert_eq!(log.ty, MsgType::Array as u32);
        let entry = log.children().next().unwrap();
        let mut names = Vec::new();
        for f in entry.children() {
            names.push(f.name.to_owned());
            if f.name == "time" {
                assert_eq!(f.as_u64(), Some(1_700_000_000_123));
            }
        }
        assert_eq!(names, ["msg", "id", "time"]);
    }
}
