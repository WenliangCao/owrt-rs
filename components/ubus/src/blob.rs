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
pub fn attr_at(buf: &[u8], offset: usize) -> Option<(Attr<'_>, usize)> {
    if buf.len() < offset + 4 {
        return None;
    }
    let id_len = u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap());
    let raw_len = (id_len & LEN_MASK) as usize;
    if raw_len < 4 || buf.len() < offset + raw_len {
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
    pub fn as_str(&self) -> Option<&'a str> {
        if self.ty != MsgType::String as u32 {
            return None;
        }
        let end = self.data.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&self.data[..end]).ok()
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

    /// Nested table/array contents.
    pub fn children(&self) -> impl Iterator<Item = Field<'a>> + 'a {
        fields(self.data)
    }
}

/// Builder for a blob head attr containing raw ubus attrs and/or blobmsg fields.
pub struct BlobBuf {
    data: Vec<u8>,
}

impl Default for BlobBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl BlobBuf {
    /// Head attr with id 0 and (for now) empty payload.
    pub fn new() -> Self {
        Self {
            data: vec![0, 0, 0, 4],
        }
    }

    fn set_raw_len(&mut self, offset: usize, raw_len: usize) {
        let id_len = u32::from_be_bytes(self.data[offset..offset + 4].try_into().unwrap());
        let value = (id_len & !LEN_MASK) | (raw_len as u32 & LEN_MASK);
        self.data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn open(&mut self, id: u32, extended: bool) -> usize {
        let offset = self.data.len();
        let mut id_len = (id << 24) & ID_MASK;
        if extended {
            id_len |= EXTENDED;
        }
        self.data.extend_from_slice(&(id_len | 4).to_be_bytes());
        offset
    }

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
        let offset = self.open(id, false);
        self.data.extend_from_slice(value.as_bytes());
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
        let offset = self.open(ty as u32, true);
        self.data
            .extend_from_slice(&(name.len() as u16).to_be_bytes());
        self.data.extend_from_slice(name.as_bytes());
        self.data.push(0);
        let hdr_end = offset + 4 + pad4(2 + name.len() + 1);
        self.data.resize(hdr_end, 0);
        offset
    }

    pub fn msg_string(&mut self, name: &str, value: &str) -> &mut Self {
        let offset = self.msg_open(MsgType::String, name);
        self.data.extend_from_slice(value.as_bytes());
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

    pub fn msg_u64(&mut self, name: &str, value: u64) -> &mut Self {
        let offset = self.msg_open(MsgType::Int64, name);
        self.data.extend_from_slice(&value.to_be_bytes());
        self.close(offset);
        self
    }

    pub fn msg_bool(&mut self, name: &str, value: bool) -> &mut Self {
        let offset = self.msg_open(MsgType::Int8, name);
        self.data.push(value as u8);
        self.close(offset);
        self
    }

    pub fn msg_open_table(&mut self, name: &str) -> usize {
        self.msg_open(MsgType::Table, name)
    }

    pub fn msg_open_array(&mut self, name: &str) -> usize {
        self.msg_open(MsgType::Array, name)
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
