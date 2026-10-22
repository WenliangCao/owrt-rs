//! A method normally returns one DATA frame. Only multi-reply methods need a
//! heap-allocated list in addition to their payload storage.

use std::borrow::Cow;
use owrt_ubus::BlobBuf;

pub struct Reply {
    pub code: i32,
    pub data: Payloads,
}

pub enum Payloads {
    One(Cow<'static, [u8]>),
    Blob(BlobBuf),
    Many(Vec<Vec<u8>>),
}

impl Reply {
    pub fn empty(code: i32) -> Self {
        Self { code, data: Payloads::Many(Vec::new()) }
    }

    pub fn one(code: i32, data: Vec<u8>) -> Self {
        Self { code, data: Payloads::One(Cow::Owned(data)) }
    }

    /// Keep the Blob's owned allocation and borrow its payload for sending.
    /// The four-byte head stays in that same allocation until the reply drops.
    pub fn blob(code: i32, data: BlobBuf) -> Self {
        Self { code, data: Payloads::Blob(data) }
    }

    pub fn constant(code: i32, data: &'static [u8]) -> Self {
        Self { code, data: Payloads::One(Cow::Borrowed(data)) }
    }

    pub fn many(code: i32, data: Vec<Vec<u8>>) -> Self {
        Self { code, data: Payloads::Many(data) }
    }
}

impl Payloads {
    pub fn len(&self) -> usize {
        match self { Self::One(_) | Self::Blob(_) => 1, Self::Many(data) => data.len() }
    }

    pub fn single(&self) -> Option<&[u8]> {
        match self {
            Self::One(data) => Some(data),
            Self::Blob(data) => Some(data.payload()),
            Self::Many(data) if data.len() == 1 => Some(&data[0]),
            Self::Many(_) => None,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        let (one, many): (Option<&[u8]>, &[Vec<u8>]) = match self {
            Self::One(data) => (Some(data), &[]),
            Self::Blob(data) => (Some(data.payload()), &[]),
            Self::Many(data) => (None, data),
        };
        one.into_iter().chain(many.iter().map(Vec::as_slice))
    }
}

impl std::ops::Index<usize> for Payloads {
    type Output = [u8];
    fn index(&self, index: usize) -> &Self::Output {
        match self {
            Self::One(data) => { assert_eq!(index, 0); data }
            Self::Blob(data) => { assert_eq!(index, 0); data.payload() }
            Self::Many(data) => &data[index],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_blob_payload_keeps_its_allocation_and_wire_bytes() {
        let mut blob = BlobBuf::with_capacity(256);
        let table = blob.msg_open_table("values");
        blob.msg_string_bytes("raw", b"value\xff\0ignored");
        let list = blob.msg_open_array("list");
        blob.msg_string("", "first");
        blob.msg_string("", "");
        blob.msg_close(list);
        blob.msg_close(table);
        let expected = blob.payload().to_vec();
        let pointer = blob.payload().as_ptr();
        let reply = Reply::blob(7, blob);
        assert_eq!((reply.code, reply.data.len()), (7, 1));
        assert_eq!(reply.data.single(), Some(expected.as_slice()));
        assert_eq!(reply.data.single().unwrap().as_ptr(), pointer);
        assert_eq!(reply.data.iter().collect::<Vec<_>>(), [expected.as_slice()]);
        assert_eq!(&reply.data[0], expected);
        // The owned buffer outlives construction and all borrowed access paths.
        let moved = [reply];
        assert_eq!(moved[0].data.single().unwrap().as_ptr(), pointer);
    }

    #[test]
    fn empty_blob_is_one_empty_data_reply_and_multi_replies_keep_order() {
        let empty = Reply::blob(0, BlobBuf::new());
        assert_eq!(empty.data.len(), 1);
        assert_eq!(empty.data.single(), Some(b"".as_slice()));
        assert_eq!(empty.data.iter().collect::<Vec<_>>(), [b"".as_slice()]);
        assert_eq!(&empty.data[0], b"");
        let absent = Reply::empty(0);
        assert_eq!(absent.data.len(), 0);
        assert_eq!(absent.data.single(), None);
        assert_eq!(absent.data.iter().count(), 0);
        let many = Reply::many(0, vec![b"first".to_vec(), Vec::new(), b"last".to_vec()]);
        assert_eq!(many.data.len(), 3);
        assert_eq!(many.data.single(), None);
        assert_eq!(many.data.iter().collect::<Vec<_>>(), [b"first".as_slice(), b"", b"last"]);
        assert_eq!(&many.data[2], b"last");
    }

    #[test]
    #[should_panic]
    fn owned_blob_index_rejects_a_second_data_reply() {
        let reply = Reply::blob(0, BlobBuf::new());
        let _ = &reply.data[1];
    }

    #[test]
    fn empty_payload_is_distinct_from_no_data_and_multi_replies_keep_order() {
        let absent = Reply::empty(4);
        assert_eq!((absent.code, absent.data.len()), (4, 0));
        assert!(absent.data.single().is_none());
        let empty = Reply::one(0, Vec::new());
        assert_eq!(empty.data.single(), Some(b"".as_slice()));
        let many = Reply::many(0, vec![b"first".to_vec(), Vec::new(), b"last".to_vec()]);
        assert!(many.data.single().is_none());
        assert_eq!(many.data.iter().collect::<Vec<_>>(), [b"first".as_slice(), b"", b"last"]);
        assert_eq!(Reply::many(0, vec![b"only".to_vec()]).data.single(), Some(b"only".as_slice()));
    }
}
