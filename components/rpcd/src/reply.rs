//! A method normally returns one DATA frame. Only multi-reply methods need a
//! heap-allocated list in addition to their payload storage.

use std::borrow::Cow;

pub struct Reply {
    pub code: i32,
    pub data: Payloads,
}

pub enum Payloads {
    One(Cow<'static, [u8]>),
    Many(Vec<Vec<u8>>),
}

impl Reply {
    pub fn empty(code: i32) -> Self {
        Self { code, data: Payloads::Many(Vec::new()) }
    }

    pub fn one(code: i32, data: Vec<u8>) -> Self {
        Self { code, data: Payloads::One(Cow::Owned(data)) }
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
        match self { Self::One(_) => 1, Self::Many(data) => data.len() }
    }

    pub fn single(&self) -> Option<&[u8]> {
        match self {
            Self::One(data) => Some(data),
            Self::Many(data) if data.len() == 1 => Some(&data[0]),
            Self::Many(_) => None,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        let (one, many): (Option<&[u8]>, &[Vec<u8>]) = match self {
            Self::One(data) => (Some(data), &[]),
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
            Self::Many(data) => &data[index],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
