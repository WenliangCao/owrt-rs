// Appended only to the generated private shared_inline16 cache module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordData(DataStorage);

#[derive(Clone, Debug, Eq, PartialEq)]
enum DataStorage {
    Inline { len: u8, bytes: [u8; 16] },
    Heap(Box<[u8]>),
}

impl RecordData {
    pub fn from_slice(source: &[u8]) -> Self {
        if source.len() <= 16 {
            let mut bytes = [0; 16];
            bytes[..source.len()].copy_from_slice(source);
            Self(DataStorage::Inline {
                len: source.len() as u8,
                bytes,
            })
        } else {
            Self(DataStorage::Heap(source.into()))
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match &self.0 {
            DataStorage::Inline { len, bytes } => &bytes[..usize::from(*len)],
            DataStorage::Heap(bytes) => bytes,
        }
    }
}

impl std::ops::Deref for RecordData {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}
