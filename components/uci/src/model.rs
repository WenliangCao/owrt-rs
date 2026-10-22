//! Data model mirroring uci.h: package / section / option / delta / ptr.
//! Lists are `Vec`s in libuci list order; elements are addressed by index
//! where the C code holds pointers.

/// enum uci_command (uci.h). The discriminant order matters for
/// `uci_command_char` lookup in delta.c.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    Add,
    Remove,
    Change,
    Rename,
    Reorder,
    ListAdd,
    ListDel,
}

impl Cmd {
    pub const ALL: [Cmd; 7] = [
        Cmd::Add,
        Cmd::Remove,
        Cmd::Change,
        Cmd::Rename,
        Cmd::Reorder,
        Cmd::ListAdd,
        Cmd::ListDel,
    ];

    /// `uci_command_char[]` (delta.c): 0 for Change.
    pub fn prefix(self) -> u8 {
        match self {
            Cmd::Add => b'+',
            Cmd::Remove => b'-',
            Cmd::Change => 0,
            Cmd::Rename => b'@',
            Cmd::Reorder => b'^',
            Cmd::ListAdd => b'|',
            Cmd::ListDel => b'~',
        }
    }
}

/// struct uci_delta: `e.name` is the option (may be NULL).
#[derive(Clone, PartialEq, Eq)]
pub struct Delta {
    pub cmd: Cmd,
    pub section: String,
    pub option: Option<String>,
    pub value: Option<Vec<u8>>,
}

/// Owned immutable UCI value. Short values need no separate heap allocation;
/// longer values retain their complete bytes in an exact-sized allocation.
/// The inline size keeps this representation the size of Vec on 64-bit hosts.
#[derive(PartialEq, Eq)]
pub struct Bytes(StoredBytes);

#[derive(Clone, PartialEq, Eq)]
enum StoredBytes {
    Inline { len: u8, data: [u8; 15] },
    Heap(Box<[u8]>),
}

impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bytes").field("len", &self.len()).finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Delta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Delta").field("cmd", &self.cmd)
            .field("section", &self.section).field("option", &self.option)
            .field("value_len", &self.value.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

impl Clone for Bytes {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }

    fn clone_from(&mut self, source: &Self) {
        match (&mut self.0, &source.0) {
            (StoredBytes::Heap(dst), StoredBytes::Heap(src)) if dst.len() == src.len() => {
                dst.copy_from_slice(src);
            }
            _ => self.0 = source.0.clone(),
        }
    }
}

impl Bytes {
    pub fn as_slice(&self) -> &[u8] {
        match &self.0 {
            StoredBytes::Inline { len, data } => &data[..usize::from(*len)],
            StoredBytes::Heap(data) => data,
        }
    }
}

impl Default for Bytes {
    fn default() -> Self {
        Self(StoredBytes::Inline { len: 0, data: [0; 15] })
    }
}

impl From<&[u8]> for Bytes {
    fn from(value: &[u8]) -> Self {
        if value.len() <= 15 {
            let mut data = [0; 15];
            data[..value.len()].copy_from_slice(value);
            Self(StoredBytes::Inline { len: value.len() as u8, data })
        } else {
            Self(StoredBytes::Heap(value.into()))
        }
    }
}

impl From<&str> for Bytes {
    fn from(value: &str) -> Self {
        Self::from(value.as_bytes())
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(value: Vec<u8>) -> Self {
        if value.len() <= 15 {
            Self::from(value.as_slice())
        } else {
            Self(StoredBytes::Heap(value.into_boxed_slice()))
        }
    }
}

impl std::ops::Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

#[cfg(test)]
mod storage_tests {
    use super::{Bytes, Section};

    #[test]
    fn metadata_owns_utf8_across_short_and_long_values() {
        for value in ["", "123456789012345", "1234567890123456", "接口名称", "接口名称非常长的元数据"] {
            let source = value.to_owned();
            let section = Section {
                name: source.clone(),
                ty: source.clone(),
                anonymous: false,
                options: vec![],
            };
            drop(source);
            assert_eq!(section.name.as_str(), value);
            assert_eq!(section.ty.as_bytes(), value.as_bytes());
            assert_eq!(section.clone(), section);
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn inline_values_do_not_enlarge_each_value() {
        assert!(std::mem::size_of::<Bytes>() <= std::mem::size_of::<Vec<u8>>());
    }

    #[test]
    fn debug_omits_configuration_values_including_delta_and_lookup_data() {
        use super::{Cmd, Delta, OptionValue, Ptr};
        for secret in ["password", "long-wifi-password-never-log"] {
            let bytes = secret.as_bytes().to_vec();
            let values = [
                format!("{:?}", Bytes::from(secret)),
                format!("{:?}", OptionValue::List(vec![secret.into()])),
                format!("{:?}", Delta { cmd: Cmd::Change, section: "radio0".into(),
                    option: Some("key".into()), value: Some(bytes.clone()) }),
                format!("{:?}", Ptr { value: Some(bytes.clone()), ..Ptr::default() }),
            ];
            for rendered in values {
                assert!(!rendered.contains(secret), "{rendered}");
                assert!(!rendered.contains(&format!("{bytes:?}")), "{rendered}");
            }
        }
    }
}

/// struct uci_option: UCI_TYPE_STRING or UCI_TYPE_LIST. Values are bytes:
/// libuci preserves them and never assumes UTF-8.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OptionValue {
    Str(Bytes),
    List(Vec<Bytes>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opt {
    pub name: String,
    pub value: OptionValue,
}

/// struct uci_section. `name` is always set once the section is visible to
/// callers (anonymous sections get their `cfgXXXXXX` name in
/// `uci_fixup_section`, which runs in `uci_add_section` right after alloc).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub ty: String,
    pub anonymous: bool,
    pub options: Vec<Opt>,
}

/// struct uci_package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub sections: Vec<Section>,
    pub has_delta: bool,
    pub uses_conf2: bool,
    pub path: Option<String>,
    /// `n_section`: incremented in uci_alloc_section, decremented when
    /// uci_set replaces a section's type; never decremented on delete.
    pub n_section: i32,
    pub delta: Vec<Delta>,
    pub saved_delta: Vec<Delta>,
}

impl Package {
    /// uci_alloc_package
    pub fn new(name: &str) -> Package {
        Package {
            name: name.to_owned(),
            sections: Vec::new(),
            has_delta: false,
            uses_conf2: false,
            path: None,
            n_section: 0,
            delta: Vec::new(),
            saved_delta: Vec::new(),
        }
    }

    /// uci_lookup_list(&p->sections, name)
    pub fn find_section(&self, name: &str) -> Option<usize> {
        self.sections.iter().position(|s| s.name == name)
    }
}

impl Section {
    /// uci_lookup_list(&s->options, name)
    pub fn find_option(&self, name: &str) -> Option<usize> {
        self.options.iter().position(|o| o.name == name)
    }
}

/// enum uci_type subset used by struct uci_ptr `target`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Unspec,
    Package,
    Section,
    Option,
}

pub const LOOKUP_DONE: u32 = 1 << 0;
pub const LOOKUP_COMPLETE: u32 = 1 << 1;
pub const LOOKUP_EXTENDED: u32 = 1 << 2;

/// struct uci_ptr with indices into `Context::root` / package / section in
/// place of the C pointers.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Ptr {
    pub target: Option<Target>,
    pub flags: u32,
    pub p: Option<usize>,
    pub s: Option<usize>,
    pub o: Option<usize>,
    pub package: Option<String>,
    pub section: Option<String>,
    pub option: Option<String>,
    pub value: Option<Vec<u8>>,
}

impl std::fmt::Debug for Ptr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ptr").field("target", &self.target).field("flags", &self.flags)
            .field("p", &self.p).field("s", &self.s).field("o", &self.o)
            .field("package", &self.package).field("section", &self.section)
            .field("option", &self.option)
            .field("value_len", &self.value.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

impl Ptr {
    pub fn complete(&self) -> bool {
        self.flags & LOOKUP_COMPLETE != 0
    }
}
