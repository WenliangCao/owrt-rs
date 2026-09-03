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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delta {
    pub cmd: Cmd,
    pub section: String,
    pub option: Option<String>,
    pub value: Option<Vec<u8>>,
}

/// struct uci_option: UCI_TYPE_STRING or UCI_TYPE_LIST.
#[derive(Clone, Debug, PartialEq, Eq)]
/// option/list values are bytes: libuci keeps them byte for byte (any byte >= 0x20 plus
/// tab/CR/LF) and never assumes UTF-8
pub enum OptionValue {
    Str(Vec<u8>),
    List(Vec<Vec<u8>>),
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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

impl Ptr {
    pub fn complete(&self) -> bool {
        self.flags & LOOKUP_COMPLETE != 0
    }
}
