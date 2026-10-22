//! file.c: uci_escape / uci_export_package. Values are written byte for
//! byte, as libuci does (they are not UTF-8 validated anywhere).

use crate::context::FLAG_EXPORT_NAME;
use crate::model::{OptionValue, Package};
use std::io::{self, Write};

/// uci_escape: `'` becomes `'\''`.
pub fn escape(s: &[u8]) -> Vec<u8> {
    if !s.contains(&b'\'') {
        return s.to_vec();
    }
    let mut out = Vec::with_capacity(s.len() + 8);
    for &c in s {
        if c == b'\'' {
            out.extend_from_slice(b"'\\''");
        } else {
            out.push(c);
        }
    }
    out
}

/// uci_escape written straight to the stream, no intermediate copy.
pub(crate) fn write_escaped<W: Write>(w: &mut W, s: &[u8]) -> io::Result<()> {
    let mut rest = s;
    while let Some(i) = rest.iter().position(|&c| c == b'\'') {
        w.write_all(&rest[..i])?;
        w.write_all(b"'\\''")?;
        rest = &rest[i + 1..];
    }
    w.write_all(rest)
}

fn quoted<W: Write>(w: &mut W, s: &[u8]) -> io::Result<()> {
    w.write_all(b" '")?;
    write_escaped(w, s)?;
    w.write_all(b"'")
}

/// Bytes one export of `p` needs, give or take the quoting: lets the caller
/// size an output buffer once instead of growing it.
pub fn size_hint(p: &Package) -> usize {
    let mut n = 16 + p.name.len();
    for sec in &p.sections {
        n += 12 + sec.ty.len() + sec.name.len();
        for opt in &sec.options {
            n += match &opt.value {
                OptionValue::Str(v) => 14 + opt.name.len() + v.len(),
                OptionValue::List(items) => {
                    items.iter().map(|i| 12 + opt.name.len() + i.len()).sum()
                }
            };
        }
    }
    n
}

/// uci_export_package
pub fn export_package<W: Write>(
    w: &mut W,
    flags: u32,
    p: &Package,
    header: bool,
) -> io::Result<()> {
    if header {
        w.write_all(b"package ")?;
        write_escaped(w, p.name.as_bytes())?;
        w.write_all(b"\n")?;
    }
    for sec in &p.sections {
        w.write_all(b"\nconfig ")?;
        write_escaped(w, sec.ty.as_bytes())?;
        if !sec.anonymous || flags & FLAG_EXPORT_NAME != 0 {
            quoted(w, sec.name.as_bytes())?;
        }
        w.write_all(b"\n")?;
        for opt in &sec.options {
            match &opt.value {
                OptionValue::Str(v) => {
                    w.write_all(b"\toption ")?;
                    write_escaped(w, opt.name.as_bytes())?;
                    quoted(w, v)?;
                    w.write_all(b"\n")?;
                }
                OptionValue::List(items) => {
                    for item in items {
                        w.write_all(b"\tlist ")?;
                        write_escaped(w, opt.name.as_bytes())?;
                        quoted(w, item)?;
                        w.write_all(b"\n")?;
                    }
                }
            }
        }
    }
    w.write_all(b"\n")
}
