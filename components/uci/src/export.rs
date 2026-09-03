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

fn quoted<W: Write>(w: &mut W, s: &[u8]) -> io::Result<()> {
    w.write_all(b" '")?;
    w.write_all(&escape(s))?;
    w.write_all(b"'")
}

/// uci_export_package
pub fn export_package<W: Write>(w: &mut W, flags: u32, p: &Package, header: bool) -> io::Result<()> {
    if header {
        w.write_all(b"package ")?;
        w.write_all(&escape(p.name.as_bytes()))?;
        w.write_all(b"\n")?;
    }
    for sec in &p.sections {
        w.write_all(b"\nconfig ")?;
        w.write_all(&escape(sec.ty.as_bytes()))?;
        if !sec.anonymous || flags & FLAG_EXPORT_NAME != 0 {
            quoted(w, sec.name.as_bytes())?;
        }
        w.write_all(b"\n")?;
        for opt in &sec.options {
            match &opt.value {
                OptionValue::Str(v) => {
                    w.write_all(b"\toption ")?;
                    w.write_all(&escape(opt.name.as_bytes()))?;
                    quoted(w, v)?;
                    w.write_all(b"\n")?;
                }
                OptionValue::List(items) => {
                    for item in items {
                        w.write_all(b"\tlist ")?;
                        w.write_all(&escape(opt.name.as_bytes()))?;
                        quoted(w, item)?;
                        w.write_all(b"\n")?;
                    }
                }
            }
        }
    }
    w.write_all(b"\n")
}
