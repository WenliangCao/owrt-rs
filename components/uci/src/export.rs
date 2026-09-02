//! file.c: uci_escape / uci_export_package.

use crate::context::FLAG_EXPORT_NAME;
use crate::model::{OptionValue, Package};
use std::io::{self, Write};

/// uci_escape: `'` becomes `'\''`.
pub fn escape(s: &str) -> String {
    if !s.contains('\'') {
        return s.to_owned();
    }
    s.replace('\'', "'\\''")
}

/// uci_export_package
pub fn export_package<W: Write>(w: &mut W, flags: u32, p: &Package, header: bool) -> io::Result<()> {
    if header {
        writeln!(w, "package {}", escape(&p.name))?;
    }
    for sec in &p.sections {
        write!(w, "\nconfig {}", escape(&sec.ty))?;
        if !sec.anonymous || flags & FLAG_EXPORT_NAME != 0 {
            write!(w, " '{}'", escape(&sec.name))?;
        }
        writeln!(w)?;
        for opt in &sec.options {
            match &opt.value {
                OptionValue::Str(v) => {
                    write!(w, "\toption {}", escape(&opt.name))?;
                    writeln!(w, " '{}'", escape(v))?;
                }
                OptionValue::List(items) => {
                    for item in items {
                        write!(w, "\tlist {}", escape(&opt.name))?;
                        writeln!(w, " '{}'", escape(item))?;
                    }
                }
            }
        }
    }
    writeln!(w)
}
