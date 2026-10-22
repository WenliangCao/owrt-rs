//! cli.c: uci_show_value, uci_show_option, uci_show_section, uci_show_package
//! and uci_lookup_section_ref.  Lives in the library so a caller such as
//! reload-config can normalize a package in-process and get byte for byte what
//! `uci show <tuple>` prints, without spawning the CLI.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::model::{OptionValue, Package, Ptr, Section};
use crate::ops;
use std::io::Write;

/// Per-invocation `uci show` rendering state.
pub struct Show {
    /// CLI_FLAG_SHOW_EXT: anonymous sections print as `@type[index]`.
    pub extended: bool,
    /// `-d <str>`: separator between list items.
    pub delimiter: Vec<u8>,
    /// per-type counters behind `@type[index]`
    type_list: Vec<(String, u32)>,
    cur_section_ref: Option<String>,
}

/// `'…'` with each `'` written as `'\''`.
pub fn print_value(out: &mut impl Write, v: &[u8]) {
    let _ = out.write_all(b"'");
    for &c in v {
        if c != b'\'' {
            let _ = out.write_all(&[c]);
        } else {
            let _ = out.write_all(b"'\\''");
        }
    }
    let _ = out.write_all(b"'");
}

impl Show {
    pub fn new(extended: bool, delimiter: &[u8]) -> Show {
        Show {
            extended,
            delimiter: delimiter.to_vec(),
            type_list: Vec::new(),
            cur_section_ref: None,
        }
    }

    /// uci_reset_typelist
    fn reset(&mut self) {
        self.type_list.clear();
        self.cur_section_ref = None;
    }

    /// uci_lookup_section_ref
    fn section_ref(&mut self, s: &Section) -> String {
        if !self.extended {
            return s.name.clone();
        }
        let ti = match self.type_list.iter().position(|(t, _)| *t == s.ty) {
            Some(i) => i,
            None => {
                // new entries are pushed at the list head in C; order is
                // irrelevant for lookups
                self.type_list.push((s.ty.clone(), 0));
                self.type_list.len() - 1
            }
        };
        let ret = if s.anonymous {
            format!("@{}[{}]", self.type_list[ti].0, self.type_list[ti].1)
        } else {
            s.name.clone()
        };
        self.type_list[ti].1 += 1;
        ret
    }

    /// uci_show_value
    pub fn value(&self, out: &mut impl Write, value: &OptionValue, quote: bool) {
        match value {
            OptionValue::Str(s) => {
                if quote {
                    print_value(out, s);
                } else {
                    let _ = out.write_all(s);
                }
                let _ = out.write_all(b"\n");
            }
            OptionValue::List(items) => {
                let mut sep = false;
                for item in items {
                    if sep {
                        let _ = out.write_all(&self.delimiter);
                    }
                    let space = item
                        .iter()
                        .any(|&b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'));
                    if !space && !quote {
                        let _ = out.write_all(item);
                    } else {
                        print_value(out, item);
                    }
                    sep = true;
                }
                let _ = out.write_all(b"\n");
            }
        }
    }

    /// uci_show_option
    pub fn option(&self, out: &mut impl Write, p: &Package, s: &Section, oidx: usize, quote: bool) {
        let o = &s.options[oidx];
        let sname = self.cur_section_ref.as_deref().unwrap_or(&s.name);
        let _ = write!(out, "{}.{}.{}=", p.name, sname, o.name);
        self.value(out, &o.value, quote);
    }

    /// uci_show_section
    pub fn section(&self, out: &mut impl Write, p: &Package, s: &Section) {
        let sname = self.cur_section_ref.as_deref().unwrap_or(&s.name);
        let _ = writeln!(out, "{}.{}={}", p.name, sname, s.ty);
        for i in 0..s.options.len() {
            self.option(out, p, s, i, true);
        }
    }

    /// uci_show_package
    pub fn package(&mut self, out: &mut impl Write, p: &Package) {
        self.reset();
        for s in &p.sections {
            self.cur_section_ref = Some(self.section_ref(s));
            self.section(out, p, s);
        }
        self.reset();
    }
}

/// `uci show <tuple>` exactly as cli.c's package_cmd(CMD_SHOW) does it: an
/// extended lookup, UCI_ERR_NOTFOUND when the tuple does not resolve
/// completely, then the package, section or option it names.  Nothing is
/// written before the lookup has succeeded, so an `Err` leaves `out`
/// untouched -- the empty normalized entry contract C-03 describes.
pub fn tuple(ctx: &mut Context, tuple: &[u8], show: &mut Show, out: &mut impl Write) -> Result<()> {
    let mut ptr = Ptr::default();
    ops::lookup_ptr(ctx, &mut ptr, Some(tuple), true)?;
    if !ptr.complete() {
        return Err(Error::NotFound);
    }
    let p = &ctx.root[ptr.p.ok_or(Error::NotFound)?];
    match (ptr.s, ptr.o) {
        (Some(sidx), Some(oidx)) => show.option(out, p, &p.sections[sidx], oidx, true),
        (Some(sidx), None) => show.section(out, p, &p.sections[sidx]),
        _ => show.package(out, p),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with(dir: &std::path::Path, name: &str, text: &str) -> Context<'static> {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), text).unwrap();
        let mut ctx = Context::new();
        ctx.set_confdir(dir.to_str().unwrap());
        ctx.set_conf2dir("");
        ctx
    }

    #[test]
    fn package_prints_like_the_cli() {
        let dir = std::env::temp_dir().join(format!("uci-show-{}", std::process::id()));
        let mut ctx = ctx_with(&dir, "net", "config interface 'lan'\n\toption proto 'static'\n\tlist dns '1.1.1.1'\n\tlist dns 'a b'\nconfig device\n\toption name 'br'\nconfig device\n\toption name 'eth0'\n");
        let mut out = Vec::new();
        tuple(&mut ctx, b"net", &mut Show::new(true, b" "), &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "net.lan=interface\nnet.lan.proto='static'\nnet.lan.dns='1.1.1.1' 'a b'\nnet.@device[0]=device\nnet.@device[0].name='br'\nnet.@device[1]=device\nnet.@device[1].name='eth0'\n"
        );
        // a dotted name that does not resolve leaves the output empty (C-03)
        let mut out = Vec::new();
        assert!(tuple(
            &mut ctx,
            b"net.nosuch",
            &mut Show::new(true, b" "),
            &mut out
        )
        .is_err());
        assert!(out.is_empty());
        // one that resolves prints the element (C-03c)
        let mut out = Vec::new();
        tuple(
            &mut ctx,
            b"net.lan.proto",
            &mut Show::new(true, b" "),
            &mut out,
        )
        .unwrap();
        assert_eq!(out, b"net.lan.proto='static'\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
