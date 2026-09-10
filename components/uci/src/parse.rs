//! file.c parser: uci_getln, parse_backslash, parse_*_quote, parse_str,
//! next_arg, assert_eol, uci_parse_package/config/option/line, uci_import,
//! plus uci_parse_argument (used by batch mode and delta parsing) and
//! uci_perror's static `error_info` buffer.
//!
//! The parser works in place on a byte buffer exactly like libuci: decoded
//! characters are written back at `target` (<= `pos`), strings are
//! NUL-terminated inside the buffer, and `pos` is the byte offset reported
//! in parse errors.

use crate::context::{Context, ParseInfo, FLAG_PERROR, FLAG_STRICT};
use crate::error::{Error, Result};
use crate::model::{Package, Ptr, LOOKUP_DONE};
use crate::ops;
use std::io::BufRead;
use std::sync::Mutex;

/// LINEBUF (file.c)
const LINEBUF: usize = 32;

/// The state of a `struct uci_parse_context` that outlives one
/// uci_parse_argument call (see `Pctx::carry`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Carry {
    pub info: ParseInfo,
    bufsz: usize,
}

/// struct uci_parse_context
pub struct Pctx<'r> {
    reader: &'r mut dyn BufRead,
    pub buf: Vec<u8>,
    /// pctx->bufsz: the fgets chunk sizing libuci's NUL handling depends on
    bufsz: usize,
    pub buf_filled: usize,
    pub pos: usize,
    pub line: i32,
    pub byte: usize,
    pub reason: Option<&'static str>,
    pub name: Option<String>,
    /// Index into `ctx.root` of the package being filled (libuci keeps it
    /// outside the root list until uci_switch_config; we add it early and
    /// remove it again on a failed import, which is the only observable
    /// difference).
    pub package: Option<usize>,
    pub section: Option<usize>,
    pub merge: bool,
    /// feof(pctx->file)
    pub eof: bool,
}

fn isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

impl<'r> Pctx<'r> {
    pub fn new(reader: &'r mut dyn BufRead) -> Pctx<'r> {
        Pctx {
            reader,
            buf: Vec::with_capacity(LINEBUF),
            bufsz: LINEBUF,
            buf_filled: 0,
            pos: 0,
            line: 0,
            byte: 0,
            reason: None,
            name: None,
            package: None,
            section: None,
            merge: false,
            eof: false,
        }
    }

    #[inline]
    pub fn char_at(&self, i: usize) -> u8 {
        self.buf.get(i).copied().unwrap_or(0)
    }
    #[inline]
    pub fn cur(&self) -> u8 {
        self.char_at(self.pos)
    }
    fn set_char(&mut self, i: usize, c: u8) {
        if i < self.buf.len() {
            self.buf[i] = c;
        } else if i == self.buf.len() {
            self.buf.push(c);
        }
    }
    /// pctx_str(pctx, i): the NUL-terminated C string at offset i.
    pub fn str_at(&self, i: usize) -> String {
        let end = self.buf[i.min(self.buf.len())..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| i + p)
            .unwrap_or(self.buf.len());
        String::from_utf8_lossy(&self.buf[i.min(self.buf.len())..end]).into_owned()
    }
    /// the NUL-terminated C string at offset i, as bytes (values are not UTF-8 validated)
    pub fn bytes_at(&self, i: usize) -> Vec<u8> {
        let start = i.min(self.buf.len());
        let end = self.buf[start..].iter().position(|&b| b == 0).map(|p| start + p).unwrap_or(self.buf.len());
        self.buf[start..end].to_vec()
    }
    /// strlen(pctx_cur_str(pctx))
    fn cur_strlen(&self) -> usize {
        self.buf[self.pos.min(self.buf.len())..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.buf.len().saturating_sub(self.pos))
    }
    pub fn cur_str_is_empty(&self) -> bool {
        self.cur() == 0
    }

    /// fgets(p, size, file): consume at most `size - 1` bytes, stopping after
    /// a newline. Returns what was consumed; empty means EOF.
    fn fgets(&mut self, size: usize) -> Vec<u8> {
        let max = size.saturating_sub(1);
        let mut out = Vec::new();
        while out.len() < max {
            let available = match self.reader.fill_buf() {
                Ok(b) => b,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            if available.is_empty() {
                break;
            }
            let take = available.len().min(max - out.len());
            match available[..take].iter().position(|&b| b == b'\n') {
                Some(i) => {
                    out.extend_from_slice(&available[..=i]);
                    self.reader.consume(i + 1);
                    break;
                }
                None => {
                    out.extend_from_slice(&available[..take]);
                    self.reader.consume(take);
                }
            }
        }
        out
    }

    /// uci_getln: fetch a line into the buffer at `offset`. libuci reads with
    /// fgets into a buffer that starts at LINEBUF and doubles until the line
    /// ends in a newline, and it measures each chunk with strlen. A NUL byte
    /// therefore drops only the bytes between it and the end of *that* chunk;
    /// the rest of the line is appended by the next fgets and the line still
    /// ends at its own newline. A chunk that starts with a NUL ends the line
    /// where it is without counting it (`if (!p || !*p) return;`).
    pub fn getln(&mut self, offset: usize) {
        // "It takes 2 slots for fgets to read 1 char." libuci doubles once,
        // which is always enough because offset <= bufsz - 1 there.
        while offset + 1 >= self.bufsz {
            self.bufsz *= 2;
        }
        let mut ofs = offset;
        loop {
            self.buf.truncate(ofs);
            let chunk = self.fgets(self.bufsz - ofs);
            if chunk.is_empty() {
                self.eof = true;
                return;
            }
            let len = chunk.iter().position(|&b| b == 0).unwrap_or(chunk.len());
            if len == 0 {
                return;
            }
            self.buf.extend_from_slice(&chunk[..len]);
            ofs += len;
            self.buf_filled = ofs;
            if self.buf[ofs - 1] == b'\n' {
                self.line += 1;
                return;
            }
            self.bufsz *= 2;
        }
    }

    /// uci_parse_error
    fn parse_error<T>(&mut self, reason: &'static str) -> Result<T> {
        self.reason = Some(reason);
        self.byte = self.pos;
        Err(Error::Parse)
    }

    pub fn info(&self) -> ParseInfo {
        ParseInfo {
            reason: self.reason,
            line: self.line,
            byte: self.byte,
        }
    }

    /// uci_parse_argument reuses `ctx->pctx` for every call on the same
    /// stream, so batch mode keeps one context -- its line counter, its grown
    /// buffer and its last parse error -- until something calls uci_cleanup or
    /// hands it a different stream.
    pub fn carry(&self) -> Carry {
        Carry {
            info: self.info(),
            bufsz: self.bufsz,
        }
    }

    pub fn restore(&mut self, c: Carry) {
        self.reason = c.info.reason;
        self.line = c.info.line;
        self.byte = c.info.byte;
        self.bufsz = c.bufsz;
    }

    /// parse_backslash: true if the escaped char is to be parsed.
    fn parse_backslash(&mut self) -> bool {
        self.pos += 1;
        let c = self.cur();
        if c == 0
            || c == b'\n'
            || (c == b'\r' && self.char_at(self.pos + 1) == b'\n' && self.char_at(self.pos + 2) == 0)
        {
            let p = self.pos;
            self.getln(p);
            return false;
        }
        true
    }

    fn skip_whitespace(&mut self) {
        while self.cur() != 0 && isspace(self.cur()) {
            self.pos += 1;
        }
    }

    fn addc(&mut self, target: &mut usize) {
        let c = self.cur();
        self.set_char(*target, c);
        *target += 1;
        self.pos += 1;
    }

    /// uci_increase_pos
    fn increase_pos(&mut self, add: usize) -> bool {
        if self.pos + add > self.buf_filled {
            return false;
        }
        self.pos += add;
        true
    }

    fn parse_double_quote(&mut self, target: &mut usize) -> Result<()> {
        self.pos += 1;
        loop {
            match self.cur() {
                b'"' => {
                    self.pos += 1;
                    return Ok(());
                }
                0 => {
                    let p = self.pos;
                    self.getln(p);
                    if self.cur() == 0 {
                        return self.parse_error("EOF with unterminated \"");
                    }
                }
                b'\\' => {
                    if !self.parse_backslash() {
                        continue;
                    }
                    self.addc(target);
                }
                _ => self.addc(target),
            }
        }
    }

    fn parse_single_quote(&mut self, target: &mut usize) -> Result<()> {
        self.pos += 1;
        loop {
            match self.cur() {
                b'\'' => {
                    self.pos += 1;
                    return Ok(());
                }
                0 => {
                    let p = self.pos;
                    self.getln(p);
                    if self.cur() == 0 {
                        return self.parse_error("EOF with unterminated '");
                    }
                }
                _ => self.addc(target),
            }
        }
    }

    /// parse_str: one shell-style word, decoded in place at `target`.
    fn parse_str(&mut self, target: &mut usize) -> Result<()> {
        let mut next = true;
        'done: loop {
            match self.cur() {
                b'\'' => self.parse_single_quote(target)?,
                b'"' => self.parse_double_quote(target)?,
                b'#' => {
                    let p = self.pos;
                    self.set_char(p, 0);
                    break 'done;
                }
                0 => break 'done,
                b';' => {
                    next = false;
                    break 'done;
                }
                b'\\' => {
                    if self.parse_backslash() {
                        self.addc(target);
                    }
                    // `continue` in a do-while still evaluates the condition
                }
                _ => self.addc(target),
            }
            if self.cur() == 0 || isspace(self.cur()) {
                break;
            }
        }
        if self.cur() != 0 && next {
            self.pos += 1;
        }
        let t = *target;
        self.set_char(t, 0);
        Ok(())
    }

    /// next_arg: returns the buffer offset of the argument (C string).
    pub fn next_arg(&mut self, required: bool, name: bool, package: bool) -> Result<usize> {
        self.skip_whitespace();
        let val = self.pos;
        let mut ptr = self.pos;
        if self.cur() == b';' {
            let p = self.pos;
            self.set_char(p, 0);
            self.pos += 1;
        } else {
            self.parse_str(&mut ptr)?;
        }
        if self.char_at(val) == 0 {
            if required {
                return self.parse_error("insufficient arguments");
            }
            return Ok(val);
        }
        if name && !ops::validate_str(&self.str_at(val), name, package) {
            return self.parse_error("invalid character in name field");
        }
        Ok(val)
    }

    fn assert_eol(&mut self, flags: u32) -> Result<()> {
        self.skip_whitespace();
        let ofs = self.next_arg(false, false, false)?;
        if self.char_at(ofs) != 0 && flags & FLAG_STRICT != 0 {
            return self.parse_error("too many arguments");
        }
        Ok(())
    }

    /// strtok(pctx_cur_str(pctx), " \t") without moving `pos`.
    fn strtok_word(&mut self) -> Option<Vec<u8>> {
        let mut i = self.pos;
        while matches!(self.char_at(i), b' ' | b'\t') {
            i += 1;
        }
        if self.char_at(i) == 0 {
            return None;
        }
        let start = i;
        while self.char_at(i) != 0 && !matches!(self.char_at(i), b' ' | b'\t') {
            i += 1;
        }
        let word = self.buf[start..i].to_vec();
        if self.char_at(i) != 0 {
            self.set_char(i, 0);
        }
        Some(word)
    }

    /// uci_switch_config
    fn switch_config(&mut self, ctx: &mut Context) -> Result<()> {
        if self.package.is_some() {
            // the package is already in ctx.root
            self.package = None;
            self.section = None;
        }
        let Some(name) = self.name.clone() else {
            return Ok(());
        };
        if ctx.find_package(&name).is_some() {
            return Err(Error::Duplicate);
        }
        ctx.root.push(Package::new(&name));
        self.package = Some(ctx.root.len() - 1);
        Ok(())
    }

    fn parse_package(&mut self, ctx: &mut Context, single: bool) -> Result<()> {
        let add = self.cur_strlen() + 1;
        if !self.increase_pos(add) {
            return self.parse_error("package without name");
        }
        let ofs_name = self.next_arg(true, true, true)?;
        self.assert_eol(ctx.flags)?;
        let name = self.str_at(ofs_name);
        if single {
            return Ok(());
        }
        self.name = Some(name);
        self.switch_config(ctx)
    }

    fn parse_config(&mut self, ctx: &mut Context) -> Result<()> {
        if self.package.is_none() {
            if self.name.is_none() {
                return self.parse_error("attempting to import a file without a package name");
            }
            self.switch_config(ctx)?;
        }
        let add = self.cur_strlen() + 1;
        if !self.increase_pos(add) {
            return self.parse_error("config without name");
        }
        let ofs_type = self.next_arg(true, false, false)?;
        let ty = self.str_at(ofs_type);
        if !ops::validate_type(&ty) {
            return self.parse_error("invalid character in type field");
        }
        let ofs_name = self.next_arg(false, true, false)?;
        self.assert_eol(ctx.flags)?;
        let ty = self.str_at(ofs_type);
        let name = self.str_at(ofs_name);
        let pidx = self.package.expect("package set");
        let internal = !self.merge;

        if name.is_empty() {
            let sidx = ops::add_section(ctx, pidx, &ty, internal)?;
            self.section = Some(sidx);
        } else {
            let existing = ctx.root[pidx].find_section(&name);
            if let Some(sidx) = existing {
                if ctx.flags & FLAG_STRICT != 0 && ctx.root[pidx].sections[sidx].ty != ty {
                    return self.parse_error(
                        "section of different type overwrites prior section with same name",
                    );
                }
            }
            let mut ptr = Ptr {
                flags: LOOKUP_DONE,
                p: Some(pidx),
                s: existing,
                package: Some(ctx.root[pidx].name.clone()),
                section: Some(name),
                value: Some(ty.as_bytes().to_vec()),
                ..Ptr::default()
            };
            ops::set(ctx, &mut ptr, internal)?;
            self.section = ptr.s;
        }
        Ok(())
    }

    fn parse_option(&mut self, ctx: &mut Context, list: bool) -> Result<()> {
        let Some(sidx) = self.section else {
            return self.parse_error("option/list command found before the first section");
        };
        let add = self.cur_strlen() + 1;
        if !self.increase_pos(add) {
            return self.parse_error("option without name");
        }
        let ofs_name = self.next_arg(true, true, false)?;
        let ofs_value = self.next_arg(false, false, false)?;
        self.assert_eol(ctx.flags)?;
        let name = self.str_at(ofs_name);
        let value = self.bytes_at(ofs_value);
        let pidx = self.package.expect("package set");
        let internal = !self.merge;
        let s = &ctx.root[pidx].sections[sidx];
        let mut ptr = Ptr {
            flags: LOOKUP_DONE,
            p: Some(pidx),
            s: Some(sidx),
            o: s.find_option(&name),
            package: Some(ctx.root[pidx].name.clone()),
            section: Some(s.name.clone()),
            option: Some(name),
            value: Some(value),
            ..Ptr::default()
        };
        if list {
            ops::add_list(ctx, &mut ptr, internal)
        } else {
            ops::set(ctx, &mut ptr, internal)
        }
    }

    /// uci_parse_line: split `;`-combined commands, dispatch by keyword.
    fn parse_line(&mut self, ctx: &mut Context, single: bool) -> Result<()> {
        self.skip_whitespace();
        loop {
            let Some(word) = self.strtok_word() else {
                return Ok(());
            };
            let rest = &word[1..];
            match word[0] {
                b'#' => return Ok(()),
                b'p' if rest.is_empty() || rest == b"ackage" => self.parse_package(ctx, single)?,
                b'c' if rest.is_empty() || rest == b"onfig" => self.parse_config(ctx)?,
                b'o' if rest.is_empty() || rest == b"ption" => self.parse_option(ctx, false)?,
                b'l' if rest.is_empty() || rest == b"ist" => self.parse_option(ctx, true)?,
                _ => return self.parse_error("invalid command"),
            }
        }
    }
}

/// uci_import. `merge` names a package already in `ctx.root` to merge into
/// (delta-tracked). Returns the index of the last parsed package.
pub fn import(
    ctx: &mut Context,
    reader: &mut dyn BufRead,
    name: Option<&str>,
    merge: Option<usize>,
    single: bool,
) -> Result<Option<usize>> {
    ctx.cleanup();
    let mut pctx = Pctx::new(reader);
    if let (Some(pidx), true) = (merge, single) {
        pctx.package = Some(pidx);
        pctx.merge = true;
    }
    if let Some(n) = name {
        if !ops::validate_package(n) {
            return Err(Error::Inval);
        }
        pctx.name = Some(n.to_owned());
    }
    // packages this import added to root (removed again on a fatal error)
    let root_before = ctx.root.len();

    while !pctx.eof {
        pctx.pos = 0;
        pctx.getln(0);
        if pctx.char_at(0) == 0 {
            continue;
        }
        if let Err(e) = pctx.parse_line(ctx, single) {
            ctx.err = Some(e);
            ctx.pctx = Some(pctx.info());
            if ctx.flags & FLAG_PERROR != 0 {
                perror(ctx, None);
            }
            if e != Error::Parse || ctx.flags & FLAG_STRICT != 0 {
                if !pctx.merge {
                    ctx.root.truncate(root_before);
                }
                return Err(e);
            }
        }
    }

    if pctx.package.is_none() && name.is_some() {
        if let Err(e) = pctx.switch_config(ctx) {
            ctx.err = Some(e);
            ctx.pctx = Some(pctx.info());
            return Err(e);
        }
    }
    let result = pctx.package;
    ctx.cleanup();
    Ok(result)
}

/// uci_parse_argument's fetch of the next line: `*str == NULL` case.
pub fn parse_argument_line(pctx: &mut Pctx) {
    pctx.pos = 0;
    pctx.getln(0);
}

/// uci_parse_argument's argument step: one shell-style word from the
/// current line position (`next_arg(false, false, false)`).
pub fn parse_argument(pctx: &mut Pctx) -> Result<String> {
    let ofs = pctx.next_arg(false, false, false)?;
    Ok(pctx.str_at(ofs))
}

/// parse_argument, but returning the raw bytes (delta values are not UTF-8 validated).
pub fn parse_argument_bytes(pctx: &mut Pctx) -> Result<Vec<u8>> {
    let ofs = pctx.next_arg(false, false, false)?;
    Ok(pctx.bytes_at(ofs))
}

/// The static `error_info[128]` buffer of uci_get_errorstr. It is only
/// rewritten on a parse error while a parser context exists and gets a
/// newline appended on every call, so its content leaks into later messages
/// of the same process exactly as in libuci.
static ERROR_INFO: Mutex<String> = Mutex::new(String::new());

/// uci_perror(ctx, prefix): prints `prefix: <errstr><error_info>` to stderr.
pub fn perror(ctx: &Context, prefix: Option<&str>) {
    let mut info = ERROR_INFO.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(s) = ctx.parse_error_info() {
        let mut s = s;
        s.truncate(126);
        *info = s;
    }
    info.push('\n');
    let err = ctx.err.map(Error::strerror).unwrap_or("Success");
    eprint!(
        "{}{}{}{}",
        prefix.unwrap_or(""),
        if prefix.is_some() { ": " } else { "" },
        err,
        *info
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn load(text: &str) -> (Context, usize) {
        let mut ctx = Context::new();
        let mut r = Cursor::new(text.as_bytes().to_vec());
        let idx = import(&mut ctx, &mut r, Some("t"), None, true).unwrap().unwrap();
        (ctx, idx)
    }

    #[test]
    fn parses_quotes_and_continuations() {
        let (ctx, i) = load(
            "config 'type' 'section'\n\toption 'opt' 'val'\n\toption mul \"\\\"Hello, \\\nWorld.\\'\n\"\n\tlist l 'a b'\n\tlist l c # comment\n",
        );
        let p = &ctx.root[i];
        assert_eq!(p.sections[0].name, "section");
        assert_eq!(p.sections[0].ty, "type");
        let o = &p.sections[0].options;
        assert_eq!(o[0].value, crate::model::OptionValue::Str("val".into()));
        assert_eq!(o[1].value, crate::model::OptionValue::Str("\"Hello, World.'\n".into()));
        assert_eq!(o[2].value, crate::model::OptionValue::List(vec!["a b".into(), "c".into()]));
    }

    #[test]
    fn anonymous_names_and_errors() {
        let (ctx, i) = load("config foo\n\toption x 1\nconfig bar 'n'\n");
        assert!(ctx.root[i].sections[0].name.starts_with("cfg01"));
        assert!(ctx.root[i].sections[0].anonymous);
        assert!(!ctx.root[i].sections[1].anonymous);

        let mut ctx = Context::new();
        let mut r = Cursor::new(b"config\n".to_vec());
        assert_eq!(import(&mut ctx, &mut r, Some("t"), None, true), Err(Error::Parse));
        assert_eq!(ctx.pctx.as_ref().unwrap().reason, Some("invalid command"));
        assert!(ctx.root.is_empty());

        let mut r = Cursor::new(b"option a b\n".to_vec());
        assert_eq!(import(&mut ctx, &mut r, Some("t"), None, true), Err(Error::Parse));
        assert_eq!(
            ctx.pctx.as_ref().unwrap().reason,
            Some("option/list command found before the first section")
        );
        let mut r = Cursor::new(b"config a b c\n".to_vec());
        assert_eq!(import(&mut ctx, &mut r, Some("t"), None, true), Err(Error::Parse));
        assert_eq!(ctx.pctx.as_ref().unwrap().reason, Some("too many arguments"));
        assert_eq!(ctx.pctx.as_ref().unwrap().line, 1);
    }
}
