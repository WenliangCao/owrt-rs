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
use crate::model::{OptionValue, Package, Ptr, LOOKUP_DONE};
use crate::ops;
use std::io::{BufRead, Write};
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

impl std::fmt::Debug for Pctx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pctx")
            .field("buffer_bytes", &self.buf.len())
            .field("pos", &self.pos)
            .field("line", &self.line)
            .field("byte", &self.byte)
            .field("reason", &self.reason)
            .field("eof", &self.eof)
            .finish_non_exhaustive()
    }
}

fn isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn skip_space(input: &[u8]) -> &[u8] {
    &input[input
        .iter()
        .position(|&c| !isspace(c))
        .unwrap_or(input.len())..]
}

/// Borrow one complete literal without editing the input. Anything requiring
/// decoding, continuation or special command handling stays with next_arg.
fn literal_word(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let input = skip_space(input);
    if input.first() == Some(&b'\'') {
        let end = 1 + input[1..].iter().position(|&c| c == b'\'' || c == 0)?;
        if input[end] != b'\'' || input.get(end + 1).is_some_and(|&c| !isspace(c)) {
            return None;
        }
        Some((&input[1..end], &input[end + 1..]))
    } else {
        let end = input
            .iter()
            .position(|&c| isspace(c) || matches!(c, 0 | b'\'' | b'"' | b'\\' | b'#' | b';'))
            .unwrap_or(input.len());
        if end == 0 || input.get(end).is_some_and(|&c| !isspace(c)) {
            return None;
        }
        Some((&input[..end], &input[end..]))
    }
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
        self.bytes_view(i).to_vec()
    }
    fn bytes_view(&self, i: usize) -> &[u8] {
        let start = i.min(self.buf.len());
        let end = self.buf[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(self.buf.len());
        &self.buf[start..end]
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
    /// a newline. Append directly to the parser buffer and return the number
    /// consumed. `bufsz`, rather than Vec capacity, still defines C's chunks.
    fn fgets(&mut self, size: usize) -> usize {
        let max = size.saturating_sub(1);
        let start = self.buf.len();
        while self.buf.len() - start < max {
            let available = match self.reader.fill_buf() {
                Ok(b) => b,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            if available.is_empty() {
                break;
            }
            let take = available.len().min(max - (self.buf.len() - start));
            match available[..take].iter().position(|&b| b == b'\n') {
                Some(i) => {
                    self.buf.extend_from_slice(&available[..=i]);
                    self.reader.consume(i + 1);
                    break;
                }
                None => {
                    self.buf.extend_from_slice(&available[..take]);
                    self.reader.consume(take);
                }
            }
        }
        self.buf.len() - start
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
            let consumed = self.fgets(self.bufsz - ofs);
            if consumed == 0 {
                self.eof = true;
                return;
            }
            let len = self.buf[ofs..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(consumed);
            self.buf.truncate(ofs + len);
            if len == 0 {
                return;
            }
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
            || (c == b'\r'
                && self.char_at(self.pos + 1) == b'\n'
                && self.char_at(self.pos + 2) == 0)
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

    /// Complete literal words need no decoding. Keep their bytes in place
    /// and only write the terminator, retaining parse_str's cursor position.
    /// Quotes, escapes, comments and semicolons within an unquoted word use
    /// the general parser, as do joined quotes and words spanning getln.
    fn literal_arg(&mut self) -> Option<usize> {
        if self.cur() != b'\'' {
            let start = self.pos;
            let rest = self.buf.get(start..)?;
            let len = rest
                .iter()
                .position(|&c| {
                    c == 0 || isspace(c) || matches!(c, b'\'' | b'"' | b'\\' | b'#' | b';')
                })
                .unwrap_or(rest.len());
            let end = start + len;
            let delimiter = self.char_at(end);
            if delimiter != 0 && !isspace(delimiter) {
                return None;
            }
            self.pos = end + usize::from(delimiter != 0);
            self.set_char(end, 0);
            return Some(start);
        }
        let start = self.pos + 1;
        let end = start
            + self
                .buf
                .get(start..)?
                .iter()
                .position(|&c| c == b'\'' || c == 0)?;
        if self.buf[end] != b'\'' {
            return None;
        }
        let next = self.char_at(end + 1);
        if next != 0 && !isspace(next) {
            return None;
        }
        self.pos = end + 1 + usize::from(next != 0);
        self.buf[end] = 0;
        Some(start)
    }

    /// next_arg: returns the buffer offset of the argument (C string).
    pub fn next_arg(&mut self, required: bool, name: bool, package: bool) -> Result<usize> {
        self.skip_whitespace();
        let mut val = self.pos;
        let mut ptr = self.pos;
        if self.cur() == b';' {
            let p = self.pos;
            self.set_char(p, 0);
            self.pos += 1;
        } else if let Some(offset) = self.literal_arg() {
            val = offset;
        } else {
            self.parse_str(&mut ptr)?;
        }
        if self.char_at(val) == 0 {
            if required {
                return self.parse_error("insufficient arguments");
            }
            return Ok(val);
        }
        if name
            && !std::str::from_utf8(self.bytes_view(val))
                .is_ok_and(|s| ops::validate_str(s, name, package))
        {
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
    fn strtok_word(&mut self) -> Option<&[u8]> {
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
        if self.char_at(i) != 0 {
            self.set_char(i, 0);
        }
        Some(&self.buf[start..i])
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
        if !std::str::from_utf8(self.bytes_view(ofs_type)).is_ok_and(ops::validate_type) {
            return self.parse_error("invalid character in type field");
        }
        let ofs_name = self.next_arg(false, true, false)?;
        self.assert_eol(ctx.flags)?;
        let ty = std::str::from_utf8(self.bytes_view(ofs_type)).expect("validated section type");
        let name = std::str::from_utf8(self.bytes_view(ofs_name)).expect("validated section name");
        let pidx = self.package.expect("package set");
        let internal = !self.merge;

        if name.is_empty() {
            let sidx = ops::add_section(ctx, pidx, ty, internal)?;
            self.section = Some(sidx);
        } else {
            let existing = ctx.root[pidx].find_section(name);
            // A fresh non-merge section needs no lookup object or delta.
            // Validation already ran before assert_eol, in the usual order.
            if internal && existing.is_none() {
                self.section = Some(ops::alloc_section(
                    &mut ctx.root[pidx],
                    ty,
                    Some(name),
                    None,
                ));
                return Ok(());
            }
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
                section: Some(name.to_owned()),
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
        let name = std::str::from_utf8(self.bytes_view(ofs_name)).expect("validated option name");
        let value = self.bytes_view(ofs_value);
        let pidx = self.package.expect("package set");
        let internal = !self.merge;
        let s = &ctx.root[pidx].sections[sidx];
        let existing = s.find_option(name);
        // A non-merge import already has validated names and resolved indices.
        // Append directly through the same primitive as uci_add_list, including
        // scalar-to-list conversion; no temporary Ptr or delta is needed.
        if internal && list {
            ops::append_list(&mut ctx.root[pidx].sections[sidx], name, existing, value);
            return Ok(());
        }
        // Scalar updates, merge/delta tracking and empty string semantics
        // continue through the general operations below.
        if internal && existing.is_none() && !value.is_empty() {
            let value = OptionValue::Str(value.into());
            ops::alloc_option(&mut ctx.root[pidx].sections[sidx], name, value, None);
            return Ok(());
        }
        let mut ptr = Ptr {
            flags: LOOKUP_DONE,
            p: Some(pidx),
            s: Some(sidx),
            o: existing,
            package: Some(ctx.root[pidx].name.clone()),
            section: Some(s.name.clone()),
            option: Some(name.to_owned()),
            value: Some(value.to_vec()),
            ..Ptr::default()
        };
        if list {
            ops::add_list(ctx, &mut ptr, internal)
        } else {
            ops::set(ctx, &mut ptr, internal)
        }
    }

    /// Fresh imports commonly contain one literal command per physical line.
    /// Validate the complete line before changing anything, then use the same
    /// insertion/append operations as the general parser. Merge, updates and
    /// all syntax needing decoding retain their existing error/side-effect path.
    fn try_literal_line(&mut self, ctx: &mut Context) -> bool {
        let Some(pidx) = self.package.filter(|_| !self.merge) else {
            return false;
        };
        let line = skip_space(&self.buf[self.pos.min(self.buf.len())..]);
        // strtok_word only accepts space/tab after the command itself.
        let Some(end) = line.iter().position(|&c| matches!(c, b' ' | b'\t')) else {
            return false;
        };
        let command = &line[..end];
        if !matches!(command, b"config" | b"option" | b"list") {
            return false;
        }
        let Some((first, rest)) = literal_word(&line[end..]) else {
            return false;
        };
        let rest = skip_space(rest);
        let (second, rest) = if rest.is_empty() {
            (&[][..], rest)
        } else {
            let Some(word) = literal_word(rest) else {
                return false;
            };
            word
        };
        if !skip_space(rest).is_empty() {
            return false;
        }
        if command == b"config" {
            let Some(ty) = std::str::from_utf8(first)
                .ok()
                .filter(|s| ops::validate_type(s))
            else {
                return false;
            };
            let Some(name) = std::str::from_utf8(second)
                .ok()
                .filter(|s| !s.is_empty() && ops::validate_name(s))
            else {
                return false;
            };
            let p = &mut ctx.root[pidx];
            if p.find_section(name).is_some() {
                return false;
            }
            self.section = Some(ops::alloc_section(p, ty, Some(name), None));
        } else {
            let Some(sidx) = self.section else {
                return false;
            };
            let Some(name) = std::str::from_utf8(first)
                .ok()
                .filter(|s| !s.is_empty() && ops::validate_name(s))
            else {
                return false;
            };
            let section = &mut ctx.root[pidx].sections[sidx];
            let existing = section.find_option(name);
            if command == b"list" {
                ops::append_list(section, name, existing, second);
            } else if existing.is_none() && !second.is_empty() {
                ops::alloc_option(section, name, OptionValue::Str(second.into()), None);
            } else {
                return false;
            }
        }
        // import resets pos before the next getln; no following command remains.
        self.pos = self.buf.len();
        true
    }

    /// uci_parse_line: split `;`-combined commands, dispatch by keyword.
    fn parse_line(&mut self, ctx: &mut Context, single: bool) -> Result<()> {
        self.skip_whitespace();
        loop {
            ctx.check_io_budget()?;
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
        if let Err(error) = ctx.check_io_budget() {
            if !pctx.merge {
                ctx.root.truncate(root_before);
            }
            return ctx.fail(error);
        }
        pctx.pos = 0;
        pctx.getln(0);
        if pctx.char_at(0) == 0 {
            continue;
        }
        if pctx.try_literal_line(ctx) {
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
    let mut info = ERROR_INFO
        .lock()
        .expect("UCI error formatting panicked while holding error state");
    if let Some(s) = ctx.parse_error_info() {
        let mut s = s;
        s.truncate(s.floor_char_boundary(126));
        *info = s;
    }
    info.push('\n');
    let err = ctx.err.map(Error::strerror).unwrap_or("Success");
    let _ = write!(
        std::io::stderr(),
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

    #[test]
    fn caller_supplied_unicode_error_reason_can_be_reported_without_panicking() {
        let mut ctx = Context::new();
        ctx.err = Some(Error::Parse);
        ctx.pctx = Some(ParseInfo {
                reason: Some("错误原因错误原因错误原因错误原因错误原因错误原因错误原因错误原因错误原因错误原因错误原因错误原因"),
                line: 1,
                byte: 0,
            });
        perror(&ctx, Some("unicode-test"));
    }

    fn load(text: &str) -> (Context<'static>, usize) {
        let mut ctx = Context::new();
        let mut r = Cursor::new(text.as_bytes().to_vec());
        let idx = import(&mut ctx, &mut r, Some("t"), None, true)
            .unwrap()
            .unwrap();
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
        assert_eq!(
            o[1].value,
            crate::model::OptionValue::Str("\"Hello, World.'\n".into())
        );
        assert_eq!(
            o[2].value,
            crate::model::OptionValue::List(vec!["a b".into(), "c".into()])
        );
    }

    #[test]
    fn plain_runs_preserve_joined_quotes_escapes_and_raw_bytes() {
        let mut ctx = Context::new();
        let mut input = Cursor::new(b"config t s\noption joined pre' middle '\"end\"tail\noption escaped a\\ b\noption multiline 'first\nsecond'\noption raw '\xff\xfe'\noption semi before; option after next\n".to_vec());
        let i = import(&mut ctx, &mut input, Some("t"), None, true)
            .unwrap()
            .unwrap();
        let values: Vec<&OptionValue> = ctx.root[i].sections[0]
            .options
            .iter()
            .map(|o| &o.value)
            .collect();
        let expected: Vec<OptionValue> = [
            &b"pre middle endtail"[..],
            &b"a b"[..],
            &b"first\nsecond"[..],
            // The exact C parser terminates this unquoted value at ';' and
            // consumes the rest of this line; the following option is absent.
            &b"\xff\xfe"[..],
            &b"before"[..],
        ]
        .into_iter()
        .map(|v| OptionValue::Str(v.into()))
        .collect();
        assert_eq!(values, expected.iter().collect::<Vec<_>>());
    }

    #[test]
    fn quoted_words_keep_empty_literals_joins_and_following_arguments() {
        let mut input = Cursor::new(
            b"'first'\t'with # ; \\ literal' '' 'joined'after 'before'\"after\" '\xff'".to_vec(),
        );
        let mut pctx = Pctx::new(&mut input);
        pctx.getln(0);
        for expected in [
            &b"first"[..],
            &b"with # ; \\ literal"[..],
            &b""[..],
            &b"joinedafter"[..],
            &b"beforeafter"[..],
            &b"\xff"[..],
            &b""[..],
        ] {
            assert_eq!(parse_argument_bytes(&mut pctx).unwrap(), expected);
        }
    }

    #[test]
    fn plain_words_keep_cursor_offsets_and_raw_bytes() {
        let mut input = Cursor::new(b"alpha\tbeta gamma".to_vec());
        let mut pctx = Pctx::new(&mut input);
        pctx.getln(0);
        for (expected, pos) in [(&b"alpha"[..], 6), (&b"beta"[..], 11), (&b"gamma"[..], 16)] {
            assert_eq!(parse_argument_bytes(&mut pctx).unwrap(), expected);
            assert_eq!(pctx.pos, pos);
        }
        assert!(parse_argument_bytes(&mut pctx).unwrap().is_empty());

        let mut input = Cursor::new(b"\xff\xfe raw\\ word pre'fix' tail#comment".to_vec());
        let mut pctx = Pctx::new(&mut input);
        pctx.getln(0);
        for expected in [
            &b"\xff\xfe"[..],
            &b"raw word"[..],
            &b"prefix"[..],
            &b"tail"[..],
            &b""[..],
        ] {
            assert_eq!(parse_argument_bytes(&mut pctx).unwrap(), expected);
        }
    }

    #[test]
    fn literal_lines_match_general_parser_and_preserve_fallback_errors() {
        let lines: &[&[u8]] = &[
            b" config type second\n",
            b"config 'type' 'second'\n",
            b"config other initial\n",
            b"config type\n",
            b"config type ''\n",
            b"config type second extra\n",
            b"config\rtype second\n",
            b"config type bad-name\n",
            b"config type 'incomplete\n",
            b"option fresh value\n",
            b"option fresh '\xff # ; \\ bytes'\n",
            b"option fresh\n",
            b"option old value\n",
            b"option fresh 'joined'after\n",
            b"option fresh pre\\ fix\n",
            b"option fresh value # comment\n",
            b"option fresh value; option later ignored\n",
            b"list old first\n",
            b"list old\n",
            b"list fresh ''\n",
            b"list fresh raw\xff\n",
            b"o fresh value\n",
            b"option fresh value",
            b"list fresh 'value'",
            b"# ignored\n",
        ];
        for &line in lines {
            for strict in [false, true] {
                for merge in [false, true] {
                    for section in [None, Some(0)] {
                        let run = |fast: bool| {
                            let (mut ctx, pidx) = load("config base initial\noption old base\n");
                            if !strict {
                                ctx.flags &= !FLAG_STRICT;
                            }
                            let mut reader = Cursor::new(line);
                            let mut pctx = Pctx::new(&mut reader);
                            pctx.package = Some(pidx);
                            pctx.section = section;
                            pctx.merge = merge;
                            pctx.getln(0);
                            let result = if fast && pctx.try_literal_line(&mut ctx) {
                                Ok(())
                            } else {
                                pctx.parse_line(&mut ctx, true)
                            };
                            let error = result.err().map(|e| (e, pctx.info()));
                            (ctx.root, pctx.section, error)
                        };
                        assert_eq!(
                            run(true),
                            run(false),
                            "line={line:?}, strict={strict}, merge={merge}, section={section:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn large_import_preserves_section_order_duplicates_and_package_switches() {
        let mut text = String::from("package first\n");
        for i in (0..40).rev() {
            text.push_str(&format!("config type section{i}\noption value old{i}\n"));
        }
        text.push_str(
            "config type section21\noption value replaced\nconfig type\noption anon yes\n",
        );
        text.push_str("config type section0\nlist members one\nlist members two\npackage second\n");
        for i in 0..35 {
            text.push_str(&format!("config other section{i}\noption value new{i}\n"));
        }
        text.push_str("config other section21\noption value second\n");
        let mut ctx = Context::new();
        import(
            &mut ctx,
            &mut Cursor::new(text.as_bytes()),
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(ctx.root.len(), 2);
        let first = &ctx.root[0];
        assert_eq!(first.sections.len(), 41);
        for (i, section) in first.sections[..40].iter().enumerate() {
            assert_eq!(section.name, format!("section{}", 39 - i));
            assert!(!section.anonymous);
        }
        assert_eq!(
            first.sections[18].options[0].value,
            OptionValue::Str("replaced".into())
        );
        assert!(first.sections[40].anonymous);
        assert_eq!(
            first.sections[39].options[1].value,
            OptionValue::List(vec!["one".into(), "two".into()])
        );
        let second = &ctx.root[1];
        assert_eq!(second.sections.len(), 35);
        assert_eq!(second.sections[21].ty, "other");
        assert_eq!(
            second.sections[21].options[0].value,
            OptionValue::Str("second".into())
        );
    }

    #[test]
    fn large_import_keeps_strict_type_errors_and_merge_updates() {
        let mut text = String::new();
        for i in 0..40 {
            text.push_str(&format!("config type s{i}\noption value old\n"));
        }
        let mut strict = Context::new();
        let conflict = format!("{text}config other s20\n");
        assert_eq!(
            import(
                &mut strict,
                &mut Cursor::new(conflict.as_bytes()),
                Some("t"),
                None,
                true
            ),
            Err(Error::Parse)
        );
        assert!(strict.root.is_empty());
        assert_eq!(
            strict.pctx.unwrap().reason,
            Some("section of different type overwrites prior section with same name")
        );

        let (mut ctx, pidx) = load(&text);
        let mut merge = Cursor::new(b"config type s20\noption value updated\nconfig type added\n");
        import(&mut ctx, &mut merge, Some("t"), Some(pidx), true).unwrap();
        assert_eq!(ctx.root[pidx].sections.len(), 41);
        assert_eq!(
            ctx.root[pidx].sections[20].options[0].value,
            OptionValue::Str("updated".into())
        );
        assert_eq!(ctx.root[pidx].sections[40].name, "added");
    }

    #[test]
    fn anonymous_names_and_errors() {
        let (ctx, i) = load("config foo\n\toption x 1\nconfig bar 'n'\n");
        assert!(ctx.root[i].sections[0].name.starts_with("cfg01"));
        assert!(ctx.root[i].sections[0].anonymous);
        assert!(!ctx.root[i].sections[1].anonymous);

        let mut ctx = Context::new();
        let mut r = Cursor::new(b"config\n".to_vec());
        assert_eq!(
            import(&mut ctx, &mut r, Some("t"), None, true),
            Err(Error::Parse)
        );
        assert_eq!(ctx.pctx.as_ref().unwrap().reason, Some("invalid command"));
        assert!(ctx.root.is_empty());

        let mut r = Cursor::new(b"option a b\n".to_vec());
        assert_eq!(
            import(&mut ctx, &mut r, Some("t"), None, true),
            Err(Error::Parse)
        );
        assert_eq!(
            ctx.pctx.as_ref().unwrap().reason,
            Some("option/list command found before the first section")
        );
        let mut r = Cursor::new(b"config a b c\n".to_vec());
        assert_eq!(
            import(&mut ctx, &mut r, Some("t"), None, true),
            Err(Error::Parse)
        );
        assert_eq!(
            ctx.pctx.as_ref().unwrap().reason,
            Some("too many arguments")
        );
        assert_eq!(ctx.pctx.as_ref().unwrap().line, 1);
    }
}
