//! delta.c: delta file format, load/apply, save, filter (revert).

use crate::context::{Context, FLAG_SAVED_DELTA};
use crate::error::{Error, Result};
use crate::file;
use crate::model::{Cmd, Delta, Ptr};
use crate::ops;
use crate::parse::{self, Pctx};
use std::fs::File;
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};

/// uci_delta_save
pub fn delta_save<W: Write>(w: &mut W, name: &str, h: &Delta) -> io::Result<()> {
    let prefix = h.cmd.prefix();
    if prefix != 0 {
        w.write_all(&[prefix])?;
    }
    write!(w, "{}.{}", name, h.section)?;
    if let Some(o) = &h.option {
        write!(w, ".{o}")?;
    }
    if h.cmd == Cmd::Remove && h.value.is_none() {
        writeln!(w)
    } else {
        let v = h.value.as_deref().unwrap_or(b"");
        write!(w, "='")?;
        crate::export::write_escaped(w, v)?;
        w.write_all(b"'\n")
    }
}

/// uci_set_savedir: move `dir` to the end of delta_path and make it savedir.
pub fn set_savedir(ctx: &mut Context, dir: &str) {
    if let Some(i) = ctx.delta_path.iter().position(|d| d == dir) {
        ctx.delta_path.remove(i);
    }
    ctx.delta_path.push(dir.to_owned());
    ctx.savedir = dir.to_owned();
}

/// uci_add_delta_path: insert before the savedir (kept last).
pub fn add_delta_path(ctx: &mut Context, dir: &str) -> Result<()> {
    if ctx.delta_path.iter().any(|d| d == dir) {
        return Err(Error::Duplicate);
    }
    let at = ctx.delta_path.len().saturating_sub(1);
    ctx.delta_path.insert(at, dir.to_owned());
    Ok(())
}

/// strtoul(s, NULL, 10) truncated to int, as the C code does for positions.
pub fn strtoul_int(s: &str) -> i32 {
    let t = s.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut v: u64 = 0;
    for b in digits.bytes().take_while(|b| b.is_ascii_digit()) {
        let Some(next) = v
            .checked_mul(10)
            .and_then(|v| v.checked_add((b - b'0') as u64))
        else {
            // strtoul returns ULONG_MAX on overflow, even with a minus sign.
            // The pinned aarch64 C ABI has a 64-bit unsigned long.
            return u64::MAX as i32;
        };
        v = next;
    }
    let v = if neg { v.wrapping_neg() } else { v };
    v as i32
}

/// uci_parse_delta_tuple
pub fn parse_delta_tuple(pctx: &mut Pctx) -> Result<(Cmd, Ptr)> {
    let arg = parse::parse_argument_bytes(pctx)?;
    if !pctx.cur_str_is_empty() {
        return Err(Error::Inval);
    }
    let first = arg.first().copied().unwrap_or(0);
    let c = Cmd::ALL
        .iter()
        .copied()
        .find(|c| c.prefix() == first)
        .unwrap_or(Cmd::Change);
    let rest = if c != Cmd::Change {
        &arg[1..]
    } else {
        &arg[..]
    };
    let mut ptr = Ptr::default();
    ops::parse_ptr(&mut ptr, rest)?;
    if ptr.section.is_none() {
        return Err(Error::Inval);
    }
    if ptr.flags & crate::model::LOOKUP_EXTENDED != 0 {
        return Err(Error::Inval);
    }
    if c != Cmd::Remove && ptr.value.is_none() {
        return Err(Error::Inval);
    }
    match c {
        Cmd::Reorder => {
            if ptr.value.is_none() || ptr.option.is_some() {
                return Err(Error::Inval);
            }
        }
        Cmd::Rename => {
            if !ptr
                .value
                .as_deref()
                .and_then(|v| std::str::from_utf8(v).ok())
                .is_some_and(ops::validate_name)
            {
                return Err(Error::Inval);
            }
        }
        Cmd::ListAdd | Cmd::ListDel if ptr.option.is_none() => {
            return Err(Error::Inval);
        }
        _ => {}
    }
    Ok((c, ptr))
}

/// uci_parse_delta_line
fn parse_delta_line(ctx: &mut Context, pidx: usize, pctx: &mut Pctx) -> Result<()> {
    let (cmd, mut ptr) = parse_delta_tuple(pctx)?;
    if ptr.package.as_deref() != Some(ctx.root[pidx].name.as_str()) {
        return Err(Error::Parse);
    }
    if ctx.flags & FLAG_SAVED_DELTA != 0 {
        ctx.root[pidx].saved_delta.push(Delta {
            cmd,
            section: ptr.section.clone().unwrap_or_default(),
            option: ptr.option.clone(),
            value: ptr.value.clone(),
        });
    }
    ptr.p = Some(pidx);
    match cmd {
        Cmd::Reorder => {
            ops::expand_ptr(ctx, &mut ptr, true)?;
            let Some(sidx) = ptr.s else {
                return Err(Error::NotFound);
            };
            let pos = strtoul_int(&String::from_utf8_lossy(
                ptr.value.as_deref().unwrap_or(b""),
            ));
            ops::reorder_section(ctx, pidx, sidx, pos, true)
        }
        Cmd::Rename => ops::rename(ctx, &mut ptr, true),
        Cmd::Remove => ops::delete(ctx, &mut ptr, true),
        Cmd::ListAdd => ops::add_list(ctx, &mut ptr, true),
        Cmd::ListDel => ops::del_list(ctx, &mut ptr, true),
        Cmd::Add => {
            ops::set(ctx, &mut ptr, true)?;
            if ptr.option.is_none() {
                if let Some(sidx) = ptr.s {
                    ctx.root[pidx].sections[sidx].anonymous = true;
                }
            }
            Ok(())
        }
        Cmd::Change => ops::set(ctx, &mut ptr, true),
    }
}

/// uci_parse_delta: returns the number of lines applied successfully.
fn parse_delta(ctx: &mut Context, reader: &mut dyn io::BufRead, pidx: usize) -> Result<usize> {
    ctx.cleanup();
    let mut pctx = Pctx::new(reader);
    let mut changes = 0;
    while !pctx.eof {
        ctx.check_io_budget()?;
        pctx.pos = 0;
        pctx.getln(0);
        if pctx.char_at(0) == 0 {
            continue;
        }
        if parse_delta_line(ctx, pidx, &mut pctx).is_ok() {
            changes += 1;
        }
    }
    ctx.cleanup();
    Ok(changes)
}

/// uci_load_delta_file: open errors are swallowed (0 changes, no stream).
fn load_delta_file(
    ctx: &mut Context,
    p: Option<usize>,
    filename: &str,
    flush: bool,
) -> Result<(usize, Option<File>)> {
    let stream = match file::open_stream(ctx, filename, false, flush, false) {
        Ok(f) => f,
        Err(e @ (Error::TimedOut | Error::Cancelled)) => return ctx.fail(e),
        Err(e) => {
            ctx.err = Some(e);
            return Ok((0, None));
        }
    };
    let mut changes = 0;
    if let Some(pidx) = p {
        match file::read_whole(ctx, &stream) {
            Ok(data) => {
                let mut reader: &[u8] = &data;
                changes = parse_delta(ctx, &mut reader, pidx)?;
            }
            Err(e @ (Error::TimedOut | Error::Cancelled)) => return ctx.fail(e),
            Err(_) => {}
        }
    }
    Ok((changes, Some(stream)))
}

/// uci_load_delta: apply every delta_path entry, then open (and with
/// `flush`, truncate) the savedir file.
pub fn load_delta(ctx: &mut Context, pidx: usize, flush: bool) -> Result<usize> {
    if !ctx.root[pidx].has_delta {
        return Ok(0);
    }
    let mut changes = 0;
    for i in 0..ctx.delta_path.len() {
        let filename = format!("{}/{}", ctx.delta_path[i], ctx.root[pidx].name);
        let (c, f) = load_delta_file(ctx, Some(pidx), &filename, false)?;
        changes += c;
        if let Some(f) = f {
            crate::sys::unlock(&f);
        }
    }
    let filename = format!("{}/{}", ctx.savedir, ctx.root[pidx].name);
    let (_, f) = load_delta_file(ctx, None, &filename, flush)?;
    if let Some(f) = &f {
        if flush && changes > 0 && f.set_len(0).is_err() {
            crate::sys::unlock(f);
            return Err(Error::Io);
        }
        crate::sys::unlock(f);
    }
    ctx.err = None;
    Ok(changes)
}

/// Replay a commit's delta chain without consuming its saved draft. Keep the
/// savedir lock until the caller has installed the new configuration, so a
/// concurrent save cannot append changes that this commit would then discard.
pub(crate) fn prepare_commit(ctx: &mut Context, pidx: usize) -> Result<(usize, Option<File>)> {
    let mut changes = 0;
    // set_savedir keeps savedir last. Other delta paths remain read-only.
    for dir in ctx.delta_path.clone() {
        if dir == ctx.savedir {
            continue;
        }
        let filename = format!("{}/{}", dir, ctx.root[pidx].name);
        let (count, stream) = load_delta_file(ctx, Some(pidx), &filename, false)?;
        changes += count;
        drop(stream);
    }
    let filename = format!("{}/{}", ctx.savedir, ctx.root[pidx].name);
    ctx.err = None;
    match std::fs::metadata(&filename) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((changes, None)),
        Err(_) => return Err(Error::Io),
        Ok(_) => {}
    }
    let stream = file::open_stream(ctx, &filename, false, true, false)?;
    if ctx.delta_path.contains(&ctx.savedir) {
        let data = file::read_whole(ctx, &stream)?;
        changes += parse_delta(ctx, &mut data.as_slice(), pidx)?;
    }
    ctx.err = None;
    Ok((changes, Some(stream)))
}

/// uci_filter_delta: rewrite `<savedir>/<name>` without the entries matching
/// section/option. Any error (missing file, malformed line) leaves the file
/// untouched, as the C TRAP_SAVE/`done:` path does.
fn filter_delta(ctx: &mut Context, name: &str, section: Option<&str>, option: Option<&str>) {
    let filename = format!("{}/{}", ctx.savedir, name);
    let mut f = match file::open_stream(ctx, &filename, false, true, false) {
        Ok(f) => f,
        Err(e) => {
            ctx.err = Some(e);
            return;
        }
    };
    let mut list: Vec<Delta> = Vec::new();
    let ok = {
        let Ok(data) = file::read_whole(ctx, &f) else {
            crate::sys::unlock(&f);
            return;
        };
        let mut reader: &[u8] = &data;
        let mut pctx = Pctx::new(&mut reader);
        let mut ok = true;
        while !pctx.eof {
            pctx.pos = 0;
            pctx.getln(0);
            if pctx.char_at(0) == 0 {
                continue;
            }
            let (c, ptr) = match parse_delta_tuple(&mut pctx) {
                Ok(x) => x,
                Err(e) => {
                    ctx.err = Some(e);
                    ok = false;
                    break;
                }
            };
            let mut matched = true;
            if let Some(sec) = section {
                if ptr.section.as_deref() != Some(sec) {
                    matched = false;
                }
            }
            if matched {
                if let Some(opt) = option {
                    if ptr.option.as_deref() != Some(opt) {
                        matched = false;
                    }
                }
            }
            if !matched {
                if let Some(sec) = ptr.section {
                    list.push(Delta {
                        cmd: c,
                        section: sec,
                        option: ptr.option,
                        value: ptr.value,
                    });
                }
            }
        }
        ok
    };
    if ok {
        let rebuilt = (|| -> io::Result<()> {
            f.seek(SeekFrom::Start(0))?;
            f.set_len(0)?;
            // libuci writes through stdio; a bare File would turn every token
            // and every escaped byte into its own write(2)
            let mut w = BufWriter::new(&f);
            for h in &list {
                delta_save(&mut w, name, h)?;
            }
            w.flush()
        })();
        if rebuilt.is_err() {
            ctx.err = Some(Error::Io);
        }
    }
    crate::sys::unlock(&f);
    ctx.cleanup();
}

/// uci_revert
pub fn revert(ctx: &mut Context, ptr: &mut Ptr) -> Result<()> {
    ops::expand_ptr(ctx, ptr, false)?;
    let pidx = ptr.p.ok_or(Error::Inval)?;
    if !ctx.root[pidx].has_delta {
        return Err(Error::Inval);
    }
    save(ctx, pidx)?;
    let package = ctx.root[pidx].name.clone();
    let section = ptr.section.clone();
    let option = ptr.option.clone();
    ctx.root.remove(pidx);
    filter_delta(ctx, &package, section.as_deref(), option.as_deref());
    let newidx = file::load(ctx, &package)?;
    // keep the caller's index stable
    if newidx != pidx && pidx < ctx.root.len() {
        let p = ctx.root.remove(newidx);
        ctx.root.insert(pidx, p);
    }
    ptr.p = Some(pidx);
    ctx.err = None;
    Ok(())
}

/// uci_save: append the in-memory delta to `<savedir>/<name>`.
pub fn save(ctx: &mut Context, pidx: usize) -> Result<()> {
    if !ctx.root[pidx].has_delta {
        return file::commit(ctx, pidx, false);
    }
    if ctx.root[pidx].delta.is_empty() {
        return Ok(());
    }
    match std::fs::metadata(&ctx.savedir) {
        Err(_) => {
            let mode = std::fs::metadata(&ctx.confdir)
                .map(|m| m.mode() & 0o7777)
                .unwrap_or(crate::context::DIRMODE);
            let _ = std::fs::DirBuilder::new().mode(mode).create(&ctx.savedir);
        }
        Ok(m) if !m.is_dir() => return Err(Error::Io),
        Ok(_) => {}
    }
    let name = ctx.root[pidx].name.clone();
    let filename = format!("{}/{}", ctx.savedir, name);
    ctx.err = None;
    let f = file::open_stream(ctx, &filename, true, true, true)?;
    let deltas: Vec<Delta> = std::mem::take(&mut ctx.root[pidx].delta);
    // libuci appends through a stdio FILE*; without a BufWriter one `uci set`
    // costs a write(2) per token and per escaped byte
    let mut w = BufWriter::new(&f);
    for h in &deltas {
        if delta_save(&mut w, &name, h).is_err() {
            let _ = w.flush();
            crate::sys::unlock(&f);
            return Err(Error::Io);
        }
    }
    let flushed = w.flush();
    drop(w);
    crate::sys::unlock(&f);
    if flushed.is_err() {
        return Err(Error::Io);
    }
    Ok(())
}
