//! rpcd uci.c port on top of `owrt_uci` (contract C7). Each ubus call gets a
//! fresh uci context whose delta path is set the way `rpc_uci_set_savedir`
//! does; `ctx.err` tracking mirrors the C cursor so status mapping (including
//! the places where a trailing `uci_unload` resets the error) stays literal.

use crate::session::{arg, arg_str, Reply};
use crate::Ctx;
use owrt_ubus::blob::{self, Field, MsgType};
use owrt_ubus::{status, BlobBuf, Connection};
use owrt_uci::model::{LOOKUP_COMPLETE, LOOKUP_EXTENDED};
use owrt_uci::{delta, file, ops, Cmd, Context, Error, OptionValue, Ptr};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::time::{Duration, Instant};

pub const RUN_DIR: &str = crate::session::RUN_DIR;
pub const SNAPSHOT_FILES: &str = "/var/run/rpcd-rs/snapshot-files/";
pub const SNAPSHOT_DELTA: &str = "/var/run/rpcd-rs/snapshot-delta/";
pub const UCI_DIR: &str = "/etc/config/";
pub const APPLY_TIMEOUT: i32 = 60;

fn savedir_of(sid: &str) -> String {
    format!("{RUN_DIR}/uci-{sid}")
}

/// Pending rollback state (`apply_sid` lives in the session store; the timer here).
#[derive(Default)]
pub struct Apply {
    pub deadline: Option<Instant>,
    rollback_in_progress: bool,
    pending_events: std::collections::BTreeSet<String>,
    last_event: Option<String>,
    pub event_retry: Option<Instant>,
}

pub fn signature() -> Vec<(&'static str, Vec<(&'static str, MsgType)>)> {
    use MsgType::*;
    let get = vec![("config", String), ("section", String), ("option", String), ("type", String), ("match", Table), ("ubus_rpc_session", String)];
    vec![
        ("configs", vec![]),
        ("get", get.clone()),
        ("state", get),
        ("add", vec![("config", String), ("type", String), ("name", String), ("values", Table), ("ubus_rpc_session", String)]),
        ("set", vec![("config", String), ("section", String), ("type", String), ("match", Table), ("values", Table), ("ubus_rpc_session", String)]),
        ("delete", vec![("config", String), ("section", String), ("type", String), ("match", Table), ("option", String), ("options", Array), ("ubus_rpc_session", String)]),
        ("rename", vec![("config", String), ("section", String), ("option", String), ("name", String), ("ubus_rpc_session", String)]),
        ("order", vec![("config", String), ("sections", Array), ("ubus_rpc_session", String)]),
        ("changes", vec![("config", String), ("ubus_rpc_session", String)]),
        ("revert", vec![("config", String), ("ubus_rpc_session", String)]),
        ("commit", vec![("config", String), ("ubus_rpc_session", String)]),
        ("apply", vec![("rollback", Int8), ("timeout", Int32), ("ubus_rpc_session", String)]),
        ("confirm", vec![("ubus_rpc_session", String)]),
        ("rollback", vec![("ubus_rpc_session", String)]),
        ("reload_config", vec![]),
    ]
}

// ------------------------------------------------------------ helpers

/// rpc_uci_verify_str
fn verify_str(name: &str, mut extended: bool, ty: bool) -> bool {
    let b = name.as_bytes();
    if b.is_empty() {
        return false;
    }
    if extended && b[0] != b'@' {
        extended = false;
    }
    let mut i = if extended { 1 } else { 0 };
    while i < b.len() {
        let c = b[i];
        if !c.is_ascii_alphanumeric() && c != b'_' && ((!ty && !extended) || c != b'-') {
            break;
        }
        i += 1;
    }
    if extended {
        if b.get(i) != Some(&b'[') {
            return false;
        }
        i += 1;
        // strtol(++c, &e, 10): optional whitespace/sign then digits
        let start = i;
        let mut j = i;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < b.len() && (b[j] == b'-' || b[j] == b'+') {
            j += 1;
        }
        let d0 = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        let e = if j > d0 { j } else { start };
        return e > start && b.get(e) == Some(&b']') && e + 1 == b.len();
    }
    i == b.len()
}
fn verify_name(s: &str) -> bool {
    verify_str(s, false, false)
}
fn verify_type(s: &str) -> bool {
    verify_str(s, false, true)
}
fn verify_section(s: &str) -> bool {
    verify_str(s, true, false)
}

/// Record a libuci call result the way UCI_HANDLE_ERR / the error path do.
macro_rules! tr {
    ($ctx:expr, $e:expr) => {{
        let r = $e;
        $ctx.err = r.as_ref().err().copied();
        r
    }};
}

/// rpc_uci_status
fn uci_status(ctx: &Context) -> i32 {
    uci_error(ctx.err)
}

fn uci_error(error: Option<Error>) -> i32 {
    match error {
        None => status::OK,
        Some(Error::Inval) => status::INVALID_ARGUMENT,
        Some(Error::NotFound) => status::NOT_FOUND,
        Some(_) => status::UNKNOWN_ERROR,
    }
}

/// rpc_uci_replace_savedir: drop every delta path, then uci_set_savedir(path).
fn replace_savedir(ctx: &mut Context, path: Option<&str>) {
    ctx.delta_path.clear();
    if let Some(p) = path {
        delta::set_savedir(ctx, p);
    }
}

/// rpc_uci_set_savedir
fn set_savedir(ctx: &mut Context, sid: Option<&str>) {
    match sid {
        None => replace_savedir(ctx, Some("/tmp/.uci")),
        Some(sid) => replace_savedir(ctx, Some(&savedir_of(sid))),
    }
}

fn read_access(rctx: &Ctx, ctx: &mut Context, sid: Option<&str>, config: &str) -> bool {
    set_savedir(ctx, sid);
    match sid {
        None => true,
        Some(sid) => rctx.sessions.borrow_mut().access(sid, "uci", config, "read"),
    }
}

fn write_access(rctx: &Ctx, ctx: &mut Context, sid: Option<&str>, config: &str) -> bool {
    set_savedir(ctx, sid);
    match sid {
        None => true,
        Some(sid) => rctx.sessions.borrow_mut().access(sid, "uci", config, "write"),
    }
}

/// rpc_uci_format_blob
fn format_blob(v: &Field) -> Option<String> {
    match v.ty {
        t if t == MsgType::String as u32 => v.as_str().map(str::to_owned),
        t if t == MsgType::Int64 as u32 => Some(u64::from_be_bytes(v.data.get(..8)?.try_into().ok()?).to_string()),
        t if t == MsgType::Int32 as u32 => Some(u32::from_be_bytes(v.data.get(..4)?.try_into().ok()?).to_string()),
        t if t == MsgType::Int16 as u32 => Some(u16::from_be_bytes(v.data.get(..2)?.try_into().ok()?).to_string()),
        t if t == MsgType::Int8 as u32 => Some(if *v.data.first()? != 0 { "1" } else { "0" }.to_owned()),
        _ => None,
    }
}

/// rpc_uci_lookup
fn lookup(ctx: &mut Context, ptr: &mut Ptr) -> owrt_uci::Result<()> {
    let mut l = ptr.clone();
    if l.s.is_none() && l.section.as_deref().is_some_and(|s| s.starts_with('@')) {
        l.flags |= LOOKUP_EXTENDED;
    }
    let r = tr!(ctx, ops::lookup_ptr(ctx, &mut l, None, true));
    if r.is_ok() {
        *ptr = l;
    }
    r
}

/// rpc_uci_match_option
fn match_option(o: &OptionValue, cmp: &str) -> bool {
    match o {
        OptionValue::List(items) => items.iter().any(|e| e.as_slice() == cmp.as_bytes()),
        OptionValue::Str(s) => s.split(|&b| b == b' ' || b == b'\t').filter(|t| !t.is_empty()).any(|t| t == cmp.as_bytes()),
    }
}

/// rpc_uci_match_section
fn match_section(s: &owrt_uci::Section, ty: Option<&str>, matches: Option<&[u8]>) -> bool {
    if let Some(t) = ty {
        if s.ty != t {
            return false;
        }
    }
    let Some(matches) = matches else { return true };
    let mut matched = false;
    let mut empty = true;
    for cur in blob::fields(matches) {
        let Some(cmp) = format_blob(&cur) else { continue };
        for o in &s.options {
            if o.name != cur.name {
                continue;
            }
            if !match_option(&o.value, &cmp) {
                return false;
            }
            matched = true;
        }
        empty = false;
    }
    empty || matched
}

fn dump_option(b: &mut BlobBuf, o: &OptionValue, name: &str) {
    match o {
        OptionValue::Str(s) => {
            b.msg_string_bytes(name, s);
        }
        OptionValue::List(items) => {
            let c = b.msg_open_array(name);
            for e in items {
                b.msg_string_bytes("", e);
            }
            b.msg_close(c);
        }
    }
}

fn dump_section(b: &mut BlobBuf, s: &owrt_uci::Section, name: &str, index: i32) {
    let c = b.msg_open_table(name);
    b.msg_bool(".anonymous", s.anonymous);
    b.msg_string(".type", &s.ty);
    b.msg_string(".name", &s.name);
    if index >= 0 {
        b.msg_u32(".index", index as u32);
    }
    for o in &s.options {
        dump_option(b, &o.value, &o.name);
    }
    b.msg_close(c);
}

fn dump_package(b: &mut BlobBuf, p: &owrt_uci::Package, name: &str, ty: Option<&str>, matches: Option<&[u8]>) {
    let c = b.msg_open_table(name);
    for (i, s) in p.sections.iter().enumerate() {
        if !match_section(s, ty, matches) {
            continue;
        }
        dump_section(b, s, &s.name, i as i32);
    }
    b.msg_close(c);
}

// Whole-package dumps visit every section, so size their Blob once. This is
// only an allocation hint: oversized replies retain normal BlobBuf growth.
fn package_reply_capacity(p: &owrt_uci::Package) -> usize {
    fn header(name: &str) -> usize { 4 + blob::pad4(3 + name.len()) }
    fn string(name: &str, len: usize) -> usize { header(name) + blob::pad4(len + 1) }
    let mut size = 4 + header("values");
    for s in &p.sections {
        size += header(&s.name) + header(".anonymous") + 4
            + string(".type", s.ty.len()) + string(".name", s.name.len())
            + header(".index") + 4;
        for o in &s.options {
            size += match &o.value {
                OptionValue::Str(value) => string(&o.name, value.len()),
                OptionValue::List(values) => header(&o.name)
                    + values.iter().map(|v| string("", v.len())).sum::<usize>(),
            };
        }
        // Avoid reserving an unbounded estimate before serialization.
        if size >= 64 * 1024 { return 64 * 1024; }
    }
    size
}

fn code(c: i32) -> Reply {
    Reply::empty(c)
}
fn with(c: i32, d: Vec<u8>) -> Reply {
    Reply::one(c, d)
}

fn field_data<'a>(raw: &'a [u8], name: &str, ty: MsgType) -> Option<&'a [u8]> {
    arg(raw, name, ty).map(|f| f.data)
}

// ------------------------------------------------------------ methods

fn get_common(rctx: &Ctx, raw: &[u8], use_state: bool) -> Reply {
    let Some(config) = arg_str(raw, "config") else { return code(status::INVALID_ARGUMENT) };
    let sid = arg_str(raw, "ubus_rpc_session");
    let mut ctx = Context::new();
    if !read_access(rctx, &mut ctx, sid, config) {
        return code(status::PERMISSION_DENIED);
    }
    let mut ptr = Ptr { package: Some(config.to_owned()), ..Ptr::default() };
    if use_state {
        delta::set_savedir(&mut ctx, "/var/state");
    }
    let Ok(pidx) = tr!(ctx, file::load_cached(&mut ctx, config, &mut rctx.uci_read_cache.borrow_mut())) else {
        return code(uci_status(&ctx));
    };
    if let Some(section) = arg_str(raw, "section") {
        ptr.section = Some(section.to_owned());
        if let Some(option) = arg_str(raw, "option") {
            ptr.option = Some(option.to_owned());
        }
    }
    let mut result = Reply::empty(0);
    if lookup(&mut ctx, &mut ptr).is_ok() && ptr.flags & LOOKUP_COMPLETE != 0 {
        let p = &ctx.root[pidx];
        let (ty, matches) = if ptr.s.is_none() {
            (arg_str(raw, "type"), field_data(raw, "match", MsgType::Table))
        } else { (None, None) };
        let capacity = if ptr.s.is_none() && ty.is_none() && matches.is_none() {
            package_reply_capacity(p)
        } else { 256 };
        let mut b = BlobBuf::with_capacity(capacity);
        match (ptr.s, ptr.o) {
            (None, _) => dump_package(&mut b, p, "values", ty, matches),
            (Some(s), None) => dump_section(&mut b, &p.sections[s], "values", -1),
            (Some(s), Some(o)) => dump_option(&mut b, &p.sections[s].options[o].value, "value"),
        }
        result = Reply::blob(0, b);
    }
    // out: uci_unload resets the cursor error before rpc_uci_status()
    rctx.uci_read_cache.borrow_mut().recycle(ctx.root.remove(pidx));
    ctx.err = None;
    result.code = uci_status(&ctx);
    result
}

fn add(rctx: &Ctx, raw: &[u8]) -> Reply {
    let (Some(config), Some(ty)) = (arg_str(raw, "config"), arg_str(raw, "type")) else {
        return code(status::INVALID_ARGUMENT);
    };
    let sid = arg_str(raw, "ubus_rpc_session");
    let mut ctx = Context::new();
    if !write_access(rctx, &mut ctx, sid, config) {
        return code(status::PERMISSION_DENIED);
    }
    if !verify_type(ty) {
        return code(status::INVALID_ARGUMENT);
    }
    let name = arg_str(raw, "name");
    if let Some(n) = name {
        if !verify_name(n) {
            return code(status::INVALID_ARGUMENT);
        }
    }
    let mut ptr = Ptr { package: Some(config.to_owned()), ..Ptr::default() };
    let Ok(pidx) = tr!(ctx, file::load(&mut ctx, config)) else {
        return code(uci_status(&ctx));
    };
    let mut err = 0;
    'body: {
        if let Some(n) = name {
            ptr.section = Some(n.to_owned());
            ptr.value = Some(ty.as_bytes().to_vec());
            ptr.option = None;
            if lookup(&mut ctx, &mut ptr).is_err() {
                break 'body;
            }
            if tr!(ctx, ops::set(&mut ctx, &mut ptr, false)).is_err() {
                break 'body;
            }
        } else {
            match tr!(ctx, ops::add_section(&mut ctx, pidx, ty, false)) {
                Ok(sidx) => ptr.section = Some(ctx.root[pidx].sections[sidx].name.clone()),
                Err(_) => break 'body,
            }
        }
        if let Some(values) = field_data(raw, "values", MsgType::Table) {
            for cur in blob::fields(values) {
                ptr.flags = 0;
                ptr.o = None;
                ptr.option = Some(cur.name.to_owned());
                if !verify_name(cur.name) {
                    if err == 0 {
                        err = status::INVALID_ARGUMENT;
                    }
                    continue;
                }
                if lookup(&mut ctx, &mut ptr).is_err() || ptr.s.is_none() {
                    if err == 0 {
                        err = status::NOT_FOUND;
                    }
                    continue;
                }
                if cur.ty == MsgType::Array as u32 {
                    for elem in cur.children() {
                        match format_blob(&elem) {
                            None => {
                                if err == 0 {
                                    err = status::INVALID_ARGUMENT;
                                }
                            }
                            Some(v) => {
                                ptr.value = Some(v.into_bytes());
                                let _ = tr!(ctx, ops::add_list(&mut ctx, &mut ptr, false));
                            }
                        }
                    }
                } else {
                    match format_blob(&cur) {
                        None => {
                            if err == 0 {
                                err = status::INVALID_ARGUMENT;
                            }
                        }
                        Some(v) => {
                            ptr.value = Some(v.into_bytes());
                            let _ = tr!(ctx, ops::set(&mut ctx, &mut ptr, false));
                        }
                    }
                }
            }
        }
        if err == 0 {
            let _ = tr!(ctx, delta::save(&mut ctx, pidx));
            let mut b = BlobBuf::new();
            b.msg_string("section", ptr.section.as_deref().unwrap_or(""));
            ctx.unload(pidx);
            ctx.err = None;
            return with(uci_status(&ctx), b.into_payload());
        }
    }
    ctx.unload(pidx);
    ctx.err = None;
    code(if err != 0 { err } else { uci_status(&ctx) })
}

/// rpc_uci_merge_set
fn merge_set(ctx: &mut Context, opt: &Field, ptr: &mut Ptr) -> i32 {
    ptr.flags = 0;
    ptr.o = None;
    ptr.option = Some(opt.name.to_owned());
    ptr.value = None;
    if !verify_name(opt.name) {
        return status::INVALID_ARGUMENT;
    }
    if lookup(ctx, ptr).is_err() || ptr.s.is_none() {
        return status::NOT_FOUND;
    }
    if opt.ty == MsgType::Array as u32 {
        if ptr.o.is_some() {
            let _ = tr!(ctx, ops::delete(ctx, ptr, false));
            ptr.flags = 0;
        }
        let mut rv = status::INVALID_ARGUMENT;
        for cur in opt.children() {
            let Some(v) = format_blob(&cur) else { continue };
            ptr.value = Some(v.into_bytes());
            let _ = tr!(ctx, ops::add_list(ctx, ptr, false));
            rv = 0;
        }
        return rv;
    }
    let existing_list = match (ptr.p, ptr.s, ptr.o) {
        (Some(p), Some(s), Some(o)) => matches!(ctx.root[p].sections[s].options[o].value, OptionValue::List(_)),
        _ => false,
    };
    if existing_list {
        let _ = tr!(ctx, ops::delete(ctx, ptr, false));
        ptr.flags = 0;
        let Some(v) = format_blob(opt) else { return status::INVALID_ARGUMENT };
        ptr.value = Some(v.into_bytes());
        let _ = tr!(ctx, ops::set(ctx, ptr, false));
    } else {
        let Some(v) = format_blob(opt) else { return status::INVALID_ARGUMENT };
        let same = match (ptr.p, ptr.s, ptr.o) {
            (Some(p), Some(s), Some(o)) => match &ctx.root[p].sections[s].options[o].value {
                OptionValue::Str(cur) => cur.as_slice() == v.as_bytes(),
                OptionValue::List(_) => false,
            },
            _ => false,
        };
        ptr.value = Some(v.into_bytes());
        if !same {
            let _ = tr!(ctx, ops::set(ctx, ptr, false));
        }
    }
    0
}

fn set(rctx: &Ctx, raw: &[u8]) -> Reply {
    let config = arg_str(raw, "config");
    let values = field_data(raw, "values", MsgType::Table);
    let section = arg_str(raw, "section");
    let ty = arg_str(raw, "type");
    let matches = field_data(raw, "match", MsgType::Table);
    let (Some(config), Some(values)) = (config, values) else { return code(status::INVALID_ARGUMENT) };
    if section.is_none() && ty.is_none() && matches.is_none() {
        return code(status::INVALID_ARGUMENT);
    }
    let sid = arg_str(raw, "ubus_rpc_session");
    let mut ctx = Context::new();
    if !write_access(rctx, &mut ctx, sid, config) {
        return code(status::PERMISSION_DENIED);
    }
    if let Some(s) = section {
        if !verify_section(s) {
            return code(status::INVALID_ARGUMENT);
        }
    }
    let mut ptr = Ptr { package: Some(config.to_owned()), ..Ptr::default() };
    let Ok(pidx) = tr!(ctx, file::load(&mut ctx, config)) else {
        return code(uci_status(&ctx));
    };
    let mut err = 0;
    if let Some(s) = section {
        ptr.section = Some(s.to_owned());
        for cur in blob::fields(values) {
            let rv = merge_set(&mut ctx, &cur, &mut ptr);
            if rv != 0 {
                err = rv;
            }
        }
    } else {
        let names: Vec<(String, bool)> = ctx.root[pidx]
            .sections
            .iter()
            .map(|s| (s.name.clone(), match_section(s, ty, matches)))
            .collect();
        for (name, ok) in names {
            if !ok {
                continue;
            }
            ptr.s = None;
            ptr.section = Some(name);
            for cur in blob::fields(values) {
                let rv = merge_set(&mut ctx, &cur, &mut ptr);
                if rv != 0 {
                    err = rv;
                }
            }
        }
    }
    if err == 0 && ptr.s.is_none() {
        err = status::NOT_FOUND;
    }
    if err == 0 {
        let _ = tr!(ctx, delta::save(&mut ctx, pidx));
    }
    ctx.unload(pidx);
    ctx.err = None;
    code(if err != 0 { err } else { uci_status(&ctx) })
}

/// rpc_uci_merge_delete; `opt` is the "options" array or the "option" string.
fn merge_delete(ctx: &mut Context, opt: Option<&Field>, ptr: &mut Ptr) -> i32 {
    if lookup(ctx, ptr).is_err() || ptr.s.is_none() {
        return status::NOT_FOUND;
    }
    let Some(opt) = opt else {
        ptr.o = None;
        ptr.option = None;
        let _ = tr!(ctx, ops::delete(ctx, ptr, false));
        return 0;
    };
    if opt.ty == MsgType::Array as u32 {
        let mut rv = status::NOT_FOUND;
        for cur in opt.children() {
            if cur.ty != MsgType::String as u32 {
                continue;
            }
            let Some(name) = cur.as_str() else { continue };
            ptr.o = None;
            ptr.option = Some(name.to_owned());
            if lookup(ctx, ptr).is_err() || ptr.o.is_none() {
                continue;
            }
            let _ = tr!(ctx, ops::delete(ctx, ptr, false));
            ptr.flags = 0;
            rv = 0;
        }
        return rv;
    }
    if opt.ty == MsgType::String as u32 {
        ptr.o = None;
        ptr.option = opt.as_str().map(str::to_owned);
        if lookup(ctx, ptr).is_err() || ptr.o.is_none() {
            return status::NOT_FOUND;
        }
        let _ = tr!(ctx, ops::delete(ctx, ptr, false));
        return 0;
    }
    status::INVALID_ARGUMENT
}

fn delete(rctx: &Ctx, raw: &[u8]) -> Reply {
    let Some(config) = arg_str(raw, "config") else { return code(status::INVALID_ARGUMENT) };
    let section = arg_str(raw, "section");
    let ty = arg_str(raw, "type");
    let matches = field_data(raw, "match", MsgType::Table);
    if section.is_none() && ty.is_none() && matches.is_none() {
        return code(status::INVALID_ARGUMENT);
    }
    let sid = arg_str(raw, "ubus_rpc_session");
    let mut ctx = Context::new();
    if !write_access(rctx, &mut ctx, sid, config) {
        return code(status::PERMISSION_DENIED);
    }
    if let Some(t) = ty {
        if !verify_type(t) {
            return code(status::INVALID_ARGUMENT);
        }
    }
    if let Some(s) = section {
        if !verify_section(s) {
            return code(status::INVALID_ARGUMENT);
        }
    }
    let options = arg(raw, "options", MsgType::Array);
    let option = arg(raw, "option", MsgType::String);
    let opt = options.as_ref().or(option.as_ref());
    let mut ptr = Ptr { package: Some(config.to_owned()), ..Ptr::default() };
    let Ok(pidx) = tr!(ctx, file::load(&mut ctx, config)) else {
        return code(uci_status(&ctx));
    };
    let mut err = 0;
    if let Some(s) = section {
        ptr.section = Some(s.to_owned());
        err = merge_delete(&mut ctx, opt, &mut ptr);
    } else {
        let names: Vec<(String, bool)> = ctx.root[pidx]
            .sections
            .iter()
            .map(|s| (s.name.clone(), match_section(s, ty, matches)))
            .collect();
        for (name, ok) in names {
            if !ok {
                continue;
            }
            ptr.s = None;
            ptr.section = Some(name);
            err = merge_delete(&mut ctx, opt, &mut ptr);
        }
        if err == 0 && ptr.section.is_none() {
            err = status::NOT_FOUND;
        }
    }
    if err == 0 {
        let _ = tr!(ctx, delta::save(&mut ctx, pidx));
    }
    ctx.unload(pidx);
    ctx.err = None;
    code(if err != 0 { err } else { uci_status(&ctx) })
}

fn rename(rctx: &Ctx, raw: &[u8]) -> Reply {
    let (Some(config), Some(section), Some(name)) = (arg_str(raw, "config"), arg_str(raw, "section"), arg_str(raw, "name")) else {
        return code(status::INVALID_ARGUMENT);
    };
    let sid = arg_str(raw, "ubus_rpc_session");
    let mut ctx = Context::new();
    if !write_access(rctx, &mut ctx, sid, config) {
        return code(status::PERMISSION_DENIED);
    }
    if !verify_name(name) {
        return code(status::INVALID_ARGUMENT);
    }
    let mut ptr = Ptr {
        package: Some(config.to_owned()),
        section: Some(section.to_owned()),
        value: Some(name.as_bytes().to_vec()),
        option: arg_str(raw, "option").map(str::to_owned),
        ..Ptr::default()
    };
    let Ok(pidx) = tr!(ctx, file::load(&mut ctx, config)) else {
        return code(uci_status(&ctx));
    };
    'body: {
        if tr!(ctx, ops::lookup_ptr(&mut ctx, &mut ptr, None, true)).is_err() {
            break 'body;
        }
        if (ptr.option.is_some() && ptr.o.is_none()) || ptr.s.is_none() {
            ctx.err = Some(Error::NotFound);
            break 'body;
        }
        if tr!(ctx, ops::rename(&mut ctx, &mut ptr, false)).is_err() {
            break 'body;
        }
        let _ = tr!(ctx, delta::save(&mut ctx, pidx));
    }
    ctx.unload(pidx);
    ctx.err = None;
    code(uci_status(&ctx))
}

fn order(rctx: &Ctx, raw: &[u8]) -> Reply {
    let (Some(config), Some(sections)) = (arg_str(raw, "config"), field_data(raw, "sections", MsgType::Array)) else {
        return code(status::INVALID_ARGUMENT);
    };
    let sid = arg_str(raw, "ubus_rpc_session");
    let mut ctx = Context::new();
    if !write_access(rctx, &mut ctx, sid, config) {
        return code(status::PERMISSION_DENIED);
    }
    let mut ptr = Ptr { package: Some(config.to_owned()), ..Ptr::default() };
    let Ok(pidx) = tr!(ctx, file::load(&mut ctx, config)) else {
        return code(uci_status(&ctx));
    };
    let mut err = 0;
    let mut i: i32 = 0;
    for cur in blob::fields(sections) {
        if cur.ty != MsgType::String as u32 {
            if err == 0 {
                err = status::INVALID_ARGUMENT;
            }
            continue;
        }
        ptr.s = None;
        ptr.section = cur.as_str().map(str::to_owned);
        if tr!(ctx, ops::lookup_ptr(&mut ctx, &mut ptr, None, true)).is_err() || ptr.s.is_none() {
            if err == 0 {
                err = status::NOT_FOUND;
            }
            continue;
        }
        let sidx = ptr.s.unwrap();
        let _ = tr!(ctx, ops::reorder_section(&mut ctx, pidx, sidx, i, false));
        i += 1;
    }
    if err == 0 {
        let _ = tr!(ctx, delta::save(&mut ctx, pidx));
    }
    ctx.unload(pidx);
    ctx.err = None;
    code(if err != 0 { err } else { uci_status(&ctx) })
}

/// rpc_uci_dump_change
fn dump_change(b: &mut BlobBuf, d: &owrt_uci::Delta) {
    let ty = match d.cmd {
        Cmd::Reorder => "order",
        Cmd::Remove => "remove",
        Cmd::Rename => "rename",
        Cmd::Add => "add",
        Cmd::ListAdd => "list-add",
        Cmd::ListDel => "list-del",
        Cmd::Change => "set",
    };
    let c = b.msg_open_array("");
    b.msg_string("", ty);
    b.msg_string("", &d.section);
    if let Some(name) = &d.option {
        b.msg_string("", name);
    }
    if let Some(v) = &d.value {
        if d.cmd == Cmd::Reorder {
            b.msg_u32("", strtoul10(&String::from_utf8_lossy(v)) as u32);
        } else {
            b.msg_string("", &String::from_utf8_lossy(v));
        }
    }
    b.msg_close(c);
}

/// strtoul(s, NULL, 10) (unsigned long, saturating on overflow like glibc/musl)
fn strtoul10(s: &str) -> u64 {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'-' || b[i] == b'+') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut v: u64 = 0;
    let mut overflow = false;
    while i < b.len() && b[i].is_ascii_digit() {
        match v.checked_mul(10).and_then(|x| x.checked_add((b[i] - b'0') as u64)) {
            Some(x) => v = x,
            None => overflow = true,
        }
        i += 1;
    }
    if overflow {
        return u64::MAX;
    }
    if neg { v.wrapping_neg() } else { v }
}

fn changes(rctx: &Ctx, raw: &[u8]) -> Reply {
    let sid = arg_str(raw, "ubus_rpc_session");
    let mut ctx = Context::new();
    if let Some(config) = arg_str(raw, "config") {
        if !read_access(rctx, &mut ctx, sid, config) {
            return code(status::PERMISSION_DENIED);
        }
        let Ok(pidx) = tr!(ctx, file::load(&mut ctx, config)) else {
            return code(uci_status(&ctx));
        };
        let mut b = BlobBuf::new();
        let c = b.msg_open_array("changes");
        for d in &ctx.root[pidx].saved_delta {
            dump_change(&mut b, d);
        }
        b.msg_close(c);
        ctx.unload(pidx);
        ctx.err = None;
        return with(uci_status(&ctx), b.into_payload());
    }
    set_savedir(&mut ctx, sid);
    let Ok(configs) = tr!(ctx, file::list_config_files(&ctx)) else {
        return code(uci_status(&ctx));
    };
    let mut b = BlobBuf::new();
    let c = b.msg_open_table("changes");
    for name in &configs {
        if let Some(sid) = sid {
            if !rctx.sessions.borrow_mut().access(sid, "uci", name, "read") {
                continue;
            }
        }
        let Ok(pidx) = tr!(ctx, file::load(&mut ctx, name)) else { continue };
        if !ctx.root[pidx].saved_delta.is_empty() {
            let d = b.msg_open_array(name);
            for delta in &ctx.root[pidx].saved_delta {
                dump_change(&mut b, delta);
            }
            b.msg_close(d);
        }
        ctx.unload(pidx);
        ctx.err = None;
    }
    b.msg_close(c);
    with(0, b.into_payload())
}

/// rpc_uci_trigger_event: `service event {type: config.change, data:{package}}`
fn send_event(conn: &mut Connection, config: &str) -> bool {
    let Ok(id) = conn.lookup_id("service", 1000) else { return false };
    let mut b = BlobBuf::new();
    b.msg_string("type", "config.change");
    let c = b.msg_open_table("data");
    b.msg_string("package", config);
    b.msg_close(c);
    conn.invoke_status(id, "event", b.payload(), 1000).is_ok_and(|r| r.status == 0)
}

fn trigger_event(rctx: &Ctx, conn: Option<&mut Connection>, config: &str) {
    let sent = conn.is_some_and(|conn| send_event(conn, config));
    let mut apply = rctx.apply.borrow_mut();
    if sent {
        apply.pending_events.remove(config);
    } else {
        apply.pending_events.insert(config.to_owned());
    }
    if apply.pending_events.is_empty() {
        apply.event_retry = None;
    } else if apply.event_retry.is_none() {
        apply.event_retry = Some(Instant::now() + Duration::from_secs(1));
    }
}

/// Retry at most one failed notification per tick. The files are already
/// committed/restored; procd needs the current package, not an old payload.
pub fn retry_event(rctx: &Ctx, conn: &mut Connection) {
    let config = {
        let mut apply = rctx.apply.borrow_mut();
        if !apply.event_retry.is_some_and(|at| at <= Instant::now()) {
            return;
        }
        let next = apply.last_event.as_ref().and_then(|last| {
            apply.pending_events.range((std::ops::Bound::Excluded(last.clone()), std::ops::Bound::Unbounded)).next()
        }).or_else(|| apply.pending_events.first()).cloned();
        apply.last_event = next.clone();
        apply.event_retry = Some(Instant::now() + Duration::from_secs(1));
        next
    };
    if let Some(config) = config {
        trigger_event(rctx, Some(conn), &config);
    }
}

fn revert_commit(rctx: &Ctx, conn: &mut Connection, raw: &[u8], commit: bool) -> Reply {
    if rctx.sessions.borrow().apply_sid.is_some() {
        return code(status::PERMISSION_DENIED);
    }
    let Some(config) = arg_str(raw, "config") else { return code(status::INVALID_ARGUMENT) };
    let sid = arg_str(raw, "ubus_rpc_session");
    let mut ctx = Context::new();
    if !write_access(rctx, &mut ctx, sid, config) {
        return code(status::PERMISSION_DENIED);
    }
    if commit {
        if let Ok(pidx) = tr!(ctx, file::load(&mut ctx, config)) {
            let _ = tr!(ctx, file::commit(&mut ctx, pidx, false));
            ctx.unload(pidx);
            ctx.err = None;
            trigger_event(rctx, Some(conn), config);
        }
    } else {
        let mut ptr = Ptr { package: Some(config.to_owned()), ..Ptr::default() };
        if tr!(ctx, ops::lookup_ptr(&mut ctx, &mut ptr, None, true)).is_ok() {
            if let Some(pidx) = ptr.p {
                let _ = tr!(ctx, delta::revert(&mut ctx, &mut ptr));
                ctx.unload(pidx);
                ctx.err = None;
            }
        }
    }
    code(uci_status(&ctx))
}

fn configs() -> Reply {
    match file::list_config_files_in(owrt_uci::context::CONFDIR) {
        Ok(list) => {
            let mut b = BlobBuf::with_capacity(256);
            let c = b.msg_open_array("configs");
            for name in &list {
                b.msg_string("", name);
            }
            b.msg_close(c);
            with(status::OK, b.into_payload())
        }
        Err(error) => code(uci_error(Some(error))),
    }
}

/// rpc_uci_purge_dir: unlink the regular files in `path`, then rmdir it.
pub fn purge_dir(path: &str) {
    let Ok(m) = fs::metadata(path) else { return };
    if !m.is_dir() {
        return;
    }
    if let Ok(rd) = fs::read_dir(path) {
        for e in rd.flatten() {
            let p = e.path();
            if fs::metadata(&p).map(|m| m.is_file()).unwrap_or(false) {
                let _ = fs::remove_file(&p);
            }
        }
        let _ = fs::remove_dir(path);
    }
}

/// rpc_uci_purge_savedirs: glob(RUN_DIR/uci-*) at startup.
pub fn purge_savedirs() {
    let Ok(rd) = fs::read_dir(RUN_DIR) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with("uci-") {
            purge_dir(&format!("{RUN_DIR}/{name}"));
        }
    }
}

/// rpc_uci_apply_config (cursor state is whatever the caller set up)
fn commit_config(ctx: &mut Context, config: &str) {
    if let Ok(pidx) = tr!(ctx, file::load(ctx, config)) {
        let _ = tr!(ctx, file::commit(ctx, pidx, false));
        ctx.unload(pidx);
        ctx.err = None;
    }
}

fn apply_config(rctx: &Ctx, ctx: &mut Context, conn: Option<&mut Connection>, config: &str) {
    commit_config(ctx, config);
    trigger_event(rctx, conn, config);
}

/// Keep the current file intact until the complete snapshot has been written.
fn restore_file(src: &str, target: &str, file: &str) -> std::io::Result<()> {
    let mut input = fs::File::open(format!("{src}{file}"))?;
    let path = format!("{target}{file}");
    let destination = match fs::canonicalize(&path) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => path.into(),
        Err(error) => return Err(error),
    };
    let metadata = match fs::metadata(&destination) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let permissions = match &metadata {
        Some(metadata) => metadata.permissions(),
        None => input.metadata()?.permissions(),
    };
    let parent = destination.parent().ok_or_else(|| std::io::Error::other("rollback destination has no parent"))?;
    let template = parent.join(".rpcd-rollback-XXXXXX");
    let (mut output, temporary) = owrt_uci::sys::mkstemp(&template.to_string_lossy())?;
    let result = (|| {
        std::io::copy(&mut input, &mut output)?;
        if let Some(metadata) = &metadata {
            rustix::fs::fchown(&output,
                Some(rustix::process::Uid::from_raw(metadata.uid())),
                Some(rustix::process::Gid::from_raw(metadata.gid())))?;
        }
        // chown may clear set-id bits, so restore the mode afterwards.
        output.set_permissions(permissions)?;
        output.sync_all()?;
        fs::rename(&temporary, &destination)?;
        fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

/// A partial rollback snapshot must never become authoritative.
fn copy_snapshot(src: &str, target: &str, file: &str) -> std::io::Result<()> {
    let mut input = fs::File::open(format!("{src}{file}"))?;
    let mut output = fs::OpenOptions::new()
        .write(true).create(true).truncate(true).mode(0o600)
        .open(format!("{target}{file}"))?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()
}

/// glob("<dir>/*", GLOB_PERIOD): sorted names including "." and "..".
fn glob_period(dir: &str) -> Vec<String> {
    let Ok(rd) = fs::read_dir(dir) else { return vec![] };
    let mut names: Vec<String> = vec![".".to_owned(), "..".to_owned()];
    names.extend(rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()));
    names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    names
}

fn file_size(path: &str) -> Option<u64> {
    fs::metadata(path).ok().map(|m| m.size())
}

/// rpc_uci_apply_access
fn apply_access(rctx: &Ctx, sid: &str, dir: &str, names: &[String]) -> i32 {
    if names.len() < 3 {
        return status::NO_DATA;
    }
    let mut c = 0;
    for config in names {
        if config.starts_with('.') {
            continue;
        }
        match file_size(&format!("{dir}/{config}")) {
            Some(n) if n > 0 => {}
            _ => continue,
        }
        if !rctx.sessions.borrow_mut().access(sid, "uci", config, "write") {
            return status::PERMISSION_DENIED;
        }
        c += 1;
    }
    if c == 0 {
        return status::NO_DATA;
    }
    0
}

/// rpc_uci_do_rollback over the snapshot-files listing.
pub fn do_rollback(rctx: &Ctx, mut conn: Option<&mut Connection>, names: &[String]) -> std::io::Result<()> {
    // Once restoration starts, only a complete rollback may retire its state.
    // A failed batch may already have replaced some files on disk.
    rctx.apply.borrow_mut().rollback_in_progress = true;
    let apply_sid = rctx.sessions.borrow().apply_sid.clone();
    let deny = match &apply_sid {
        Some(sid) => apply_access(rctx, sid, SNAPSHOT_FILES.trim_end_matches('/'), names),
        None => status::NOT_FOUND,
    };
    let tmp = apply_sid.as_deref().map(|sid| format!("{}/", savedir_of(sid))).unwrap_or_default();
    let mut failure = if deny == 0 {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(tmp.trim_end_matches('/')).err()
    } else { None };
    if !names.iter().any(|name| !name.starts_with('.')) {
        failure = Some(std::io::Error::other("rollback snapshot is unavailable"));
    }
    for config in names {
        if config.starts_with('.') {
            continue;
        }
        // The snapshot is already a committed config. Do not merge any deltas.
        let restored = restore_file(SNAPSHOT_FILES, UCI_DIR, config).and_then(|()| {
            if deny == 0 { restore_file(SNAPSHOT_DELTA, &tmp, config) } else { Ok(()) }
        });
        if let Err(error) = restored {
            failure = Some(error);
        }
    }
    if let Some(error) = failure {
        // A temporary flash/filesystem error must not consume the only backup.
        rctx.apply.borrow_mut().deadline = Some(Instant::now() + Duration::from_secs(1));
        return Err(error);
    }
    purge_dir(SNAPSHOT_FILES);
    purge_dir(SNAPSHOT_DELTA);
    rctx.apply.borrow_mut().deadline = None;
    rctx.apply.borrow_mut().rollback_in_progress = false;
    rctx.sessions.borrow_mut().apply_sid = None;
    // Restore every file before a procd event can wait for a reply. Manual
    // rollback retains its synchronous event attempts; a timer queues them.
    for config in names.iter().filter(|name| !name.starts_with('.')) {
        trigger_event(rctx, conn.as_deref_mut(), config);
    }
    Ok(())
}

/// The apply rollback timer fired.
pub fn apply_timeout(rctx: &Ctx) {
    let names = glob_period(SNAPSHOT_FILES.trim_end_matches('/'));
    if let Err(error) = do_rollback(rctx, None, &names) {
        eprintln!("rpcd-rs: rollback failed, retaining snapshots for retry: {error}");
    }
}

fn apply(rctx: &Ctx, conn: &mut Connection, raw: &[u8]) -> Reply {
    let rollback = arg(raw, "rollback", MsgType::Int8).and_then(|f| f.as_bool()).unwrap_or(false);
    let has_apply = rctx.sessions.borrow().apply_sid.is_some();
    if has_apply && rollback {
        return code(status::PERMISSION_DENIED);
    }
    let Some(sid) = arg_str(raw, "ubus_rpc_session") else { return code(status::INVALID_ARGUMENT) };
    if rctx.sessions.borrow().apply_sid.as_deref().is_some_and(|owner| owner != sid) {
        // Like confirm/rollback, unchecked apply may discard only this
        // session's snapshot. Other sessions must not cancel its safety timer.
        return code(status::PERMISSION_DENIED);
    }
    if rctx.apply.borrow().rollback_in_progress {
        return code(status::UNKNOWN_ERROR);
    }
    let timeout: i32 = arg(raw, "timeout", MsgType::Int32).and_then(|f| f.as_u32()).map(|v| v as i32).unwrap_or(APPLY_TIMEOUT);
    purge_dir(SNAPSHOT_FILES);
    purge_dir(SNAPSHOT_DELTA);
    if has_apply {
        // The owner explicitly made its pending apply permanent. There is no
        // snapshot left to restore or retry after this successful cancellation.
        rctx.apply.borrow_mut().deadline = None;
        rctx.sessions.borrow_mut().apply_sid = None;
        return code(0);
    }
    if !has_apply {
        let mut ctx = Context::new();
        set_savedir(&mut ctx, Some(sid));
        // Preserve the existing empty-directory behavior for NO_DATA and
        // permission-denied requests, but never ignore a creation failure.
        let directories = [SNAPSHOT_FILES, SNAPSHOT_DELTA].into_iter().try_for_each(|path| {
            fs::DirBuilder::new().recursive(true).mode(0o700).create(path)
        });
        if directories.is_err() {
            return code(status::UNKNOWN_ERROR);
        }
        let dir = savedir_of(sid);
        let names = glob_period(&dir);
        let tmp = format!("{dir}/");
        let ret = apply_access(rctx, sid, &dir, &names);
        if ret != 0 {
            return code(ret);
        }
        let configs: Vec<_> = names.iter().filter(|config| {
            !config.starts_with('.') && file_size(&format!("{dir}/{config}")).is_some_and(|n| n > 0)
        }).collect();
        // Back up the complete batch before committing its first package.
        // Otherwise a later ENOSPC can leave an earlier package applied and
        // a truncated snapshot that the rollback timer would copy over it.
        let snapshots = (|| -> std::io::Result<()> {
            for config in &configs {
                copy_snapshot(UCI_DIR, SNAPSHOT_FILES, config)?;
                copy_snapshot(&tmp, SNAPSHOT_DELTA, config)?;
            }
            Ok(())
        })();
        if snapshots.is_err() {
            purge_dir(SNAPSHOT_FILES);
            purge_dir(SNAPSHOT_DELTA);
            return code(status::UNKNOWN_ERROR);
        }
        if rollback {
            rctx.sessions.borrow_mut().apply_sid = Some(sid.to_owned());
        }
        for config in configs {
            apply_config(rctx, &mut ctx, Some(conn), config);
        }
        if rollback {
            let msecs: i64 = if timeout > 0 && timeout <= i32::MAX / 1000 { timeout as i64 * 1000 } else { i32::MAX as i64 };
            rctx.apply.borrow_mut().deadline = Some(Instant::now() + Duration::from_millis(msecs as u64));
        }
    }
    code(0)
}

fn confirm(rctx: &Ctx, raw: &[u8]) -> Reply {
    let Some(sid) = arg_str(raw, "ubus_rpc_session") else { return code(status::INVALID_ARGUMENT) };
    let apply_sid = rctx.sessions.borrow().apply_sid.clone();
    let Some(apply_sid) = apply_sid else { return code(status::NO_DATA) };
    if apply_sid != sid {
        return code(status::PERMISSION_DENIED);
    }
    if rctx.apply.borrow().rollback_in_progress {
        return code(status::UNKNOWN_ERROR);
    }
    purge_dir(SNAPSHOT_FILES);
    purge_dir(SNAPSHOT_DELTA);
    rctx.apply.borrow_mut().deadline = None;
    rctx.sessions.borrow_mut().apply_sid = None;
    code(0)
}

fn rollback(rctx: &Ctx, conn: &mut Connection, raw: &[u8]) -> Reply {
    let apply_sid = rctx.sessions.borrow().apply_sid.clone();
    let Some(apply_sid) = apply_sid else { return code(status::NO_DATA) };
    let Some(sid) = arg_str(raw, "ubus_rpc_session") else { return code(status::INVALID_ARGUMENT) };
    if apply_sid != sid {
        return code(status::PERMISSION_DENIED);
    }
    let names = glob_period(SNAPSHOT_FILES.trim_end_matches('/'));
    match do_rollback(rctx, Some(conn), &names) {
        Ok(()) => code(0),
        Err(error) => {
            eprintln!("rpcd-rs: rollback failed, retaining snapshots for retry: {error}");
            code(status::UNKNOWN_ERROR)
        }
    }
}

/// rpc_uci_reload: `/sbin/reload_config` two seconds after the reply.
fn reload_config(ctx: &Ctx) -> Reply {
    ctx.delayed.borrow_mut().exec(&["/sbin/reload_config"]);
    code(0)
}

pub fn call(rctx: &Ctx, conn: &mut Connection, method: &str, raw: &[u8]) -> Reply {
    match method {
        "configs" => configs(),
        "get" => get_common(rctx, raw, false),
        "state" => get_common(rctx, raw, true),
        "add" => add(rctx, raw),
        "set" => set(rctx, raw),
        "delete" => delete(rctx, raw),
        "rename" => rename(rctx, raw),
        "order" => order(rctx, raw),
        "changes" => changes(rctx, raw),
        "revert" => revert_commit(rctx, conn, raw, false),
        "commit" => revert_commit(rctx, conn, raw, true),
        "apply" => apply(rctx, conn, raw),
        "confirm" => confirm(rctx, raw),
        "rollback" => rollback(rctx, conn, raw),
        "reload_config" => reload_config(rctx),
        _ => code(status::METHOD_NOT_FOUND),
    }
}

#[cfg(test)]
mod reply_capacity_tests {
    use super::*;

    #[test]
    fn whole_package_capacity_covers_padding_lists_and_raw_values() {
        for sections in [0, 1, 64] {
            let mut p = owrt_uci::Package::new("sample");
            for i in 0..sections {
                p.sections.push(owrt_uci::Section {
                    name: format!("section{i}"), ty: "example".into(), anonymous: i % 2 != 0,
                    options: vec![
                        owrt_uci::Opt { name: "raw".into(), value: OptionValue::Str(b"raw\xff".as_slice().into()) },
                        owrt_uci::Opt { name: "list".into(), value: OptionValue::List(vec!["".into(), "123456789".into()]) },
                    ],
                });
            }
            let capacity = package_reply_capacity(&p);
            let mut b = BlobBuf::with_capacity(capacity);
            dump_package(&mut b, &p, "values", None, None);
            assert_eq!(b.into_payload().len() + 4, capacity);
        }
        let mut p = owrt_uci::Package::new("sample");
        p.sections.push(owrt_uci::Section {
            name: "s".into(), ty: "t".into(), anonymous: false,
            options: vec![owrt_uci::Opt { name: "large".into(),
                value: OptionValue::Str(vec![b'x'; 100_000].into()) }],
        });
        assert_eq!(package_reply_capacity(&p), 64 * 1024);
        let mut b = BlobBuf::with_capacity(package_reply_capacity(&p));
        dump_package(&mut b, &p, "values", None, None);
        assert!(b.into_payload().len() > 100_000);
    }
}
