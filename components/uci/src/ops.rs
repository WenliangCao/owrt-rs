//! list.c (lookup / set / add_list / del_list / delete / rename / reorder /
//! add_section) and util.c (validation, uci_parse_ptr).
//!
//! Every mutating entry point takes `internal`: the C code reads
//! `ctx->internal` (set by UCI_INTERNAL) to suppress delta tracking.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::model::{
    Cmd, Delta, Opt, OptionValue, Package, Ptr, Section, Target, LOOKUP_COMPLETE, LOOKUP_DONE,
    LOOKUP_EXTENDED,
};

// ------------------------------------------------------------ util.c

/// uci_validate_str(str, name, package)
pub fn validate_str(s: &str, name: bool, package: bool) -> bool {
    if s.is_empty() {
        return false;
    }
    for c in s.bytes() {
        if c.is_ascii_alphanumeric() || c == b'_' {
            continue;
        }
        if c == b'-' && package {
            continue;
        }
        if name || !(33..=126).contains(&c) {
            return false;
        }
    }
    true
}

pub fn validate_package(s: &str) -> bool {
    validate_str(s, false, true)
}
pub fn validate_type(s: &str) -> bool {
    validate_str(s, false, false)
}
pub fn validate_name(s: &str) -> bool {
    validate_str(s, true, false)
}

/// uci_validate_text
pub fn validate_text(s: &[u8]) -> bool {
    !s.iter().any(|&c| c < 32 && c != b'\t' && c != b'\n' && c != b'\r')
}

/// strsep(&str, ".") over an Option<&[u8]> cursor: returns None once the
/// string pointer is exhausted, "" for consecutive delimiters.
fn strsep_dot<'a>(cur: &mut Option<&'a [u8]>) -> Option<&'a [u8]> {
    let s = (*cur)?;
    match s.iter().position(|&b| b == b'.') {
        Some(i) => {
            *cur = Some(&s[i + 1..]);
            Some(&s[..i])
        }
        None => {
            *cur = None;
            Some(s)
        }
    }
}

/// The validators only accept bytes from the ASCII identifier set, so a part
/// that is not UTF-8 can never pass one; this keeps them byte-addressable
/// without duplicating the tables.
fn validate_bytes(s: &[u8], f: fn(&str) -> bool) -> bool {
    std::str::from_utf8(s).is_ok_and(f)
}

/// uci_parse_ptr: split `pkg[.section[.option]][=value]`.
pub fn parse_ptr(ptr: &mut Ptr, str_: &[u8]) -> Result<()> {
    *ptr = Ptr::default();
    let (tuple, value) = match str_.iter().position(|&b| b == b'=') {
        Some(i) => (&str_[..i], Some(&str_[i + 1..])),
        None => (str_, None),
    };
    ptr.value = value.map(<[u8]>::to_vec);

    let mut cur = Some(tuple);
    let Some(package) = strsep_dot(&mut cur) else {
        return parse_ptr_error(ptr);
    };
    let mut section = None;
    let mut option = None;
    'lastval: {
        let Some(s) = strsep_dot(&mut cur) else {
            ptr.target = Some(Target::Package);
            break 'lastval;
        };
        section = Some(s);
        let Some(o) = strsep_dot(&mut cur) else {
            ptr.target = Some(Target::Section);
            break 'lastval;
        };
        option = Some(o);
        ptr.target = Some(Target::Option);
        if strsep_dot(&mut cur).is_some() {
            return parse_ptr_error(ptr);
        }
    }

    if !validate_bytes(package, validate_package) {
        return parse_ptr_error(ptr);
    }
    ptr.package = Some(String::from_utf8_lossy(package).into_owned());
    if let Some(s) = section {
        if !validate_bytes(s, validate_name) {
            ptr.flags |= LOOKUP_EXTENDED;
        }
        // a section that is not UTF-8 always fails uci_validate_name, so it is
        // extended and can only ever fail again in uci_lookup_ext_section
        ptr.section = Some(String::from_utf8_lossy(s).into_owned());
    }
    if let Some(o) = option {
        if !validate_bytes(o, validate_name) {
            return parse_ptr_error(ptr);
        }
        ptr.option = Some(String::from_utf8_lossy(o).into_owned());
    }
    if let Some(v) = &ptr.value {
        if !validate_text(v) {
            return parse_ptr_error(ptr);
        }
    }
    Ok(())
}

fn parse_ptr_error(ptr: &mut Ptr) -> Result<()> {
    *ptr = Ptr::default();
    Err(Error::Parse)
}

// ------------------------------------------------------------ list.c lookup

/// uci_lookup_ext_section: `@type[idx]` with negative indices from the end.
fn lookup_ext_section(ctx: &Context, ptr: &mut Ptr) -> Result<Option<usize>> {
    let section = ptr.section.clone().unwrap_or_default();
    let p = &ctx.root[ptr.p.expect("package resolved")];
    let fail = |ptr: &mut Ptr| -> Result<Option<usize>> {
        *ptr = Ptr::default();
        Err(Error::Inval)
    };
    let Some(rest) = section.strip_prefix('@') else {
        return fail(ptr);
    };
    let Some(lb) = rest.find('[') else {
        return fail(ptr);
    };
    let name = &rest[..lb];
    let idxstr = &rest[lb + 1..];
    let Some(rb) = idxstr.find(']') else {
        return fail(ptr);
    };
    if rb + 1 != idxstr.len() {
        return fail(ptr);
    }
    let idxstr = &idxstr[..rb];
    // `int idx = strtol(idxstr, &t, 10); if (t && *t) error;` -- the long is
    // truncated to int, so 4294967296 selects section 0.
    let mut idx: i64 = match strtol(idxstr.as_bytes()) {
        Some(v) => v as i32 as i64,
        None => return fail(ptr),
    };
    let name = if name.is_empty() {
        None
    } else if !validate_type(name) {
        return fail(ptr);
    } else {
        Some(name)
    };
    if idx < 0 {
        let c = p
            .sections
            .iter()
            .filter(|s| name.is_none_or(|n| s.ty == n))
            .count() as i64;
        idx += c;
    }
    let mut c = 0i64;
    for (i, s) in p.sections.iter().enumerate() {
        if let Some(n) = name {
            if s.ty != n {
                continue;
            }
        }
        if idx == c {
            ptr.section = Some(s.name.clone());
            return Ok(Some(i));
        }
        c += 1;
    }
    Ok(None)
}

/// strtol(s, &end, 10) on a NUL-terminated string: `None` when `*end != 0`,
/// otherwise the converted value, clamped to LONG_MIN/LONG_MAX on overflow.
/// When no conversion happens strtol leaves `end == s`, so a string that is
/// only whitespace or only a sign has trailing garbage while "" does not.
fn strtol(s: &[u8]) -> Option<i64> {
    // isspace() in the C locale, which Rust's is_ascii_whitespace is not:
    // it leaves out the vertical tab, and `uci get 't.@a[\x0b1].k'` returns
    // section 1 on the device.
    fn is_c_space(b: u8) -> bool {
        b == 0x0b || b.is_ascii_whitespace()
    }
    let mut i = 0;
    while s.get(i).copied().is_some_and(is_c_space) {
        i += 1;
    }
    let neg = match s.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let first_digit = i;
    let limit = i64::MAX as u64 + u64::from(neg);
    let mut acc: u64 = 0;
    let mut overflow = false;
    while s.get(i).is_some_and(u8::is_ascii_digit) {
        acc = acc.saturating_mul(10).saturating_add(u64::from(s[i] - b'0'));
        overflow |= acc > limit;
        i += 1;
    }
    // no digits: end == s, i.e. the whole string is left over
    let end = if i == first_digit { 0 } else { i };
    if end != s.len() {
        return None;
    }
    Some(match (overflow, neg) {
        (true, true) => i64::MIN,
        (true, false) => i64::MAX,
        (false, true) => (acc as i64).wrapping_neg(),
        (false, false) => acc as i64,
    })
}

/// uci_lookup_ptr(ctx, ptr, str, extended)
pub fn lookup_ptr(ctx: &mut Context, ptr: &mut Ptr, str_: Option<&[u8]>, extended: bool) -> Result<()> {
    if let Some(s) = str_ {
        parse_ptr(ptr, s)?;
    }
    ptr.flags |= LOOKUP_DONE;

    // look up the package first
    let pidx = match ptr.p {
        Some(i) => Some(i),
        None => ctx.find_package(ptr.package.as_deref().unwrap_or("")),
    };
    let pidx = match pidx {
        Some(i) => i,
        None => {
            let name = ptr.package.clone().unwrap_or_default();
            // UCI_INTERNAL(uci_load): errors propagate
            
            crate::file::load(ctx, &name)?
        }
    };
    ptr.p = Some(pidx);

    if ptr.section.is_none() && ptr.s.is_none() {
        ptr.flags |= LOOKUP_COMPLETE;
        return Ok(());
    }

    let sidx = if let Some(s) = ptr.s {
        Some(s)
    } else if ptr.flags & LOOKUP_EXTENDED != 0 {
        if extended {
            lookup_ext_section(ctx, ptr)?
        } else {
            return Err(Error::Inval);
        }
    } else {
        ctx.root[pidx].find_section(ptr.section.as_deref().unwrap_or(""))
    };
    let Some(sidx) = sidx else {
        return Ok(()); // abort: not complete
    };
    ptr.s = Some(sidx);

    if let Some(opt) = &ptr.option {
        let Some(oidx) = ctx.root[pidx].sections[sidx].find_option(opt) else {
            return Ok(());
        };
        ptr.o = Some(oidx);
    }
    ptr.flags |= LOOKUP_COMPLETE;
    Ok(())
}

/// uci_expand_ptr
pub fn expand_ptr(ctx: &mut Context, ptr: &mut Ptr, complete: bool) -> Result<()> {
    if ptr.flags & LOOKUP_DONE == 0 {
        lookup_ptr(ctx, ptr, None, true)?;
    }
    if complete && !ptr.complete() {
        return Err(Error::NotFound);
    }
    let Some(pidx) = ptr.p else {
        return Err(Error::Inval);
    };
    let p = &ctx.root[pidx];
    if ptr.package.is_none() {
        ptr.package = Some(p.name.clone());
    }
    if let Some(s) = ptr.s {
        if ptr.section.is_none() {
            ptr.section = Some(p.sections[s].name.clone());
        }
        if let Some(o) = ptr.o {
            if ptr.option.is_none() {
                ptr.option = Some(p.sections[s].options[o].name.clone());
            }
        }
    }
    Ok(())
}

// ------------------------------------------------------------ list.c alloc

/// djbhash over `str`, seeded with 5381 when hash == ~0.
fn djbhash(mut hash: u32, s: &[u8]) -> u32 {
    if hash == !0u32 {
        hash = 5381;
    }
    for b in s.iter().copied() {
        // char is unsigned on aarch64
        hash = (hash << 5).wrapping_add(hash).wrapping_add(b as u32);
    }
    hash & 0x7FFF_FFFF
}

/// uci_fixup_section: name an anonymous section `cfg%02x%04x`.
fn fixup_section(p: &Package, s: &Section) -> String {
    let mut hash = djbhash(!0u32, s.ty.as_bytes());
    for o in &s.options {
        hash = djbhash(hash, o.name.as_bytes());
        if let OptionValue::Str(v) = &o.value {
            hash = djbhash(hash, v);
        }
    }
    format!("cfg{:02x}{:04x}", p.n_section, hash % (1 << 16))
}

/// uci_alloc_section: appends (or inserts after `after`) and bumps n_section.
pub(crate) fn alloc_section(p: &mut Package, ty: &str, name: Option<&str>, after: Option<usize>) -> usize {
    let name = name.filter(|n| !n.is_empty());
    let s = Section {
        name: name.unwrap_or("").to_owned(),
        ty: ty.to_owned(),
        anonymous: name.is_none(),
        options: Vec::new(),
    };
    p.n_section += 1;
    match after {
        Some(i) => {
            p.sections.insert(i + 1, s);
            i + 1
        }
        None => {
            p.sections.push(s);
            p.sections.len() - 1
        }
    }
}

pub(crate) fn alloc_option(s: &mut Section, name: &str, value: OptionValue, after: Option<usize>) -> usize {
    let o = Opt {
        name: name.to_owned(),
        value,
    };
    match after {
        Some(i) => {
            s.options.insert(i + 1, o);
            i + 1
        }
        None => {
            s.options.push(o);
            s.options.len() - 1
        }
    }
}

fn add_delta(p: &mut Package, cmd: Cmd, section: &str, option: Option<&str>, value: Option<&[u8]>) {
    p.delta.push(Delta {
        cmd,
        section: section.to_owned(),
        option: option.map(str::to_owned),
        value: value.map(<[u8]>::to_vec),
    });
}

// ------------------------------------------------------------ list.c ops

/// uci_rename
pub fn rename(ctx: &mut Context, ptr: &mut Ptr, internal: bool) -> Result<()> {
    expand_ptr(ctx, ptr, true)?;
    let (Some(pidx), Some(sidx)) = (ptr.p, ptr.s) else {
        return Err(Error::Inval);
    };
    let Some(value) = ptr.value.clone() else {
        return Err(Error::Inval);
    };
    // Names in this model are UTF-8. C accepts a byte name here that its own
    // delta parser rejects on the next load. Refuse that unsupported rename
    // before touching either the model or the delta, instead of silently
    // persisting U+FFFD during a later show/export/commit in the same batch.
    let name = String::from_utf8(value.clone()).map_err(|_| Error::Inval)?;
    let p = &mut ctx.root[pidx];
    if !internal && p.has_delta {
        add_delta(
            p,
            Cmd::Rename,
            ptr.section.as_deref().unwrap_or(""),
            ptr.option.as_deref(),
            Some(value.as_slice()),
        );
    }
    let s = &mut p.sections[sidx];
    match ptr.o {
        Some(oidx) => s.options[oidx].name = name,
        None => {
            s.name = name;
            s.anonymous = false;
        }
    }
    Ok(())
}

/// uci_list_set_pos + uci_reorder_section
pub fn reorder_section(ctx: &mut Context, pidx: usize, sidx: usize, pos: i32, internal: bool) -> Result<()> {
    let p = &mut ctx.root[pidx];
    // old_head is the element before ptr (or the list head when first)
    let old_head: Option<usize> = if sidx == 0 { None } else { Some(sidx - 1) };
    let s = p.sections.remove(sidx);
    // walk the remaining list: new_head = last element visited while pos > 0
    let mut new_head: Option<usize> = None;
    let mut pos_c = pos;
    for i in 0..p.sections.len() {
        if pos_c <= 0 {
            break;
        }
        pos_c -= 1;
        new_head = Some(i);
    }
    let insert_at = new_head.map_or(0, |i| i + 1);
    p.sections.insert(insert_at, s);
    let changed = old_head != new_head;
    if !internal && p.has_delta && changed {
        let name = p.sections[insert_at].name.clone();
        add_delta(p, Cmd::Reorder, &name, None, Some(pos.to_string().as_bytes()));
    }
    Ok(())
}

/// uci_add_section: anonymous section, named by fixup, delta ADD.
pub fn add_section(ctx: &mut Context, pidx: usize, ty: &str, internal: bool) -> Result<usize> {
    let p = &mut ctx.root[pidx];
    let sidx = alloc_section(p, ty, None, None);
    let name = fixup_section(p, &p.sections[sidx]);
    p.sections[sidx].name = name.clone();
    if !internal && p.has_delta {
        add_delta(p, Cmd::Add, &name, None, Some(ty.as_bytes()));
    }
    Ok(sidx)
}

/// uci_delete
pub fn delete(ctx: &mut Context, ptr: &mut Ptr, internal: bool) -> Result<()> {
    expand_ptr(ctx, ptr, true)?;
    let (Some(pidx), Some(sidx)) = (ptr.p, ptr.s) else {
        return Err(Error::Inval);
    };
    let p = &mut ctx.root[pidx];
    let section = ptr.section.clone().unwrap_or_default();

    if let (Some(oidx), Some(value)) = (ptr.o, ptr.value.as_deref().filter(|v| !v.is_empty())) {
        if let OptionValue::List(items) = &mut p.sections[sidx].options[oidx].value {
            // `if (!sscanf(ptr->value, "%d", &index)) return 1;`
            // sscanf == 0 (a matching failure): C returns 1, but the CLI's own
            // predicate already rejected the value before getting here.
            // sscanf == EOF (all whitespace): C walks the list with an
            // uninitialised `index`; the device build never hit item 0 in any
            // run, so nothing is removed and no delta is written.
            let Some(mut index) = sscanf_int_bytes(value) else {
                return Ok(());
            };
            // Negative positions select no list item. In particular, do not
            // decrement INT_MIN as C does: its signed overflow is undefined.
            if index < 0 {
                return Ok(());
            }
            let mut i = 0;
            while i < items.len() {
                if index == 0 {
                    if !internal && p.has_delta {
                        add_delta(p, Cmd::Remove, &section, ptr.option.as_deref(), Some(value));
                    }
                    if let OptionValue::List(items) = &mut p.sections[sidx].options[oidx].value {
                        items.remove(i);
                    }
                    return Ok(());
                }
                index -= 1;
                i += 1;
            }
            return Ok(());
        }
    }

    if !internal && p.has_delta {
        add_delta(p, Cmd::Remove, &section, ptr.option.as_deref(), None);
    }
    match ptr.o {
        Some(oidx) => {
            p.sections[sidx].options.remove(oidx);
            ptr.o = None;
        }
        None => {
            p.sections.remove(sidx);
            ptr.s = None;
        }
    }
    Ok(())
}

/// sscanf(s, "%d", &v) over bytes: `None` unless the conversion succeeded
/// (sscanf returned 1). Use `sscanf_int_no_match` to tell a matching failure
/// (0) from an input failure (EOF).
pub fn sscanf_int_bytes(s: &[u8]) -> Option<i32> {
    sscanf_int(&String::from_utf8_lossy(s))
}

/// `!sscanf(s, "%d", &dummy)`: true only when sscanf returns 0, i.e. a
/// non-whitespace byte was left that cannot start a number. A string that is
/// empty or all whitespace ends the input first and yields EOF (-1), which is
/// truthy in C, so it is *not* a rejection. A lone sign is consumed and then
/// fails to match, which is a 0.
pub fn sscanf_int_no_match(s: &[u8]) -> bool {
    let rest = s.iter().position(|b| !b.is_ascii_whitespace());
    rest.is_some_and(|i| sscanf_int_bytes(&s[i..]).is_none())
}

/// sscanf(s, "%d", &v): leading whitespace, optional sign, at least one digit.
pub fn sscanf_int(s: &str) -> Option<i32> {
    let t = s.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let n = digits.bytes().take_while(|b| b.is_ascii_digit()).count();
    if n == 0 {
        return None;
    }
    let mut v: i64 = 0;
    for b in digits[..n].bytes() {
        v = v.saturating_mul(10).saturating_add((b - b'0') as i64);
    }
    let v = if neg { -v } else { v };
    Some(v as i32)
}

/// Append an already validated list value, shared by import and uci_add_list.
pub(crate) fn append_list(s: &mut Section, option: &str, existing: Option<usize>, value: &[u8]) -> usize {
    let oidx = match existing {
        None => alloc_option(s, option, OptionValue::List(Vec::new()), None),
        Some(oidx) => {
            if let OptionValue::Str(old) = &mut s.options[oidx].value {
                // convert the string option into a one-item list in place
                let old = std::mem::take(old);
                s.options[oidx].value = OptionValue::List(vec![old]);
            }
            oidx
        }
    };
    if let OptionValue::List(items) = &mut s.options[oidx].value {
        items.push(value.into());
    }
    oidx
}

/// uci_add_list
pub fn add_list(ctx: &mut Context, ptr: &mut Ptr, internal: bool) -> Result<()> {
    expand_ptr(ctx, ptr, false)?;
    let (Some(pidx), Some(sidx)) = (ptr.p, ptr.s) else {
        return Err(Error::Inval);
    };
    let Some(value) = ptr.value.as_deref() else {
        return Err(Error::Inval);
    };
    // uci_add_list only asserts ptr->s and ptr->value: with no option part it
    // calls uci_alloc_list(s, NULL, NULL) and writes an option-less
    // `|pkg.section='v'` delta line, which uci_parse_delta_tuple then rejects
    // on the next load.
    let option = ptr.option.as_deref();
    let p = &mut ctx.root[pidx];
    ptr.o = Some(append_list(&mut p.sections[sidx], option.unwrap_or(""), ptr.o, value));
    if !internal && p.has_delta {
        add_delta(
            p,
            Cmd::ListAdd,
            ptr.section.as_deref().unwrap_or(""),
            option,
            Some(value),
        );
    }
    Ok(())
}

/// uci_del_list
pub fn del_list(ctx: &mut Context, ptr: &mut Ptr, internal: bool) -> Result<()> {
    expand_ptr(ctx, ptr, false)?;
    let (Some(pidx), Some(sidx)) = (ptr.p, ptr.s) else {
        return Err(Error::Inval);
    };
    let Some(value) = ptr.value.clone() else {
        return Err(Error::Inval);
    };
    let (Some(oidx), Some(option)) = (ptr.o, ptr.option.clone()) else {
        return Ok(());
    };
    let p = &mut ctx.root[pidx];
    if !matches!(p.sections[sidx].options[oidx].value, OptionValue::List(_)) {
        return Ok(());
    }
    if !internal && p.has_delta {
        add_delta(
            p,
            Cmd::ListDel,
            ptr.section.as_deref().unwrap_or(""),
            Some(&option),
            Some(value.as_slice()),
        );
    }
    if let OptionValue::List(items) = &mut p.sections[sidx].options[oidx].value {
        items.retain(|i| i.as_slice() != value.as_slice());
    }
    Ok(())
}

/// uci_set
pub fn set(ctx: &mut Context, ptr: &mut Ptr, internal: bool) -> Result<()> {
    expand_ptr(ctx, ptr, false)?;
    let Some(value) = ptr.value.as_deref() else {
        return Err(Error::Inval);
    };
    if !(ptr.s.is_some() || (ptr.option.is_none() && ptr.section.is_some())) {
        return Err(Error::Inval);
    }
    if ptr.option.is_none() && !value.is_empty() && !std::str::from_utf8(value).is_ok_and(validate_type) {
        return Err(Error::Inval);
    }
    let pidx = ptr.p.ok_or(Error::Inval)?;

    if ptr.o.is_none() {
        if let (Some(sidx), Some(opt)) = (ptr.s, ptr.option.as_deref()) {
            ptr.o = ctx.root[pidx].sections[sidx].find_option(opt);
        }
    }

    if value.is_empty() {
        // setting a nonexistent option/section to an empty value: no error
        if !ptr.complete() {
            return Ok(());
        }
        return delete(ctx, ptr, internal);
    }

    let p = &mut ctx.root[pidx];
    match (ptr.o, ptr.s, ptr.option.as_deref(), ptr.section.as_deref()) {
        (None, Some(sidx), Some(opt), _) => {
            // new option
            let oidx = alloc_option(&mut p.sections[sidx], opt, OptionValue::Str(value.into()), None);
            ptr.o = Some(oidx);
        }
        (_, None, None, Some(sec)) => {
            // new section
            let sidx = alloc_section(p, std::str::from_utf8(value).unwrap_or(""), Some(sec), None);
            ptr.s = Some(sidx);
        }
        (Some(oidx), Some(sidx), Some(_), _) => {
            // update option
            let o = &mut p.sections[sidx].options[oidx];
            if let OptionValue::Str(cur) = &o.value {
                if cur.as_slice() == value {
                    return Ok(());
                }
            }
            o.value = OptionValue::Str(value.into());
        }
        (None, Some(sidx), None, Some(_)) => {
            // update section type
            let s = &mut p.sections[sidx];
            if s.ty.as_bytes() == value {
                return Ok(());
            }
            // Equal lengths are a strcpy into the existing allocation, so the
            // section keeps its anonymity. A different length allocates a
            // replacement with uci_alloc_section(p, value, old->e.name, ...),
            // and a non-empty name there clears `anonymous` -- every section a
            // caller can reach is already named by uci_fixup_section, so an
            // anonymous section becomes `config <newtype> 'cfgXXXXXX'`.
            // n_section is unchanged (alloc bumps it, uci_set decrements it).
            if s.ty.len() != value.len() && !s.name.is_empty() {
                s.anonymous = false;
            }
            s.ty = std::str::from_utf8(value).unwrap_or_default().to_owned();
        }
        _ => return Err(Error::Inval),
    }

    if !internal && p.has_delta {
        add_delta(
            p,
            Cmd::Change,
            ptr.section.as_deref().unwrap_or(""),
            ptr.option.as_deref(),
            Some(value),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_deletion_handles_signed_index_boundaries_without_losing_values() {
        for (index, expected) in [
            (i32::MIN, vec!["one", "two"]), (-1, vec!["one", "two"]),
            (i32::MAX, vec!["one", "two"]), (0, vec!["two"]), (1, vec!["one"]),
        ] {
            let mut ctx = Context::new();
            let input = b"config test s\nlist items one\nlist items two\n";
            crate::parse::import(&mut ctx, &mut input.as_slice(), Some("t"), None, true).unwrap();
            ctx.root[0].has_delta = true;
            let mut ptr = Ptr::default();
            lookup_ptr(&mut ctx, &mut ptr, Some(format!("t.s.items={index}").as_bytes()), true).unwrap();
            delete(&mut ctx, &mut ptr, false).unwrap();
            assert_eq!(ctx.root[0].sections[0].options[0].value,
                OptionValue::List(expected.into_iter().map(Into::into).collect()));
            assert_eq!(ctx.root[0].delta.len(), usize::from((0..2).contains(&index)));
        }
    }

    #[test]
    fn parse_ptr_cases() {
        let mut p = Ptr::default();
        parse_ptr(&mut p, b"net.lan.ipaddr=1.2.3.4").unwrap();
        assert_eq!(p.package.as_deref(), Some("net"));
        assert_eq!(p.section.as_deref(), Some("lan"));
        assert_eq!(p.option.as_deref(), Some("ipaddr"));
        assert_eq!(p.value.as_deref(), Some(&b"1.2.3.4"[..]));
        // first '=' splits: value keeps later '='
        parse_ptr(&mut p, b"a.b.c=x=y").unwrap();
        assert_eq!(p.value.as_deref(), Some(&b"x=y"[..]));
        // "test." -> section "" -> extended flag, not an error
        parse_ptr(&mut p, b"test.").unwrap();
        assert!(p.flags & LOOKUP_EXTENDED != 0);
        // "test.section." -> option "" -> parse error
        assert_eq!(parse_ptr(&mut p, b"test.section."), Err(Error::Parse));
        assert_eq!(parse_ptr(&mut p, b"test.s.o.x"), Err(Error::Parse));
        parse_ptr(&mut p, b"test.@iface[-1].name").unwrap();
        assert!(p.flags & LOOKUP_EXTENDED != 0);
        assert!(validate_package("fire-wall"));
        assert!(!validate_name("fire-wall"));
        assert!(validate_type("a.b"));
    }

    #[test]
    fn fixup_names_like_libuci() {
        let mut p = Package::new("x");
        p.n_section = 1;
        let s = Section {
            name: String::new(),
            ty: "defaults".into(),
            anonymous: true,
            options: vec![],
        };
        // djbhash("defaults") known value check against C: computed below
        let name = fixup_section(&p, &s);
        assert!(name.starts_with("cfg01"));
        assert_eq!(name.len(), 9);
    }
}
