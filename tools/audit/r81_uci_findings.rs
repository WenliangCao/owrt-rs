//! R81 uci audit: unit tests that encode the C (libuci 66127cd7) behaviour for
//! each finding. Every test is expected to FAIL on the current owrt-uci until
//! the corresponding finding is fixed. Not run (no cargo on the audit host).
//!
//! Run: cp tools/audit/r81_uci_findings.rs components/uci/tests/ &&
//!      cargo test -p owrt-uci --test r81_uci_findings
//! `keeps_anonymity_on_same_length_type_change` is the control: it passes on
//! both implementations.

use owrt_uci::model::{OptionValue, Ptr, LOOKUP_DONE};
use owrt_uci::{ops, parse, Context, Error};
use std::io::Cursor;

fn load(text: &[u8]) -> (Context, usize) {
    let mut ctx = Context::new();
    let mut r = Cursor::new(text.to_vec());
    let idx = parse::import(&mut ctx, &mut r, Some("t"), None, true).unwrap().unwrap();
    (ctx, idx)
}

fn set_type(ctx: &mut Context, pidx: usize, ty: &str) {
    let name = ctx.root[pidx].sections[0].name.clone();
    let mut ptr = Ptr {
        flags: LOOKUP_DONE,
        p: Some(pidx),
        s: Some(0),
        package: Some("t".into()),
        section: Some(name),
        value: Some(ty.as_bytes().to_vec()),
        ..Ptr::default()
    };
    ops::set(ctx, &mut ptr, true).unwrap();
}

/// F1. list.c uci_set "update section": strlen differs -> uci_alloc_section(p,
/// value, old->e.name, ...) with a non-empty name -> anonymous = false.
#[test]
fn type_change_with_different_length_drops_anonymity_like_c() {
    let (mut ctx, i) = load(b"config foo\n\toption x 1\n");
    assert!(ctx.root[i].sections[0].anonymous);
    set_type(&mut ctx, i, "longertype");
    assert!(!ctx.root[i].sections[0].anonymous, "C exports `config longertype 'cfg01xxxx'`");
}

#[test]
fn keeps_anonymity_on_same_length_type_change() {
    let (mut ctx, i) = load(b"config foo\n");
    set_type(&mut ctx, i, "bar"); // strcpy in place in C
    assert!(ctx.root[i].sections[0].anonymous);
}

/// F2. cli.c: `if (ptr.value && !sscanf(ptr.value, "%d", &dummy)) return 1;`
/// sscanf("") and sscanf("  ") return EOF (-1), which is truthy, so the C CLI
/// proceeds and uci_delete removes the whole option. Only a non-empty,
/// non-numeric value (sscanf == 0) is rejected.
#[test]
fn cli_delete_index_predicate_matches_sscanf() {
    let rejects = |v: &str| std::str::from_utf8(v.as_bytes()).ok().and_then(ops::sscanf_int).is_none();
    assert!(rejects("abc"));
    assert!(!rejects("7"));
    assert!(!rejects(""), "uci delete p.s.o= must delete the option (exit 0)");
    assert!(!rejects("  "), "uci delete p.s.o=' ' must delete the option (exit 0)");
}

/// F4. file.c uci_getln: fgets stops at the buffer boundary (LINEBUF 32,
/// doubling), strlen stops at the NUL; the bytes from the NUL to the boundary
/// are dropped, the rest of the same line is appended, the line still ends at
/// its own '\n'. owrt-uci truncates the whole line at the NUL and glues the
/// NEXT line onto it (the unterminated quote then swallows `config other`).
#[test]
fn nul_inside_a_long_line_keeps_the_line_boundary_like_fgets() {
    let mut text = b"config a\n\toption o '".to_vec();
    text.extend(std::iter::repeat(b'a').take(40));
    text.push(0);
    text.extend(std::iter::repeat(b'b').take(30));
    text.extend_from_slice(b"'\nconfig other\n");
    let mut ctx = Context::new();
    let mut r = Cursor::new(text);
    let idx = parse::import(&mut ctx, &mut r, Some("t"), None, true)
        .expect("C parses this file")
        .unwrap();
    let p = &ctx.root[idx];
    assert_eq!(p.sections.len(), 2, "C still sees `config other` as its own line");
    // 40 a + the 20 b that fgets read after the 63-byte boundary
    let OptionValue::Str(v) = &p.sections[0].options[0].value else { panic!() };
    assert_eq!(v.len(), 60);
}

/// F5. list.c uci_add_list only asserts ptr->s and ptr->value; with no option
/// it creates a list with a NULL name and writes `|t.s='v'` to the delta
/// (which the next load ignores). Exit status 0, no error.
#[test]
fn add_list_without_option_succeeds_like_c() {
    let (mut ctx, i) = load(b"config a s\n");
    let mut ptr = Ptr::default();
    ops::lookup_ptr(&mut ctx, &mut ptr, Some(b"t.s=v"), true).unwrap();
    assert!(ptr.p == Some(i));
    assert_eq!(ops::add_list(&mut ctx, &mut ptr, false), Ok(()));
}

/// F6. list.c uci_rename does not validate the new name; uci_parse_ptr only
/// runs uci_validate_text (bytes >= 0x20 pass), so a non-UTF-8 name is accepted.
#[test]
fn rename_to_non_utf8_is_accepted_like_c() {
    let (mut ctx, _) = load(b"config a s\n");
    let mut ptr = Ptr::default();
    ops::lookup_ptr(&mut ctx, &mut ptr, Some(b"t.s=\xff\xfe"), true).unwrap();
    assert_eq!(ops::rename(&mut ctx, &mut ptr, false), Ok(()));
}

/// F6b. util.c uci_parse_ptr: a non-UTF-8 byte in the package or option part
/// fails uci_validate_package/name -> UCI_ERR_PARSE, not UCI_ERR_INVAL.
#[test]
fn non_utf8_package_name_is_a_parse_error_like_c() {
    let mut ptr = Ptr::default();
    assert_eq!(ops::parse_ptr(&mut ptr, b"t\xff.s"), Err(Error::Parse));
    assert_eq!(ops::parse_ptr(&mut ptr, b"t.s.o\xff"), Err(Error::Parse));
}

/// F7. list.c uci_lookup_ext_section: `idx = strtol(idxstr, &t, 10); if (t && *t)
/// error;` with `int idx`. Whitespace-only -> no conversion, t == idxstr, *t == ' '
/// -> UCI_ERR_INVAL. 4294967296 converts, then truncates to int 0.
#[test]
fn ext_index_parsing_matches_strtol_into_int() {
    let (mut ctx, _) = load(b"config a\nconfig a\n");
    let mut ptr = Ptr::default();
    assert_eq!(ops::lookup_ptr(&mut ctx, &mut ptr, Some(b"t.@a[ ]"), true), Err(Error::Inval));
    let mut ptr = Ptr::default();
    ops::lookup_ptr(&mut ctx, &mut ptr, Some(b"t.@a[4294967296]"), true).unwrap();
    assert!(ptr.complete(), "(int)4294967296 == 0 selects the first section");
    assert_eq!(ptr.s, Some(0));
}
