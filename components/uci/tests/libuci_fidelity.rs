//! Cases from the R81 cold audit (F25), with every expectation taken from the
//! device's own C libuci (`extracted/rootfs-files/sbin/uci` +
//! `lib/libuci.so.20250120`, OpenWrt 25.12.5) run in a chroot on an aarch64
//! host, cross-read against upstream `uci` at 66127cd7.
//!
//! Where the audit's demo file guessed a number, the number here is the one the
//! C binary printed; `tools/r83_uci_findings.sh` re-derives the same values from
//! the C side and compares the CLI byte for byte.

use owrt_uci::model::{OptionValue, Ptr, LOOKUP_DONE};
use owrt_uci::{ops, parse, Context, Error};
use std::io::Cursor;

#[test]
fn reorder_strtoul_saturates_before_narrowing_to_int() {
    for (value, expected) in [
        ("", 0),
        ("  +1tail", 1),
        ("-1", -1),
        ("4294967297", 1),
        ("18446744073709551615", -1),
        ("18446744073709551616", -1),
        ("18446744073709551617", -1),
        ("-18446744073709551615", 1),
        ("-18446744073709551616", -1),
        ("-18446744073709551617", -1),
        ("99999999999999999999999999999999999999999999", -1),
    ] {
        assert_eq!(owrt_uci::delta::strtoul_int(value), expected, "{value}");
    }
}

fn load(text: &[u8]) -> (Context<'static>, usize) {
    let mut ctx = Context::new();
    let mut r = Cursor::new(text.to_vec());
    let idx = parse::import(&mut ctx, &mut r, Some("t"), None, true)
        .unwrap()
        .unwrap();
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

// ---------------------------------------------------------------- retype

/// list.c uci_set "update section": a different strlen goes through
/// `uci_alloc_section(p, value, old->e.name, ...)`, whose non-empty name
/// clears `anonymous`.
///
/// C: `uci set t.@device[0]=interface` -> `t.cfg010f15='interface'` in the
/// delta and `config interface 'cfg010f15'` after commit.
#[test]
fn type_change_with_different_length_drops_anonymity_like_c() {
    let (mut ctx, i) = load(b"config foo\n\toption x 1\n");
    assert!(ctx.root[i].sections[0].anonymous);
    let n_section = ctx.root[i].n_section;
    set_type(&mut ctx, i, "longertype");
    assert!(
        !ctx.root[i].sections[0].anonymous,
        "C exports `config longertype 'cfgXXXXXX'`"
    );
    // uci_alloc_section bumps n_section, uci_set decrements it again
    assert_eq!(ctx.root[i].n_section, n_section);
    // the generated name is kept as it was, uci_fixup_section does not re-run
    assert!(ctx.root[i].sections[0].name.starts_with("cfg01"));
}

/// The control: an equal strlen is a strcpy into the existing allocation, so
/// the section stays anonymous. C: `uci set t.@device[0]=bridge` still shows
/// `t.@bridge[0]` and commits `config bridge` with no name.
#[test]
fn keeps_anonymity_on_same_length_type_change() {
    let (mut ctx, i) = load(b"config foo\n");
    set_type(&mut ctx, i, "bar");
    assert!(ctx.root[i].sections[0].anonymous);
}

/// A named section keeps its name either way.
#[test]
fn named_section_type_change_keeps_the_name() {
    let (mut ctx, i) = load(b"config device 'foo'\n");
    set_type(&mut ctx, i, "interface");
    assert!(!ctx.root[i].sections[0].anonymous);
    assert_eq!(ctx.root[i].sections[0].name, "foo");
}

// ---------------------------------------------------------------- delete

/// cli.c CMD_DEL: `if (ptr.value && !sscanf(ptr.value, "%d", &dummy)) return 1;`
/// Only a matching failure (sscanf == 0) rejects. An empty or all-whitespace
/// value exhausts the input first, which is EOF (-1) and therefore truthy.
///
/// Verified with the C binary on `uci delete t.@rule[0].l=<v>`: rc 1 for
/// "abc", "-", "+", "-x", "x1", " a"; rc 0 for "", " ", "\t", "  1", "0x1",
/// "1abc", "0", "2", "2147483648", "-1".
#[test]
fn cli_delete_index_predicate_matches_sscanf() {
    for v in ["abc", "-", "+", "-x", "x1", " a"] {
        assert!(
            ops::sscanf_int_no_match(v.as_bytes()),
            "sscanf({v:?}) returns 0 -> exit 1"
        );
    }
    for v in [
        "",
        " ",
        "\t",
        "   ",
        "  1",
        "0x1",
        "1abc",
        "0",
        "2",
        "2147483648",
        "-1",
    ] {
        assert!(
            !ops::sscanf_int_no_match(v.as_bytes()),
            "sscanf({v:?}) is 1 or EOF -> not rejected"
        );
    }
    // a value that is not UTF-8 cannot start a number either
    assert!(ops::sscanf_int_no_match(b"\xff"));
}

/// list.c uci_delete only enters the list-index branch for `ptr->value &&
/// *ptr->value`, so an empty value deletes the whole option whatever its type.
/// C: `uci delete t.@rule[0].opt=` -> rc 0, delta `-t.cfg0192bd.opt`.
#[test]
fn empty_index_deletes_the_whole_option_like_c() {
    for text in [
        &b"config rule\n\toption opt 'v'\n"[..],
        &b"config rule\n\tlist opt 'a'\n\tlist opt 'b'\n"[..],
    ] {
        let (mut ctx, i) = load(text);
        ctx.root[i].has_delta = true;
        let mut ptr = Ptr::default();
        ops::lookup_ptr(&mut ctx, &mut ptr, Some(b"t.@rule[0].opt="), true).unwrap();
        assert_eq!(ops::delete(&mut ctx, &mut ptr, false), Ok(()));
        assert!(ctx.root[i].sections[0].options.is_empty());
        let d = &ctx.root[i].delta;
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].cmd, owrt_uci::model::Cmd::Remove);
        assert_eq!(d[0].option.as_deref(), Some("opt"));
        assert_eq!(d[0].value, None, "`-t.<sec>.opt` carries no value");
    }
}

/// An all-whitespace index reaches the list walk with an uninitialised
/// `index`; the device build removed nothing in three runs and wrote no delta.
#[test]
fn blank_index_removes_nothing_and_writes_no_delta() {
    let (mut ctx, i) = load(b"config rule\n\tlist l 'a'\n\tlist l 'b'\n");
    ctx.root[i].has_delta = true;
    let mut ptr = Ptr::default();
    ops::lookup_ptr(&mut ctx, &mut ptr, Some(b"t.@rule[0].l= "), true).unwrap();
    assert_eq!(ops::delete(&mut ctx, &mut ptr, false), Ok(()));
    let OptionValue::List(items) = &ctx.root[i].sections[0].options[0].value else {
        panic!()
    };
    assert_eq!(items.len(), 2);
    assert!(ctx.root[i].delta.is_empty());
}

// ---------------------------------------------------------------- getln

#[test]
fn owned_values_preserve_bytes_across_scalar_list_and_size_changes() {
    for len in [1, 14, 15, 16, 17, 4096] {
        let value = vec![0xfe; len];
        let mut input = b"config rule named\noption value '".to_vec();
        input.extend_from_slice(&value);
        input.extend_from_slice(b"'\n");
        let (mut ctx, i) = load(&input);
        drop(input);
        let mut ptr = Ptr::default();
        ops::lookup_ptr(&mut ctx, &mut ptr, Some(b"t.named.value=tail"), true).unwrap();
        ops::add_list(&mut ctx, &mut ptr, true).unwrap();
        let OptionValue::List(items) = &ctx.root[i].sections[0].options[0].value else { panic!() };
        assert_eq!(items[0].as_slice(), value);
        assert_eq!(items[1].as_slice(), b"tail");
        let cloned = ctx.root[i].clone();

        ptr.value = Some(b"short".to_vec());
        ops::set(&mut ctx, &mut ptr, true).unwrap();
        ptr.value = Some(value.clone());
        ops::set(&mut ctx, &mut ptr, true).unwrap();
        let OptionValue::Str(current) = &ctx.root[i].sections[0].options[0].value else { panic!() };
        assert_eq!(current.as_slice(), value);
        drop(ctx);

        let OptionValue::List(items) = &cloned.sections[0].options[0].value else { panic!() };
        assert_eq!(items[0].as_slice(), value);
        assert_eq!(items[1].as_slice(), b"tail");
    }
}

/// file.c uci_getln: fgets stops at the buffer boundary (LINEBUF 32, doubling
/// after every partial read) and strlen stops at the NUL, so only the bytes
/// between the NUL and the end of *that* chunk are dropped. The line still
/// ends at its own newline, and the next line stays a line of its own.
///
/// Value lengths printed by the C binary: 40a+30b -> 59, 100a+100b -> 185.
#[test]
fn nul_inside_a_long_line_keeps_the_line_boundary_like_fgets() {
    for (n_a, n_b, expected) in [(40usize, 30usize, 59usize), (100, 100, 185)] {
        let mut text = b"config a\n\toption o '".to_vec();
        text.extend(std::iter::repeat_n(b'a', n_a));
        text.push(0);
        text.extend(std::iter::repeat_n(b'b', n_b));
        text.extend_from_slice(b"'\nconfig other\n");
        let (ctx, i) = load(&text);
        let p = &ctx.root[i];
        assert_eq!(
            p.sections.len(),
            2,
            "C still sees `config other` as its own line"
        );
        assert_eq!(p.sections[1].ty, "other");
        let OptionValue::Str(v) = &p.sections[0].options[0].value else {
            panic!()
        };
        assert_eq!(v.len(), expected, "{n_a}a NUL {n_b}b");
        assert_eq!(v.iter().filter(|&&b| b == b'a').count(), n_a);
    }
}

/// When the NUL lands inside the very first fgets chunk the rest of the line
/// is lost and the next line is glued on, so the quote never closes. The C
/// binary reports `Parse error (EOF with unterminated ') at line 2, byte 29`
/// for 5a/5b and `... byte 24` for 0a/0b.
#[test]
fn nul_within_the_first_chunk_swallows_the_next_line_like_c() {
    for (n_a, n_b, byte) in [(5usize, 5usize, 29usize), (0, 0, 24)] {
        let mut text = b"config a\n\toption o '".to_vec();
        text.extend(std::iter::repeat_n(b'a', n_a));
        text.push(0);
        text.extend(std::iter::repeat_n(b'b', n_b));
        text.extend_from_slice(b"'\nconfig other\n");
        let mut ctx = Context::new();
        let mut r = Cursor::new(text);
        assert_eq!(
            parse::import(&mut ctx, &mut r, Some("t"), None, true),
            Err(Error::Parse)
        );
        let info = ctx.pctx.as_ref().unwrap();
        assert_eq!(info.reason, Some("EOF with unterminated '"));
        assert_eq!((info.line, info.byte), (2, byte), "{n_a}a NUL {n_b}b");
    }
}

/// `if (!p || !*p) return;` -- a chunk that starts with a NUL ends the line
/// where it is, without counting it. C drops the whole `option` line and keeps
/// both sections.
#[test]
fn nul_at_the_start_of_a_line_drops_that_line_like_c() {
    let (ctx, i) = load(b"config a\n\0option o 'v'\nconfig b\n");
    let p = &ctx.root[i];
    assert_eq!(p.sections.len(), 2);
    assert_eq!(p.sections[0].ty, "a");
    assert!(p.sections[0].options.is_empty());
    assert_eq!(p.sections[1].ty, "b");
}

// ---------------------------------------------------------------- add_list

/// list.c uci_add_list only asserts ptr->s and ptr->value; with no option part
/// it creates a list whose name is NULL and writes `|pkg.section='v'` to the
/// delta. C: `uci add_list t.@rule[0]=x` -> rc 0, delta `|t.cfg0192bd='x'`.
#[test]
fn add_list_without_option_succeeds_like_c() {
    let (mut ctx, i) = load(b"config a s\n");
    ctx.root[i].has_delta = true;
    let mut ptr = Ptr::default();
    ops::lookup_ptr(&mut ctx, &mut ptr, Some(b"t.s=v"), true).unwrap();
    assert!(ptr.p == Some(i));
    assert_eq!(ops::add_list(&mut ctx, &mut ptr, false), Ok(()));
    let d = &ctx.root[i].delta;
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].cmd, owrt_uci::model::Cmd::ListAdd);
    assert_eq!(d[0].option, None, "`|t.s='v'` has no option part");
    assert_eq!(d[0].value.as_deref(), Some(&b"v"[..]));
}

/// That delta line is rejected again on the next load (uci_parse_delta_tuple
/// requires an option for LIST_ADD), so it counts as zero changes and a
/// following commit rewrites nothing.
#[test]
fn option_less_list_add_delta_is_rejected_on_load() {
    let mut r = Cursor::new(b"|t.s='v'\n".to_vec());
    let mut pctx = parse::Pctx::new(&mut r);
    pctx.getln(0);
    assert_eq!(
        owrt_uci::delta::parse_delta_tuple(&mut pctx),
        Err(Error::Inval)
    );
}

// ---------------------------------------------------------------- rename

/// Intentional difference: refuse an unrepresentable name atomically rather
/// than replacing its bytes on a same-process export or commit. The original
/// accepts it here but rejects the resulting rename delta on the next load.
#[test]
fn rename_to_non_utf8_is_refused_without_mutating_model_or_delta() {
    let (mut ctx, i) = load(b"config a s\n");
    ctx.root[i].has_delta = true;
    let mut ptr = Ptr::default();
    ops::lookup_ptr(&mut ctx, &mut ptr, Some(b"t.s=\xff\xfe"), true).unwrap();
    let before = ctx.root[i].clone();
    assert_eq!(ops::rename(&mut ctx, &mut ptr, false), Err(Error::Inval));
    assert_eq!(ctx.root[i], before);
}

/// ... and is rejected again on load, so it never reaches the config file.
#[test]
fn non_utf8_rename_delta_is_rejected_on_load() {
    let mut r = Cursor::new(b"@t.s='\xff\xfe'\n".to_vec());
    let mut pctx = parse::Pctx::new(&mut r);
    pctx.getln(0);
    assert_eq!(
        owrt_uci::delta::parse_delta_tuple(&mut pctx),
        Err(Error::Inval)
    );
}

// ---------------------------------------------------------------- parse_ptr

/// util.c uci_parse_ptr: a byte that is not in the identifier set fails
/// uci_validate_package / uci_validate_name, and that path throws
/// UCI_ERR_PARSE, not UCI_ERR_INVAL. C: `uci get $'t\xff.s'` and
/// `uci get $'t.s.o\xff'` both print `uci: Parse error` and exit 1.
#[test]
fn non_utf8_package_name_is_a_parse_error_like_c() {
    let mut ptr = Ptr::default();
    assert_eq!(ops::parse_ptr(&mut ptr, b"t\xff.s"), Err(Error::Parse));
    assert_eq!(ops::parse_ptr(&mut ptr, b"t.s.o\xff"), Err(Error::Parse));
    // a section that is not a valid name only sets the extended flag
    ops::parse_ptr(&mut ptr, b"t.\xff.o").unwrap();
    assert!(ptr.flags & owrt_uci::model::LOOKUP_EXTENDED != 0);
    // the fourth component is rejected before any validation runs
    assert_eq!(ops::parse_ptr(&mut ptr, b"t\xff.s.o.x"), Err(Error::Parse));
    // the value only has to pass uci_validate_text
    ops::parse_ptr(&mut ptr, b"t.s.o=\xff\xfe").unwrap();
    assert_eq!(ptr.value.as_deref(), Some(&b"\xff\xfe"[..]));
    assert_eq!(ops::parse_ptr(&mut ptr, b"t.s.o=\x01"), Err(Error::Parse));
}

// ---------------------------------------------------------------- ext index

/// list.c uci_lookup_ext_section: `int idx = strtol(idxstr, &t, 10); if (t &&
/// *t) error;`. strtol leaves the end pointer at the start when it converts
/// nothing, so " " has trailing garbage while "" does not, and the long result
/// is truncated to int.
///
/// Verified against the C binary on three `config a` sections carrying
/// distinct option values (rc / selected section):
///   "" -> 0, " " -> Invalid argument, " 1" -> 1, "1 " -> Invalid argument,
///   "0x1"/"1abc" -> Invalid argument, 4294967296 -> 0, 4294967297 -> 1,
///   99999999999999999999999 -> last, -99999999999999999999999 -> 0,
///   -4294967296 -> 0, -4294967295 -> 1, 2147483648/2147483647 -> not found.
#[test]
fn ext_index_parsing_matches_strtol_into_int() {
    let text =
        b"config a\n\toption k 'zero'\nconfig a\n\toption k 'one'\nconfig a\n\toption k 'two'\n";
    let pick = |idx: &str| -> Result<Option<usize>, Error> {
        let (mut ctx, _) = load(text);
        let mut ptr = Ptr::default();
        let tuple = format!("t.@a[{idx}].k");
        ops::lookup_ptr(&mut ctx, &mut ptr, Some(tuple.as_bytes()), true).map(|()| ptr.s)
    };
    for idx in [" ", "1 ", "0x1", "1abc", "-", "+"] {
        assert_eq!(pick(idx), Err(Error::Inval), "index {idx:?}");
    }
    for (idx, want) in [
        ("", Some(0)),
        ("0", Some(0)),
        (" 1", Some(1)),
        // isspace() includes the vertical tab; verified against the rootfs
        // /sbin/uci, which answers `one` for this index
        ("\u{0b}1", Some(1)),
        ("\t1", Some(1)),
        ("\u{0c}1", Some(1)),
        ("\r1", Some(1)),
        ("+1", Some(1)),
        ("-1", Some(2)),
        ("-3", Some(0)),
        ("4294967296", Some(0)),
        ("4294967297", Some(1)),
        ("99999999999999999999999", Some(2)),
        ("-99999999999999999999999", Some(0)),
        ("-4294967296", Some(0)),
        ("-4294967295", Some(1)),
        ("3", None),
        ("-4", None),
        ("2147483647", None),
        ("2147483648", None),
    ] {
        assert_eq!(pick(idx).unwrap(), want, "index {idx:?}");
    }
}
