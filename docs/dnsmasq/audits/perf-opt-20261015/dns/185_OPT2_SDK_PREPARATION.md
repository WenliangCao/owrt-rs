# Separate profile2 SDK preparation, not a build result

Source `8035114257c8706047d2038c2bb8126391331925` changes release
`opt-level = 3` to2. It also inherits the separate `f8adb016` collision-fixture
repair inside `hosts.rs`'s final `#[cfg(test)]` module and its audit document.
The non-test prefix is byte-identical to185, but the source manifest correctly
records two changed SDK input hashes: Cargo.toml and hosts.rs. The audit doc is
outside the SDK inventory. `lto = true`,
`codegen-units = 1`, panic/strip, features, System allocator, SDK recipe and
hardening remain unchanged. This source is not combined with6ab.

The [static binding](185-opt2-sdk-preparation.json) records the separate179-file
manifest and Git identity. Reading the actual canonical Makefile confirms its
`RUSTFLAGS` contains no `opt-level` override. The canonical builder removes
inherited `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS`; it does not inject
`-Copt-level=3`. Thus the original recipe does not inherently override profile2.
Any future run must also exclude Cargo profile environment overrides and verify
the prepared manifest and effective compiler invocation. No such run occurred.

There is a reporting caveat: the existing builder hardcodes `opt_level: '3'`
in its receipt metadata. That field is not a compiler argument. Before any803
build is selected, its final receipt must accurately bind profile2 and actual
compiler flags, through a separately reviewed receipt or a minimal metadata-only
builder copy. The canonical builder used for7c and6ab stays byte-identical.
This preparation neither alters a builder nor claims the hardcoded field is
evidence of the actual optimization level.

The existing local rust-lld text reduction of about5.15% remains local codegen
evidence. It is not an original SDK size or performance result. This compiler
experiment stays behind6ab's actual related gates and the authorized sequential
7c/6ab SDK work. There was no upload, build, test run or Oracle access here.
