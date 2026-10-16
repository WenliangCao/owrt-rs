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

The canonical builder hardcodes `opt_level: '3'` in its receipt metadata;
that field is not a compiler argument. A separate
[`perf_opt_sdk_build_opt2.py`](../../../../../tools/dnsmasq/perf_opt_sdk_build_opt2.py)
copy is now prepared for803. It checks the exact source release profile,
rejects ambient `CARGO_PROFILE_RELEASE_*`, and records level2. It enables
Cargo's documented verbose log output, then retains both actual lib/bin rustc
commands and rejects missing, conflicting or wrong optimization settings before
claiming `built-unqualified`. Target, codegen1, panicabort, strip and binary fat
LTO are also checked. Compiler/linker/package commands and original budgets
are unchanged. The original7c/6ab builder remains exactly `f4540b1c…`.

Four rejection/parser tests and a tiny real local Rust1.98.1 Cargo logging
fixture passed. This is tooling validation; no803 product or SDK build ran.
The [builder preparation](185-opt2-sdk-builder-preparation.json) binds exact
tool/control hashes. It requires Python3.11+ for stdlib TOML parsing and still
awaits independent local review. No remote upload or build is authorized while
the original native240/owner32/full44 queue owns Oracle. Cargo's
[verbosity configuration](https://doc.rust-lang.org/cargo/reference/config.html#termverbose)
and [profile precedence](https://doc.rust-lang.org/cargo/reference/profiles.html)
were checked against its official documentation using `find-docs`.

The existing local rust-lld text reduction of about5.15% remains local codegen
evidence. It is not an original SDK size or performance result. This compiler
experiment stays behind6ab's actual related gates and the authorized sequential
7c/6ab SDK work. Only local tooling controls ran; no803 product test, SDK build,
upload or Oracle access occurred in this preparation.
