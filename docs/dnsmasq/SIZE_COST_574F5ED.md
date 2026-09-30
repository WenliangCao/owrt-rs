# Size diagnosis and DYN1 linkage candidate

This inspection uses existing artifacts only. No diagnostic build, default
recipe change, throughput comparison or router operation has been performed.
The product snapshot remains `574f5ed88d8d3c9453f0ac9c25a891933b5a128b`.
The 989,991-byte Rust artifact still exceeds the 269,305-byte image C artifact by
720,686 bytes (+267.6%); resource acceptance remains incomplete.

`elf_cost.py` reads ELF headers without running the executable. Its two valid
artifact checks agree with independently recorded readelf fields; malformed
magic and a truncated file are rejected. Other program headers overlap LOAD
ranges, so they are not added again as independent storage.

| Final ELF accounting | C | Rust | Rust minus C |
| --- | ---: | ---: | ---: |
| Executable/read-only LOAD file bytes | 249,912 | 963,960 | +714,048 |
| Writable LOAD file bytes | 18,577 | 25,935 | +7,358 |
| File bytes outside LOAD ranges | 816 | 96 | -720 |
| Total file bytes | 269,305 | 989,991 | +720,686 |
| LOAD zero-fill bytes | 1,199 | 6,281 | +5,082 |

About 99.1% of the file-size difference lies in the executable/read-only LOAD
range, which contains code, read-only data and unwind information. These are
storage measurements, not RSS, PSS, USS, page-rounded mappings or runtime peaks.
Both final ELFs have had section headers removed by SDK sstrip.

An initial read of the Cargo release path failed because SDK `CONFIG_AUTOREMOVE`
had removed it. The existing `.pkgdir` copy survived and was recovered without
rebuilding. It is 991,360 bytes: SDK sstrip removed only 1,369 bytes. All 13
allocated file-backed sections match the delivered ELF after accounting for
loader zero-fill of a trailing zero byte. Thus additional stripping cannot
explain or remove the 720 KiB-class regression.

| Existing Rust pre-sstrip section | Bytes |
| --- | ---: |
| `.text` | 821,752 |
| `.eh_frame` | 72,788 |
| `.rodata` | 52,684 |
| `.data.rel.ro` | 22,784 |
| `.eh_frame_hdr` | 10,188 |
| `.gcc_except_table` | 6,108 |
| `.data` | 2,856 |
| `.got` | 208 |

`.text` alone accounts for 83.0% of the delivered Rust file. The existing copy
has no symbol table, so this inspection cannot accurately divide it among
dnsmasq product code, monomorphized Rust standard-library code, compiler
intrinsics and statically linked musl. A linker map is needed before assigning
precise savings to one library. The 89,084 bytes of unwind-related sections are
visible, but removing unwind support blindly would change diagnostic/FFI
assumptions and is not the first candidate.

The current Rust profile already uses opt-level 3, fat LTO, one codegen unit,
panic=abort and symbol stripping. Its SDK link retains BFD, 4 KiB maximum pages,
NOW, RELRO and packed relative relocations. The image C ELF is dynamic PIE;
Rust is static ET_EXEC. This layout/security difference is an open compatibility
issue, not an optimization advantage. Both have non-executable GNU_STACK and
separate non-WX LOAD ranges. C's shared libraries remain required by other image
components; their full sizes cannot be claimed as exclusive space saved by Rust.

The exact installed Rust 1.98.1 compiler lists `crt-static`, accepts disabling
that feature, and reports its absence from the resulting target cfg. Rust
documents `crt-static` as the runtime-linkage switch; a flag alone does not
establish the resulting ELF, so the candidate must pass structural verification.
[Rust linkage reference](https://doc.rust-lang.org/reference/linkage.html#static-and-dynamic-c-runtimes)

The SDK GCC 14.3.0 specs were read without compilation. They select
`/lib/ld-musl-aarch64.so.1` for a non-static executable, `Scrt1.o` for PIE, and
pass `-pie` through to the linker. Its reported file search resolves musl and
startup objects inside the matching SDK. The SDK libc file hash differs from the
stripped image libc file; the runtime gate therefore explicitly uses the already
verified image loader/libraries instead of assuming file identity.

The sole first candidate, **DYN1**, is frozen for review as follows:

1. Keep every product file at the 574f5ed freeze and retain all configuration,
   protocol, resource limits, optimization level, LTO, panic, strip, linker and
   existing security flags. Use fresh private diagnostic directories.
2. Append only `-Ctarget-feature=-crt-static`, `-Clink-self-contained=no` and
   `-Clink-arg=-pie`. The intent is a dynamic C runtime from the image while
   retaining Rust dependencies statically. No shared Rust runtime or new image
   library is permitted. `link-self-contained=no` selects the SDK's non-Rust
   startup/library inputs; this still requires verification of the actual link.
   [rustc code-generation options](https://doc.rust-lang.org/rustc/codegen-options/index.html#link-self-contained)
3. Retain the pre-sstrip ELF, stripped diagnostic copy, full commands, linker
   map and dependency identities. Rebuild one unchanged B0 only if needed to
   obtain an equivalent map; it is a baseline observation, not another candidate.
   Do not invoke package/image installation or modify the default recipe.
4. Reject unless the result is AArch64 ET_DYN PIE, uses the image musl loader,
   has full RELRO/NOW, non-executable stack, no writable-executable LOAD and no
   text relocations. Every NEEDED object must resolve to the verified image
   library set; unresolved/new dependencies are failure.
5. Before any performance work, run the existing frozen artifact gates:
   configuration acceptance against target C, UDP no-route corpus, TCP daemon,
   reload/cache/hosts, TCP connection snapshots, signal shutdown and DHCP smoke.
   Keep all previous known-gap qualifications; a linkage experiment cannot
   promote incomplete functionality to accepted delivery.
6. For this size screen, require at least 5% lower stripped ELF bytes than B0:
   at most **940,491 bytes** against the delivered 989,991-byte B0. Report APK
   size separately if packaging is subsequently requested. A smaller ELF does
   not prove lower CPU, latency or memory use, and does not by itself resolve
   the regression relative to C. Any protection or functional regression rejects
   the candidate; no observed size benefit means revert the experiment.

Root review of this plan is not deployment permission. Diagnostic linking must
wait until the C measurement window is clear. No formal throughput comparison
is authorized by this plan, and a passing candidate will not automatically
change the package default.

After DYN1, opt-level `s` or `2` may be worth a separately frozen constant-cost
experiment if a map/profile supports it. Current rustc documentation does not
promise `z` is smaller than `s`; changing optimization level can trade instruction
count against code footprint. These are unmeasured later directions, not part
of DYN1 or a reason to search an exhaustive flag matrix.
[Optimization-level documentation](https://doc.rust-lang.org/rustc/codegen-options/index.html#opt-level)

Evidence: ignored `private/dnsmasq-rewrite/size-cost-574f5ed/` contains segment and
section inventories, the recovered pre-sstrip artifact, allocated-section
identity checks, calibration, exact compiler option output and SDK specs. The
source/artifact identities and size regression remain anchored by
`PACKAGE_574F5ED_RESULT.md`.
