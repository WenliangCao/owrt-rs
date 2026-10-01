# DYN1 isolated linkage screen

DYN1 passes the frozen linkage/size screen and its scoped functionality gates.
It is a retained candidate, not the package default or completed resource
acceptance. No throughput, CPU or runtime-memory improvement was measured.
The full functional gaps of product snapshot `574f5ed` remain in force.

The product files are unchanged from
`574f5ed88d8d3c9453f0ac9c25a891933b5a128b`. `build_dyn1.py` verifies the frozen
input hashes, copies component inputs into a fresh private directory and uses
the same Rust 1.98.1, SDK linker, O3, LTO, codegen-units, panic, stripping and
existing hardening flags. Its only candidate switches are the three specified
in `SIZE_COST_574F5ED.md`; the additional linker-map output is diagnostic.
The default Makefile was not changed, no APK was installed, and no router was
contacted. The build ran in a slot explicitly coordinated with the C-cost agent.

| Property | Baseline B0 | DYN1 |
| --- | ---: | ---: |
| Stripped ELF bytes | 989,991 | 870,915 |
| Difference from B0 | — | -119,076 (-12.03%) |
| ELF type | Static ET_EXEC | Dynamic ET_DYN PIE |
| `.text` before SDK sstrip | 821,752 | 707,236 |
| `.rodata` | 52,684 | 38,448 |
| `.eh_frame` | 72,788 | 69,000 |
| `.eh_frame_hdr` | 10,188 | 9,660 |
| `.gcc_except_table` | 6,108 | 6,060 |
| `.data.rel.ro` | 22,784 | 22,536 |

The candidate is below the predeclared 940,491-byte threshold. Dynamic symbol,
PLT and relocation metadata add some space back; the table does not equate the
entire decrease with one library's size. It still exceeds the exact image C
ELF's 269,305 bytes by **601,610 bytes**. Shared libc/libgcc already required by
the image are not charged as exclusive C space or presented as newly recovered
firmware space.

DYN1 ELF SHA256:
`19a293eb586402b66204a56beb3a905fd359d3db814c85caf3357c27318fa50f`.
Readelf/program-header checks confirm AArch64 PIE, GNU_RELRO/NOW, a
non-executable stack, no writable-executable LOAD segment and no TEXTREL.
NEEDED contains only `libc.so` and `libgcc_s.so.1`. The candidate was run through
the exact image musl loader/library bundle; dependency resolution, file hashes,
the runner and CLI version output are retained. This restores the C reference's
PIE layout property rather than trading it away for size.

| Gate against the frozen baseline/reference | Result |
| --- | --- |
| Target C/B0/DYN1 bounded CLI configuration cases | 12 exact exit-code matches: 8 accepted, 4 rejected |
| Target C/Rust UDP no-route | 558 requests, zero differences |
| Target C/Rust TCP daemon | 15 cases, 116 replies, zero differences |
| Target C/Rust reload/cache/hosts | 23 checks, zero differences |
| TCP hosts snapshots | 8 queries and 2 shutdowns matched |
| SIGTERM and SIGINT smoke | 7 checks each, successful shutdown |
| DHCP daemon smoke | 5 checks; Rust-only, not full C service equivalence |

These are the existing frozen gates plus direct candidate CLI acceptance. The
unchanged host parser's four detailed C configuration gates remain separately
recorded in `PACKAGE_574F5ED_RESULT.md`; they were not misrepresented as a
candidate-musl unit-test executable. Existing packet-level calibration and
independent target C expected results were retained. The runner hash appearing
in gate outputs identifies the private invocation script; the candidate ELF
hash above identifies the actual executable.

Evidence is under ignored `private/dnsmasq-rewrite/dyn1-574f5ed/`: candidate
manifest, source hashes, command/flags, warnings, linker map, pre-sstrip and final
ELFs, dependency/protection verification, every gate's configuration/traces and
the local ELF inventory. Artifact hashes were rechecked after recovery.

No new default is selected by this result. Runtime CPU, tail latency, PSS/USS,
FD/thread/child behavior under representative load, longer lifetimes and the
remaining functional contracts still require their own frozen evidence. The
remaining 601,610-byte regression relative to C is not waived.
