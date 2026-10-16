# Per-method hot input sections: local feasibility boundary

Selected research source: `c95c5571fe8915c4a67af8e438026e5f4f5d3a61`, based on
`9e8459dd704d339b10596721eaa2d3bef1f943c1`. The source diff contains only 22 Linux
`cfg_attr(link_section = ".text.hot.dnsmasq.<method>")` additions across eight
files; no inline attribute, optimization level, PGO, linker script or KEEP change.
The earlier shared-section source `ffc3ac37cffc9fb4b522a3ee73934ab971a2d44b` remains
retained but is not selected.

Existing exact SDK evidence inspected locally:

| Artifact | ELF SHA256 | Same-link map SHA256 |
|---|---|---|
| Accepted G185 | `9109e9871e83f652788621b2fbd5845f7d63e4bf7d05593b5098f741c31d7f99` | `e1c8638fbb2ff229d736d697dae78a519a914beb975cbf017f7666dd1dbe314f` |
| Exact 9e | `a91f0c88b1253dbd987508894214f30afc45e26a2b0dff6d1b94b5082a670087` | `346acb9555f6956c7f271e627bd635fe8c32983923a82dffc88052be853f89c0` |

Both GNU maps put `*(.text.hot .text.hot.*)` before
`*(SORT_BY_NAME(.text.sorted.*))` and
`*(.text .stub .text.* .gnu.linkonce.t.*)`: G lines 7071–7073, 9e lines 7089–7091.
The existing hot wildcard has no intervening input rows in these two artifacts.
Distinct `.text.hot.dnsmasq.<method>` inputs therefore match the existing hot
collection rule; their actual presence, order, padding and concentration still
require the new canonical SDK map. No alphabetical order is promised by the
ordinary wildcard. GNU ld assigns matching inputs in script order and performs
garbage collection at input-section granularity; KEEP would prevent collection.
[GNU wildcard rules](https://sourceware.org/binutils/docs/ld/Input-Section-Wildcards.html),
[GNU KEEP rules](https://sourceware.org/binutils/docs/ld/Input-Section-Keep.html).

The original SDK gate does not require one `.text._R…` section per function.
`perf_opt_sdk_build.py` calls `build_package.audit_elf` and hashes the same-link
map. The static gate checks AArch64 static PIE, valid non-W+X load segments,
non-executable stack, RELRO, no interpreter/DT_NEEDED/TEXTREL, plus the original
payload and ELF/APK budgets. The existing `.text.hot.*` path belongs to executable
`.text`; a new artifact must still pass every original gate. Section names alone
are not proof of runtime hardening.

The profiling limitation is separate. `elf_link_map_report.input_sections`
feeds the standalone section-size report and the map paths in
`perf_link_map_profile.py` and `loop_owner_profile_analyze.py`. G and 9e expose
2701 and 2706 text input sections respectively, but no standalone Rust `_R…`
symbol-address rows in their map bodies. A shared `.text.dns_hot` would lose
individual input ranges. Per-method sections preserve those ranges without a
parser change; labels remain **input-section labels**, not original mangled
symbols or guaranteed exact function sizes. Inlined code, optimizer clones and
padding may share a range. Three annotated methods are inside
`DnsDaemon<R: Random>`: their inherited type parameter may produce multiple
instances in one method section. No one-label/one-function claim is made.

Compiler boundary: root's local musl LTO/rust-lld prototype did **not** establish
concentration. Its ELF changed from 5,024,648 to 5,024,616 bytes, function sizes
matched individually, and the inspected hot set remained spread over 23 pages
and a 671,160-byte span, with addresses mostly shifted by −32. Root's subsequent
map-only inspection reports 19 surviving method sections matching the sizes of
19 emitted ranges. These are reported local prototype observations, not a new
build or independent local artifact audit by this reviewer. LLD behavior does
not prove what the pinned SDK GNU linker will do.

Proceed only to canonical SDK layout validation. If its actual map does not
show the selected inputs concentrated under the original hot rule, stop this
proposal; do not add a linker script to rescue it. If it does, the original
965/SDK/standalone-signal gates and original device/native/owner protocols still
apply. Future G→c95 measurements describe the whole inherited candidate, not
an isolated grouping effect. The prior 531 address bins and 63 pages describe
address distribution, not instruction-cache misses or a predicted gain.

This review changed no product source, built nothing, and made no Oracle or
router call. It used retained ELF/map/recipe/tool sources, local compiler
identities, local Rust Reference documentation and official GNU documentation.
