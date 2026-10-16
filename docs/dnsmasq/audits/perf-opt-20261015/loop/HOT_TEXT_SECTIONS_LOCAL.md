# UDP hot input-section placement experiment

Frozen source `c95c5571` is an independent 9e child. Its only product changes
are 22 Linux-only section attributes. Removing those attributes restores each
changed source file byte-for-byte to 9e. There are no logic, inlining, optimization
level, allocator or API changes; name-copy and reply-chunk prototypes are excluded.
The local musl all-target compilation passes.

The purpose is to test code locality on the A53, not infer a cache problem from
whole ELF size. Prior G sampling and A53 stage results motivate this experiment
but do not predict its gain. It preserves the existing compiler and linker
configuration and relies on the SDK's already present `.text.hot.*` rule.

| Local final musl result | 9e | ffc3 common section | c95 unique sections |
| --- | ---: | ---: | ---: |
| Whole ELF bytes | 5024648 | 5024128 | 5024616 |
| Selected emitted ranges | 19 | 19 | 19 |
| Their total bytes | 40708 | 40708 | 40708 |
| Their 4096-byte address pages | 24 | 11 | 24 |
| Span including gaps | 671160 | 40708 | 671160 |

Every selected emitted range retains its size in both experiments. These full
range address pages are not the earlier sampled address bins, cache fills,
misses, IPC, or a simultaneously resident working set.

The common section `ffc3ac37` does cluster these ranges under local rust-lld.
It is unselected because combining functions in one input section couples
linker garbage collection and loses the original same-link map granularity.
The actual SDK maps have no separate Rust symbol rows to reconstruct those
individual ranges. No original profile parser is modified to hide that loss.

The successor assigns unique `.text.hot.dnsmasq.<function>` input sections.
The local rust-lld default leaves them dispersed: it has **not** established
that the selected layout works under the deployment linker. A map-only relink
produced an identical ELF and explicitly shows 19 such surviving input sections.
The other annotated methods are inlined. The original GNU SDK map has an empty
`.text.hot.*` selection before ordinary text, making the canonical SDK build
the next layout check. If its own map does not actually cluster these sections,
stop this experiment; do not alter the linker or choose a favorable rerun.

The unique names retain per-input-section GC and map ranges without KEEP or a
new linker script. Original static-PIE, RX/NX, RELRO, relocation, payload and size
gates remain mandatory. Profile names must be reported as input-section labels,
not claimed to be original mangled functions or free of inlined code/clones.

The initial source-edit selection found two different `step` methods before
writing any file; that failure and the subsequent unchanged-control check are
retained. The corrected selection identifies SinglePoll and DatagramSocket
explicitly. No router or Oracle work occurred in this local screen.

[Exact source substitution, artifacts, map and emitted ranges](hot-text-sections-local.json).
