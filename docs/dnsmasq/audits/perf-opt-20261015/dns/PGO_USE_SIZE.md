# PGO use size: growth concentrates in trained caller bodies

The rejected profile-use ELF grew 151,560 bytes over frozen E. Its `.text`
output section accounts for +141,072 bytes; `.rodata` adds only 1,296 bytes.
The largest increase is `run_inner`, 30,368 to193,124 bytes. Other trained
caller bodies also expand while several former standalone callees disappear.
This is consistent with aggressive inlining/reorganization under PGO, but
linker maps alone do not prove the exact inlining transfers or their CPU cost.

Both same-link maps are bound to the E/use build receipts. This analysis was
local, with no new build, training or timing. It uses map storage ranges and
training counter activity; it does not inspect use machine code or compiler
optimization remarks. The use artifact still fails both original size budgets.

## Output section decomposition

| Section | E bytes | Use bytes | Change |
| --- | ---: | ---: | ---: |
| `.text` | 1,817,780 | 1,958,852 | +141,072 |
| `.eh_frame` | 96,448 | 100,040 | +3,592 |
| `.rela.dyn` | 53,520 | 55,920 | +2,400 |
| `.eh_frame_hdr` | 18,812 | 20,764 | +1,952 |
| `.data.rel.ro` | 45,424 | 47,000 | +1,576 |
| `.rodata` | 92,076 | 93,372 | +1,296 |
| `.gcc_except_table` | 5,640 | 6,788 | +1,148 |
| `.data` | 2,848 | 2,856 | +8 |

The other nonzero-address output section sizes are unchanged. Listed section
growth sums to153,044 bytes; file growth is151,560, leaving -1,484 bytes of
placement/alignment/file-layout difference outside these section-size deltas.
The use ELF was not downloaded for this analysis, so that residual is not
assigned to a particular file padding/header interval.

Executable input ranges are non-overlapping and total1,817,552 /1,958,640
bytes, leaving228 /212 bytes of `.text` gaps. Thus input-code growth is141,088
bytes and the text-gap change is-16. The entire input-code increase belongs
to the fat-LTO dnsmasq object; external C/assembly archive inputs remain126,624
bytes. That object contains inlined library code as well as application code,
so it must not be described as exclusively handwritten dnsmasq instructions.

Read-only inputs include merged overlapping string sections: naively summing
their declarations gives100,629 /102,001 bytes, larger than `.rodata` itself.
Their physical range unions are91,840 /93,212 bytes. This report therefore
uses the final `.rodata` output sizes and does not pair anonymous constant
ordinals or double-count overlapping input declarations.

## Largest linked code changes

Sizes below are the input sections named by those functions. Zero means no
standalone section with that exact identity, not removed functionality.

| Function / input identity | E | Use | Change |
| --- | ---: | ---: | ---: |
| `dnsmasq_rs::run_inner` | 30,368 | 193,124 | +162,756 |
| `DnsDaemon::poll_inner` | 12,452 | 46,976 | +34,524 |
| `LocalProvider::resolve_events` | 16,112 | 38,616 | +22,504 |
| `CacheContext::insert_reply_with_events` | 5,580 | 27,008 | +21,428 |
| `CacheContext::answer_from_cache` | 0 | 21,024 | +21,024 |
| `DnsConfig::apply` | 13,788 | 28,140 | +14,352 |
| `LocalAnswerer::answer_parsed_with_query_events` | 14,032 | 28,204 | +14,172 |
| `SinglePoll::process_udp` | 4,484 | 16,300 | +11,816 |
| `std::sys::process::unix::common::Command::spawn` | 0 | 10,308 | +10,308 |
| `SocketListener::process_once_on_listener<EventProvider, step_dhcp closure#9>` | 0 | 9,132 | +9,132 |

| Function / input identity | E | Use | Change |
| --- | ---: | ---: | ---: |
| `SinglePoll::step` | 17,600 | 0 | -17,600 |
| `CacheContext::answer_records_filtered` | 13,524 | 0 | -13,524 |
| `StateProvider<resolve_events closure#43>::resolve` | 13,372 | 0 | -13,372 |
| `SocketListener::process_once_on_listener<EventProvider, step_dhcp closure#8>` | 10,404 | 0 | -10,404 |
| `SinglePoll::advance_neighbors` | 10,612 | 772 | -9,840 |
| `EventProvider::lease_query_reply` | 9,360 | 0 | -9,360 |
| `LocalProvider::new_with_log` | 9,004 | 0 | -9,004 |
| `SinglePoll::step_hosts_files` | 8,708 | 0 | -8,708 |
| `std::process::Command::spawn` | 8,276 | 0 | -8,276 |
| `SinglePoll::wait_for_files` | 7,296 | 0 | -7,296 |

The first eight growth rows alone add302,576 bytes; other shrinkage offsets
that expansion. Closure#8 and closure#9 above are deliberately distinct, as
are different generic instantiations and LLVM clone suffixes. Likewise, the
two `Command::spawn` rows are different symbols, not a matched one-function
transfer. Complete raw identities and the largest40 increases/decreases are
retained in the derived result.

## Training activity versus cold code

| Unique profile match | E linked bytes | Use linked bytes | Net change |
| --- | ---: | ---: | ---: |
| At least one positive training counter | 864,508 | 1,096,432 | +231,924 |
| All recorded counters zero | 523,616 | 456,508 | -67,108 |
| No unique profile-symbol match | 429,428 | 405,700 | -23,728 |

This separates the dominant net expansion from cold-code claims: uniquely
matched zero-counter code shrinks overall, even though some individual cold
sections grow or become standalone. The largest eight growth rows all have
positive training counters, and seven are placed in `.text.hot` by the use
build. Counter presence does not quantify hotness or establish CPU benefit.

PGO also reclassifies placement: `.text.hot` contains649,476 bytes in use,
and `.text.unlikely` grows from67,084 to672,228. That large unlikely-section
total is not itself cold-code growth; many unchanged or smaller symbols moved
from ordinary placement. Correspondence removes only that placement prefix.

Exact full mangled symbol plus input-object basename yields2,295 matched
sections,396 only in E and640 only in use, with no duplicate identity folded.
No crate-disambiguator hash normalization was necessary because canonical
paths preserve those identities. Demangled names are display labels only.
For the training-profile join, only the optional codegen-module prefix before
`;` is removed; a symbol must have exactly one record. Sixteen ambiguous
profile symbols remain unmatched rather than combined. All generic, closure,
LLVM clone and monomorphization identity remains intact.

The map establishes storage movement and expansion, not the exact optimizer
decision that caused it. A later fixed compiler-option experiment can test
that mechanism, but this report neither changes thresholds nor claims CPU,
cache-efficiency or latency improvement.

[Derived section/function/profile comparison](pgo-use-size-result.json) and
[replay script](analyze_pgo_use_size.py). Original maps, the full exploratory
comparison and compiler/profile logs remain private. The Xcode LLVM demangler
is used only for labels, never for identity matching or size measurements.
