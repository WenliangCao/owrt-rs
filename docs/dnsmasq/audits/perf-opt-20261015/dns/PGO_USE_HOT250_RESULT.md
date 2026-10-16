# Fixed-profile hot250 build: smaller, still over both size budgets

The single authorized hot250 build succeeded, but its ELF and APK still exceed
the unchanged release budgets. The controller stopped at that gate. No new
training, weight changes, threshold search, correctness qualification, timing,
router access or deployment followed.

| Artifact | Previous PGO use | hot250 | Change | Existing budget | Still over |
| --- | ---: | ---: | ---: | ---: | ---: |
| ELF bytes | 2,288,419 | 2,267,939 | -20,480 | 2,200,000 | 67,939 |
| APK bytes | 1,293,382 | 1,282,729 | -10,653 | 1,200,000 | 82,729 |

ELF SHA256:
`009c0cd7456da949657a7ba78269adf4c8925c10738d8cfe19ff777308419fbe`.
APK SHA256:
`a62447d88da1e185b2303977ccb865e5b9523fe1d46dd43ce6283c0360ad5d16`.

The plan was frozen in `e31e2654`, SHA256
`c7782f756f2f002e560af0147369700d6a42c36bc3f6c8a7be196d23e155c0b0`,
and independently reviewed before execution. The actual invocation equals
the previous use flags plus only `-Cllvm-args=-hot-callsite-threshold=250`.
The missing-function warning option remained present; real pinned-compiler
argument-accumulation tests preceded the build. Original source E, canonical
build slot, SDK, optimization/LTO settings and release recipe are unchanged.

All 50 original raw profiles, the original training receipt and merged SHA256
`71adfc9533505fbe8ec7f564ad7029626e7cb504cd5287c246b1897d9d46b723`
were verified before and after. The experiment reused those bytes; it did not
run another collection pass or merge different weights.

The same-link map reports `.text` -20,352 bytes and `.gcc_except_table` -1,504;
`.eh_frame` decreases136 and `.eh_frame_hdr` decreases8. `.data.rel.ro` and
`.rela.dyn` each increase24; `.rodata` is unchanged. These section deltas are
storage observations, not CPU evidence. Exact-symbol checks of the previous
largest growth sites show the dominant caller bodies largely remain:

| Same exact function identity | Previous use | hot250 | Change |
| --- | ---: | ---: | ---: |
| `run_inner` | 193,124 | 191,908 | -1,216 |
| `DnsDaemon::poll_inner` | 46,976 | 41,504 | -5,472 |
| `LocalProvider::resolve_events` | 38,616 | 38,136 | -480 |
| `CacheContext::insert_reply_with_events` | 27,008 | 26,804 | -204 |
| `CacheContext::answer_from_cache` | 21,024 | 21,024 | 0 |
| `DnsConfig::apply` | 28,140 | 28,140 | 0 |
| `LocalAnswerer::answer_parsed_with_query_events` | 28,204 | 28,204 | 0 |
| `SinglePoll::process_udp` | 16,300 | 15,728 | -572 |

The build's static PIE/RELRO/bind-now/NX checks passed; no interpreter, needed
libraries or writable-executable load appeared. Map/prestrip/ELF hashes and
absence of profiler runtime symbols passed. No PGO missing-function or
profile/CFG/staleness diagnostics were found; ordinary source/SDK warnings
remain retained. The artifact was never run, so runtime protection,
functional equivalence and performance acceptance remain unestablished.

The build command exited0; the controller's final state is **failed because
the original ELF/APK budgets were exceeded**. Postflight confirmed all179
source /106 SDK file hashes and fixed tools were unchanged, no process
remained, the SDK recipe was restored and the lock was available. Root and
loop received the explicit release for the queued54bd SDK build. No other
threshold was tried automatically.

[Complete result and exact identities](pgo-use-hot250-result.json). All raw
outputs, ELF/APK and maps remain in Oracle private `dns/private/pgo-use-hot250`.
The final 182,553-byte compressed textual receipt/map transfer finished before
the SDK reservation was released.
