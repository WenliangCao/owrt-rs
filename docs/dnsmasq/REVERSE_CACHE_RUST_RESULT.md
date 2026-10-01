# Reverse-cache frozen Rust before/after result

The original product source `ac8a3b6` completes all **125/125 command rows** in
the frozen main [C baseline](REVERSE_CACHE_PRIMITIVE_RESULT.md): **66 match and
59 differ**. All 14 probe processes exit zero; there are no missing rows,
startup failures or comparator failures. One of the 59 differing rows explicitly
reports the absent reverse-address lookup API.

Private candidate `19620e34` subsequently matches **125/125** of those same
command rows with zero differences, unsupported rows or fixture failures. All
14 candidate probe processes exit zero on their first execution. The same
adapter and frozen C files are used, with only the explicit projection changing
from before to reverse. The four-process, 44-row C multi-target cohort is
neither rerun nor compared with Rust. Its variable order remains C-only
evidence; this scoped pass is not product adoption or full reverse support.

| Profile | Completed rows | Differences |
| --- | --- | --- |
| direction-v4 | 10 | 5 |
| direction-v6 | 11 | 6 |
| replace-v4 | 7 | 4 |
| replace-v6 | 7 | 4 |
| same-target-two-addresses | 9 | 6 |
| nodata-owner-scope | 9 | 6 |
| nxdomain-owner-scope | 9 | 4 |
| no-negcache | 5 | 0 |
| pressure-forward-insert | 11 | 3 |
| pressure-reverse-insert | 11 | 6 |
| reverse-lookup-expiry | 10 | 3, including one unsupported API row |
| reverse-insert-expiry | 8 | 3 |
| rd0-pressure | 11 | 5 |
| mixed-case-target | 7 | 4 |
| **Total** | **125** | **59** |

The differences expose missing reverse answers, missing stored entries and
insertion counts, pressure victims/counters, and negative-owner extraction.
The existing early return for address-form non-NXDOMAIN PTR also skips its
forward negative fallback. The no-negcache profile matches all five rows.
Matching extraction-status or initial-miss rows are not counted as implemented
reverse features.

The [adapter boundary](REVERSE_CACHE_RUST_ADAPTER.md) appends instrumentation to
an ignored source copy. Each original file remains an exact byte prefix; only
two source files receive appended probe code and one binary entrypoint is
added. Original and instrumented file manifests prove that no existing decision
branch was changed. The before projection contains no reverse enum variant and
never creates cache records. Actual P/Q/N/M calls exercise product functions;
state inspection follows its actual active LRU. The absent A operation is
reported as unsupported, leaving state untouched and remaining in the denominator.

The saved C matrix and result hashes are pinned. Configuration and command files
are copied unchanged; C is not executed again. Comparison retains packet field,
TTL and record order, original-case PTR/question names, direction, target case,
address, absolute expiry, active LRU, existence, stale state and counters. It
removes only compression bytes and C's hash-bucket diagnostic. Every profile's
saved-row calibration detects one changed TTL and rejects a missing row.

Identities:

- Product source: `ac8a3b6851adb93d62a8f7b334c2b727deffedd0`.
- Adapter commit: `cdfc853`.
- Source archive SHA-256:
  `7ea90c0e2e1f50d8f84fc9d718108c2dd332887dbe3de8eac719408d3dbd327c`.
- Adapter tool SHA-256:
  `1aa96c03de23770157fa0a88230f8c700fcfa10862efdb59146a2fe81971175a`.
- Instrumented native probe ELF SHA-256:
  `d22daf61c5df924b1e0cc458854eee9e7cddf0083b2f591c1aa155b7015951eb`.
- Frozen C matrix SHA-256:
  `dd8c3201822afde8b480e39fe7631ddf6d109bc72948c4a21e16e63040d9a6b5`.
- Frozen C result SHA-256:
  `63e97d2c01e391036f9b71de7ea3bff47030816043b2aaecdcf308c406ae396f`.

`rust-before-build-01` builds outside sudo with Rust 1.98.1 and a fresh release
target directory. `rust-before-01` executes the finished probe through
`run_isolated.sh` and returns exit 1 for the recorded 59 differences. The first
build/run completes without a retry or fixture change. This ELF is an
instrumented source probe, not the product daemon ELF or a deployment artifact.

Raw stdout/stderr, all rows/differences, unchanged C input files, source archive,
append-only manifests and probe ELF are retained under
`private/dnsmasq-rewrite/reverse-cache-gate-20261001/private/`, mirrored from
`/home/ubuntu/dns-reverse-cache-20261001/work01/private/`.
`rust-before-evidence-sha256.json` covers 187 retained files for this unit.
No product source was edited, no C cohort was rerun and no router or timing
experiment was performed.

## Private candidate after identity

- Candidate source: `19620e34e322309c162d9b9b92546051c7728c5e`.
- Source archive SHA-256:
  `63ba6faa60aaa44547f43a504c57bb5a439b1227beacb734613f4abff9ac0090`.
- Instrumented candidate probe ELF SHA-256:
  `7c1ccfc0786d4a4e58f1833101ac48626a99183371179d169572b7b1ba6fee94`.

`rust-after-build-01` builds outside sudo with a fresh Rust 1.98.1 release
target. `rust-after-01` executes the original 125-row main corpus through the
isolated wrapper and returns exit 0. The after projection reads actual
ReverseIpv4/ReverseIpv6 entries and invokes the real lookup_reverse API; it
does not inject records or reorder state. All 14 per-profile saved-row TTL and
missing-row controls pass. Original-case target/question fields, flags, TTLs,
ordered records, active LRU, direction/address/expiry, counters and existence
are compared exactly apart from the previously specified compression and C
bucket diagnostics.

The after source, probe, complete observations and append-only manifests are
retained beside the before evidence with `rust-after-evidence-sha256.json`.
The native-source primitive pass does not establish actual-image UDP service,
DO/AD metadata admission, malformed direct PTR, local/lease coexistence, typed
transfer, multi-target ordering, resource or deployment acceptance.
