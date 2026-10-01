# Private typed receiver partial-EOF differences before repair

The current private whole-frame receiver **does not match the exact C partial
EOF contract**. The before-fix differential compares eight mapped cases and
24 state observations: **19 match / 5 differ**, exit 1, with no infrastructure
failures. Three cases expose differences. No production receiver, encoder,
cache importer or caller logic was changed for this run.

The [independent C baseline](TCP_PARTIAL_EOF_C_BASELINE.md) passes 171/171
checks across nine cases. Its ninth case, a partial native `ssize_t -1` end
sentinel, has no counterpart in the private length/count framing. Its three
states are explicitly recorded as **C-only, not representable**, not included
in the 24 paired states or counted as passes.

| Case | Differing states | Observed difference |
| --- | ---: | --- |
| Operation/frame header then EOF, prior pending state | 1 | C starts insertion and clears prior pending immediately; Rust retains the pending record and visible alias until a later explicit start |
| Completed replacement record then EOF before a legitimate second record | 2 | C removes the old owner and leaves the replacement pending; Rust keeps the original committed owner. The difference remains after the next start |
| Completed new record under pressure, partial second record | 2 | C evicts the owner, invalidates its alias and increments `live_freed` once; Rust retains both and leaves the eviction counter unchanged. The difference remains after the next start |

The no-operation EOF, incomplete first-record scalar/name/address, and complete
transaction controls match. For pressure, both implementations execute the
same fixed observation lookups, including the filler lookup that changes LRU
order. No victim or state difference is normalized away.

The ignored test adapter lives inside the actual `tcp_transfer` module. It
uses the real encoder to build a valid complete typed transaction, verifies
that the real decoder accepts it, writes the selected prefix through the real
anonymous pipe, closes the writer and calls the existing `Receiver::receive`.
As in the current main caller, it invokes `Cache::import_counted` **only** for
`Received::Transaction`; it does not add cache actions on EOF or error. A
`cfg(test)` getter exposes pending count and failure state for diagnostics.
Ordinary lookups and actual counters provide the behavioral comparison.

| Semantic boundary | Native bytes | Typed bytes / full frame | Actual typed outcome |
| --- | ---: | ---: | --- |
| No operation | 0 | 0 / 44 | `Eof` |
| Operation/frame length only | 1 | 4 / 44 | `UnexpectedEof` |
| Partial first scalar | 8 | 21 / 44 | `UnexpectedEof` |
| Partial first name | 12 | 25 / 44 | `UnexpectedEof` |
| Partial first address | 46 | 41 / 44 | `UnexpectedEof` |
| First complete record of two | 47 | 44 / 81 | `UnexpectedEof` |
| Partial second address | 93 | 78 / 81 | `UnexpectedEof` |
| Complete one-record transaction | 55 | 44 / 44 | `Transaction` |

These are semantic cutpoints of valid complete encodings, not byte-for-byte
framing equivalence. The typed scalar cut is inside its name-length field.
The record-prefix cases declare a real second record and retain its legitimate
untransmitted tail; no invalid count or invented frame length is used. Native
return 0 and typed `Eof`/`UnexpectedEof` are compared as no completed transaction,
while the exact typed result remains in the saved metadata.

Comparison calibrations accept an identical trace and reject pending-count
changes, insertion-count changes and missing observations. Before, after-receive
and after-next-start stages must all be present, with exact lookup results,
absolute expiries, pending state, failure state and counters.

Runtime base: `e5ee749`; adapter/tool commit: `b1c8d2b`. Test executable SHA:
`8e561ea851ab7aea0b1dbebc8f1874880d977b17ab901c070e34da0a29eb87de`.
The JSON records the complete Rust source manifest, probe/tool/source-archive
identities, cutpoint mapping and all five differences. The C positive, negative
and original failed pressure calibration remain preserved separately.

Raw before-fix evidence, source archive and the actual probe executable are
retained in the independent gate worktree's ignored
`private/partial-eof-evidence/rust-before-evidence.tar.gz`, and on oracle under
`/home/ubuntu/tcp-partial-eof-gate-20261001/rust-before/`.

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh runuser -u ubuntu -- \
  python3 tools/dnsmasq/cache_partial_eof_rust_diff.py \
  --baseline /home/ubuntu/tcp-partial-eof-gate-20261001/private/baseline-02 \
  --cargo /home/ubuntu/.cargo/bin/cargo \
  --out private/partial-eof-before
```

All compilation and executions ran in the isolation wrapper. This is a retained
failing qualification, not acceptance or a repair. It does not cover arbitrary
malformed lengths/flags/pointers, SOA blocks, OOM, target-musl or performance.
No router was accessed.
