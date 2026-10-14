# F10: repeated-address loading contract remains open

Status: **OPEN / P2, conditional missing PTR answers; no product repair or waiver**.
The bounded TCP pagination repair remains independently justified. Its unchanged
old/new Rust answers do not establish equivalence with exact-image C.
The [diagnosis](repeated-order.md) binds the 188 failing observations to mixed
`F_REVERSE` groups and preserves both successful memory controls and failures.

A separate worktree was created at
`/Users/USER/Developer/owrt-dnsmasq-full-rotation-contract`, branch
`fix/dnsmasq-full-rotation-contract-20261014`, starting at
`19bd6162e1b33c92a1e5ea26e864497800c7cfed`. It has no product changes. The decision
below concerns the compatibility contract, not deployment readiness.

The forward A address set remains correct in the demonstrated cases, while its
rotation differs. Reverse queries can omit names that C returns. UDP and TCP
remain alive; this finding is not a demonstrated service interruption.

## Independent six-line counterexample

The final PTR probe in the integrated worktree uses these six hosts records,
default EDNS size 1232 and cache size 1000:

```text
192.0.2.2 old.test
192.0.2.1 x.test
192.0.3.186 a.test
192.0.3.185 a.test
192.0.2.1 y.test
192.0.2.2 y.test
```

192.0.2.1 and 192.0.3.186 occupy the same temporary reverse bucket. Looking up
the first `a.test` entry while loading its second address severs that entry's
next link to `x.test`. C then grants `y.test` another reverse owner for IP1.
IP2 remains owned by `old.test`, giving `y.test` mixed reverse groups.

| Observation | Exact C, two fresh runs | Old integrated Rust and final `19bd6162` |
| --- | --- | --- |
| UDP and TCP PTR 192.0.2.1 | Both `y.test` and `x.test` | Only `x.test`; `y.test` is missing |
| UDP and TCP PTR 192.0.2.2 | `old.test` | `old.test` |
| Repeated A queries for `y.test` | Both addresses, constant order | Both addresses, alternating order |

All PTR replies have RCODE 0 and TC 0, including UDP: the missing name is not a
truncation artifact. Both implementations remain responsive. All 28 observations
match between the two Rust versions, and between the two C starts. This smaller
counterexample establishes client-visible missing PTR data independently of the
large-table source model.

The integrated worktree's derived tool and result are
`docs/dnsmasq/audits/full-20261014/final/ptr-boundary/probe.py` and `summary.json`;
the integration audit owns their commit. Raw replies/logs remain in its ignored
`private/f10-ptr-20261014` and Oracle
`/dev/shm/full-f10-ptr-20261014/private`. This report does not replace those
identity-bearing receipts or treat the single observed PTR order as universal.

## Why a flag-only repair is insufficient

Exact C's temporary reverse hash and name lookup reuse `crec.next`. The
duplicate-name lookup can sever the reverse hash's existing chain, allowing
later records for the same address to gain another `F_REVERSE` flag. The
resulting groups affect both forward round robin and reverse lookup.

- `cache_find_by_name` rotates only the first matching reverse/immortal group.
  Assigning the C flags would change the observed forward order.
- `cache_find_by_addr` enumerates every matching reverse entry, and
  `answer_request` emits each PTR. The existing Rust `Hosts.reverse` map holds
  one ID per address; `dns/local.rs` currently emits one hosts PTR. The large
  exact-C dump contains 374 addresses with multiple reverse entries, up to
  120 entries per address. A flag-only repair would leave this API inconsistent.
- Removing a source must remove its existing reverse entries without promoting
  suppressed records. An address can still have other actual reverse owners.
  Selecting one map entry and deleting it is no longer enough.

The distinction is not limited to a TCP snapshot: the focused diagnostic shows
it in consecutive parent UDP queries too. Changing pagination, retaining an
unbounded history of deltas, or skipping duplicate records cannot repair it.

## Interfaces and lifetimes a full repair would affect

1. **Generation loading.** One temporary reverse hash spans configured
   `host-record`, default `/etc/hosts`, explicit/addn directory files, and the
   initial `hostsdir` scan. It is not reset between files. Its bucket count is
   `(max(edns_packet_max, 512) + 255 + 10) / sizeof(void*)`; 187 is only this
   default 64-bit fixture. The loader currently receives `DnsConfig` and TTL,
   while packet sizing is owned by scalar/service configuration. That value and
   an explicit begin/end generation boundary would need to reach the loader.
2. **Duplicate lookup.** The temporary links must reflect all matching entries
   of the requested family in lookup order before round-robin mutation. They
   change even when a duplicate is found early and with `no-round-robin`.
   A/AAAA, three or more records, expansion, and configured/file overlaps need
   controls; the two-address model alone does not prove them.
3. **Initial versus incremental hostsdir.** Initial and HUP scans continue the
   generation's bulk hash. Later inotify reads remove the path UID and call C's
   `read_hostsfile` with a null reverse hash, checking real reverse owners.
   The existing asynchronous Rust file owner stages and publishes per source;
   temporary loader state must neither leak into TCP snapshots nor accidentally
   survive into later incremental reads. This must be kept separate from the
   independent inotify allocation/publication repair.
4. **Reverse lookup callers.** The DNS answer path needs an iterator over actual
   reverse owners. DHCP and other first-match callers need their own explicit
   selection contract. Clone, source removal, failed publication, old TCP
   generations and query logging must preserve that same owner set.
5. **Retained DHCP state.** C preserves DHCP cache entries during `cache_reload`
   and rebuilds lease DNS after the reload. Duplicate-name lookup can link a
   retained DHCP entry into the transient chain. The current source model's
   terminating free-cache sentinel is proven only for its static fixture; it
   does not justify claiming DHCP/reload equivalence.

## Bounded memory does not imply zero cost

A direct loader-only representation could use one sentinel-encoded `usize`
next ID per accepted entry plus a bucket-head vector. At 60,000 entries and
187 buckets on this target, that is **481,496 payload bytes**. This is an
arithmetic lower bound using ideal 8-byte IDs, not a measured Rust peak or an
assumption about `Option<usize>` layout. Allocation capacity, allocator metadata,
clones and persistent multi-PTR indexes are additional. A growable vector can retain more capacity than
its length. Reserving it, propagating reservation failure and releasing it when
the bulk generation finishes are part of the failure contract.

That temporary state must have one loading owner. Copying 60,000 next IDs into
each of 20 TCP clients would add about 9.6 MB of payload alone and undermine the
purpose of the pagination repair. Sharing an ever-growing lineage would instead
create unbounded retention. Neither is proposed.

A persistent index of multiple PTR owners adds separate storage. A vector per
address creates many small allocations for the common unique-address case;
retaining the single-owner map with an additional index only for duplicates
reduces that cost but adds removal/clone invariants. No implementation has been
measured, so no PSS, peak-memory or performance improvement is claimed. Any
repair must repeat the 64 MiB warm/cold/rolling/HUP gates and fallible-load
controls on its own fresh ELF. The present 28–37 MB warm/rolling peaks cannot
be transferred to an unbuilt design.

## PTR order has a wider dependency

C scans name-hash buckets in increasing bucket order, then follows each bucket's
chain. `cache_hash` prepends unrelated names while preserving only specific
same-name flag groups. Rehashing reinserts records; table growth counts accepted
names (including duplicates), and HUP does not shrink the table.

The name hash mixes bytes from the `typestr` structure, including relocated
pointer bytes. C initial ordering can therefore vary between processes; the
retained C/C control already differs on three observations. Reproducing one
fixed filename/insertion order is not a proof of C PTR order compatibility.
With many PTRs, packet truncation can make ordering affect which records fit,
so comparing an unqualified unordered set is also insufficient.

A compatibility test must keep raw packets and separately check record values,
TTL, counts, flags and truncation at each transport/size. It may treat an order
as variable only where repeated exact-C controls demonstrate that variability.
No fixed canonical order or broad RRset waiver is adopted here.

## Available decisions

| Approach | Consequence |
| --- | --- |
| Reproduce the full observed C loading/reverse contract | Requires the lifecycle, owner-set, caller and memory work above, plus fresh validation. It is a broader change than TCP order pagination. |
| Keep the current first-owner behavior as an explicit compatibility exception | Small product cost, but requires an explicit accepted contract change. F10 cannot be called fixed or exact-C equivalent. |
| Keep F10 open while completing independent repairs | Preserves evidence and avoids introducing an unvalidated cross-cutting emulation layer. Full drop-in compatibility remains unproven. |

**Recommendation for this iteration: keep F10 open.** Complete and evaluate the
independent memory/inotify repairs against their own gates. Decide the reverse
contract from the demonstrated client-visible behavior and the cost of matching
it before implementing more state. No product behavior was changed to suppress
the failing comparison, and no compatibility exception has been assumed.
