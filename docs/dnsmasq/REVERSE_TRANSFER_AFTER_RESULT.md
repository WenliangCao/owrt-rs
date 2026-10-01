# Reverse import local-conflict correction and retained order boundary

Private candidate `54346fd` now matches **184/184 deterministic observations**
from the frozen reverse-transfer baseline, closing the three configured-CNAME
differences in [the before result](REVERSE_TRANSFER_BEFORE_RESULT.md). The
separate **12-observation ordering case still differs**: four rows against
each native trace and two against each SDK-musl trace. The full comparator
therefore still exits **1**. This is not a complete reverse-transfer pass.

The correction changes only `import_counted`: reverse records bypass the
forward local-name callback and use the existing absolute-expiry insertion
path. Forward records retain the callback and its current-parent precedence.
The API documentation now states this direction boundary. No fields, slots,
reverse scans, export order, LRU algorithm or counters were changed by this fix.

C's reverse flags select address-based replacement directly, so an unrelated
parent configured CNAME with the same PTR target name cannot abort import.
The corrected candidate commits that dynamic reverse entry, counts one real
parent insertion and returns it on address lookup. The other 19 deterministic
cases remain exact, including local reverse coexistence, same-name forward
protection, parent pressure, failure-prefix effects and expiry/clamp behavior.

The native/SDK C schedules were completed before either Rust comparison and
were not rerun. Their 184 deterministic observations agree across three
processes per runtime; the SDK executable is a matching-source primitive,
not the stock-image dnsmasq ELF. The Rust after run is native Linux. Its
test-only adapter and local view are unchanged from the completed before run.
All executions run inside the Linux isolation wrapper.

The multiple-PTR case retains the same exact differences as before. Eight rows
match native C, including the child and parent LRU states before address
lookup; that does not qualify the complete ordering case. Native and SDK C
produce different address traversal orders. The candidate's child/parent
lookup and resulting LRU order fail to match any complete retained C trace.
No sorting, set equality, threshold change or extra process was used to accept
that boundary.

The original forward transfer fixture separately passes **307/307** on a fresh,
uninstrumented copy of `54346fd`, including its parent local-conflict cases.
This reuses the original independently frozen C baseline and does not change
the original tool, fixture or denominator.

| Artifact | SHA-256 |
| --- | --- |
| Reverse after probe | `cfba36221fa5d6524081a3fc639311b5c4642104b45eb65b7de0eb3c7dfd5f00` |
| C + before archive | `c799b6ddbbbc5582c6da244d1e029e28ca7499b57f8a0b371ed7cb73c7a463a2` |

The [sanitized JSON](REVERSE_TRANSFER_AFTER_RESULT.json) records all source,
probe, result and archive identities. The C/before archive includes the first
observer panic, original test artifact and both instrumented source copies;
743 retained files were independently hash-verified after download. Raw after
and forward307 evidence are retained separately alongside it in the gate
worktree's ignored `private/evidence/`. Remote originals remain under
`/home/ubuntu/dnsmasq-reverse-transfer-20261001/work01/private/`.

No product promotion, TCP sender/receiver adoption, new snapshot representation,
partial pipe EOF, allocation/OOM, resource cost, stock-image service, router or
performance acceptance follows. The unresolved multi-PTR ordering behavior
remains a concrete compatibility gap.
