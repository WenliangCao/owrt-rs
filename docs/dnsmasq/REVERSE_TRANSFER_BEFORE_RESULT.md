# Reverse typed import before local-conflict repair

Frozen candidate `62894d6` matches **181/184 deterministic state observations**
from the [exact-C baseline](REVERSE_TRANSFER_C_BASELINE.md). The three differences
belong to one case: the parent has a configured CNAME whose owner equals an
imported reverse record's PTR target. C imports the record and increments the
parent insertion count; Rust rejects it through the forward local-conflict
callback, leaving the parent LRU and address lookup empty.

The test-only adapter invokes the actual `capture_commit_counted` and
`import_counted` APIs. It supplies the existing private TCP caller's relevant
current-parent local predicates: forward lease matching and the configured
CNAME predicate, which has no direction check. Configuration uses the actual
parser and lease fixtures use the actual publication builder. The adapter
does not add a reverse guard, replace insertion decisions, replay child counters
or choose a snapshot representation. This is an API integration boundary with
a supplied local view, not a live TCP daemon result.

The other deterministic cases match, including IPv4/IPv6 replacement, protected
forward/local entries, local-first reverse coexistence, shared capacity,
reverse-victim RRset removal, empty/no-commit/failed transaction distinctions,
absolute expiry and absence of repeated TTL clamping. The CNAME failure is a
direction error: C sends pure reverse/family flags and `cache_recv_insert` passes
them to `really_insert`, whose reverse path does not consult forward local-name
conflicts. The typed importer must preserve that distinction.

The separate 12-observation multiple-PTR ordering case has four differing rows
against each native C trace and two against each SDK-musl trace. All differences
are address-lookup order and the resulting LRU order. Child and parent LRU
before the first lookup match, preserving the export/commit double reversal.
The Rust trace does not match any complete retained C trace; the two observed
C orders and every Rust difference remain explicit. These rows are not folded
into the 184 deterministic denominator and are not normalized into passes.

The first adapter attempt, `rust-before-01`, compiled successfully but panicked
on the first case because its LRU observer unwrapped a free slot. The C observer
already skips free slots. Commit `22fe510` makes the Rust observer skip them and
retains execution failures in its result. The fresh `rust-before-02` run completes
the frozen matrix without changing candidate runtime code. The failed build
artifact, source copy and trace remain retained; no C process was rerun.

Probe SHA-256:
`77c04f4d36fdcaffa72c6ad6ff8dbab6ed1436b040690653be4b41a15473d028`.
The [sanitized JSON](REVERSE_TRANSFER_BEFORE_RESULT.json) records source,
instrumentation, probe, result and differing-row identities. Raw data remains
ignored under the gate worktree's `private/` and on oracle at
`/home/ubuntu/dnsmasq-reverse-transfer-20261001/work01/private/rust-before-02/`.
Both build and execution used Linux isolation. No router, timing, allocation,
OOM, actual-image service or private TCP representation acceptance is claimed.
