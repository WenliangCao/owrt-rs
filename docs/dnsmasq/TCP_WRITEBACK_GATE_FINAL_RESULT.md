# Final private TCP writeback candidate gate

Frozen private candidate `86b81ab` matched **12/12** C-first real-service
observations on its first final paired run. C also passed all 12 observations.
There were no protocol, counter, cache-winner, deadline or cleanup failures.
The gate and subscriber are unchanged from baseline commit `cfbdd19`.

This run was warranted by candidate changes since the earlier `bcf9e88` result:
partial-transfer parent blocking and clock preservation, completed worker joins
before slot reuse, readiness polling without descriptor duplication, and codec
bounds. The earlier result remains separately recorded; it is not substituted
for evidence on this final binary. The intermediate `bb137e8` artifact was not
run by this gate; the final artifact superseded that pending request.

The final candidate matched both held-parent cases:

- One existing worker returned two sequential cold-query replies before the
  parent resumed. Queued UBus metrics still showed the original one insertion;
  after imports and the doctor commit they showed four. Both UDP lookups then
  hit the imported records without upstream traffic.
- Two accepted workers returned distinct same-name answers and closed before
  release. Queued metrics still showed five insertions and two active slots.
  After draining and joining, there were eight insertions and zero active
  slots. The first accepted worker's `192.0.2.21` answer won in both the parent
  cache and a replacement worker's inherited cache, without upstream traffic.

| Subscriber-held case | C | Final Rust |
| --- | ---: | ---: |
| Two sequential child queries | 0.380 ms | 0.678 ms |
| Competing slots and child closes | 0.468 ms | 0.671 ms |

These are recorded hold durations, not performance comparisons. All doctor
replies were rewritten to `192.0.2.250` within C's unchanged 100 ms timeout;
the harness's 75 ms local deadline was unchanged. Both daemons finished with
zero active TCP slots and no child processes. Parent descriptor counts were
15 for C and 7 for Rust. Negative comparator calibration rejected an invented
early cache insertion and an incorrect slot winner. No timing run was retried.

Reference ELF SHA-256:
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
Final candidate ELF SHA-256:
`21d2a14a0690332958bbf381f0047bc6cc81d4cc1660d6effa017b2ea8462a6d`.
The final artifact is
`/home/ubuntu/dnsmasq-tcp-private-20261001/final-02/components/dnsmasq/target/release/dnsmasq-rs`.

Ignored raw inputs, outputs, all 30 UBus counters, subscriber messages, monotonic
event order and cleanup records are retained in
`private/tcp-writeback-gates/paired-final-86b81ab-01`, with matching oracle data
under `/home/ubuntu/dnsmasq-rewrite-20260929/tcp-writeback-gates/private/`.
The accompanying JSON records their hashes and the compact semantic results.

The [baseline's scope limits](TCP_WRITEBACK_GATE_BASELINE.md) still apply:
one transaction per event additionally rests on matching source anchors; these
two cases do not exhaust batch-drain variants, saturate capacity or cover the
separate CD-plus-bogus reply composition issue. This result is for isolated
private integration only. No physical router state was accessed or modified.
