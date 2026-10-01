# Private TCP writeback candidate gate result

Private candidate `bcf9e88` matched **12/12** C-first real-service observations
on its first paired run. There were no protocol, timing, counter, cache-winner,
or cleanup failures. The independent C baseline was committed as `cfbdd19`
before the candidate was run; the tool and helper were unchanged between runs.

The real UDP DNS doctor subscriber held the parent while an existing TCP worker
answered two sequential cold queries. The queued asynchronous UBus snapshot saw
no parent cache insertions from either child transaction or the doctor query.
Both later UDP cache hits had the expected addresses and no upstream traffic.

With two accepted workers, both same-name answers and both client closes
preceded subscriber release. The queued metrics showed two active slots. C and
Rust then imported both transactions, reached active count zero, and returned
`192.0.2.21` from the parent cache: the first accepted worker's answer won after
the second accepted worker's lower slot was processed first. A newly accepted
worker inherited that answer without upstream traffic.

| Subscriber-held case | C | Rust |
| --- | ---: | ---: |
| Two sequential child queries | 0.406 ms | 0.603 ms |
| Competing slots and child closes | 0.474 ms | 0.702 ms |

These intervals establish ample completion within the unchanged 100 ms C doctor
timeout for this run; they are not latency benchmarks. Both doctor replies were
rewritten to `192.0.2.250`, so an expired callback could not silently pass. Both
sides ended with no worker processes and an active TCP gauge of zero. Recorded
parent descriptor counts were 15 for C and 7 for Rust; absolute counts are not
required to match across implementations.

The paired run retained all 30 UBus counters, DNS inputs and outputs, upstream
requests, monotonic event order, process cleanup checks, and subscriber wire
messages in ignored `private/tcp-writeback-gates/paired-bcf9e88-01`. The JSON
report records hashes, compact observations and resource results. Negative
comparator calibration rejected both an early cache insertion and a reversed
slot winner. No timing failure was retried.

- C ELF SHA-256:
  `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
- Candidate ELF SHA-256:
  `0b574df741a66c4f01a0e94c2c3bb404a6ab84b56783bde7fa94e994ba992d6c`.
- Candidate oracle artifact:
  `/home/ubuntu/dnsmasq-tcp-private-20261001/bcf9e88/components/dnsmasq/target/release/dnsmasq-rs`.

This result supports the tested private writeback integration. The
[baseline](TCP_WRITEBACK_GATE_BASELINE.md) states the source anchors and limits:
one transaction per event additionally relies on source inspection, and these
two cases do not test full TCP-capacity saturation or every batch-drain variant.
No physical router state was accessed or modified.
