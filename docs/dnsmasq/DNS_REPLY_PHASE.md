# DNS upstream reply envelope phase

This phase covers the bounded, pre-cache part of an upstream reply. It is
socket independent and does not implement address extraction, rebind policy,
cache insertion, EDE generation, DNSSEC validation, or fanout identity
rewriting.

| C source | Contract | Rust | Evidence |
|---|---|---|---|
| `rrfilter.c:75-297`, `rrfilter_desc` | Remove all additional OPT records only for one valid question; check every kept owner/RDATA name before mutation; pointers into removed bytes leave the packet unchanged; pointers after removed bytes are shifted; unknown RDATA stays opaque | `dns::reply::strip_opt` | `tools/dnsmasq/dns_reply_diff.py`, sanitizer C oracle; run-1200b: 1,537 accepted / 890 excluded packets, 19,981 commands, 0 mismatch |
| `edns0.c:19-78` | Last OPT wins for envelope metadata; TSIG in last additional and TKEY query mark signed replies; signed OPT/AD handling is preserved while process_reply still applies its CD/RA envelope policy | `find_pseudoheader`, `ReplyPolicy`, `prepare_reply` | Differential corpus includes multiple OPT, TSIG/TKEY and signed/non-signed cases |
| `forward.c:697-780` (`process_reply`) | Preserve extended RCODE; restore client EDNS UDP size or strip the added OPT; clear AD unless signed or DNSSEC proxy is enabled; restore requested CD and set RA | `prepare_reply` | Differential `E` commands compare RCODE, signed bit, flags, size and bytes |
| `forward.c:1355-1450` (`return_reply`) and `rfc1035.c:395-416` | For an over-limit UDP fanout, keep the question and the last OPT only, clear answer/authority/additional counts and set TC; do not cut inside an RR | `limit_udp_reply` | Differential `T` commands compare bounded output and counts |

The repeatable oracle is:

```sh
python3 tools/dnsmasq/dns_reply_diff.py \
  --output private/dnsmasq-rewrite/dns-reply/run-N \
  --count 1200
```

The tool verifies exact reference source hashes, builds the extracted C oracle
with AddressSanitizer and UndefinedBehaviorSanitizer, builds the Rust driver,
calibrates mismatch and output-count checks, and stores all raw inputs and
executables below ignored `private/`. The independent gate excludes malformed
or structurally truncated packets before comparison; each exclusion is
recorded in `excluded.json` with its reason. It does not turn malformed input
into a success claim.

The current envelope API intentionally stops before `process_reply`'s remaining
work: cache/rebind/address extraction, DNSSEC validation and filtering,
configuration `rrfilter`, EDE insertion, and per-recipient ID/name fanout. A
zero-mismatch oracle run proves only the listed bounded transformations for the
accepted corpus.
