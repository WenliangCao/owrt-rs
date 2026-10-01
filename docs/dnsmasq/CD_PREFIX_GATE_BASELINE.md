# Ordinary CD cache-prefix baseline

Exact native C dnsmasq 2.93 passed **10 cases / 136 observations** before a Rust
candidate was tested. This freezes behavior that ordinary CD admission checks
must preserve: CD suppresses the final cache commit, while extraction still
starts a transaction, removes conflicting old records, stages replacements,
and can evict live records.

The real isolated daemon gate is `tools/dnsmasq/dns_cd_prefix_diff.py`. It holds
an owner's first UDP reply while an independent CNAME query warms that owner.
It verifies old direct and alias hits, then releases the first reply. Four
request-CD/raw-reply-CD combinations run for A over IPv4 and AAAA over IPv6.
A fifth case per family fills a three-record cache and releases a two-address
CD reply. This is ten bounded cases, with real UBus counters at every stage.
There are no DO queries, signatures, extra options, bogus-address settings,
DNSSEC validation or physical-router actions in this gate.

| Observation | Ordinary request/reply, no CD | Either request or raw reply has CD |
| --- | --- | --- |
| Insert counter after one-address held reply | 2 → 3 | Remains 2 |
| Existing alias queried as CNAME | Cached `owner.test` | Cached `owner.test` |
| Direct owner query | Cached replacement | Forwarded; reply left pending |
| Another CD query receives empty NOERROR without SOA | No new insertion | No new insertion |
| Existing alias queried as CNAME after that empty reply | Still cached | Forwarded |
| Final repaired owner and alias | Cached final address | Cached final address |

The target's uncommitted slot keeps the old alias's UID relationship until the
next `cache_start_insert`. Its target **name** is therefore still visible via
a CNAME query. An A/AAAA query through that alias does not expose the staged
address: the target is absent from the hash table and the lookup forwards.
The gate queries CNAME first so it can inspect this intermediate state without
answering a forwarded alias query and accidentally clearing the pending chain.

The empty reset reply is especially useful: its request has CD, its answer is
ordinary empty NOERROR with no SOA, and `neg-ttl` is unset. It inserts nothing,
but must still clear the previous pending chain. A CNAME lookup immediately
after that reply directly proves the old pointer became invalid. The held
direct-owner response remains unanswered during this check, preventing an
unrelated cache commit from manufacturing the result.

Both pressure cases start with alias + target + filler. The uncommitted
replacement contains two addresses. The inserted counter remains three while
`dns_cache_live_freed` becomes **one**; the filler probe then forwards. Cleanup
and recovery preserve that live-eviction count. All final owner and alias
queries hit the repaired cache with no upstream sends.

Relevant exact-C source anchors are `rfc1035.c:789` (unconditional start),
`rfc1035.c:1114-1123` (ordered address insert and CNAME target relationship),
`rfc1035.c:1202-1209` (CD/no-cache gate only around end), `cache.c:650-663`
(pending-chain cleanup), `cache.c:530-575` (conflict removal and target slot
preservation), and `cache.c:795-840` (reuse with the same UID and stage the
replacement). Runtime observations remain the authority for the claimed
client-visible results.

The no-CD cases are live negative controls. Comparator calibration separately
rejects one invented insertion counter and one extra upstream send. All 30
counters, raw DNS inputs and outputs, monotonic event order, process cleanup
checks, and the exact tool copy are retained in ignored
`private/tcp-writeback-gates/cd-prefix-c-baseline-03`; the JSON report hashes
those raw files and records the observed boundaries. Original exploratory
runs `-01` and `-02` are also retained: their fixture improvements are documented
in the JSON. None of these runs failed a timing deadline or was silently retried.

Reference ELF SHA-256:
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
Tool SHA-256:
`305f09469faf5da96b19f113b9cb39724856e362c091c8e54937565932f42822`.

The tool also accepts the existing strict `--c-binary` / `--c-identity` image
runner pair; no alternate image identity is accepted. A candidate comparison
adds `--rust`; every case obtains its actual C observations first. Cache-hit
TTLs may differ by at most one second, while flags, record order, routes and
counters are exact. This baseline makes no parity claim for Rust yet.
