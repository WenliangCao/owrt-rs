# Final shared-index ordinary allocation and layout check

Frozen private source `0eaaef8` passes the unchanged five-case ordinary cache
allocator/layout check against forward predecessor `7a9cadd` and the original
legacy expected vectors. Both sources run `empty`, `one`, `many`, `dangling`
and `failed`: **10 executions**, with equal commit and whole-case allocation/
deallocation vectors, identical actual layouts and zero retained bytes after
every cache drop. This is an untimed regression check, not performance acceptance.

| Type | Native AArch64 size | Alignment |
| --- | ---: | ---: |
| Cache | 168 | 8 |
| Slot | 160 | 8 |
| Entry | 120 | 8 |
| Record | 56 | 8 |

| Case | Commit alloc/realloc calls | Requested bytes | Live-byte change | Dealloc calls/bytes |
| --- | ---: | ---: | ---: | ---: |
| empty | 0/0 | 0 | 0 | 0/0 |
| one | 3/0 | 245 | 245 | 0/0 |
| many | 263/0 | 30,342 | 17,946 | 6/12,396 |
| dangling | 1/0 | 8 | -9 | 2/17 |
| failed | 0/0 | 0 | 0 | 0/0 |

The previous `ordinary_layout_wrapper.py`, original driver, allocator, inputs
and expected vectors remain byte-identical. The wrapper appends a size accessor
only to generated private module copies and retains the original measurement
intervals. Candidate inputs were copied from a Git archive of the frozen
revision and checked again after execution. The final cache source SHA-256 is
`5d62b11382abcb2c59cef411a060365f1675ebeca839101c1cb194d26e9160d2`.

Two preparation failures remain retained. An `adf3977` preparation used a
nonexistent isolation-script path and exited before Python, compilation or
sampling. A first `0eaaef8` invocation gave the old wrapper a relative output
path, producing a duplicated Rust module path; forward compilation failed
before any sample executed. The completed invocation changes only that CLI
argument to an absolute path in a fresh output directory. No passing sample
was repeated and no candidate/input/threshold was changed. The source-only
`adf3977` to `0eaaef8` difference is comment wrapping and reuse of a local Copy
`Kind` value; only the latter source executed allocator cases.

The [derived JSON](REVERSE_SHARED_INDEX_ALLOCATION_RESULT.json) pins source,
wrapper, probes, vectors, logs and archive identities. Raw evidence and both
failed preparations are retained under ignored
`private/dnsmasq-rewrite/reverse-resource-static-20261001/final-0eaaef8/` and
on oracle under
`/home/ubuntu/dnsmasq-reverse-resource-static-20261001/0eaaef8-01/`.
Execution used the Linux isolation wrapper. No router was accessed.

The matrix covers ordinary insertion, commit and drop; it does not exercise
lookup allocation, reverse records, mixed populations, transfer capture, service
memory or OOM. Reverse records now occupy the shared name index and can allocate
additional keys and slot vectors. Their heap cost is **not measured here** and
must not be called free because ordinary vectors and structure sizes match.
No CPU, RSS, latency or production-delivery claim follows.
