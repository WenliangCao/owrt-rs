# R131 batch capacity accounting

The repeated 1 KiB, eight-handler memory increase has a bounded allocator
explanation. This does **not** turn the frozen `>24 KiB` VmData guard into a
pass, and it does not resolve the separate shared-workload latency failures.

The actual Server diagnostic uses the production `dispatch_event`, eight
same-owner objects, the exact `r124.memory` event envelope, and drains and
checks all eight frames after each event. It runs against the target musl
build on Oracle; the test is in a diagnostic copy, not the release source.

| Phase | Relay frame | Retained event_batch capacity |
| --- | ---: | ---: |
| 16-byte warmup | 72 B | 576 B |
| First 1 KiB event | 1080 B | 9216 B |
| 1000th event | 1080 B | 9216 B |
| 10000th event | 1080 B | 9216 B |
| Client removed | — | 9216 B |

The allocation pointer remains unchanged from the first 1 KiB event through
the 10000th. The buffer belongs to Server, rather than each connection, and
`clear()` resets its length without releasing capacity. The test establishes
this retained buffer's plateau for the tested input; it is not a general
no-leak proof for all daemon state or workloads.

An isolated Vec diagnostic executes the same seven-frame append sequence
(eight-byte header, then 1072-byte blob) with Rust's **same bundled** static
musl 1.2.5 archive used by the R131 link map. The retained capacity grows
`576 → 1152 → 2304 → 4608 → 9216`. The strace records a **28672-byte mmap**
at the last growth and a matching **28672-byte munmap** when the Vec is
dropped. Repeating 10000 events keeps the pointer and capacity unchanged.

This matches the official allocator's rule: size class 32 has a 9344-byte
slot, its low-use group has three slots, and `3 × 9344 + 16` rounds to
28672 bytes. See [musl 1.2.5 mallocng malloc.c](https://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/malloc.c?h=v1.2.5)
and [meta.h](https://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/meta.h?h=v1.2.5).
The official files were downloaded and hashed; the linked archive identifies
itself as 1.2.5. The R131 map and the diagnostic map both select this bundled
archive, not OpenWrt's dynamic libc for Rust allocations.

The mechanism reproduces the router's extra 28 KiB VmData. The 9216-byte
buffer also needs about three resident pages, consistent with the observed
12 KiB RssAnon difference. However, the exact release daemon's individual
allocation pointers were not traced: **this is a reproducible allocator
mechanism and capacity accounting, not a claim of exact release allocation
attribution**. The independent router plateau supplies the production-ELF
boundedness observation; these Oracle diagnostics do not replace it.

No runtime implementation or frozen release ELF was changed. Two discarded
diagnostic attempts are retained: a test-only immutable/mutable borrow compile
error, and incorrect initial capacity assertions (512/8640 instead of the
observed 576/9216). They produced no performance result.

The [derived identities and result](r131-batch-capacity-accounting.json)
reference retained source, ELF, logs and strace evidence under
`private/r131-event-batch/correctness/memory-capacity/`.
