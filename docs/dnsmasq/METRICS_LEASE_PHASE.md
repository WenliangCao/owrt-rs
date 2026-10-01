# Lease operation counters

`LeaseStore` now counts successful IPv4 allocations and actual removals at the
same operations as `lease.c:874` and `lease.c:634`. `LocalProvider` exposes a
read-only snapshot. The three u32 values wrap at the public ubus wire width;
they are cumulative for the store lifetime, including lease-file restoration.
They are not an active-lease gauge and are not reset by hosts reload, renewal,
file flush or DNS publication. This adds 12 bytes of counter payload per store,
with no allocation, socket, thread or per-lease field.

The exact C removal statement chooses its slot from the stored IPv4 address.
Consequently an expired or explicitly pruned `0.0.0.0` restored record increments
`leases_pruned_6` even in this `NO_DHCP6` build. That branch is preserved, rather
than declaring the public slot permanently zero. A full store, a rejected
duplicate allocation, renewal and repeated removal of an absent address do
not increment allocation/removal counters.

`tools/dnsmasq/lease_metrics_diff.py` compiles the unmodified, hash-pinned
`lease.c` in an observation driver and links the matching reference objects,
six target COPTS and ubus/libubox dependencies. The driver invokes actual
`lease4_allocate`, `lease_set_expires`, `read_leases`, `lease_prune` and
`cache_reload`; it neither reimplements their counter arithmetic nor generates
expected values from Rust. Rust runs production store operations on the same
ordered commands and lease files. Every row compares operation outcome,
three counters and active count, without sorting observations.

The gate covers capacity failure, renewal, infinite leases, expiry equality,
clock rollback, explicit and unknown targets, repeated removals, restoration
of live/expired/infinite and zero-address leases, and counter preservation
through cache reload. Forty fixed-seed sequences add pressure and interleaved
expiry/reload operations. A separate unit test checks u32 wrap and Rust's
explicit duplicate-address rejection; C's duplicate recovery defect remains
outside the ordinary equivalence corpus.

Evidence is retained in ignored
`private/dnsmasq-rewrite/lease-metrics-20261001/`:

- `gate-01`: **47 scenarios, 3,764 ordered observations, 3,764 matches**.
- `calibration-01`: deliberately changes one observed Rust counter;
  **3,763 matches, one mismatch, exit 1**.
- Each run records the full input, both outputs, stderr, compiler commands,
  comparison rows, source/object/tool hashes and both executable identities.
- Host lease unit tests: **14 passed**; affected source also passed musl
  all-targets Clippy with warnings denied. Ignored tests are not included.

The comparator first checks equal and unequal fixed inputs; the first C trace
must additionally match independent allocation/full/expiry calibration values.
The ordinary run and injected failure use identical case and observation
counts. No listeners or physical devices are used.

Reproduction on the Linux build host:

```sh
python3 tools/dnsmasq/lease_metrics_diff.py \
  --reference-build /path/to/exact-c-build \
  --out private/lease-metrics
```

This closes the lease-store counter primitive only. DHCP message counters,
live main/ubus publication, TCP lifecycle, complete metrics and permission
contracts still require their own integration gates. It establishes no
performance or production acceptance claim.
