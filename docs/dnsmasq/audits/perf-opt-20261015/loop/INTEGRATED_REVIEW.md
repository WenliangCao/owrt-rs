# Integrated owner and publication review

Reviewed `51b03959..a929d975`, including selected D6/D7 lease publication,
`9f739ffc` insertion and `a929d975` same-call hosts bucket reuse. The
[receipt](integrated-review.json) binds all 20 changed product files and the
complete diff. This was a local static review, not another runtime gate.
No new concrete correctness or lifetime blocker was found. Later product
commits still need a delta review before the final snapshot is qualified.

## Interactions checked

- **UDP packet lifetime:** `main.rs:4987` moves the receive buffer into a local
  owner for the entire synchronous call and restores it afterward. Deferred
  admission already owns bytes; deferred MAC and interface-record paths call
  `into_owned` before retaining them. Interface enumeration only queues its
  collector and cannot receive another datagram on this stack. The synchronous
  early-failure recursion operates on the same valid buffer. EDNS decoration
  has separate owned bytes. Stale answers still send before refresh, whose
  submission owns its required packet. No lease publication stores this packet
  borrow, and the 16-packet fairness budget remains unchanged.
- **TCP frame lifetime and partial writes:** `service.rs:54` owns the answer
  Vec separately from its two-byte prefix. `main.rs:2981` advances the same
  total wire offset; prefix-only short writes, payload writes, EAGAIN/EINTR,
  close-after-100 and stale-close-before-refresh retain their old decisions.
  The complete-input fast path returns exactly one frame and leaves the next
  frame to the owner. No new answer references a mutable lease generation.
- **Upstream scratch:** `upstream.rs:771` retains capacity, not readiness.
  Tokens, fds and deadlines are rebuilt after each timer pass and EINTR;
  readiness never carries into a later poll. Socket tokens still guard against
  deletion/reuse during processing. Poll-wide failure clears pending work,
  then the emptied scratch is restored. Neither D6/D7 nor insertion changes
  this transport state.
- **Terminal retirement:** `main.rs:2046` is reached only after the successful
  daemon loop has stopped, helper/file work has drained, the logger has
  finished and the PID file is cleaned. `run_inner` returns through `run` to
  `main`, without a restart loop. Only `DnsDaemon.cache` is forgotten; its
  fields own memory and shared immutable record storage, with no IO Drop or
  external callbacks. TCP cache views can still share those roots, but they
  are also being destroyed before process exit. Lease persistence, helpers,
  descriptors, local lease generations and log writers keep ordinary Drop.
- **D6/D7 copy-on-write:** `lease_names.rs:203,432,471` shares immutable name
  bytes between retained inputs, records and lowercase map keys. Mixed-case
  records keep their original spelling and receive a separate canonical key.
  `active`, expiry fields, reverse ownership and index ordering remain inside
  each cloned `LeaseNames`; removing an expired parent record cannot mutate
  an accepted TCP reader. `One` to `Many` preserves the old ordered insertion
  calculation. Blocked records still retain their original input for reload.
- **Insertion and hosts publication:** `wire.rs:148` counts the exact escaped
  length, including binary zero/one/dot escapes and root, without allocating;
  the 75-byte policy boundary is unchanged on insertion and release.
  `cache.rs:919` retains the name clone only on the reverse-index path that
  actually consumes it; capture/transfer still clones its own record data.
  `lease_names.rs:366` computes a hosts bucket once for the same name/capacity;
  no hosts mutation occurs before its two scans. Lookup retains the existing
  IPv4-only rotation before `cache.prepare_name` and conflict handling.

The separately authorized `b1136023` stale-negative-CNAME correction remains
an explicit compatibility fix. This review does not describe that behavior
change as a transparent optimization or alter its exact-C expected result.

## Resource obligations

Outbound framing preserves the answer Vec's spare capacity. For the recorded
60-byte answer with capacity 128, a blocked connection retains 66 additional
heap bytes plus 8 inline bytes. This is a measured tradeoff, not a blanket
memory improvement. Full blocked-client/process-tree memory gates remain
required. Upstream scratch similarly keeps approximately 16 bytes per highest
observed socket count, plus 48 inline bytes on the measured 64-bit ABI, until
resolver destruction. Neither retention can be dismissed using allocation
counts alone. Terminal retirement reclaims cache memory at process exit and
must never be moved into reload or a continuing library lifecycle.

## Bounded owner stopping statement

The evidence supports stopping **the concrete owner experiments screened so
far**, while retaining the implementation and measurement limits:

- L08 inline socket owners save about 610 instructions for a one-owner
  lifetime, project roughly 0.37% of A's UDP-miss instruction total, add 16
  inline bytes and regress the 150-owner case. No product replacement was made.
- L10 eliminating nested zero-timeout ppoll projects about 1.99% of A's
  UDP-miss instructions before safe generation/error bookkeeping. That is
  below the fresh deployed CPU range (4.60%) and frozen 8-tick precision floor
  (3.07%). The native-glibc isolated screen is not a device speedup bound.
- L07 metrics work is only 0.046%/0.124% of the control/A instruction samples.
- L06 unchecked receive batching changes the deferred-error boundary; the
  checked single-packet variant adds 3.57% instructions and saves no syscall.

These measurements are bound to the recorded control/A SDK artifacts, **not
the final C candidate**. If the final candidate materially changes the cost
denominator or observed variation, reevaluate these projections. In particular,
A's UDP/TCP misses still contain substantial cache/user work, and the 12.99%
inlined send-function sample label is not an estimate of removable cost.
Neither the 93.82% sampled kernel share in A TCP-hit nor these rejected ideas
proves that every remaining daemon path is irreducible. Exact candidate-wide
correctness, full timing and resource acceptance remain separate requirements.
