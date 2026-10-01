# Final shared-index reverse transfer regression

Private source `0eaaef8` preserves **184/184 deterministic observations** from
the existing reverse-transfer gate, with no execution failures. The separate
**12 ordering observations remain unresolved**: four differing rows against
each native C trace and two against each SDK-musl trace. The full comparator
continues to exit **1**, exactly as for `54346fd`; this is not a complete gate
pass.

This source-specific replay is required because the shared name index changes
forward/reverse same-name scanning and mixed eviction. It uses a fresh private
source copy, unchanged test adapter, the original 21-case matrix and all six
saved exact C traces. **No C execution was repeated.** Actual Rust capture and
import APIs preserve replacement, local coexistence, configured-CNAME handling,
shared pressure, empty/failed transaction effects and absolute-expiry behavior
in the deterministic cases.

The multiple-PTR case retains the same complete comparison results as before:
the child and parent states before lookup match C's export/commit reversal,
while address traversal and its LRU effects differ. No sorting, set comparison,
new favorable reference run or order-field normalization was introduced. The
native and SDK traces remain distinct source-runtime observations; they do not
establish stock-image ELF behavior.

The native Rust probe SHA-256 is
`486dc4795cb6b2dfef74ea4457f139396bd502b99ac8e63db5db261210f96c76`.
The [sanitized JSON](REVERSE_SHARED_INDEX_TRANSFER_RESULT.json) pins the frozen
source, adapter, probe, expected baseline and all artifact identities. Raw
inputs, outputs, probe and instrumented source are retained in the detached
gate worktree's ignored `private/evidence/final-0eaaef8/` and on oracle in
`/home/ubuntu/dnsmasq-reverse-transfer-20261001/work01/private/rust-final-0eaaef8-01/`.
The downloaded archive was verified against its complete file-hash manifest.

Build and execution used Linux isolation. No router, private TCP integration,
resource, OOM, performance or production acceptance is implied. The separate
[ordinary allocation check](REVERSE_SHARED_INDEX_ALLOCATION_RESULT.md) does not
measure the new reverse name-index heap.
