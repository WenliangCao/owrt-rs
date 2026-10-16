# Accepted G: original 50-window UDP stage diagnostic

Local preparation only. Source `a34e73107bc15f29b29b83499ceb0e0bc746d915`
is accepted G plus the reviewed diagnostic hooks and reply-buffer adaptation.
Actual Linux gate receipts, SDK ELF/map/build, independent reviews and quiet
release remain unset. No device or Oracle work was started by this preparation.

The [plan](A53_G_UDP_STAGE_DEVICE_PLAN.json) preserves the original five groups,
each with five alternating pairs:

1. Exact image C / accepted G.
2. G / diagnostic full calibration.
3. Own full / receive.
4. Own full / before-answer.
5. Own full / skip-local.

The original workload, four modes, counter schema, 6,000 matching queries,
1,000 prewarm threshold, 5,000 selected cuts, statistics and failure policy
remain unchanged. The existing reviewed capture-boundary health helper is
reused. E/F are restoration-only roles; five immutable artifact copies are
required so G cannot replace E's recovery identity.

Before-answer takes G's cached reply buffer and uses its original send-then-
recycle path. It does not restore the old E diagnostic's forced 128-byte
allocation per cut. This source property is not a new measured allocation
claim or zero-allocation gate.

Each cut retains its own contemporary full controls. Calibration does not
prove zero instrumentation cost. Synthetic TTL/writing, function frames,
branch prediction and cache/layout effects remain; stage differences are
not additive function costs, IPC evidence or allocation prices. All modes
remain excluded from product-candidate acceptance.
