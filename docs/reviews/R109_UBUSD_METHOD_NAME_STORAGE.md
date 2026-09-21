# R109: isolate method-name storage from the rejected R97 layout

This experiment is frozen against the accepted `bd6b6db` source. R100/R101
already replaced ADD/REMOVE reply construction with fixed stack encoding and
borrowed sending; this experiment does not change that path.

## Hypothesis

The rejected R97 method-storage candidate changed two independent things at
once: it removed the second `Vec<u8>` holding each method name, and it changed
the completed method list and blobs to `Box<[T]>`. Its physical registration
recheck was slower for the one-method lane, so those effects were not
separable. R109 keeps the existing `Vec<Method>` list and `Vec<u8>` blob
ownership, but removes only the duplicate name allocation. ACL lookup reads
the canonical blobmsg name already stored in the blob.

This is a bounded allocation/layout experiment. It does not alter wire bytes,
method order, ACL string semantics, type reference counting, object ownership,
reply ordering, event delivery, or receive behavior. It must be rejected if
any existing compatibility gate fails or if the physical registration CPU
direction is not better without an unacceptable memory regression.

## Frozen comparison

The router must remain on stock C. Use the exact image `libubus` caller and
the serial ADD/REMOVE loop, with daemon and caller pinned to separate cores.
Compare the R109 ELF against the exact C daemon and the accepted R103/R100 Rust
ELF under fresh disposable namespaces. Measure `CLOCK_PROCESS_CPUTIME_ID` for
the complete loop, with signature validation and final empty lookup outside
the timed interval. One ratio per physical window is the statistical unit;
segments are aggregated and are not independent samples.

Primary lanes are `register_1_8` and `register_16_8`; retain `register_64_8`
as a scale check. Record daemon CPU, client CPU, total CPU, wall time, RSS
diagnostics, exact binary/library identities, protocol checks, and cleanup.
No result from the failed R97 A/A precision screen is pooled with this series.

## Decision rule

Keep the source change only if all compatibility and recovery checks pass and
the registered lane improves relative to the accepted Rust baseline without a
measured increase in retained or peak requested heap. A C comparison can show
whether the remaining gap moved, but cannot by itself justify a whole-component
claim. If the one-method lane remains slower, revert this experiment and retain
the result as evidence that the duplicate name allocation was not its dominant
cost. A failure to resolve effects near one percent remains evidence-limited;
it is not a language-limit conclusion.

## Physical result and decision

The canonical release rebuild is ELF `1dfb317c…15259`. It passed the 35-test
router unit run, the six functional/recovery host gates, and the seven-group
wire/ACL differential; every candidate window preserved stock production, boot,
configuration, mounts, and cleanup.

The ten-window fixed-slot comparison against accepted R103 used the exact image
`libubus` caller and 10,000 timed cycles per serial segment. Candidate/R103
medians (exact rank intervals) were:

| Metric | Change |
| --- | ---: |
| daemon CPU | **−1.19%** (−2.11%, −0.70%) |
| caller CPU | −0.10% (−0.40%, +0.19%) |
| total CPU | **−0.66%** (−1.13%, −0.42%) |
| wall | −0.31% (−1.72%, +0.76%) |

The independent ten-window exact-image C comparison gave daemon CPU **−7.01%**
(−8.85%, −6.48%), total CPU **−3.77%** (−4.84%, −3.32%), wall **−4.34%**
(−6.79%, −4.00%), and caller CPU +0.00% (−0.40%, +0.46%). The C comparison
is the same one-method/8-byte registration workload; it does not establish
all-signature or whole-component superiority.

The router requested-heap fixture reproduced each side twice. For 128 objects
with one 8-byte method, retained requested bytes fell from 76,652 to 63,340
(−17.4%); construction peak fell from 78,336 to 66,896. All listed method/name
layouts decreased, with identical reallocation counts where only the duplicate
name allocation was removed. This is allocator-request accounting, not RSS/PSS.

**Decision: accept R109 into the current ubusd source baseline.** The duplicate
method-name allocation is now removed. The result is accepted for registration
workloads covered here; 16/64-method CPU, steady-state lookup/invoke, RSS/PSS,
and nine-component integration remain separate targets.

Evidence: [R109 R103 comparison](r109-name-fixed-slot-cpu-results.json),
[R109 C comparison](r109-stock-cpu-results.json), [heap plan](r109-name-memory-plan.json),
and the canonical router gate output retained under `private/r109-method-name-storage/`.
