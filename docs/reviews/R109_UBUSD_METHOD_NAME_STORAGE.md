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
