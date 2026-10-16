# Avoid the remaining lease-expiry conversion before any expiry is possible

Independent185 child5e67562f records a conservative generation lower bound as
accepted lease records are added. Parent-name expiry comes only from these
records and is extended by max/immortality; it cannot precede this bound.
Deletion or extension deliberately leaves the old bound early. Snapshots copy
it and rebuilds calculate a new one, without an extra full-generation scan.

The shortcut applies only when the policy is Forever, or when now and every
retained finite expiry are nonnegative and now is strictly below the bound.
In the latter case now−expiry cannot wrap and every original live predicate
is true. A negative expiry disables the shortcut for the generation; negative
now, an unknown bound and the boundary itself use the original path. No
name-specific expiry, CNAME traversal or reverse removal is skipped unless
every removal condition is already false. Existing inactive entries stay
inactive after clock rollback. A read-only peer review found no missing
forward/nonterminal/reverse case; runtime qualification is still pending.

The early return discards only the dotted-name conversion cache. Local record
assembly still performs its original conversion when needed, and the eligible
fresh-cache ownership check uses the previously tested bounded converter.
Lookup, owner precedence, logging and reply assembly remain unchanged. This
source is not mixed into185 or the separate owner-clock prototype722d2762.

[The local prepared-query control](lease-expiry-bound-local-counts.json) adds
the same64 unrelated live lease names to both sides and explicitly recycles
replies. After1000 prewarm,8000 queries show185one allocation/21requested bytes
per call versus zero for5e, with equal checksum468800 and zero reallocations
or net live-byte delta. Expired generations, negative-time fallbacks and other
owner configurations are outside that zero-count claim. No CPU benefit is
inferred from these counts.

Two new boundary/snapshot/parent-name tests and the existing sticky-expiry
regression pass; musl all-target checking passes. The whole Mac library run
is **not** all-pass:722 tests pass, one old hosts fixture cannot find a target
bucket in its fixed10,000-name pool, and8 are ignored. Its exact executable,
source patch and logs are retained. The hosts source is byte-identical to185;
independent runs reproduced the generator failure in the preserved executable
and in unmodified185 hosts code with read-only bucket observation. Separate test-only repair7c2708f6 is now applied to this child asf3e0a145.
Its final Mac library run passes723 with8 ignored, and the musl all-target
check passes. The original5e allocation counts and failed run above retain
their original identities. No current185 source, measured artifact or frozen
correctness input is changed.

This remains local research. Exact-source related Linux gates, SDK construction
and any fixed performance screen must wait for the current185 acceptance work
and must bind a final source including the separate fixture repair if used.
