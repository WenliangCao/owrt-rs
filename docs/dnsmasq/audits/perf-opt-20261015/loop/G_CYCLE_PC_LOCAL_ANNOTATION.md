# Original G cycle PCs: local source investigation

The original single Oracle UDP cycles:u capture was annotated against frozen
G ELF9109e987, its existing named linker ranges and exact executable PT_LOAD
bytes. All four downloaded text files match the original capture hashes;
5497samples/54970000periods match the original self report. This reads existing
evidence locally and neither reruns profiling nor consumes the timing host.

Two leading PCs inside answer_parsed_with_query_events follow dependent cache
content/Record loads and test the optional-entry discriminator or record kind.
Together they account for100samples,1.819% of all periods. The source is the
inlined read-only name/CNAME inspection. The independently prepared2b direct
Arc slice removes one content-storage load; it retains the later Record load.
The sample does not measure the cost saved by that prototype.

The three leading names_for PCs follow the shard-root/table load, control-byte
load and stored-key-length load. They confirm the sampled addresses are in the
existing indexed lookup; they do not establish cache misses or justify changing
its collision protection, sharding contract or snapshot semantics.

LeaseNames::lookup and its emitted iterator-fold range have91+88samples,
3.256% of all periods. Several PCs are in iterator-state setup/empty completion.
The cached-address ownership path only needs existence, motivating isolated
5300212f's boolean operation. The original lookup remains the comparison
reference; no table, expiry rule or snapshot layout is changed.

These are sparse self-cycle samples with possible skid, not exact instruction
costs, inclusive callers, cache-stall proof or A53 measurements. The1200000
non-user and1640000vDSO periods remain in the denominator. The unnamed input
section is not relabeled. A generic section-table ELF reader initially rejected
the stripped artifact; standard program-header decoding then read the same
verified bytes, with the initial local failure retained.

[Selected PCs, exact instructions and complete private receipt](g-cycle-pc-local-annotation.json).
