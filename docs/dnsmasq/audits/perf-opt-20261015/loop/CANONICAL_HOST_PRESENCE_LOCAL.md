# Reuse already-folded query spelling for hosts presence

Independent6ab child2155eaba gives the cache ownership check a crate-private
folded-name entry point. Both input paths already lowercase ASCII through
wire_to_dotted or query_dotted_name; root/binary labels and conversion failure
keep their original handling. The public name_exists entry still preserves
its empty-table shortcut and mixed-case normalization/allocation semantics.
No index, memo, generation rule or public API is added.

The final725Mac library tests/8ignored and musl all-target check pass. The
existing two cached_local_shortcut tests also pass with debug assertions active.
Source-only peer review found no reachable precondition violation; its durable
review is maintained by correctness. This is not Linux or full qualification.

The local final control reproduces6ab77096845. The cache guard still occupies
528B, but calls the476B folded helper instead of the844B public path. The
public path becomes464B plus the shared helper; combined code grows96B and
whole local ELF grows288B. A caller's whole emitted range is not its executed
instruction count; general public calls can pay an extra call. There is no
claim of fewer cached allocations (the old input was already lowercase), or
measured CPU improvement.

Keep the source separate and lower priority than the queued803 compiler and
1df inline-address experiments. No remote preparation or timing is scheduled.

[Checks, original logs and local codegen](canonical-host-presence-local.json).
