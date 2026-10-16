# Reuse a selected positive record for its expiry check

Source0958f89c is an independent185 child. After `get` checks the slot,
generation and entry presence, the selector already requires positive A/AAAA.
The remaining validity condition is exactly the existing `policy.expired`;
CNAME target validation cannot apply. Replacing the general `is_valid` call
therefore avoids reading the same slot/content/record chain again. The strict
`is_stale` check and original TTL policy remain unchanged.

Mac library722/0/8ignored and musl all-target checks pass. One focused test
checks150 combinations of A/AAAA,5stale policies and signed-time expiry edges;
original hint replacement, generation, cache identity, read-only and LRU checks
remain. The separate prior hosts-fixture repair is included as its own commit.

The local final AArch64 build removes both outlined `is_valid` call sites
from the local and shared local/cache entry functions. These functions grow
4508→4540B and3980→4060B respectively; their stack frames remain384/608B.
The unstripped local executable falls5022408→5022168B. This is code-generation
evidence only: neither a canonical SDK artifact nor a runtime call count or
performance result. Frozen185 is unchanged. No Linux functional or timing
reservation has been consumed.

[Exact local commands, identities, code ranges and logs](fresh-validity-local-codegen.json).
