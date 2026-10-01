# DHCP publication and selective forward-cache invalidation

`Cache` now implements `lease_names::PublicationCache`. Publication calls the
ordinary indexed lookup at C's time zero, promotes matching IPv4/CNAME entries,
and selects the last dynamic hash match as `cache_add_dhcp_entry` does. It then
applies the selected conflict set until a conflicting local blocker stops the
scan. An IPv4 trigger removes IPv4/NODATA and CNAME; a CNAME trigger can also
remove AAAA, NXDOMAIN and generic records. Other names remain indexed.

The local blocker participates in lookup rotation before deletion. For example,
a mortal non-reverse prior DHCP entry after two dynamic IPv4 entries can rotate
between them; the first dynamic entry in that new order is removed and the
other survives. `no-round-robin` changes this outcome, so `ForwardPublication`
carries that configuration explicitly. Reverse owners precede dynamic entries;
non-reverse immortal records follow them. Deleted CNAME targets do not preserve
their old generation, and later slot reuse cannot redirect the old alias.

`reverse_owned` returns false because this cache currently admits only forward
entries; upstream PTR/reverse-cache support is not implemented by this trait.
It must not be mistaken for a positive reverse-ownership compatibility result.

`tools/dnsmasq/lease_cache_diff.py` compiles the unchanged exact `cache.c` inside
its driver and links the remaining verified C objects. The fixture places local
blockers through actual `get_config_crec/cache_hash`, then uses real
`cache_add_dhcp_entry/cache_find_by_name`. These are cache-state fixtures, not a
claim that every constructed mixture can arise from a normal upstream packet.
The comparator checks every returned record in order with kind, payload,
negative flag and absolute expiry, plus command/completion counts. No response
order is sorted. Calibration rejects changed TTL and missing results and checks
C insertion/hit, IPv4 deletion, and AAAA/NXDOMAIN preservation independently.

Evidence in `private/dnsmasq-rewrite/udp-policy-20261001/linux/lease-cache-04/`
passes 70 traces / 1,876 operations. Coverage includes two trigger orders,
IPv4/NODATA/AAAA/NXDOMAIN/generic/CNAME mixtures, reverse/mortal/immortal local
blockers, both round-robin settings, target deletion and slot reuse, and time
zero expiry. Earlier `lease-cache-01/02` are probe build failures (panic/LTO
link settings), with no comparisons; `lease-cache-03/` is the first valid pass.
The existing cache transition gate still passes 22,571 operations with
ASan/UBSan in `cache-regression-after-02/`; its existing 138 cross-generic-type
ordering variations remain recorded. Sixteen cache unit tests and library
clippy pass, including 100 slot reuses with ownership checks.

The current blocker merge models a contiguous same-name dynamic group. C's
`cache_hash` can place a later local blocker differently if an unrelated name
has split that group in its hash bucket; the supplied blocker flags do not
encode that position. Directed collider validation confirms a difference in
`linux/lease-cache-collisions-01/`: both distinct-bucket controls pass, but both
same-bucket cases differ after publication. With round-robin C removes both
dynamic IPv4 entries while Rust retains one; with no-round-robin C retains both
while Rust removes both. The live C process chooses a colliding name with the
read-only `X` helper and confirms it with `V`; both implementations then receive
the same concrete insertion/publication/query operations. No result is sorted.

That fixture inserts the prior DHCP blocker directly through `cache_hash`.
Normal complete publication first unhashes DHCP entries, and cache insertion
can reject a conflict with an already published DHCP name. A reachable daemon
sequence reproducing this synthetic initial state has not yet been established;
neither unreachability nor full compatibility is claimed. The flags-only
publication interface cannot express the demonstrated initial ordering, so this
remains an explicit incomplete contract, not a waived passing case. The current
gate therefore does not establish arbitrary hash-bucket publication equivalence,
full `answer_request`/daemon equivalence, reverse caching, allocation failure,
or performance acceptance. This boundary must remain open in the master report.
