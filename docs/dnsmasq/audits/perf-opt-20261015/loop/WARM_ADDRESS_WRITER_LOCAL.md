# Encode a fitting address reply in its existing warm buffer

Independent6ab child6dadfec2 changes only fresh-address reply assembly. It
requires disabled query logging, a valid4/16-byte A/AAAA result, enough packet
limit, and enough existing capacity for both the complete reply and the original
writer's min(limit,128) reservation. Growth, overflow and logging retain the
original PacketWriter body byte-for-byte. Header flags, original question case
and binary bytes, fixed0xc00c owner, IN type/class, TTL and lengths remain the
same. Source peer190e015c passes; no new persistent state or unsafe code is added.

The original general-versus-fresh comparison now spans18432 tuples: root,
original mixed-case, binary and maximum names; logging on/off; capacities
0/64/128/512; and every prior type/time/flags/DO/filter/limit case. Original short
fixtures retain cache4, while long-name fixtures use16. All725Mac library tests
pass with8existing ignored; musl all-target compilation passes. This remains
local validation, not original Linux/C-corpus qualification.

| Separate local revision | Fresh function bytes/frame | Other writer | Whole ELF delta vs6ab |
| --- | ---: | ---: | ---: |
| b1fc4225 append chunks | 2332 / 304 | in same function | −136B |
| 40bc9086 single resize | 2056 / 304 | in same function | +72B |
| a9f495c9 outlined fallback | 1164 / 160 | 1092 / 288 | +496B |
| 6dadfec2 fixed field slice | 952 / 160 | 1092 / 288 | −16B |

All variants and logs remain. The final local ELF restores the wrapper frame
before tail-branching to fallback; SDK behavior is unmeasured. The warm path
also adds full-reply zeroing and a memset call before its writes. Neither code
size nor frame reduction proves a CPU gain. No allocation saving is claimed:
the guard deliberately selects cases where the old writer also needed no growth.

The original hot15 probe never returns packets through recycle_cached_reply;
its local buffer stays empty. That probe can reveal cold fallback/layout costs,
but cannot measure this warm branch. Keep the original probe untouched and use
the ordinary owner if this direction is later selected. Current5c remains the
only timed candidate; this prototype has no SDK or remote execution preparation.

[All local identities and checks](warm-address-writer-local.json).
