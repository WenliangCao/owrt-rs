# FIX6 F2 independent packet review

**F2 is fixed in the original reproducer.** Two fresh four-way runs, each
normal/debug × UDP/TCP, reproduce the original invalid CNAME in `before` and
return byte-for-byte identical final replies from current `fix` and exact-image
C: **8/8**, with no TTL tolerance or packet-field exclusion. This conclusion
covers the original F2 fixture; it is not a general DNS equivalence claim.

This reviewer downloaded the two retained results read-only and wrote
[a new standalone decoder](check_f2.py). It imports neither the product parser
nor any earlier audit parser and does not read the driver's `canonical` or
comparison fields. [The full receipt](f2-result.json) retains every client
packet, decoded header/question/ordered section/RR, owner/class/type/TTL/RDATA,
wire owner and RDATA offsets, warm replies, health replies and upstream traffic.
Semantic comparison normalizes only name compression; labels remain raw bytes,
case remains significant, and duplicate records retain their order. The stronger
fix/C byte comparison includes compression and wire RDLENGTHs as well.

The inputs are the unchanged FIX5 `cname-profiles.json` / `terminal_extended.py`
fixture, with no target host anchor, original final pointer **`c062`**, and three
uncompressed `other.example` records. The warm query is `alias.example A`,
returning `alias → target` plus `target A 192.0.2.77`, both TTL 300; the final query
is `alias.example ANY`. The checker verifies that actual configuration, both
questions, and all expected CNAME owners and targets.

| Role | ELF SHA-256 | Final length | Final upstream requests |
| --- | --- | ---: | ---: |
| Exact-image C | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` | 154 | 0 |
| main | `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863` | 223 | 1 |
| before: retained FIX5 release, product inputs of `2113d540` | `7a56d4302dc8fbd3df8d5c441d2b910c0cf2222d9d3b105ef599ad4ca2150f7c` | 196 | 0 |
| fix: current `3335a978` fresh release | `a52bfb0b7725fc8d8179645b13133fbd12e2c73e1419d5e9c135115887eadd66` | 154 | 0 |

Main has the same full client semantics as C in all eight cases, including exact
TTL sequence `[300,60,60,60,60]`. Its existing extra final forwarding remains
separate from the repaired malformed reply. The main upstream query/reply IDs
match; after normalizing only that random ID, its fixture response has precisely
the same full semantics as C. Each side performs exactly one warm upstream
transaction. Those upstream requests and responses have identical semantics
across all four sides after ID normalization, with the same transport as the
client case.

The alias CNAME owner starts at byte 31 and contains `c00c`. Current fix and C
then share this exact layout for all four configured target CNAMEs:

| Raw RR | Owner offset | Owner bytes | RDATA offset | RDATA |
| --- | ---: | --- | ---: | --- |
| 1 | 59 | `c02b` | 71 | uncompressed `other.example` |
| 2 | 86 | `c02b` | **98** | uncompressed `other.example` |
| 3 | 113 | `c02b` | 125 | uncompressed `other.example` |
| 4 | 140 | `c02b` | 152 | original **`c062`** |

Thus byte 98 begins `05 6f 74 68 65 72 07 …`, a complete `other.example`.
Before still emits full `target.example` owners for raw RRs 2–4, at offsets
86/127/168. Its RDATA offsets are 71/112/153/194; byte 98 is `70`, ASCII `p`
inside an owner. The independent decoder rejects the fifth answer at that exact
byte in all eight before responses. Replacing only that invalid RDATA semantic
with C's makes every remaining before field equal to C, confirming the original
failure rather than a different timeout or unrelated bad reply.

All **32** daemon runs remain alive after the final query and exit zero. Every
warm client reply and every health reply is byte-identical to its C counterpart.
The unchanged driver closes the warmed TCP connection before sending its UDP
`ready.test` health query; these results therefore include post-close health,
without the earlier debug/TCP health-probe ordering problem.

The matching C source was also read independently and SHA-verified as
`231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222`.
`rfc1035.c:1795–1797` passes `&nameoffset` for a traversed CNAME, whereas
`:1862–1872` passes `NULL` for every configured raw RR, including TYPE5.
The raw `"t"` branch at `:1610–1617` copies the bytes unchanged. The new Rust
code translates the terminal packet's owner pointers through copied spans;
it no longer interprets raw TYPE5 RDATA as a request to advance the owner cursor.
The observed `c02b` owners and unchanged `c062` agree with that C distinction.

Input provenance:

- `/home/ubuntu/dnsmasq-audit-fix6-20261014/private/f2-01/result.json`:
  SHA-256 `ae81f228d027bc4343eabf99201bc70454195e7af4d1c513ab180ac4a66bad63`.
- `/home/ubuntu/dnsmasq-audit-fix6-20261014/private/f2-02/result.json`:
  SHA-256 `e5fe26fd38b94001a485ca5538f046de719ab0ed13c574ec70f3de723d63d4b0`.

To repeat after downloading the inputs under the same local filenames:

```sh
python3 docs/dnsmasq/audits/20261014/fix6/independent/check_f2.py \
  --result /tmp/dnsmasq-fix6-independent/f2-01.json \
  --result /tmp/dnsmasq-fix6-independent/f2-02.json \
  --c-source /tmp/dnsmasq-fix6-independent/rfc1035.c \
  --output docs/dnsmasq/audits/20261014/fix6/independent/f2-result.json
```

This reviewer did not start or interfere with daemons, change product code,
operate a physical router, push, or commit. Fresh builds, frozen-input identity
and the broader regression matrix are covered by the other FIX6 receipts.
