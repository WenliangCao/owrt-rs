# Independent raw CNAME cursor review

This reviewer read the product diff and matching C source independently, then
decoded the primary fresh four-way run from its raw packet hex with a new
standalone parser. No daemon was started by this reviewer, and no product code
was changed. The test controller's `canonical` fields and its TTL normalization
were not used by the independent checker.

**All four normal/debug × UDP/TCP cases confirm a new malformed client answer.**
Exact C, main and the pre-fix binary have identical complete DNS semantics,
including all header fields, questions, ordered sections, owner labels, types,
classes, RDATA names and TTLs. Only name compression is normalized; duplicate
records remain separate, and label case is retained. TTLs are exactly
`300, 60, 60, 60, 60`. HEAD preserves the first four answers but its fifth CNAME
contains an invalid name. All 16 daemon runs remained alive and exited zero.

The input is the primary `cname-dynamic-01/result.json` identified by path and
SHA-256 in [the independent result](independent-cname-result.json). It has no
host anchor. After warming `alias.example A`, query `alias.example ANY` with:

```text
dns-rr=target.example,5,c062
dns-rr=target.example,5,056f74686572076578616d706c6500
dns-rr=target.example,5,056f74686572076578616d706c6500
dns-rr=target.example,5,056f74686572076578616d706c6500
```

The three uncompressed records name `other.example`. C writes raw records in
reverse configuration order, so the pointer appears last. In C's 154-byte
packet, offset `98` (`0x62`) is a complete `other.example` starting with label
length `0x05`. HEAD's 196-byte packet also emits `c062` unchanged, but offset
98 is ASCII `p` (`0x70`) inside an earlier uncompressed `target.example` owner.
It is neither a valid label length nor a compression-pointer marker. The
independent parser rejects answer index 4 at exactly that byte in all cases.

The pre-fix binary emits a 209-byte valid response: its scratch packet also
contains `other.example` at offset 98, and the old canonicalization expands
the pointer before writing. Main forwards once and receives the same valid
client semantics in a 223-byte packet. C, pre-fix and HEAD make no upstream
request for the final query. Main's existing extra forwarding is distinct
from HEAD's newly malformed answer.

The source mechanism is confirmed against `rfc1035.c` SHA-256
`231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222`:

- Lines 1795–1797 pass `&nameoffset` when writing a traversed cached CNAME.
- Lines 1862–1872 pass `NULL` for all configured raw records, including TYPE5.
- Lines 1610–1617 copy the raw `"t"` bytes without changing the cursor.

In Rust, `cache_engine.rs:1808–1814` still advances its owner cursor for an
uncompressed raw TYPE5. Subsequent same-owner records consequently use full
owner names at lines 1781–1796. This layout discrepancy already existed;
the new opaque copy at line 1780 now preserves an absolute pointer into the
wrong final layout. The old underlying cursor defect therefore does not
exempt this newly demonstrated response regression.

The static review found ordinary local PTR/CNAME/MX/SRV/NAPTR names are written
uncompressed, cached SOA RDATA is already canonical, and Additional addresses
contain no embedded names. Removing canonicalization is appropriate for those
representations. The demonstrated problem is the interaction of raw output
with the retained cursor behavior, not a general failure of ordinary local
records. The repeated raw CNAME fixture is an unusual explicit configuration;
the evidence does not claim that ordinary queries or the daemon process fail.

To repeat only this independent read-only verification after downloading the
retained input and matching source into a private local directory:

```sh
python3 docs/dnsmasq/audits/20261014/fix5/dns/independent-cname-check.py \
  --result /tmp/dnsmasq-fix5-static-review/cname-dynamic-result.json \
  --c-source /tmp/dnsmasq-fix5-static-review/rfc1035.c \
  --output docs/dnsmasq/audits/20261014/fix5/dns/independent-cname-result.json
```
