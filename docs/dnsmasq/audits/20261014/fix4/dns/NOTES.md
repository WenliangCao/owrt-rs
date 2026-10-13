# Independent DNS terminal audit

This sub-audit finds a **P2 merge blocker**: the branch's new dynamic-CNAME
terminal path can drop a request or change a name-bearing raw RR when C and
main both return the same answer. The helper's underlying error is old, but
the newly affected dynamic-target cases are not exempted by that fact.

The fresh 80-case run compares the exact image C binary, main release, and the
branch's final SDK payload in the same isolated image environment. It uses
matching transports, including a warmed persistent TCP connection, with no
UDP-for-TCP oracle substitution. Both normal (`-k`) and debug (`-d`) modes are
included. [Derived results](terminal-summary.json) retain representative full
synthetic wire frames and all case outcomes; the full private result is hashed
there. No router is involved and no product code is changed.

An additional 28 raw-record controls distinguish the old helper defect from
the branch's newly affected dynamic path. A fresh 72-case N1 recheck verifies
the prior filterwin2k / known-name repair. These are fresh tests, separate from
the historical suites retained elsewhere in the repository.

Binary SHA-256:

- C: `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`
- main: `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863`
- fix SDK: `55ea363f626f3e14279f280b1dba708a1d751877ab22a3503d312985c9efd6ca`

The source reference is the retained dnsmasq 2.93 tree on oracle at
`/home/ubuntu/dnsmasq-rewrite-20260929/reference/dnsmasq-2.93`; its reference
identity records OpenWrt recipe revision
`f0a60eee2fe051741c643ea6118718aae1ef17fb` and upstream archive SHA-256
`0c00d4e5c97c8306e5fb932b348b34269c9c29a0e7df0e8e82958b407092bc19`.

## DNS-1: new dynamic raw terminal can change or drop answers (P2; blocks merge)

Warm `alias.example A` using an upstream reply containing CNAME
`alias.example -> target.example` and A `target.example = 192.0.2.77`. Configure
`dns-rr=target.example,2,c02b`, then query `alias.example NS`. The upstream NS
fixture returns a genuine authoritative CNAME + NS response, with the NS
target `target.example`, CNAME TTL 300 and NS TTL 60. Each case starts a fresh
daemon so this is its first NS request.

**All four combinations of UDP/TCP and `-k`/`-d`: C and main return identical
DNS semantics, including every TTL; fix returns UDP timeout or TCP EOF.**
The C reply's offset `0x2b` is the start of the already-written CNAME target
`06 746172676574 07 6578616d706c65 00`. Its NS RDATA `c02b` is therefore a valid
pointer to `target.example`, which also has the warm A record. The complete
C/main replies and upstream traffic are retained in
[raw-pointer-controls.json](raw-pointer-controls.json), group
`dns-raw-c02b-dynamic-01`. Compression layout is the only normalization in
the supplemental strict comparison; flags, sections, owners, classes, RR
order, RDATA and TTLs all remain compared.

The alternative `dns-rr=target.example,2,c00c` fixture makes the authoritative
upstream NS target `alias.example`. C and main again agree in all four cases,
while fix changes the returned NS target to `target.example`. That control
is C-accepted and wire-decodable; an NS target which is itself an alias is an
unusual deployment choice, so the primary availability finding above uses
`c02b` and an NS target with its own A record.

The new call at `cache_engine.rs:675-686` (introduced by `74d210d29`) processes
dynamic CNAME terminals through `append_local_terminal`. That helper builds
a temporary question for the terminal at `:1736-1737`, then unconditionally
decodes raw RDATA using `canonical_rdata()` at `:1776`. In the temporary
`target.example` packet, offset 43 is instead the low RDLENGTH byte. Decoding
`c02b` there fails and propagates out of the cached-answer path. Offset 12
instead resolves the temporary question, which explains the `c00c` wrong
target. C's `rfc1035.c:1862-1872` raw loop copies stored data using the `"t"`
format without reinterpretation.

The temporary-packet / canonicalization code is from `e77d966d0`, already
in main (main `cache_engine.rs:1681-1682,1709`), and main already calls it for
`CnameTarget::Local`. Adding `host-record=target.example,192.0.2.77` forces that
old path: **20/20 anchor controls have main == fix**, including the same
wrong-target and dropped-request symptoms. That is evidence of the old root
cause, not evidence that the newly affected dynamic path is harmless. Main's
extra upstream request in the dynamic controls is an existing local-terminal
lookup defect; the branch's wrong client response / lack of a response is
separately new. Both should be recorded without conflating their attribution.

The failure is scoped to configured name-bearing raw data with compression
pointers plus the warm dynamic CNAME path. No general daemon crash was seen:
all 84 supplemental processes remained alive and exited normally. This is
conditional request-level availability and answer correctness, not a claim
that ordinary DNS resolution is universally broken.

## DNS-2: TCP target routing differs from C; main already has it (P2)

Warm `alias.example A` with an upstream CNAME to `target.example` plus an A
record. Configure `local=/target.example/`, then query the same TCP connection
for SOA/PTR/MX/TXT/AAAA/SRV/ANY/CAA. Alternatively configure
`address=/target.example/192.0.2.4` and query ANY. All nine combinations were
tested in both debug modes: **18/18 TCP cases differ from C, and main equals
fix in every case**. The corresponding 18 UDP cases agree across all three.

For example, `target-local-debug0-tcp-16` returns empty NOERROR from C without
another upstream request. Both Rust versions forward and return the stub's
CNAME + A response, with one extra upstream request. This affects local-only
target policy and can send an otherwise locally answered query upstream.

C's `forward.c:2581` calls `answer_request`, which traverses the cached CNAME
and mutates `daemon->namebuff`; after a miss, `forward.c:2598` uses that terminal
name for `lookup_domain`. The UDP path restores the original question at
`forward.c:2021` before forwarding. Rust's transport-shared selection does not
reproduce that TCP distinction. This is a real C mismatch, not a permissible
transport normalization, but it is not introduced by this branch.

## Initial raw boundary observations and positive controls

Use the same warm CNAME, plus `dns-rr=target.example,2,c00c`, and query alias NS.
C emits the opaque `c00c` unchanged: it points to the original question,
`alias.example`. The branch decodes it in a temporary packet whose question is
`target.example`, then emits the wrong NS target. MX with `000ac00c` and raw
CNAME in an ANY answer exhibit the same problem, under both transports and
debug modes. The supplied `c00c` pointers form valid DNS names in C's output.

The malformed-pointer control `dns-rr=target.example,2,c0ff` is also accepted
by C and copied verbatim. The branch instead produces UDP timeout / TCP EOF;
the daemon remains alive. This control demonstrates unintended validation of
opaque RDATA, not a requirement to treat C's malformed answer as usable DNS.

In all 28 observed raw-pointer boundary cases, main is already incompatible
with C: it forwards and ignores the configured dynamic terminal. The branch
changes the failure mode but has not completed that compatibility repair.
Those initial controls used the generic A-reply stub for every query and did
not alone establish loss of a C-compatible client response. The supplemental
real NS upstream controls above remove that limitation and establish the new
wrong-answer / availability effect. The initial data is retained unchanged.

As positive controls, a valid uncompressed NS target and an unknown opaque RR
type both match C in all **16 cases** on the branch; all 16 differed on main.
This confirms the terminal repair is effective for ordinary data.

The fresh [N1 summary](n1-summary.json) covers three repeats, both daemon modes,
filterwin2k on/off, cold/UDP-warm/same-TCP-warm, and SOA/SRV queries. Fix equals
C **72/72 byte-for-byte response dictionaries**, including wire TTL; main
equals C in 24/72. Warm replies match byte-for-byte in 48/48, reply and warm
upstream counts match 72/72 and 48/48 respectively. All 216 processes remained
alive, exited with status 0, and answered the health query after the TCP
connection closed. The prior N1 repair is therefore confirmed on the final
SDK payload; the new blocker is an additional boundary failure.

## Results and limits

Of 80 case comparisons, main matches C in 18, fix matches C in 34, and main
equals fix in 36. All 240 processes remained alive and exited with status 0.
Health is intentionally queried before closing the TCP connection. Exact C in
`-d` blocks in that connection, so its 20 debug-TCP UDP health probes time out;
the other 220 health probes reply. This expected C control behavior is retained
in evidence, not reported as a branch failure.

The initial 80-case comparator normalizes DNS name compression and ordinary
RR TTL; original frames are retained. The supplemental dynamic controls and
N1 comparison additionally preserve all TTLs. No performance claim is made.
This focused matrix does not cover the full DNS feature space or prove every
remaining C mismatch is pre-existing.

The initial 80-case driver is pinned to commit `8922a914`, SHA-256
`4b1986d3655dbe49396a04213c68938a3e4416adcf6953dd9aec6d86f6491ac5`.
The supplemental driver adds explicit profile / anchor / upstream controls,
SHA-256 `211208583bc13a980798a4b1ed5e649c4033c501f96f5c418708782bfdd17df9`.
Its default profile set now has 88 cases and must not be mistaken for the
old 80-case run. The N1 derivative adds only a post-connection health probe to
the original vectors; SHA-256
`f6fef44055869433e048b505066614140c15981e51967550c2afbc5fc1e96f2a`.
Exact supplemental commands and output directories are retained in
[supplement-invocations.json](supplement-invocations.json).

For the original 80-case run, export the exact old script with
`git show 8922a914:docs/dnsmasq/audits/20261014/fix4/dns/terminal_boundaries.py`
and copy it to `/home/ubuntu/terminal_boundaries_fix4.py` on oracle. Then run,
selecting a fresh output directory:

```sh
sudo -n sh /home/ubuntu/dnsmasq-fix4-repair-20261013/source-final/tools/dnsmasq/run_isolated.sh \
  python3 /home/ubuntu/terminal_boundaries_fix4.py \
  --source /home/ubuntu/dnsmasq-fix4-repair-20261013/source-final \
  --image /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --main /home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-main/dnsmasq-rs \
  --fix /home/ubuntu/dnsmasq-fix4-repair-20261013/private/sdk-verify-final/payload/usr/sbin/dnsmasq \
  --out /home/ubuntu/dnsmasq-audit-fix4-20261014/private/dns-terminals-new
```

For the new blocker, copy the current
[terminal_boundaries.py](terminal_boundaries.py) to the same driver path and
add `--only raw-ns-target-pointer --qtype 2 --upstream-ns` to reproduce `c02b`.
For `c00c`, add `--only raw-ns-pointer --qtype 2 --upstream-ns
--upstream-ns-target query`. Adding `--host-anchor` selects the old Local path.
Use a fresh output directory for each run. None of these steps edits product
code or router state.
