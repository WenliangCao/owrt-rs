# Independent DNS terminal audit

This sub-audit found no demonstrated loss of a previously C-compatible main
case. It does identify two remaining conditional compatibility defects. The
complete audit's merge decision also depends on the other review areas.

The fresh 80-case run compares the exact image C binary, main release, and the
branch's final SDK payload in the same isolated image environment. It uses
matching transports, including a warmed persistent TCP connection, with no
UDP-for-TCP oracle substitution. Both normal (`-k`) and debug (`-d`) modes are
included. [Derived results](terminal-summary.json) retain representative full
synthetic wire frames and all case outcomes; the full private result is hashed
there. No router is involved and no product code is changed.

Binary SHA-256:

- C: `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`
- main: `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863`
- fix SDK: `55ea363f626f3e14279f280b1dba708a1d751877ab22a3503d312985c9efd6ca`

The source reference is the retained dnsmasq 2.93 tree on oracle at
`/home/ubuntu/dnsmasq-rewrite-20260929/reference/dnsmasq-2.93`; its reference
identity records OpenWrt recipe revision
`f0a60eee2fe051741c643ea6118718aae1ef17fb` and upstream archive SHA-256
`0c00d4e5c97c8306e5fb932b348b34269c9c29a0e7df0e8e82958b407092bc19`.

## DNS-1: TCP target routing differs from C; main already has it (P2)

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

## DNS-2: raw terminal name-bearing RDATA is still interpreted (P2, conditional)

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

`cache_engine.rs:1736-1737` constructs the temporary terminal question and
`:1776` unconditionally calls `canonical_rdata()`. C's
`rfc1035.c:1872-1885` raw-record loop writes its stored bytes with the `"t"`
format, without relocating or validating embedded name pointers. The same
temporary-question and canonicalization code is already present in main's
`append_local_terminal` (main lines 1682-1708), used for `CnameTarget::Local`.
The branch's new Dynamic call at current `cache_engine.rs:675` expands this
old helper's exposure.

In all 28 observed raw-pointer boundary cases, main is already incompatible
with C: it forwards and ignores the configured dynamic terminal. The branch
changes the failure mode but has not completed that compatibility repair.
These observations alone do not establish loss of a main path that previously
matched C. They must not be described as a fully repaired raw terminal path.

As positive controls, a valid uncompressed NS target and an unknown opaque RR
type both match C in all **16 cases** on the branch; all 16 differed on main.
This confirms the terminal repair is effective for ordinary data.

## Results and limits

Of 80 case comparisons, main matches C in 18, fix matches C in 34, and main
equals fix in 36. All 240 processes remained alive and exited with status 0.
Health is intentionally queried before closing the TCP connection. Exact C in
`-d` blocks in that connection, so its 20 debug-TCP UDP health probes time out;
the other 220 health probes reply. This expected C control behavior is retained
in evidence, not reported as a branch failure.

The semantic comparator normalizes DNS name compression and ordinary RR TTL
for cross-process comparisons; original frames (including TTL) are retained.
It preserves flags, counts, owner names, classes, RDATA, OPT words, record order
and trailing bytes. No performance claim is made. This focused matrix does
not cover the full DNS feature space or prove every remaining C mismatch is
pre-existing.

Reproduce on oracle, selecting a fresh output directory:

```sh
sudo -n sh /home/ubuntu/dnsmasq-fix4-repair-20261013/source-final/tools/dnsmasq/run_isolated.sh \
  python3 /home/ubuntu/terminal_boundaries_fix4.py \
  --source /home/ubuntu/dnsmasq-fix4-repair-20261013/source-final \
  --image /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --main /home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-main/dnsmasq-rs \
  --fix /home/ubuntu/dnsmasq-fix4-repair-20261013/private/sdk-verify-final/payload/usr/sbin/dnsmasq \
  --out /home/ubuntu/dnsmasq-audit-fix4-20261014/private/dns-terminals-new
```

Copy [terminal_boundaries.py](terminal_boundaries.py) to the driver path first.
