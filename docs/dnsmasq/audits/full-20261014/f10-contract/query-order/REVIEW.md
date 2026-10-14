# B99E counterexample: forward lookup changes cross-name PTR order

The initial F10 candidate `b99eae7e54c1d3922368513714da2eaef09cef58`, ELF
`edf0f62ca08946cd35aa5b48255575546baaec53d3273723fb25550eb14e5fac`, still differs
from exact-image C in one process's A/PTR sequence. Its owner set repair does
not reproduce the global name-hash chain. This is a retained failing control,
not a claim that the candidate satisfies the full contract.

The driver first loads a fixed, bounded set of 200 `yNNN.test` names sharing
192.0.2.1. Per-name address-hash collisions give each an actual reverse flag.
`x.test` has two different reverse addresses separated by other names in the
name hash. `cache-size=0` keeps this fixture below the 64-bucket growth threshold.
It observes complete TCP PTR replies before and after one parent UDP A query.
The C run selects the first name that `x.test` actually crosses, then HUP reloads
this five-line subset **in the same process**, preserving its observed seed:

```text
192.0.2.1 x.test
10.0.63.213 a.test
192.0.4.2 a.test
192.0.2.1 y085.test
192.0.4.1 x.test
```

| Same-process sequence | Exact-image C | B99E Rust |
| --- | --- | --- |
| TCP PTR 192.0.2.1 before A | y085.test, x.test | y085.test, x.test |
| Parent UDP A x.test | 192.0.4.1, 192.0.2.1 | 192.0.2.1, 192.0.4.1 |
| TCP PTR 192.0.2.1 after A | x.test, y085.test | y085.test, x.test |

PTR owner sets and TTLs match, all replies have TC=0 and RCODE=0, and UDP/TCP
health remains normal. Both the 201-owner discovery reply and the two-owner
minimal reply are complete TCP responses. C changes its PTR order within one
process while Rust does not. Cross-process ASLR variation cannot explain away
this transition. The selected y name is tied to this run; another C start can
select a different name from the fixed pool, which the raw receipt records.

Cause: `cache_hash` may insert a new same-name record ahead of intervening
different-name records. `cache_find_by_name` then relocates later same-flag
records along that actual bucket chain. A per-name vector plus separately
sorted reverse owners loses both initial A order and the subsequent cross-name
PTR mutation. A bounded page-shared global link representation is required;
the temporary bulk address chain remains a separate loader lifetime.

Evidence is in [summary.json](summary.json), including exact ELF identities,
all three minimal raw replies per side and SHA identities of 36 backup files.
The tool is `tools/dnsmasq/f10_ptr_query_order.py`. Oracle raw files are under
`/dev/shm/full-f10-product-20261014/private/ptr-collision-b99e-minimal`; earlier
fixed exploratory controls remain in `ptr-order-b99e`, `ptr-collision-b99e`,
`-v2`, `-v3`, `-v4`. The first 2,000-name control and the first three collision
layouts showed no transition; none was counted as proof of general equivalence.
The v4 layout first exposed the transition, then the final driver reduced it
without restarting C. No product instrumentation or C rebuild was used.

All six raw outputs are archived outside Git in this worktree's ignored
`private/f10-ptr-order-b99e/evidence.tar.gz`, extracted under `oracle/`, with
`backup-manifest.json`. Generated rootfs stages are excluded. No router or main
branch was touched. Rerun on Oracle with a fresh private output path:

```sh
tools=/home/ubuntu/full-audit-20261014/private/source/tools/dnsmasq
root=/dev/shm/full-f10-product-20261014
sudo -n sh "$tools/run_isolated.sh" env PYTHONPATH="$tools" \
  python3 "$root/f10_ptr_query_order.py" \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --rust "$root/private/release-b99e/dnsmasq-rs" \
  --output "$root/private/ptr-collision-replay" --collision
```
