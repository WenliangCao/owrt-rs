# Exact C TCP CD and policy transaction baseline

The exact native C daemon in real `-k` mode passes **152/152 checks across 65
observations**. Negative calibration expects an extra parent insertion after an
ordinary request-CD reply and fails exactly that check: **151 pass / 1 fail**,
exit 1. This is C functionality evidence, before the candidate comparison.

| Profile | Observations | Boundary |
| --- | ---: | --- |
| IN A, request CD=1, raw reply CD=0 | 15 | Ordered extraction effects without a committed transaction |
| IN AAAA, request CD=1, raw reply CD=1 | 15 | Same boundary for IPv6 records |
| Plain IN A, request CD=0, raw reply CD=1 | 5 | TCP restores CD=0 before ordinary commit; no OPT in request |
| IN A, request CD=1, three cache slots | 18 | Child eviction without parent eviction or writeback |
| IN A, request CD=1, bogus wildcard, `no-negcache` | 12 | Independent policy transaction still commits |

The ordinary profiles warm the child with an alias CNAME and its target address,
then send a DO query for the target. DO forces forwarding past unsigned cached
IN A/AAAA data; it is not a wire representation of the forwarding `no_cache`
flag. The upstream supplies the specified raw CD bit. The outgoing ordinary
response has flags `0x8190`, preserving request CD.

Extraction removes the old target from the child's lookup table and stages a
replacement, but sends no committed cache transaction to the parent. The child
alias still answers a CNAME query through the retained target identity, while
a direct address lookup goes upstream. Its controlled SERVFAIL response neither
heals the miss nor starts another ordinary extraction: the alias CNAME remains
visible afterward. A subsequent empty CD NOERROR reply starts extraction and
clears the pending target; the alias CNAME and target address then both miss.
Parent UDP owner and alias queries continue returning the original address.

In the three-slot profile, a two-address uncommitted replacement also evicts
the child's filler entry. Child lookup misses while parent UDP still hits that
filler. Parent `dns_cache_inserted` stays at 3 and `dns_cache_live_freed` stays at
0. Parent metrics cannot stand in for the child's private eviction count.

The plain control has request CD=0 and no OPT, while its upstream response has
raw CD=1. C clears outgoing CD and commits the address; both child TCP and parent
UDP subsequently hit it. This TCP behavior differs from the separately
qualified UDP raw-CD suppression boundary.

The bogus-wildcard response under request CD=1 and `no-negcache` becomes
NXDOMAIN with flags `0x8193`. Its independent transaction increases parent
insertions from 2 to 3. The negative entry coexists with the warmed positive A,
so A and alias queries still return the original positive answer. Child TCP and
parent UDP AAAA queries, which have no warmed positive record, both return
cached NXDOMAIN without upstream activity. This proves negative writeback
without wrongly requiring it to replace an existing positive record.

All raw packets, ordered upstream observations, configurations and 30-field
UBus responses are retained privately. Tool commit `ec2c9d3`; exact C ELF SHA:
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
The JSON records tool and result/trace hashes. Evidence is under the independent
gate worktree's ignored `private/cd-policy-evidence/c-baseline-evidence.tar.gz`
and oracle `/home/ubuntu/tcp-cd-gate-20261001/private/`.

The initial `baseline-01` is preserved: its 63 observations passed 137 checks
and failed three incorrect calibration expectations that the bogus NXDOMAIN
would replace the old positive A. `baseline-02` explicitly freezes coexistence
and adds two AAAA observations; no C source or binary was changed.

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/tcp_cd_policy_oracle.py \
  --reference-build /home/ubuntu/dnsmasq-rewrite-20260929/c-native-01 \
  --out private/tcp-cd-c
```

Use `--inject-error` with a fresh output directory for negative calibration.
This bounded gate does not cover arbitrary EDNS metadata, DNSSEC validation,
all LRU victim orders, malformed frames, OOM or performance. It does not claim
image-musl execution or product acceptance. No router was accessed.
