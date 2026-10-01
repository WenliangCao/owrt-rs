# Exact C partial cache-pipe EOF baseline

The unchanged exact `cache.c::cache_recv_insert`, linked with audited native
objects including the real `util.o::read_write`, passes **171/171 checks across
nine cases and 27 state observations**. Negative calibration wrongly expects
a completed record prefix to increment parent insertions before its end marker:
**170 pass / 1 fail**, exit 1. No Rust expectations or implementation generate
these results.

The driver includes unchanged `cache.c`, seeds a cache at time 100 and receives
at time 103. All records expire at 220. A real forked writer writes a bounded
prefix of a valid native insertion transaction to an anonymous pipe and closes
it. The parent invokes actual `cache_recv_insert` once, observes cache state,
then calls actual `cache_start_insert` and observes again. There is no mocked
read helper or rewritten import algorithm.

| Case | Bytes written / complete wire | Actual behavior after receive |
| --- | ---: | --- |
| No operation byte, prior pending record | 0 / 55 | Return 0; prior pending record remains; owner misses, alias CNAME remains visible |
| INSERT operation only, prior pending record | 1 / 55 | Return 0; operation starts insertion and clears prior pending; owner and alias miss |
| Partial first record length | 8 / 55 | Return 0; no completed record effects; original owner and alias remain |
| Partial first record name | 12 / 55 | Same unchanged original cache |
| Partial first record address union | 46 / 55 | Same unchanged original cache |
| Complete replacement A, EOF before next record | 47 / 102 | Return 0; old owner removed, replacement pending/unhashed, alias CNAME still visible; insertion count unchanged |
| Complete new A under pressure, partial second A | 93 / 102 | Return 0; owner evicted, alias invalidated, filler retained; `live_freed` increases once and new record stays pending |
| Complete replacement A, partial end sentinel | 54 / 55 | Same uncommitted replacement prefix; no commit |
| Complete transaction control | 55 / 55 | Return 1; replacement and alias are visible, insertion count increases once, no pending record |

The pressure case has three cache slots. Observation lookups run in the fixed
order owner, alias CNAME, filler, extra, second. These lookups update LRU order:
the filler becomes recent, so importing the new extra address evicts the owner.
Its subsequent alias lookup removes the now-invalid CNAME. The gate preserves
this actual victim and lookup order. Other cases use eight slots.

For incomplete transactions with a completed record, the next
`cache_start_insert` frees the pending prefix without restoring previously
removed or evicted entries. The replacement case then loses the old alias too.
For EOF before an operation byte, prior pending state survives until this next
start; EOF after an INSERT operation clears it immediately. `new_chain` counts
are read only as diagnostics; ordinary lookups and the actual insertion/live
eviction counters independently record the consequences.

The native ABI is little endian with `ssize_t=8`, `time_t=8`, unsigned flags=4
and `union all_addr=16` bytes. INSERT operation is 1; address flags are exactly
`F_FORWARD | F_IPV4` (136). Every union is completely zeroed before filling the
IPv4 address. Names and TTLs are valid and bounded; there are no arbitrary
lengths, invalid flags, transferred pointers or SOA/block payload paths. Every
case saves the full valid transaction, precise field offsets and the cut offset.

`plan.json` preserves the exact seed order, optional preexisting pending
insertion, intended full record list, completed-record count, semantic cut
stage and lookup order. Native framing uses an operation and a signed end
sentinel. The private typed format uses a length/count and has no sentinel:
its comparison must map semantic boundaries rather than native byte offsets.
The partial-sentinel case remains explicitly C-only, not a typed pass or an
unreported omission. The record-prefix cases include a legitimate untransmitted
tail record so each maps to a prefix of a valid complete typed transaction.

Tool commit: `c793bd0`. Driver SHA-256:
`94588a0e49a987430f934ffcf3643bcbcc4399623a77517dee6aba6bf1f83cc7`.
The source identity, config/header/source hashes, every linked object, native
oracle ELF, library hashes and compiler output are retained in the manifest.
Exact reference ELF SHA is
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`;
this source-linked primitive driver is a separate executable and does not claim
to be the stock reference daemon.

Raw evidence is retained in the independent partial-EOF gate worktree under
ignored `private/partial-eof-evidence/c-baseline-evidence.tar.gz` and on oracle
under `/home/ubuntu/tcp-partial-eof-gate-20261001/private/`. The JSON records
all calibrated states and artifact hashes. `baseline-01` preserves 166 pass /
5 fail: the initial pressure calibration incorrectly expected filler eviction
without accounting for its own observation lookups. `baseline-02` freezes the
actual victim and adds the valid intended second record to the record-prefix
case; no C implementation changed. The negative calibration is also preserved.

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/cache_partial_eof_oracle.py \
  --reference-build /home/ubuntu/dnsmasq-rewrite-20260929/c-native-01 \
  --source-identity /home/ubuntu/dnsmasq-rewrite-20260929/reference/identity.json \
  --out private/cache-partial-eof-c
```

All compilation and primitive executions use the isolation wrapper. This is
bounded native functionality evidence, with no target-musl, performance, OOM,
general malformed-input or production acceptance. No router was accessed.
