# Exact C stale TCP baseline

The real native reference, running in `-k` mode with private ubusd, passes
**164/164 checks across 41 observations**. A negative calibration changes only
the expected first stale TTL to one: **163 pass / 1 fail**, exit 1. Actual C
output is unchanged. These are C functionality checks, not Rust, target or
performance acceptance.

`tools/dnsmasq/tcp_stale_oracle.py` seeds the parent over UDP with a one-second
A record, accepts an old TCP connection while fresh, then waits past expiry.
The old connection keeps its original TTL and answer because C fixes the clock
at accept. A later connection is tested against a controlled TCP upstream whose
reply cannot be sent until the fixture explicitly releases it.

| Configuration | Observations | Later connection |
| --- | ---: | --- |
| `use-stale-cache=30`, successful refresh | 8 | Old value, TTL 0, downstream EOF, one refresh |
| `use-stale-cache=30`, upstream refresh EOF | 7 | Same stale response and EOF; no parent insertion |
| `use-stale-cache=0` | 8 | Same stale response and successful refresh |
| `use-stale-cache=1`, after retention cutoff | 10 | No response before release; fresh answer afterward; connection reusable |
| `use-stale-cache=30`, ordinary empty OPT | 8 | Stale response includes EDE 3; same close and refresh order |

Every stale response has flags `0x8180`, one A answer with TTL 0 and the old
address, no authority records, and no additional records unless the query has
an OPT. In the empty-OPT case, the response OPT has class 1232, TTL/flags zero
and RDATA `000f00020003` (EDE option 15, length 2, code 3). The synthetic seed
server supplies no OPT, so its forwarded seed reply also has no OPT; local
cached replies add the queried OPT. DO/CD combinations are outside this gate.

The fixture records downstream EOF **before upstream release**, then verifies
that the upstream reply or EOF occurs after release. While held, UBus reports
two active TCP slots: the old connection and the worker performing the stale
refresh. Both child PIDs and their distinct parent-read/child-write cache pipes
are present. The stale worker's downstream socket is already closed. After
refresh, its slot is released; closing the old connection reduces the gauge to
zero and leaves no child PIDs. This observes the held and completed states;
the independent slot-order gate remains responsible for deliberately reversing
worker-exit versus pipe-EOF order.

All profiles make exactly one UDP seed request and one TCP upstream request.
Successful refresh changes parent `dns_cache_inserted` from 1 to 2 and a later
UDP hit returns the new value without upstream activity. Failed refresh leaves
insertions at 1. Before that final parent UDP lookup, actual parent counters
remain `dns_queries_forwarded=1`, `dns_local_answered=0` and
`dns_stale_answered=0`; TCP child-local hit/stale counts are not merged into
parent counters. The JSON report retains every observed 30-field metric map.

The source contract is `forward.c::tcp_request`: only an emitted stale answer
closes downstream and enters one refresh iteration. A stale flag with no answer
does not establish delivery; the frozen-clock cases in
[DNS_STALE_METADATA_ORACLE.md](DNS_STALE_METADATA_ORACLE.md) remain the authority
for that distinction. This service gate uses simple A records.

Tool commit: `8ef0dd0`. Exact C ELF SHA-256:
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
The checked-in JSON records tool, result and trace identities. Raw configurations,
packets, UBus replies and logs stay under ignored
`private/stale-tcp-evidence/` in the independent stale-gate worktree, and on
oracle in `/home/ubuntu/tcp-stale-gate-20261001/private/`.

`baseline-01` preserves an initial calibration-code error (`counts` was absent
from the reused packet decoder); `baseline-02` preserves 153 pass / 6 fail from
incorrect calibration assumptions about inherited event/log pipes and the
seed server's omitted OPT. Neither failure modified the C reference. The fixed
pipe check identifies newly created parent read ends and child write ends,
excluding preexisting pipes. `baseline-03` is the qualified positive run;
`calibration-negative` is the qualified deliberately failing run.

Reproduce on oracle from the tool checkout:

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/tcp_stale_oracle.py \
  --reference-build /home/ubuntu/dnsmasq-rewrite-20260929/c-native-01 \
  --out private/stale-tcp-c
```

Use `--inject-error` and a fresh directory for negative calibration. All listener
and UBus executions use the loopback-only network namespace and private `/run`.
No physical router was accessed.
