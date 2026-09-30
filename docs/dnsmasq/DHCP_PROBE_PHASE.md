# DHCPv4 ICMP conflict probe

This phase implements the allocation dependency, not complete DHCP service
equivalence or router acceptance. It uses the matching OpenWrt dnsmasq 2.93
source; no physical router was accessed.

| Exact C source | Rust boundary | Evidence |
|---|---|---|
| `dhcp.c:769-826`, `config.h:42-43` | `PingCache`: 30-second cache, strict `age > 30` expiry, original offer hash retained on a hit, last expired list entry reused; six live entries trigger high-load bypass; no-ping/loopback return an uncached dummy result | Extracted `do_icmp_ping` compares result, ICMP invocation count and complete cache list after each input |
| `dnsmasq.c:2350-2430`, `network.c:884-893`, `util.c:718-749` | Linux `IcmpSocket`, 28-byte echo request, native-endian random ID, zero sequence, exact checksum convention, nonblocking raw socket and retry limit | All 65,536 IDs compared byte-for-byte; isolated Linux raw socket probes |
| `dnsmasq.c:2431-2505` | Fixed 48-byte receive, matching source address/type/sequence/ID; longer datagrams truncate as C recvfrom does | 1,000 seeded malformed/short/wrong-source/wrong-ID cases; no extra acceptance normalization |
| `dnsmasq.c:2440-2467` | Whole-second wall time with inclusive `now-start <= 3`, and at most twelve poll timeouts; each wait is 250 ms, readiness does not consume a timeout | 35 clock/backward-time/boundary cases against C; real unused-address wait |

The source identities for all five input files are pinned in
`tools/dnsmasq/dhcp_icmp_diff.py`. The C helper extracts `do_icmp_ping`,
`make_icmp_sock`, `icmp_ping`, `delay_dhcp`, `fix_fd`, `retry_send` and
`dnsmasq_time`. Its DNS/log polling hooks are inert because these dependency
tests run with DNS disabled; they are not a daemon event-loop oracle.
Generated C, raw packets, binaries and outputs remain under ignored private
storage. ASan and UBSan are enabled for the reference.

`IcmpProbe::check(now, address, hash, loopback)` returns
`io::Result<ProbeResult>`; `check_with_stop` additionally checks a caller stop
flag between sends and each 250 ms wait. The probe owns one entropy file;
each actual ping owns a temporary raw socket. `OwnedFd` closes the socket on
success, timeout, error and cancellation. `PingCache` uses six contiguous
entries: from an empty C list, a seventh allocation is impossible because a
six-live-entry list bypasses the ping and an expired entry is always reused.
Both implementations therefore have a bounded linear scan; the Rust layout
avoids per-entry heap allocation, without making an unmeasured speed claim.

The wait is deliberately not a hard monotonic three-second deadline. A quiet
probe completes after twelve quarter-second timeouts; other raw-socket
readiness can extend the wait through C's inclusive whole-second wall-clock
boundary. Clock rollback preserves C's timeout-count fallback. Cancellation
is an explicit Rust lifecycle addition, not a redefinition of a negative
probe result.

## Failure policy and allocation handoff

Two C behaviors are intentionally **not equivalent**: raw-socket creation
failure and a terminal send failure return/lead to zero from `icmp_ping`,
which `do_icmp_ping` caches as an available address. Rust returns the I/O
error and adds no cache entry. Permission or resource failure is not evidence
that an address is free. This stricter policy follows the task's conflict
safety gate; it must remain visible in service compatibility reports.

The state adapter's closure retains the I/O error and returns
`ProbeResult::Failed`. The allocator immediately stops scanning without
changing conflict epochs. The DISCOVER requested-address branch also stops,
instead of falling through to another candidate. `StateProvider` still
returns its no-reply `Outcome`, including leases/names pruned before the
probe. The caller reports the retained error after handing off that outcome;
returning an early provider error would lose those cleanup side effects.
A regression covers failure on option 50 with an expired named lease.

## Recorded checks

The final host run is
`private/dnsmasq-rewrite/dhcp-icmp-20261001/host-04/`: **67,647/67,647**
cache/wire/time comparisons, no mismatch. Counters first calibrate pass,
mismatch and missing/extra output handling; hand-checked C cache results pin
the 30/31-second boundary. Raw results and C/Rust artifact identities are
retained. Earlier runs are retained separately.

The Linux harness `tools/dnsmasq/dhcp_icmp_linux.py` requires a fresh network
namespace with only loopback, creates one private dummy interface and never
touches a physical interface. Its checks cover occupied loopback/dummy
addresses, an unused address and cache hit, cancellation followed by an
uncached retry, 32 further occupied-address probes, permission removal,
missing route, descriptor stability and process exit. C/Rust permission and
send-error observations are recorded as the policy difference above, not
counted as equal answers.

The latest Linux run is indexed under
`private/dnsmasq-rewrite/dhcp-icmp-20261001/linux-03/`, with **92/92** checks;
the preceding `linux-02/` window also passed **92/92**. In that preceding window, completed
probe FD counts stayed at **C 3 / Rust 4**, with sampled peaks **4 / 5**.
Rust's extra retained FD is the entropy source; sampling was every 20 ms and
is not an exact peak bound. The unused-address waits were about three seconds
and the stop response about 250 ms. These timings verify timeout/cancellation
behavior, not throughput or latency superiority. Both processes exited with
zero status and their `/proc` resource trees disappeared.

The initial Linux preflight rejected inherited sysfs mount contents before
creating the dummy interface or issuing ICMP. The corrected harness uses
`ip -j link`, whose rtnetlink view belongs to the current network namespace;
the rejected attempt remains in `linux-preflight-01.json`.

The affected DHCP host regression passed 87 tests, and the aarch64-musl
library clippy gate passed. Full DHCP listener/leasefile/DNS/script behavior,
ARP reply injection, procd/ujail capability setup, target-device timings and
full-service pressure/reconnect tests remain outside this phase.
