# Bound IPv4 DNS receive mechanism screen

This screen compares exact E source `4f869c88…` with the separate static-bound
pktinfo candidate `5a03fffe…`. It calls their actual native `DnsSocket` library
APIs, not a hand-written substitute. It does not parse DNS, run SinglePoll or
establish an SDK/device performance result. The small tooling changes reuse
`loop_source_socket_screen.py/.rs`; no PMU framework or product API mock was
introduced.

`bound-dns-receive-counts.json` retains all 56 fixed attempts: eight allocation
runs, eight syscall traces and 40 whole-process PMU count runs. All passed.
Each source was checked against a local manifest generated from its exact
Git commit. Every copied source file matched that manifest; private harness
inputs and final executables were hashed before/after measurement. Builds
used Rust 1.98.1, release mode, one job and the shared build lock. The counting
allocator was present only in separate allocation artifacts, never the PMU
artifacts.

Two modes use the same loopback snapshot and IPv4 address. `receive-bound4`
uses E's existing bind API and the candidate's real `bind_config` policy.
`receive-generic4` calls the original bind API in both sources as a control.
Both send 32-byte payloads into a 65,535-byte receive buffer, call the real
receive/send APIs, and verify reply bytes, peer/source address, destination,
interface-policy result and final fd count. Bursts contain one or sixteen
packets. The sixteen-packet budget stays unchanged: a one-packet burst ends
with one EAGAIN receive; a full sixteen-packet burst does not perform an
extra receive after exhausting the budget.

All eight allocation runs observed zero allocations/reallocations both during
socket bind and in the measured loop, with fd counts returning from four to
four. The syscall traces independently confirm identical call counts. Only
the configured bound candidate changes successful recvmsg control length from
32 bytes with `IP_PKTINFO` to zero; the generic control stays unchanged. The
one-packet path still has one successful and one failed recvmsg per packet.

The fixed PMU matrix used 10,000 iterations and five pairs per mode/burst,
alternating side order by repeat. All four grouped events reported 100%
running in every process. Counts include both sender and receiver, snapshot,
setup, teardown, checking and output. Nothing is subtracted. Median counts
below are whole-process counts divided by delivered packets:

| Mode / burst | E user instructions | Candidate user instructions | E kernel instructions | Candidate kernel instructions |
| --- | ---: | ---: | ---: | ---: |
| Configured bound / 1 | 570.93 | 552.93 | 26,706.25 | 26,393.97 |
| Configured bound / 16 | 402.93 | 389.81 | 24,824.28 | 24,501.74 |
| Original generic / 1 | 570.92 | 573.92 | 26,714.72 | 26,701.86 |
| Original generic / 16 | 402.93 | 410.81 | 24,823.45 | 24,818.97 |

The bound mode saves about 18/13 user instructions and 312/323 kernel
instructions per packet for bursts one/sixteen. Its paired kernel-instruction
changes are consistently -1.18%/-1.30%. The generic control's kernel change
crosses zero and is near zero; its additional branch increases user
instructions by about 3/7.9 per packet. That control regression is retained.
Cycle results are also recorded, but are not a plain-timing acceptance claim.

This establishes a small actual-API mechanism saving, not the cause of the
whole C/E hit-path gap. In particular, the unchanged terminal EAGAIN remains,
and a few hundred kernel instructions cannot be assigned the entire device
CPU difference or a previously measured per-query elapsed difference.
Full-owner, SDK, cross-scene resource and correctness gates remain separate.

One pre-measurement compilation failure is preserved: an external example
initially used Rust struct-update syntax on a config type containing a private
field. Harness-only commit `799f6ec4` changed this to public `Default` followed
by assignment. The fixed run uses fresh `r2` directories; no measurement was
replaced. The 69,645-byte derived measurement summary and 2,698-byte source
receipt were transferred; all raw sources, binaries, traces and counters
remain private on Oracle. No router was accessed.
