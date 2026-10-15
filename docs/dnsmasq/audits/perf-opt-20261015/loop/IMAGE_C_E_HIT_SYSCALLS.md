# Exact-image C versus E hit-path syscall account

This is a fixed diagnostic matrix, not a timing result. The reference is the
exact image C ELF `097a9e21…`, not the earlier Rust candidate named C. The other
side is immutable E source `4f869c88…`, SDK ELF `8b8082b9…`. Full identities,
parameters, parent/child counts, trace hashes and commands are retained in
`image-c-e-hit-syscalls.json`.

The four captures ran once, in the frozen order C UDP, E UDP, C TCP, E TCP.
Each used the original loadgen `b5ac83a1…` and upstream `01c25e6a…`, unchanged
config and workload: 800 cached names, 70/30 A/AAAA, 200 requests/s, 32 UDP or
8 TCP clients. A separate 1,000-query UDP prewarm populated the parent cache.
The observer then covered 1,000 warmup and 4,000 measured completions plus a
fixed one-second grace period. Every capture had 5,000 correct responses,
zero skips, wrong responses, timeouts or transport errors. Upstream totals
were 800 requests/replies per fixture; no upstream DNS traffic appeared in
the observed hit windows. Upstream phase counters had no epoch configured
and are not used to attribute phase boundaries.

`strace -f -v -yy -ttt -s 0 -e trace=all` followed the entire owned process
tree. C TCP created 56 children across the run; all were linked to the parent
by observed clone returns, executed no new image, and exited before grace
ended. E remained one process. All four tails were complete. Each trace ends
with one detached parent ppoll entry, reported as entered but incomplete;
it is excluded from completed call counts below. No strace durations are
used as performance measurements.

## UDP: one extra failed receive and ancillary data

| Observed call or data | Image C | E |
| --- | ---: | ---: |
| Completed ppoll | 5,000 | 5,000 |
| Successful recvmsg | 5,000 | 5,000 |
| recvmsg returning EAGAIN | 0 | 5,000 |
| sendmsg | 5,000 | 5,000 |
| Total completed calls | 15,000 | 20,000 |
| Advertised successful receive iovec capacity | 1,232 B | 65,535 B |
| Actual DNS bytes per successful receive | 32 B | 32 B |
| Returned receive control bytes, total | 0 | 160,000 B |

Both sides receive and send with flags zero. E returns `IP_PKTINFO` with
`msg_controllen=32` on every successful receive; C returns no control data.
Both send `msg_controllen=0`, with 3,500 responses of 48 bytes and 1,500 of
60 bytes. Both completed waits have six input entries and an infinite
timeout. Thus E's extra receive is directly observed, while a larger iovec
capacity does **not** establish a 65 KB copy. E's failed receives expose only
`msg_namelen`, so their control-buffer contents are not inferred.

Socket creation and initial setsockopt calls occurred before attachment.
This capture cannot establish which startup options C did or did not set.
The receive control records demonstrate the resulting behavior; source and
independent sampling must determine the cost and compatibility boundary.

## TCP: fewer reads, many more waits, different ownership

| Observed completed call or operation | Image C, parent + children | E |
| --- | ---: | ---: |
| Accepted connections | 56 (`accept`) | 56 (`accept4`) |
| New child processes | 56 | 0 |
| ppoll | 202 | 5,052 |
| Downstream reads | 10,008 (`readv`) | 5,008 (`recvfrom`) |
| Downstream writev replies | 5,000 | 5,000 |
| Read EAGAIN | 0 | 0 |
| Total completed calls, all roles | 17,930 | 15,457 |

C's children read the two-byte frame prefix separately: 5,008 prefix reads
and 5,000 32-byte body reads. E requests up to 4,096 bytes, receiving 5,000
34-byte frames and eight EOF results. Both write each response with two
iovecs: a two-byte prefix and a 48/60-byte DNS body. E therefore saves one
successful read per query, while performing 4,850 more completed ppolls in
this capture. Of E's waits, 4,911 have 14 input entries; its active-client
waits carry positive deadlines. C's parent waits track listeners and child
notification pipes; the children use blocking reads. Total syscall count
alone cannot explain CPU cost, scheduling cost or the previously observed
hit-path difference.

The complete C accounting also retains its connection-management costs:
336 netlink recvmsg calls, 112 netlink sends, 224 interface ioctls, 162 pipe
reads, 106 pipe writes, 106 wait4 calls, and 504 closes. C children perform
56 mmap/munmap pairs and 112 fcntls. E has 56 `FIONBIO` ioctls, 56 closes,
87 mmap calls and 86 munmap calls. These are real differences, not omitted
because they lie outside the DNS answer function.

## Identity and limits

C runs through the image's original musl loader and four original libraries.
Before and after capture, every ELF mapping and hash matched the exact
image manifest; executable mappings outside those files and vDSO are rejected.
The only extra file mapping is 114-byte UTC timezone data, SHA `8b858467…`,
with read-only `r--s` permissions. It is recorded separately, not treated as a
DSO. Fork descendants inherit these mappings; no exec was observed. E's
static ELF and map are bound to its SDK build receipt.

The first attempted C UDP launch failed before prewarm or observer attachment
because the diagnostic identity gate incorrectly classified timezone data as
a DSO. Its logs and directory remain intact. A separate tool fix retained
the strict ELF set and recorded non-executable data mappings. The four
captures above use a new frozen plan and new output directories; no failed
sample was replaced or selected away. The parser also retains the distinction
between detached entries and completed calls; initial derived UDP summaries
are kept separately from the corrected summaries.

No clock syscall appears in these windows, but vDSO time reads are invisible
to strace. Ancillary flags and buffer metadata do not measure user-space cmsg
parsing instructions. The denominator of 5,000 includes warmup and a fixed
grace window, so these are contextual per-query counts, not pure steady-state
costs. There is one capture per side/scene, and no latency or CPU acceptance
claim. All raw traces remain on Oracle. No router was accessed and no product
code, dynamic library or frozen workload tool was changed.
