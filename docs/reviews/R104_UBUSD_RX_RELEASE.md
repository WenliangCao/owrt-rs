# R104: release-on-short-read screen — reverted

Candidate `274528bb…` released the 4096-byte read-ahead allocation when a short
read had left no buffered frame or descriptor. It passed 35 physical-router
unit tests and the basic daemon smoke. This is not full receive-path validation.

The router memory screen showed 64 held connections at RssAnon 88 KiB, versus
400 KiB in the earlier R103 pilot. The earlier C/R89 pilots were 120/80 KiB.
These are separate exploratory observations, not a controlled memory superiority
verdict. PSS was unavailable; the tool's zero placeholders must not be interpreted
as measured zero. The holder only sent PINGs and waited; it needs explicit
HELLO/DATA/STATUS validation before confirmation experiments.

A subsequent direct-user-event CPU screen gave candidate/C changes of +12.90%
(one matched handler), +5.91% (eight), and +5.39% (unmatched). All are adverse in
this single pair. Short-read completion is common in serial request traffic and
does not imply long-term idleness; this policy introduces repeated allocation.
The magnitude and scope of that mechanism have not been independently profiled.

Commit a6ddf30 was therefore reverted by b832529. The accepted source remains
R103. No candidate was deployed. All new windows passed cleanup, stock identity,
boot/configuration and host-mount checks. The interrupted older R103 memory
window had left an owned temporary directory; its output was archived, absence
of process/root and host-mount references verified, and the directory removed.
Final stock health and zero-test-artifact checks passed.

Evidence: [screen data](r104-rx-release-screen.json). Next directions are a
smaller retained/adaptive buffer or shared read-ahead storage with explicit
partial-frame ownership, tested against fragmentation, descriptors, pipelining,
large frames, steady CPU and connection-scale memory. Immediate release is not
an acceptable solution; this says nothing about a Rust/C language limit.
