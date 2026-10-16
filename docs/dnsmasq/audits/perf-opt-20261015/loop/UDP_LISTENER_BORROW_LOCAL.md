# Defer UDP socket shared ownership until packet admission

Source `99b519dca413754d19afd9baad825924b06bbf13` is an independent child of
`185db90c9cabd26c0af09765636ef15bf6d35f79`. Only `main.rs::SinglePoll::step_udp`
changes. It is not included in 185, its SDK artifact or any 185 measurements.

The owner used to clone the listener's socket Arc before checking readiness
and receiving. It now borrows the socket for those operations and clones it
after successful receipt, size validation and short/QR rejection, immediately
before `admit_udp`. Admission can still reject: this is not a clone only for
accepted packets. Admission callbacks and deferred interface/MAC work still
receive owned shared state. No socket lifetime crosses an owner mutation while
borrowed, and no listener replacement occurs between the two lookups.

Unready listeners, WouldBlock/errors, discarded/oversized datagrams and
short/QR packets avoid one unnecessary Arc increment/decrement pair. The
receive/poll/send calls, 16-packet budget, readiness gating, diagnostic counts,
resend invalidation and pending ownership remain unchanged. In particular,
WouldBlock still preserves the most recent resend scratch; consumed/error
paths retain their original invalidation behavior.

The [source, tests and local codegen receipt](udp-listener-borrow-local.json)
records 23 passing daemon tests, including real localhost route-resend/error
controls, and passing musl all-target checks with default and diagnostic
features. No new tests or remote workload were run for this small change.
The pinned Rust 1.98.1 final musl cross-link uses opt-level 3, fat LTO, one codegen unit and
panic-abort, but is not an OpenWrt SDK build or runtime qualification.

In those local final ELFs, `step_udp` shrinks from 1,764 to 1,700 B with the same
384 B frame. The parent clones at 0x296460 before receive at 0x2966c0; the child
receives at 0x296690 and clones at 0x2967f8 only after the packet checks. Its
receive error exit at 0x296868 returns through 0x2968c4 without a socket Arc
atomic. Static release atomic call sites decrease 3→1 across the entire
function. These are control-flow/code-size observations, not 3→1 operations
per query or measured CPU savings. Whole ELF size changes 5,022,408→5,022,360 B.

## Remaining owner costs and boundaries

The earlier exact-C/E hit syscall capture completed 5,000 operations on each
side. C made 5,000 successful receives and zero EAGAIN receives; E made 5,000
successful receives plus 5,000 EAGAIN receives. If 185 retains that pattern,
this prototype removes an Arc pair on each speculative empty receive.
No 185 trace was taken here, so that frequency is conditional. Both historical
sides made 5,000 sends and 5,000 completed six-fd infinite ppolls. E's 65,535 B
receive iovec versus C's 1,232 B capacity does not establish 65 KB copying for
the observed 32 B requests. F/185 already disable pktinfo for static IPv4;
that is not a new saving.

Read-one reduced empty receives but hurt saturation, and the idle/busy
variant did not establish an A53 benefit. Neither direction is reopened.
`net.rs` still constructs a 32 B Address, MsgHdr and 40 B control buffer and
converts typed peer addresses. Raw-peer retention or reusable receive
headers would widen ownership/ABI changes without current attribution, so
no such prototype was made. The 40 B control initialization alone also does
not justify new unsafe storage.

No clock syscall in the historical trace does not prove no clock work:
vDSO reads are invisible. Independent 722 already addresses disabled wait
diagnostics and no-deadline clock reads. Required cache-expiry/TTL reads
cannot be shared across owner turns without preserving time boundaries.
Root's lease-expiry bound and cached-local qualification work remain
separate. The next diagnostic is fresh exact-C/185 stat plus cycles sampling
after the ongoing full 110 and its raw audits release the observation slot.

Historical context: `IMAGE_C_E_HIT_SYSCALLS.md`, `UDP_READ_ONE_RESULT.md`,
`UDP_IDLE_BATCH_RESULT.md`, `OWNER_CLOCK_LOCAL.md` and
`F_OWNER_RESIDUAL_NOTES.md` in the coordinator's same audit directory.
No new runtime, full behavioral acceptance or performance conclusion follows
from this local prototype.
