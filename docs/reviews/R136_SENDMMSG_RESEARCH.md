# R136 isolated ADD sendmmsg candidate

Status: the raw-syscall candidate is ready for Oracle screening, **not
promoted**. The original libc candidate is **rejected** before screening.
No main-tree component code was changed, no router work was performed, and
this note makes no performance claim.

## Narrow candidate

`tools/r136/sendmmsg-add-raw.patch` applies only to `components/ubusd`.
The ADD caller uses `send_add_status_reply`; exact LOOKUP retains the existing
`send_data_status_reply`. Monitored ADD replies still use the original
per-message server path. An already queued client also retains its original
send/queue path. The new syscall is eligible only for an empty queue and the
fixed 12- or 20-byte, descriptor-free ADD DATA blob, followed by a successful
STATUS. Total wire bytes are respectively 40 and 48.

Linux returns an entry count, not total bytes. The wrapper retains both
`msg_len` values. A partial DATA queues DATA at its exact offset followed by
STATUS; completed DATA with missing/partial STATUS queues only the unsent
STATUS suffix. EAGAIN, EINTR and other no-progress errors enqueue both frames,
without a synchronous retry. This follows the existing direct-write failure
policy; normal flush handles interruption and fatal connection failure. No
SCM_RIGHTS descriptor enters this path. With an initially empty queue, these
two fixed frames cannot approach the unchanged transmit cap.

## Rejected libc draft

The first draft, retained as `tools/r136/sendmmsg-add.patch`, called libc's
`sendmmsg`. That is not interchangeable with the Linux syscall on 64-bit musl.
The [musl 1.2.5 implementation](https://git.musl-libc.org/cgit/musl/tree/src/network/sendmmsg.c?h=v1.2.5)
loops over `sendmsg` to adapt the libc/kernel message-header ABI, and does not
stop after a successful short stream write. A receiver freeing buffer space
between those calls could let STATUS overtake DATA's unsent suffix. The small
fixed production reply is unlikely to be short, but relying on that would not
be an acceptable correctness contract.

Actual SDK-linked static-unit-test tracing confirmed two `sendmsg` syscalls,
not `sendmmsg`. The initial passing tests did not reproduce that interleaving;
their success was therefore insufficient to validate the first draft. The
root was notified immediately and its original ELF excluded from screening.

The replacement explicitly calls the Linux syscall through libc `syscall`,
using the existing Linux 64-bit `MsgHdr` representation and audited syscall
numbers (aarch64 269, x86_64 307). It compiles only for those audited Linux
architectures, with the unchanged fallback off Linux. SDK-linked tracing now
confirms real `sendmmsg` calls and the kernel's short-entry stop semantics.

## Kernel evidence and expected tradeoff

The saved physical-router evidence records kernel **6.12.94** in
`private/r134/router-finish-03/matrix/04-stock/raw/kernel.txt`. Oracle currently
runs **6.17.0-1020-oracle**; its syscall tests are supporting evidence, not a
substitute for router validation.

The saved OpenWrt source repository has a newer checkout, so this audit used
explicit Git object reads at the image's revision
`f5dae5ece4805730c5e2850f8aa84765af2f6b32`, not its working-tree contents. That
revision's `target/linux/generic/kernel-6.12` selects `.94` with archive hash
`e998a232b9418db3301cb58468e291a4f41d6ab8306029b30d991f56251dc8d2`.
None of its generic backport/pending/hack 6.12 or MediaTek 6.12 patches
references `net/socket.c`, `net/unix/af_unix.c`, `__sys_sendmmsg`, `MSG_BATCH`,
or `unix_stream_sendmsg`; neither source file is replaced by a generic or
MediaTek files overlay. This supports using the matching upstream code for
the audited syscall/Unix send behavior, without assuming that all kernel
configuration and scheduling behavior is identical on Oracle.

In the matching [Linux 6.12.94 sendmmsg implementation](https://github.com/gregkh/linux/blob/v6.12.94/net/socket.c),
the kernel invokes its sendmsg path separately for each entry, stores that
entry's byte count, and stops when the stream iterator still has unsent bytes.
If an error occurs after an entry was sent, it returns the count and suppresses
the later error. Therefore `completed == 1` may mean a short first entry or a
complete first entry followed by a failed second entry; `msg_len` distinguishes
them.

The matching [Unix-stream send implementation](https://github.com/gregkh/linux/blob/v6.12.94/net/unix/af_unix.c)
does not consume `MSG_BATCH`. Each protocol send allocates/queues its own skb
and calls the peer's data-ready callback. The candidate is consequently an
experiment in **reply wakeup timing**, not a claim of fewer syscalls: R134's
combined `sendmsg_three` already sends both replies with one syscall and can
use one skb. This candidate normally retains one syscall but creates two
protocol send operations, and the sendmmsg loop includes a reschedule point.
These are plausible costs, so no speedup should be presumed.

The public [sendmmsg manual](https://man7.org/linux/man-pages/man2/sendmmsg.2.html)
also specifies individual byte counts and suppression of an error after
progress. The exact musl header defines `mmsghdr` as a header plus an unsigned
length; `tools/r136/sendmmsg-abi.c` verifies the actual SDK layout, rather than
assuming a C representation from another libc.

## Verification completed

- Original libc draft: native GNU and SDK/musl release tests both passed
  **59/59**, before the syscall trace exposed the ABI-wrapper discrepancy.
  Those results are retained but do not validate that draft.
- Corrected raw-syscall candidate: canonical SDK compiler/linker flags,
  pinned Rust 1.98.1, and `aarch64-unknown-linux-musl` static release test
  binary: **59 passed, 0 failed**, 0.10 seconds. The original 55 tests remain,
  with four additional tests. Its independent test tree is
  `/home/ubuntu/r136-sendmmsg/raw-sdk/target`; root's original frozen build was
  not modified by this corrective verification.
- Exhaustive recovery from every sent prefix of both possible ADD replies:
  correct remaining queue length, exact byte order, no duplication, empty
  final queue. This includes DATA-short, DATA-complete/STATUS-unsent, and
  STATUS-short outcomes.
- Real nonblocking Linux socket tests cover a short first sendmmsg entry,
  `completed == 1`, untouched second entry, EAGAIN, successful two-entry
  transfer, and client backpressure followed by flush.
- The existing queued-cap test now exercises the ADD entry point and compares
  each queued frame against the separate-message reference. Existing monitored
  registration and lookup tests continue to pass.
- The actual OpenWrt 25.12.5 aarch64/musl SDK compiled all six C ABI assertions:
  `msghdr` 56 bytes; `mmsghdr` 64 bytes, alignment 8; header offset 0; `msg_len`
  offset 56 and size 4.
- SDK-linked strace of the raw wrapper's focused test recorded three kernel
  `sendmmsg` calls: one short first entry (`count=1`, `msg_len=219264`), EAGAIN
  with no progress, and two full 20-byte entries (`count=2`). It recorded no
  `sendmsg` syscall. The earlier libc trace is preserved as a negative control.

An actual kernel EINTR is not forced by these tests. The no-progress queue
test covers the corresponding result; the production wrapper does not retry
on error and therefore cannot duplicate a completed prefix after an interrupt.
No claim is made that unit tests exhaust all kernel scheduling outcomes.

Evidence is kept under `private/r136-sendmmsg/`: `oracle-tests.txt`,
`sdk-tests.txt` (rejected draft), `sdk-tests-raw.txt`, `sdk-test-identity.txt`,
`sdk-libc-sendmmsg-syscalls.txt`, `sdk-raw-sendmmsg-syscalls.txt`, `abi-check.txt`,
`openwrt-exact-patch-audit.txt`, `openwrt-kernel-identity.txt`, and
`kernel-reference/sources.json` with fetched source hashes.
The first generic cargo-test invocation failed before running tests because
optional examples referenced an omitted RPCD example module. The successful
invocation selected the intended `--bin ubusd-rs`, without modifying source or
excluding any daemon unit test.

Next gate: root-controlled Oracle A/B screening with exact build identities;
only a promising candidate should consume router time. A rejected screening
result should keep this isolated patch and evidence, with no runtime change.
