# logd-rs audit (subagent, read-only, HEAD 7eccfb0)

## 1. Findings
| id | class | sev (agent) | title | Rust evidence | C reference | verify |
|---|---|---|---|---|---|---|
| F1 | confirmed | P1 (agent) | `log write` with non-UTF-8 `event` silently drops the entry but replies OK: Field::as_str() → None skips the add block, reply_status(OK) runs unconditionally | main.rs:250-266; ubus/src/blob.rs:141-143 | logd.c:165-190 write_log uses blobmsg_get_string unconditionally | raw INVOKE with invalid UTF-8 STRING event; r28 corpus (lines 101-103) only has valid UTF-8 |
| F2 | confirmed | P3 | `log write` truncates at a char boundary; C at raw byte LINE_SIZE-1 | main.rs:256-262 | logd.c:180-183 | multibyte char across the boundary |
| F3 | intentional-documented | P2 | /dev/log datagrams with invalid UTF-8 rewritten lossily (U+FFFD); C stores raw bytes. AUDIT_ROUND1.md:91 deferred, still open | ring.rs:156 | log_add(char*, len) no validation | — |
| F4 | potential | P2 | Per-client stream backlog Client.pending has no cap/drop/disconnect policy; grows while a logread reader stalls | main.rs:84-88, 92-111 (WouldBlock keeps backlog), 157-160, 210-216 | logd.c:125 pipe + ustream write buffering (ustream.c not vendored) | SIGSTOP a logread client, flood, compare RSS on both |

## 2. Overhead
1. drain_kmsg() one read() per poll wakeup, not drain-to-EAGAIN (main.rs:301-313); C klog_cb loops. Level-triggered, so correct but more poll/read round trips per burst.
2. Per-message heap allocation (Entry.msg String, ring.rs:15-23; main.rs:253 to_owned) vs C single arena memcpy (syslog.c:330, 344). Bounded by ring capacity.
3. Device numbers favour Rust: syslog_128 -82%/-73%, log_read_100 -41%/-49% (R86; R87 same order).

## 3. Checked, equivalent
Ubus reconnect (shutdown before retry; r21/r83 gates); local-failure degradation (socketpair/set_nonblocking → UNKNOWN_ERROR, non-stream reply failure → INVALID_ARGUMENT); ring wraparound abandoned-tail eviction (ring.rs:71-88 vs syslog.c:195-206, 304-325; R83 6-config oracle differential); subscriber/client notify gating; client disconnect cleanup on Ok(0)/write error; log read type policy (lines INT32, stream/oneshot INT8/BOOL); oversize non-stream reply refusal (MAX_MSGLEN-16 → INVALID_ARGUMENT, beneficial vs C timeout); log write SOURCE_SYSLOG tagging; SIGPIPE ignored; datagram parsing (r28 33 outputs 0 diff).

## 4. Unverified
F4 comparative severity vs ustream buffering (ustream.c not in repo); socketpair/EMFILE handling untested (R83 gap); stream backlog oversize (`lines` very large) untested; C's -S 1 heap-overread bug not reproduced (device -S 64); F1/F2 static only; full C startup-order equivalence not re-derived.

## Root-agent cross-check (2026-09-13)
- F1 confirmed in source (main.rs:250-266): `as_str()` None → add skipped, `reply_status(OK)` unconditional. Reclassified to **P2**: silent data loss, but reachable only by a raw-blob client sending an invalid-UTF-8 STRING (the JSON CLI path cannot produce one); the datagram path (F3) already documents the lossy policy, so `log write` should at least apply the same lossy conversion rather than drop.
- F4 reclassified to **parity with C (intentional, P3)**: upstream libubox ustream.c `ustream_init_defaults` sets `w.max_buffers = -1` and `ustream_can_alloc` returns true for `max_buffers <= 0`, so C logd's per-client write buffering behind the 64 KiB pipe is also unbounded while a `logread -f` reader stalls. Both sides grow with the ring contents delivered to a stalled reader; neither disconnects. (Source fetched read-only from github.com/openwrt/libubox master; the pinned device copy is expected identical for this default but was not diffed.)
