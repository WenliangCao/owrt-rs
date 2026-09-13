# ubusd-rs audit (subagent, read-only, HEAD 7eccfb0)

Scope: components/ubusd/src/*, components/ubus/src/{readiness,blob,msg,sys}.rs vs private/stage2/src/ubus/ubusd*.c and libubox blob.h/blob.c/blobmsg.c. R83 (F02, F27.x) and R87 (U05) fixes verified present.

## 1. Findings
| id | class | sev | title | Rust evidence | C reference | verify |
|---|---|---|---|---|---|---|
| U-1 | potential | P2 | Level-triggered listener spins at 100% CPU under fd exhaustion: sys::accept maps EMFILE/ENFILE to Err, accept_all returns, listener stays readable, epoll_wait returns immediately. C listener is ULOOP_EDGE_TRIGGER. Socket is 0666 so any local user can trigger | ubusd/src/sys.rs:246-250 (only EAGAIN → Ok(None)); main.rs:224-245 (`Err(_) => return`); main.rs:153 (listener level-triggered) | ubusd_main.c:208-216, :361 | ulimit -n 32, 40 idle clients, sample utime 3 s; r41_inner.sh:45 only checks fd_bounded |
| U-2 | potential | P3 | Read spin on half-closed peer with queued output: after read()==0 client kept (eof && !tx_empty) but EPOLLIN never dropped; RCV_SHUTDOWN keeps EPOLLIN asserted until the queue drains. C client fds edge-triggered. Needs shutdown(SHUT_WR)+slow read; libubus never does | main.rs:263-283; readiness.rs:89-96 (ctl always sets EPOLLIN) | ubusd_main.c:221 | busprobe client: SHUT_WR after large LOOKUP, read 1 B/s, watch CPU |
| U-3 | confirmed | P3 | Attribute walks stop at a raw_len 1..3 attribute; libubox skips it and continues at pos+4. Affects attrs_of (top-level: C handles, Rust INVALID_ARGUMENT), SIGNATURE, event register/send data. Hand-crafted messages only | blob.rs:62-69; server.rs:1010, :233, :792, :832 | blob.h:244-256, blob.c:243-252 | r42 case `[attr raw_len=2][OBJID][METHOD]` INVOKE: C relays, Rust returns 2 |
| U-4 | confirmed | P3 | ADD_OBJECT reply omits OBJTYPE when both OBJTYPE and SIGNATURE present; C echoes OBJTYPE whenever attr[SIGNATURE] && obj->type | server.rs:227-229, :243, :286-290 | ubusd_proto.c:153-154 | wireprobe ADD_OBJECT with OBJTYPE + SIGNATURE |
| U-5 | confirmed | P3 | Event object blobmsg policy: duplicate pattern/object/id/data — C keeps first, Rust keeps last; `object` accepts INT16/INT8 via Field::as_u32, C requires INT32 | server.rs:792-798, :832-838; blob.rs:145-156 | blobmsg.c:211-214, :226-227; ubusd_event.c:51-54, :200-203 | r42/wireprobe with duplicated fields and INT16 object |
| U-6 | confirmed | P3 | TARGET decoded by width (Attr::as_u32 returns u16/u8 value for short payloads; None otherwise); C blob_get_u32 always reads 4 bytes | server.rs:607, :657; blob.rs:24-31 | ubusd_proto.c:456, :494 | SUBSCRIBE with 2-byte TARGET |
| U-7 | potential | P3 | ACL loader ignores per-key blobmsg types (C requires methods/tags ARRAY, acl TABLE; wrong type = absent). Root-owned files only | acl.rs:243-247, :253-257 | ubusd_acl.c:314-318, :358-370 | inject `{"user":"root","access":{"x":{"acl":"s"}}}`, compare acl query |
| U-8 | potential | P3 | Lookup-all resume after the anchor object is freed restarts from the first object → slow client gets duplicates. C has a raw pointer (use-after-free); Rust safer but not equivalent | server.rs:407-410 (unwrap_or(0)); client.rs:51-56 | ubusd_proto.c:214-239; ubusd_obj.c:202-225 | slow reader during lookup_all, remove next object, count duplicate OBJPATHs |
| U-9 | potential | P3 | try_prefix_batch size estimate ignores per-field padding → debug_assert can fire in debug builds for a non-table method entry; release only re-allocates. libubus signatures are all tables | server.rs:470-471, :487; blob.rs:394-398 | ubusd_obj.c:37-51 | cargo test with signature {"m":"x"} and prefix lookup |
| U-10 | intentional-documented | — | Silent per-client tx drop at 1 MiB and shared txq_ofs residue defect reproduced (contract §3); flush zeroes txq_len on drain (strict improvement) | client.rs:125-131, :152-155, :277 | ubusd.c:143-163, :182-183 | r41 drop mode |

No P0/P1. Readiness loop: every Client write site pushes Server::touched (server.rs:153,166,433,490,972) or is followed by sync_write_interest (main.rs:189); tokens are client ids not fds, stale ready entries rejected by clients.contains_key (main.rs:185); poller.remove precedes close (main.rs:217-222); EINTR retried and signals wake the self-pipe (readiness.rs:130, main.rs:46-61).

## 2. Hot-path overhead
1. server.rs:877-912 dispatch_event: one targets Vec + one blob.clone() per receiver (C patches OBJID in a shared buffer). Low frequency.
2. server.rs:405-416 lookup-all: path_order() Vec of all ids per `ubus list` + HashMap probe per object; device lookup_all_128 CPU -12.9% so not measurable.
3. obj.rs:150-156 path_prefix: prefix.to_vec() + result Vec per prefix lookup; batched reply already -70% CPU vs C.
4. server.rs:948-975 mirror: fresh BlobBuf, to_vec, mons Vec, payload.clone() per monitor; only with `ubus monitor` attached.
5. client.rs:324 vec![0u8; raw_len] per inbound message — parity with C calloc (ubusd_main.c:157); a reusable buffer would save one malloc+memset per relayed message.
Invoke relay, STATUS and exact lookup at or below C cost (device: invoke CPU -0.95%, lookup -13.6%).

## 3. Checked, equivalent to C
Framing (12-byte prefix, raw_len<4 / pad4>1 MiB disconnect, fd only during prefix read), MAX_TXQ_LEN, gid cap 64; write side (direct write only when queue empty, txq arithmetic, SCM_RIGHTS at offset 0, EAGAIN/EINTR, hard error → disconnect; Rust passes fd on first-write EAGAIN where C would sendmsg a closed fd — strictly better); ubus_parse_msg policy; dispatch return semantics; ADD/REMOVE_OBJECT incl. type refcount, PUBLISH ACL order, ubus.object.add/remove events; free_object order and client teardown (C leaks cmd_queue and partial message); LOOKUP all/exact/prefix incl. cmd_queue resume and NOT_FOUND rules; INVOKE forward payload order and response relay; SUBSCRIBE/UNSUBSCRIBE/NOTIFY; events (id<1024, pattern sort with avl dup semantics, no loopback, event_seen dedupe, ubus. prefix reserved); ACL (root bypass, pathless bypass, supplementary gids, file gate, user over group, glob-sorted order, F27.3a, acl query shape); monitor (root-only, attribute order, mirroring rules); process (SIGPIPE, SIGHUP self-pipe, socket dir/umask/unlink, HELLO, id allocation getrandom ≥1024). Shared weaknesses kept on purpose: unbounded cmd_queue and patterns growth, scratch never shrinks, 1 MiB announce-and-stall pin — identical in C.

## 4. Unverified
- Actual CPU under U-1/U-2 on the A53 (needs oracle/device probe; no gate exercises fd exhaustion or SHUT_WR).
- Whether r42 mutations ever produce U-3/U-5/U-6 shapes (600 passing iterations say they did not).
- msghdr/epoll_event layouts rely on tools/abi_assert.c and readiness.rs:43-49 test.
- epoll_ctl(MOD) failure inside sync_write_interest (main.rs:212) ignored, out_registered left stale; only ENOMEM/ENOENT.
