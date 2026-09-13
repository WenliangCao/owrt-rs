# httpd-rs audit (subagent, read-only, HEAD 7eccfb0)

Rust paths under components/httpd/src/ (plus components/ubus/src/conn.rs); C under private/stage3/src/uhttpd/.

## 1. Findings
| id | class | sev | title | Rust evidence | C reference | verify |
|---|---|---|---|---|---|---|
| H-01 | confirmed | P2 | REMOTE_USER never exported to CGI after Basic auth; contract §4.2 (docs/contracts/httpd.md:52) lists it | cgi.rs:187-220 env list has no REMOTE_USER | proc.c:120,156 (VAR_USER = req->realm->user), auth.c:172 sets req->realm | sandbox realm on a CGI path, script prints $REMOTE_USER (r83_httpd_compat.py:110 prints only HTTP_AUTH_*). Device has no realms → latent |
| H-02 | confirmed | P3 | Check order: Rust 100 Continue → TLS redirect → RFC1918; C RFC1918 → TLS redirect → 100 Continue. With -R -q private→public plain request gets 307 not 403 | main.rs:576, 642-658, 659-669 | client.c:339-346 | sandbox -R -q. Device: -q off |
| H-03 | confirmed | P3 | Authorization: Bearer case-sensitive on POST /ubus/call/<obj> (only `Bearer `/`bearer `); /subscribe/ is case-insensitive. Open since AUDIT_ROUND1 §5 | bridge.rs:520-526 vs 558-560 | ubus.c:132 strncasecmp | `Authorization: BEARER <sid>` → C uses sid, Rust default sid → -32002 |
| H-04 | confirmed | P3 | -E error handler not run for file handler's 403; C runs it with REDIRECT_STATUS=403 | main.rs:752 → files.rs:357-358,377-378,382 | file.c:704-713 | -E /err.html, chmod 600 /www/x. Device: no -E |
| H-05 | potential (gate-masked) | P3 | Header-phase errors: Rust appends chunk terminator `0\r\n\r\n`; C emits TE: chunked with no body/terminator. Rust protocol-correct; r27 de-chunks so both compare empty | http.rs:1121-1126, main.rs:616-633 | utils.c:59-61,95-97, client.c:169-173 | raw bytes of te-gzip/cl-alpha responses |
| H-06 | potential | P3 | Stale ubus replies after a timed-out call stay in `pending` of a pooled connection, never drained → one retained reply per timeout, ≤8 conns | conn.rs:217-219,230; bridge.rs:110-116 (Lease returns conn if no HUP/ERR; has_pending() never consulted) | libubus drops unknown-seq replies | POST /ubus call to a method sleeping > -t, repeat, watch RSS; fix: drop conn in Lease::drop if has_pending() |
| H-07 | potential | P3 | Batch responses fully materialised before send; C streams one item per 1 ms timer. 64 KiB batch of `list` → multi-MB per connection | bridge.rs:171-180,499-508 | ubus.c:824-837,203-215 | POST 64 KiB batch, sample RSS |
| H-08 | intentional (undocumented) | P3 | Chunked framing more lenient than C: extensions `;ext` accepted, trailers parsed (≤8 KiB/64 lines), sizes > INT_MAX accepted | http.rs:846-857,881-892 | client.c:495-529,224-226 | chunked POST with `2;a=b` and a trailer line |
| H-09 | intentional-documented | P3 | Malformed body on /ubus → Rust 400 + close; C 200 + -32700 | main.rs:684-687 | client.c:508-518 | known diffs chunked-bad-size/huge-size |
| H-10 | potential (perf) | P3 | 50 ms linger also governs first request of a fresh connection and every rustls handshake flight: RTT ≳ 50 ms clients pay park + thread respawn per connection/TLS round-trip. LAN unaffected | main.rs:538, http.rs:233-239,293-301, main.rs:552-562 | n/a | oracle tc netem delay 60ms, count clone per connection |
| H-11 | potential | P3 | At -N cap listener polls every 50 ms; a freed slot does not wake it (no wake-pipe write on decrement). C re-arms immediately | main.rs:844-847, 927 | client.c:622, listen.c:77-84 | hold N conns, close one, measure accept latency |
| H-12 | confirmed | P3 | -q port selection with several TLS listeners per family takes first spec; C prefers 443 | main.rs:643-646 | listen.c:208-224 | -s 0.0.0.0:8443 -s 0.0.0.0:443 -q |
| H-13 | confirmed | P3 | Bare-port `-p 80` binds v4 only; C binds v4 and v6. Device passes explicit addresses | main.rs:270-271 | listen.c:139-151 | -p 80, connect [::1]:80 |
| H-14 | confirmed | P3 | CGI `Status: abc def` → C `HTTP/1.1 000 def` (atoi), Rust ignores → 200 | cgi.rs:544-551 | proc.c:209-219 | script printing that header |
| H-15 | potential | P3 | Script-slot queue order: C LIFO, Rust Condvar notify_one ≈ arbitrary | main.rs:241-264 | file.c:849,771 | -n 1, 4 queued clients |
| H-16 | confirmed | P3 | ubusd unreachable / lookup failures: Rust -32603 (and reconnects per request); C -32000; GET /ubus/list/x always code 4 in Rust vs actual err in C | bridge.rs:239-241,464-475 | ubus.c:793-795,313-317 | stop ubusd, POST call |

## 2. Hot-path overhead
1. bridge.rs:271,282,592: reply blobmsg → Json tree → bytes: two passes + full tree allocation per RPC reply; C blobmsg_format_json streams once. Likely source of jsonrpc_c4 CPU +3.1% vs C.
2. main.rs:548 + http.rs:238: two setsockopt(SO_RCVTIMEO) per request; main.rs:884-892: three setsockopt + getsockname per accept. C: getsockname only.
3. bridge.rs:90-94,112: two poll(0) per pooled RPC (checkout and return).
4. files.rs:84-91,133: one String alloc + stat per `/` boundary candidate; format! + stat per index name for directories.
5. cgi.rs:200-204 IP formatted twice; cgi.rs:499,530,557 3-4 allocs per CGI header line; cgi.rs:334-338 50 ms try_wait+poll tick while a quiet script runs (20 wakeups/s per CGI vs C SIGCHLD). main.rs:821,839-843 O(parked) scan per listener wakeup, bounded by -N.

## 3. Checked, equivalent to uhttpd
Request line/method/version sets, keep-alive defaults, UA-specific closes; duplicate CL / CL+TE → 400; Expect 100/412; TE non-chunked → 501; 4 KiB head-line cap → 413; status line, Keep-Alive header, chunked selection; duplicate header pick = first; static 405/S_IROTH/ETag/Last-Modified/If-* preconditions/HEAD; directory 302/index order/listing format and escaping; path lookup longest prefix, PATH_INFO, docroot containment, -S realpath; error bodies; CGI interpreter/prefix match, env table incl HTTP_* order, chdir, PATH, 500/502 pages, Status/CL/TE handling, HEAD skip, -t 0, SIGKILL+reap; script slots -n 0; bridge routes, OPTIONS, 65536 cap, sid rules, error order, session.access timeout -t/2, legacy/non-legacy shapes, CORS, SSE deny/retry/framing; Basic auth order, 401 body, shadow/passwd, constant-time compare; RFC1918 filter, TLS redirect; TCP keepalive options, max_connections shared across listeners; TLS DER/cipher/startup failure/16 KiB rustls buffer. Parking design: deadline carried through park→expire→resume; connection counter decremented on every close path (927, 815, 825, 916, 932, 902) and never on park; buffered bytes never produce Idle; TLS parks only with no plaintext and no pending write; wake pipe non-blocking and drained; tokens monotonic; SO_RCVTIMEO restored to network_timeout before any dispatch (main.rs:548) so body reads/CGI never observe 50 ms. fd/process hygiene: CLOEXEC everywhere, ChildGuard kill+wait, SSE conn dropped on exit, idle pool capped 8. No leak path besides H-06.

## 4. Unverified
- files.rs:306-309 asserts musl strptime rejects %Z, so If-Modified-Since never matches on device; contract §3.5 says ≥ mtime → 304; r14 has if-modified-since-old/new passing against the device. Code comment and contract disagree.
- Exact 413 boundary (4095 vs 4096) and reset behaviour: gate-documented only.
- H-05/H-08 client-visible impact on LuCI, H-06 leak magnitude, H-10 respawn cost at realistic WAN RTT: no gate exercises them.
- Whether SO_RCVTIMEO restore at main.rs:548 can fail on a live socket (`let _ =`).
