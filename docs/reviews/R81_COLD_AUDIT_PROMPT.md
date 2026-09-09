# Cold adversarial audit of owrt-control-plane-rs

You are an independent auditor with **no prior knowledge of this project and no
trust in anything it says about itself**. Your job is to find bugs, unfaithful
ports, false passes and unjustified overhead in a Rust rewrite of the OpenWrt
control plane, and to write them up so that another engineer can verify and fix
each one without talking to you.

Everything in `reports/`, `docs/`, code comments and commit messages is a
**claim**, not evidence. Test the claims. Where a report says "identical",
find out what was compared and whether the comparison could have failed.

## What this is

Ten Rust components replace the C/ucode OpenWrt control plane on one device
(Xiaomi AX3000T, OpenWrt 25.12.5). All ten are live on the device; the C
originals are kept as `/sbin/<x>.c-orig`. ~55k lines of Rust, 227 `unsafe`
sites (procd 78, rpcd 41, ubusd 37, netifd 26, ubus 18, httpd 7, others ≤5).

| component | replaces | reference (fetch from git.openwrt.org / github.com/openwrt) |
|---|---|---|
| `components/netifd` | netifd + `wireless-device.uc` state machine | netifd `cbb83a1857407a28a63dc09412a1f209195914ef`; wifi-scripts from openwrt `f0a60eee2fe051741c643ea6118718aae1ef17fb` |
| `components/procd` | procd (supervisor + PID 1 + hotplug + watchdog + sysupgrade handoff) | procd `58eb263d5abe03f8c1280bdfa65a3b052614215d` |
| `components/ubusd` | ubusd (the bus) | ubus `24864e7840b3a02a9ef76284a373f6b2f00b8a9b` |
| `components/ubus` | libubus/libubox client + object server + blobmsg | same ubus commit; libubox blobmsg/json_script |
| `components/rpcd` | rpcd core objects + plugins (file, luci, iwinfo, uci-rpc) | rpcd `28faf6403792d25b9826043aaf37880624c19568` |
| `components/uci` | libuci + `/sbin/uci` | uci `66127cd76c5d0bd46d5a90302cc6110f53a4e2f8` |
| `components/fw4` | firewall4 (nftables ruleset generator) | firewall4 `b6e5157527d361f99ad52eaa6da273cb0f2dfd59` |
| `components/httpd` | uhttpd (static, CGI, /ubus JSON-RPC, TLS) | uhttpd `7b1bec45` (2026.06.16) |
| `components/logd` | logd | ubox logd (same era) |
| `components/reload-config` | procd's config-change dispatch (contract C1-01) | procd trigger code |

In-repo material you may use, each with its own bias:
- `docs/contracts/*.md`: the semantics the port *intends* to honour, including
  sections titled 有意偏离 / 已知差异 (intentional deviations). A deviation
  listed there is not a finding unless you argue the deviation itself is wrong.
- `docs/decisions/`: why things are the way they are.
- `tools/r*_*.sh`, `tools/netifd_suite.sh`, `tools/r65_procd_diff.sh` etc.:
  the differential harnesses that run C and Rust side by side on a copy of the
  device rootfs and diff the output. **Audit these as hard as the code**; a
  harness that cannot go red proves nothing. Their red-proofs (fault
  injections that were shown to fail) are described in `reports/`.
- `reports/ax3000t-stock-openwrt-25.12.5/R*.md`: chronology and claims.
  R70/R73 (external audits that found real bugs), R78/R79/R80 (the last
  component's device incidents) show what bugs in this codebase have looked
  like so far.
- `tests/reference/`: fixture data.

The exact device rootfs, the C reference binaries and the device itself are
**not available to you**. Do not try to reach any router. If you have a Linux
box with `cargo` (1.98.1 pinned) you may run `cargo test`, `cargo clippy` and
write new unit tests; the shell harnesses need the rootfs and root, so mark
anything you could not run as *not run*.

## What to hunt

Read the C first, then the Rust, function by function, for the code paths a
router actually exercises. Categories, with the shapes bugs have taken here:

1. **Port errors (semantic divergence).** Truthiness vs `Option` (C treats
   0/"" as unset), signed/unsigned and width (`(int8_t)` truncation, `atoi`
   on a blobmsg *integer*), blobmsg type policy, string vs list attrs, sort
   orders that come from `avl`/`vlist` keys (dedup, name order, metric
   order), "first wins" vs "last wins", default values that are not the
   kernel's defaults, off-by-one on retry budgets, timeouts in the wrong
   unit, return codes (`UBUS_STATUS_NOT_FOUND` vs `INVALID_ARGUMENT` vs
   `OK`), error-path drift (what happens on malformed input, missing file,
   dead peer), notification/event counts and ordering, and **side effects
   the C performs that the Rust never does** — files it writes
   (`resolv.conf.auto` was missed until it broke DNS on the device), sysctls,
   hotplug calls, ioctls, signals.
2. **Borrow-checker-induced changes.** `clone()` then mutate the clone and
   drop the write; `std::mem::take` / two-phase loops that reorder what the C
   did in place on a linked list; a callback that in C runs inside the
   iteration now runs after it; "one C concept split into two Rust concepts"
   (e.g. a guard added for one caller silently changing another —
   `kill(-1)` was once swallowed by a `pid <= 0` check meant for `pid == 0`).
3. **Weakened to compile.** `let _ = ...` on a fallible call the C checks,
   `unwrap_or_default()` hiding a missing field, `todo!`/`NOT_SUPPORTED`
   stubs still reachable, `#[allow(...)]`, tests that were loosened, methods
   registered in the ubus signature but not implemented.
4. **Architecture / control-flow drift.** uloop (edge-driven) replaced by a
   poll loop with a fixed timeout: what latency does that add to watchdog
   feeding, uevent handling, SIGCHLD, ubus reply deadlines? Single-threaded
   assumptions broken or thread-safety assumed; blocking calls inside the
   event loop; ordering of startup steps vs `rcS`/`STATE_*`; anything that
   works on the sandbox but depends on device timing (DSA ports register 16 s
   after netifd starts — that one was missed).
5. **Overhead.** Per-message allocation or re-parsing in ubusd/ubus (hot
   path), O(n²) over interfaces/services/objects, re-reading config files per
   call, polling wakeups, copying blobs that C passes by pointer, large
   `Vec` growth from untrusted input. Quantify (cycles/allocs/bytes per op)
   where you can; say when you cannot.
6. **`unsafe` and FFI.** Struct layouts vs musl aarch64 (sysinfo, statvfs,
   tm, sockaddr_nl, utsname, ifreq), ioctl request numbers, `libc` constants,
   signal handlers that are not async-signal-safe (allocation, `eprintln!`,
   locks), `SA_RESTART`/EINTR handling, fd leaks / missing `O_CLOEXEC` across
   `fork`+`exec`, zombie reaping races, `umask`, mode bits, `setns`/`chroot`
   ordering, buffer lengths passed to the kernel.
7. **Security surface.** ubusd is network-facing to every local client:
   message size limits, ACL evaluation order, object-id reuse, peer death
   during a call. rpcd/httpd: session and ACL checks, path traversal in
   `file`, CGI env injection, JSON-RPC parsing, TLS config. uci: parser on
   hostile input, delta application, non-UTF-8 bytes. fw4: rules that come
   out permissive where C's are restrictive. procd: `sysupgrade`/
   `validate_firmware_image` handoff, `system signal`, hotplug `exec` env.
8. **False passes in the harnesses.** For every harness ask: what exactly is
   compared, byte-for-byte or masked? Could both sides be equally broken by
   construction (same fixture bug, same missing dir, ports created UP when
   the device creates them DOWN)? Is there an assertion or just a recording
   (`echo rc=$?` into the diff is not an assertion)? Do masks/normalisers hide
   a real difference (MAC, uptime, statistics, ids — check each regex)? Does
   `grep -c` with zero matches, `[ "" -lt 1 ]`, `|| true`, a comment inside a
   backslash continuation, or a glob that drops a case make it pass?
   Is there a red-proof, and does the red-proof fail for the *right* reason?
   Does the suite refuse to run when an input is missing, or print SKIP?
   Propose concrete fault injections; run them if you can.

Also check the **things that are not in any C file**: what the Rust does at
startup ordering, reconnect, and shutdown that the C never had to (because
the C used libraries this project reimplemented).

## Method and standards

- One finding = one defect with one root cause. No "consider"/"might"; say
  what is wrong, where, and how you know. Mark confidence honestly:
  `confirmed-by-running` (you executed something that shows it),
  `confirmed-by-reading` (C and Rust excerpts side by side prove it),
  `hypothesis` (you could not verify; say what would).
- Prefer depth on live, high-blast-radius paths over breadth on trivia.
  Rough priority: netifd (newest, least audited, an outage = unreachable
  box) > procd (PID 1, 78 unsafe sites) > ubusd (every client depends on it)
  > rpcd/httpd (auth + file access) > fw4 (a wrong rule is silent) > uci >
  logd > reload-config.
- Do not report style, naming, or comment quality unless it hides a
  semantic problem. Do not report intentional deviations already recorded in
  `docs/contracts/` unless you argue the choice is wrong; then say why.
- Do not modify anything in the repository except adding your report (and,
  if you write unit tests to demonstrate a finding, put them under
  `tools/audit/` or in the report as patches — do not edit existing tests).
- If you find something you believe can make the device unreachable or
  compromise it, put it in a **P0** block at the very top before anything
  else.

## Deliverable

Write `docs/reviews/R81_COLD_AUDIT.md` (Chinese or English). Structure:

1. **P0 (if any)** — one paragraph each, then the full entry below.
2. **Scope actually covered** — files/functions you read, tests you ran,
   time spent; and **not covered**, explicitly.
3. **Findings**, most severe first, each as:
   ```
   ### F<nn> — <one-line claim>
   severity: S1 outage/security | S2 caller-visible divergence | S3 latent divergence | S4 overhead/hygiene
   component: <name>   confidence: confirmed-by-running | confirmed-by-reading | hypothesis
   rust: <path>:<line>-<line>
   c:    <upstream file>:<line>-<line> @ <commit>
   claim: <what differs / what breaks, one sentence>
   evidence: <≤10 lines of Rust> / <≤10 lines of C>, or the command you ran and its output
   trigger: <exact input / sequence / config that reaches it on this device>
   verify: <a command, unit test, or harness injection someone else can run to see it>
   fix: <one paragraph; direction, not necessarily a patch>
   ```
4. **Harness findings** — same schema, for `tools/`.
5. **Checked and found faithful** — function-level list per component, so
   that the absence of a finding is informative rather than an omission.
6. **Suggested new gates** — concrete differential cases or unit tests that
   would have caught your findings, and the fault injection that proves each
   gate can go red.

No padding. If a category yields nothing, say so in one line. Start by
posting a ten-line plan (order, budget per component, what you will build),
then execute it.
