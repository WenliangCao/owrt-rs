# reload_config_rs audit (subagent, read-only)

Scope: components/reload-config/src/{engine.rs,main.rs,process.rs,unix.rs,syslog.rs,trace.rs} vs docs/contracts/config-change-dispatch.md (C1-01, quotes the 17-line script) and the procd consumer (private/upstream-ref/procd/service/service.c:760-804, trigger.c:289-306). Note: the crate has NO dependency on components/ubus; it shells out to `uci`, `md5sum`, `ubus` exactly like the script (Cargo.toml has no [dependencies]).

## 1. Findings
| id | class | sev | title | Rust evidence | reference | verify |
|---|---|---|---|---|---|---|
| F1 | confirmed | P2 | Lock wait (flock LOCK_EX) ignores the cancellation flag; every other blocking wait polls `cancelled` every 10 ms | unix.rs:20-31 (`lock` retries only on EINTR, no `cancelled` param); engine.rs:85-95 `RunLock::acquire` no `cancelled`; engine.rs:105 acquire happens before the first `cancelled.load` (engine.rs:121); contrast process.rs:23-43 | shell original takes no lock (new code, not a regression); README claims SIGINT/SIGTERM fail-closed | two instances on one --root; SIGTERM the second while the first holds /var/run/reload-config-rs.lock; bounded by the first's timeout, hence P2 |
| F2 | intentional (undocumented in contract) | P3 | Hard caps: 4096 config entries, baseline ≤ 4096×320 bytes → Error::InvalidInput; script had no cap | engine.rs:14-15, 228-231, 401-406 | contract C-01 states no limit; §8 table does not list it | >4096 entries in /etc/config+/var/run/uci on a test root → EX_USAGE where the script proceeds; contract amendment |
| F3 | potential | P3 | Two JSON escapers (byte-oriented engine.rs:494 for the ubus payload; char-oriented trace.rs:88 for JSONL trace) can drift | engine.rs:494-508, 360-363; trace.rs:12,29,38,57,68,88 | n/a | property test feeding both |

## 2. Overhead
1. Device measurement R86 unchanged_config: 40162 → 25407 µs (-36.7%), CPU 41470 → 26320 (-36.5%).
2. Fewer forks: one `md5sum <files...>` (engine.rs:278-343) + in-memory diff (engine.rs:439-448) instead of md5sum twice; per-file `uci show` retained 1:1 (engine.rs:251).
3. Child wait: helper thread on child.wait() + 10 ms cancellation poll (process.rs:23-43); earlier try_wait+sleep loop cost ~330 ms per run with 38 children (fixed).

## 3. Checked, equivalent
- `uci -c/-C` flags are no-ops in production (compiled-in defaults uci.h:39,41; libuci.c:62; file.c:724,753,952) — /var/run/uci precedence (C-02) comes from uci itself.
- Payload `{type:"config.change",data:{package}}` matches procd's event_policy/validate_policy (service.c:760-804) and trigger_match/json_script_run (trigger.c:289-306).
- Non-UTF-8 package names reach ubus as exact bytes (engine.rs:357-363, json_escape_bytes).
- scan_config_names (engine.rs:199-238): skips dotfiles, requires is_file() (follows symlinks, matches `[ -f ]`), byte-wise sort — contract C-01.
- First run / missing baseline → zero events (engine.rs:401-410 + 439-448) — C-05, §6.
- Create/modify/delete asymmetry exactly C-04 (only entries in `previous` compared); unit test small_state_space_matches_contract_rule.
- Order preserved (baseline file order), no retry on delivery failure — C-08 / RK-01.
- Atomic baseline: same-dir temp + sync_all + rename, previous bytes preserved on failure (engine.rs:450-488; unit test).
- Malformed baseline lines skipped like busybox md5sum -c (line[32..34] == "  ").

## 4. Unverified
- On-device confirmation of /var/run/uci precedence (source-level only; contract §8 flags SRC-only).
- Whether any subscriber depends on cross-package event order.
- Which toolchain produced the on-disk 432,248-byte artifact (rust-version 1.98.1 vs README's 1.78.0/1.94.0 mentions).
- R86 results.json, R1/V1 reports, r1/c1 checker scripts, packaging/openwrt/owrt-reload-config not read in this pass.
