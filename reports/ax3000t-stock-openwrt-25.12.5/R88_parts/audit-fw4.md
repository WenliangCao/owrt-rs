# fw4-rs audit (subagent, read-only, HEAD 7eccfb0)

Scope: components/fw4/src/* vs pinned fw4.uc/main.uc/templates/*.uc (byte-identical to device copies in private/upstream-ref/rootfs-usr-share-firewall4/), /sbin/fw4 wrapper, R09 corpus, r29 fuzz, R83 fw4 notes. No panic path found in the parsers (all &str slicing at ASCII byte indices: parse.rs:520-521, 583-584, 789-816; val.rs:68-83; parse.rs:984-997; every unwrap() in sections.rs/render.rs guarded on the line above).

## 1. Findings (no P0-P2)
| id | class | sev | title | Rust evidence | ucode reference | verify |
|---|---|---|---|---|---|---|
| F1 | intentional-documented (deferred AUDIT_ROUND1.md:88, not closed by R83) | P3 | `list reflection_zone '*'` on a reflected dnat: ucode aborts the run (null member access, exit 254, empty stdout); Rust skips the entry and renders a valid ruleset | sections.rs:1526-1531 | fw4.uc:1071-1072, 2921-2928 | mock: dnat redirect, reflection 1, src zone masq 1, reflection_zone ["*"] |
| F2 | intentional-documented (AUDIT_ROUND1.md:88) | P3 | CT helper without `option port`: ucode aborts; Rust renders `tcp dport null` (nft rejects). Unreachable with shipped helpers (12/12 carry port) | sections.rs:608-612 | fw4.uc:2225, 1695-1696 | drop port from a mock helper |
| F3 | confirmed | P3 | After a load abort (bad defaults/include) `fw4 start`/`reload` exit 254 in Rust; shell wrapper exits 1 and prints "Unable to read firewall state…" | main.rs:80-82, 325-326 | /sbin/fw4:22-40, main.uc:5-13 | sandbox broken defaults + fw4 start; print/check already agree on 254 |
| F4 | confirmed | P3 | `fw4 -q check`: shell nulls stdout/stderr; Rust still prints raw_warn messages | parse.rs:377-379, main.rs:362-368 | /sbin/fw4:114-121 | -q check with ipset loadfile missing |
| F5 | confirmed | P3 | Usage text lacks the heredoc's blank lines | main.rs:257-283 | /sbin/fw4:128-165 | `fw4 bogus | diff` |
| F6 | confirmed | P3 | No "Unable to connect to ubus" warning when ubusd unreachable (renders with empty networks like ucode, silently) | input.rs:158-165, sections.rs:2057-2062 | fw4.uc:600-610 | fw4 print with ubusd stopped |
| F7 | confirmed | P3 | fs.error() texts hardcoded (ENOENT/EACCES only); wrong for EISDIR etc. | emit.rs:243-248, main.rs:86-88, render.rs:473-477 | fw4.uc:1865, 841, 471 | loadfile pointing at a directory |
| F8 | potential | P3 | Zone `option log '0.5'`: ucode truthiness of the double → jump chain + sflags; Rust log_bits()!=0 (truncated 0) → inline verdict | sections.rs:1071-1073, state.rs:214-216 | fw4.uc:2403, 2505-2508 | mock probe |
| F9 | potential (contradicts in-code comment) | P3 | Zone `list device '*'`: Rust drops the any-device entry from match_devices; by reading, ucode set() keeps null → prints `{ "br-lan", "null" }` | sections.rs:643-648 | fw4.uc:2202, 1702-1711, 1667-1672 | `print(fw4.set(["br-lan", null], true))` |
| F10 | potential | P3 | Include script killed by 30 s timeout/signal: Rust "exit code -1"; ucode system() returns negative signal number | input.rs:318-329 | main.uc:128-136 | include `sleep 60` |
| F11 | potential (reverse: ucode may abort) | P3 | `option monthdays 'foo'`: Rust accepts, prints "not supported"; ucode `(rv.days ||= [])[NaN] = true` may raise | parse.rs:883-897 | fw4.uc:1404-1410 | mock probe |
F1/F2 could be closed like R83 closed defaults/include ("abort like ucode"), ~10 lines each.

## 2. Overhead
1. Three ubus connections per run (interface dump, service get_data, device status under hw offload), each with its own lookup_id (input.rs:158-165, sections.rs:2057-2062, render.rs:564); fw4.uc uses one for the first two. Constant.
2. defaults() clones the whole Defaults per policy query (~10×/render, emit.rs:180-196). Negligible.
3. Zone cloned in three per-zone passes (render.rs:831, 909, 979); ipsets/limit zones cloned up front (render.rs:632-633). Negligible; device print 99.7→10.7 ms, check 148→61 ms.
4. /sys/class/net/<dev>/flags read uncached per device per match rule in four passes (emit.rs:141-148) — same as fw4.uc:1779.
5. rules(chain) linear scan per chain; section_id O(sections) — same complexity as ucode.

## 3. Checked, equivalent to fw4.uc
Option primitives (parse_bool/family/enum/port/mac/protocol/limit/mark/dscp/date/time/weekdays/monthdays/ipsettype/ipsetentry/identifier/includeposition/invert/subnet); parse_options machinery (REQUIRED, "must not be a list", NO_INVERT only on scalars, DEPRECATED/UNSUPPORTED, unknown-option warnings after success), section_id, warn_section formats; defaults (duplicate warning, syn_flood fallback, abort — R83 oracle-verified); include (fw4_compatible default, chain/position, readlink, auto-includes, abort — R83); zones (ubus data.zone networks, device wildcard rewriting, related_physdevs, family inference, match rules, masq groups, sflags/dflags, helper rules, auto_helper, mtu_fix gate); forwardings; rules (target guards, log prefix, ensure_tcpudp, icmp split, family inference, dscp, icmp type/code, set_mark/xmark, map_setmatch, chain selection, jumps); redirects/NAT (guard order, resolve_dest, reflection pairs and warnings, AF fallback; NAT masquerade default, snat_ip/port, srcnat chains); ipsets (match types, family, interval + kernel gate, timeout flag, loadfile parsing, print_setentries, reload-sets); read_ubus (l3_device, physdev, addresses, rule name formats, service/instance iteration); load() ordering; read_kernel_version; templates (section order, every chain, defines, limit, includes, rule/redirect fragments, zone jump/match/verdict/masq/drop-invalid/mssfix, handle_reject, syn_flood), quote/set/cidr/host/port, %.14g; offload (resolve_lower_devices, nft -c test, fallback); command surface (-q/-v, start/reload/restart/check/print/reload-sets/network/device/zone/includes/stop/flush, lock scope).

## 4. Unverified
- Loose `== null` for ""/"0" option values (fw4.uc:1623,1641,1303) vs Rust present values (val.rs:221-233, parse.rs:108-110); r29 WEIRD_STRINGS covers indirectly.
- F9/F11 depend on ucode runtime behaviour; F10 on system() convention.
- ubus non-string option values: ucode to_string vs Rust to_str (AUDIT_ROUND1.md:90 cosmetic spacing).
- ubus addresses lacking mask: Rust `0.0.0.0/null` vs ucode `null/null` (emit.rs:32-39); netifd always supplies mask.
- helper rules use ZoneRef; state file omits several zone fields (state.rs:192-195).
- UCI loading delegated to shared owrt_uci crate (uci.rs:1-6, 68-78), not re-audited here.
