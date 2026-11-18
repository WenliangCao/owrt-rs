# Antigravity audit-110 round: archived, not adopted (2026-11-18)

## What

An Antigravity (Gemini) session ran an "audit, fix, verify" round on
2026-11-17..18 and committed 120 commits on top of v0.3.3 (`0cbc328d`):
58 `fix`, 40 `perf`, 21 `test`, 1 `revert`, about +17.4k/-1.9k lines in
`components/`. The session ran out of quota while it was staging a device
benchmark. The full gate run and the device run never finished, and none of
the work was pushed or run through CI.

Decision: neither adopted nor deleted. `main` was reset to `0cbc328d`, and the
work is preserved for a future independent review.

## Where

- Git: annotated tag `archive/antigravity/audit-110-20261118` -> `983269e5`
  (range `0cbc328d..983269e5`).
- Local evidence (git-ignored): `private/audit-110-20261117/`
  - `oracle-evidence.tar.gz`: text outputs (json/log/rc/md/sh/py) from the
    oracle workspace, without rootfs overlays.
  - `oracle-bundle-md5.txt`: md5 of the before/after aarch64 binaries it
    benchmarked.
- Oracle workspace, left untouched: `oracle:/var/tmp/owrt-qual` (4.7 GB:
  `src-before`, `src-after`, `bundle-*`, `out/`, `ax3000t-stage/`).
- The router was never touched (uptime 25 days at archive time, no staged files).

## Its own oracle numbers (after vs v0.3.3, not device-verified)

Perf is net neutral. Headline figures in its chat (reload10 65% faster than C,
RSS -15% vs C) were already true of v0.3.3.

- Better, with disjoint ranges: dnsmasq udp-rules20 p50 -7.6%; joint reload10
  daemon CPU -11.8%; odhcpd update CPU -8.6%; idle CPU 0.25 -> 0 ms per 10 s.
- Worse, with disjoint ranges: dnsmasq tcp-hit CPU +3.2%; joint idle RSS +3.1%
  and anon +6%; odhcpd anon +16 KiB (+20%); binaries about +150 KB in total
  (netifd +36K, fw4 +28K, dnsmasq +28K, httpd +24K, rpcd +12K).
- Everything else is within noise (+/-3% isolated; its own joint/dhcp150
  calibration shows a 6-24% range).
- Churn: its last commits removed indexes it had added the day before.

## Before adopting anything from it

1. Review the `fix` commits individually against upstream C (they claim parity
   fixes in netifd route gating, rpcd `getHostHints`, procd respawn/stop state,
   httpd keep-alive/docroot, dnsmasq DHCP/DNS edge cases).
2. Cherry-pick only reviewed fixes and their tests; run the full gate on oracle
   and CI.
3. Treat `perf` commits as rejected unless a device benchmark shows a
   disjoint win without memory or size cost.
