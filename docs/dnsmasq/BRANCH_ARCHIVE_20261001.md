# Retired dnsmasq task branches — 2026-10-01

The user's branch-cleanup rule is recorded in the project `AGENTS.md`.
Twelve completed task branches were retired after a fresh tip/clean-worktree
check. Every original tip was tagged before any branch deletion. Eleven
attached worktrees were detached at the same commit; the ordinary TCP reference
worktree was already detached. No worktree or ignored evidence directory was
removed. Original unmerged experiment code remains research, not product code.

The cache-rr, DO-pressure, malformed-generic and writeback tooling/report
patches are covered in main. Other historical TCP work is covered by ancestry
or equivalent patches in the retained streaming reference. Tags also preserve
the exact original identities cited by historical reports, independently of
cherry-pick equivalence. Use these tags when an older note names a retired
branch. Active work retains its branches until it is complete or retired.

| Retired branch | Original tip | Durable evidence tag |
| --- | --- | --- |
| `research/dnsmasq-cache-rr-gate-20261001` | `a390fc38a326` | `evidence/20261001/dnsmasq-cache-rr-gate` |
| `research/dnsmasq-do-lookup-pressure-20261001` | `85ec21c7f790` | `evidence/20261001/dnsmasq-do-lookup-pressure` |
| `research/dnsmasq-generic-malformed-gate-20261001` | `c6a11213ee79` | `evidence/20261001/dnsmasq-generic-malformed-gate` |
| `research/dnsmasq-tcp-cd-gate-20261001` | `79314881141a` | `evidence/20261001/dnsmasq-tcp-cd-gate` |
| `research/dnsmasq-tcp-cd-reference-20261001` | `e5ee74923ea1` | `evidence/20261001/dnsmasq-tcp-cd-reference` |
| `research/dnsmasq-tcp-partial-eof-gate-20261001` | `7ce2e138e302` | `evidence/20261001/dnsmasq-tcp-partial-eof-gate` |
| `research/dnsmasq-tcp-partial-eof-reference-20261001` | `7a4c8b2f38e5` | `evidence/20261001/dnsmasq-tcp-partial-eof-reference` |
| `research/dnsmasq-tcp-reference-20261001` | `df75fb4013ee` | `evidence/20261001/dnsmasq-tcp-reference` |
| `research/dnsmasq-tcp-stale-gate-20261001` | `ed0ab4028773` | `evidence/20261001/dnsmasq-tcp-stale-gate` |
| `research/dnsmasq-tcp-stale-reference-20261001` | `2b149faea56e` | `evidence/20261001/dnsmasq-tcp-stale-reference` |
| `research/dnsmasq-tcp-stream-import-gate-20261001` | `b9e3cea3243a` | `evidence/20261001/dnsmasq-tcp-stream-import-gate` |
| `research/tcp-writeback-gates` | `d9b2ba2793d7` | `evidence/20261001/tcp-writeback-gates` |

The retained dnsmasq task branches are:

- `research/dnsmasq-reverse-cache-candidate-20261001`: active reverse implementation.
- `research/dnsmasq-reverse-cache-gate-20261001`: active independent C/Rust qualification.
- `research/dnsmasq-tcp-stream-import-20261001`: latest private TCP reference,
  with unmerged implementation and resource decisions still pending.

The preflight, full commit identities and completed-operation manifest remain
under ignored `private/dnsmasq-rewrite/branch-retirement-20261001/`.
Other components' branches were outside this task's ownership audit.
