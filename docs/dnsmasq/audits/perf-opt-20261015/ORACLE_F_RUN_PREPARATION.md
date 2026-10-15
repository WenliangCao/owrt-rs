# Oracle F/E full run preparation

The prospective rules are unchanged from `F_E_NEXT_ROUND.md`. Source F is
`3a3d8e3e848b93b0309353acfa0033d0b01a7cd0`: accepted E plus the three selected
performance changes, with no new compatibility repair. E is the direct
comparison baseline. No historical results are pooled into these pairs.

The local tool archive was generated from frozen tool commit
`91409ea3d3c4b15274e7f3377558480828b320b9`; all seven file hashes match the
preparation manifest. Oracle `root/tools-fe` and `root/private/inputs-fe` now
hold those exact sources and nine exact tools/scripts. The new loadgen
`f7c7d8e9…` and cohort validator `70204209…` apply prospectively only. The old
input directory and E's earlier attempts were not changed. The stage receipt
is `oracle-f-staging.json`; staging did not launch tests or timing workloads.

F SDK ELF `b7926bcf39cd7f33b4f0c110315ddc1ad719b39427bec53430ea05aeacd781fc`
has 2,136,859 bytes. Its map is `75efe620…`, and full build receipt is
`9e0339be…`; source identity and the E ELF `8b8082b9…` were independently
rechecked at staging. Complete F correctness qualification is still pending.
No timing starts until that receipt is bound and the coordinator's exclusive
Oracle reservation is active. The router run belongs to the separate DHCP
owner and may run concurrently only under the existing authorization.

The exact launch command is recorded in the stage receipt. It runs the
original complete controller with output `root/private/oracle-f-vs-e`, which
must not exist; E and F SDK paths are explicit, inputs are `inputs-fe`, and
CPU is 2. No `--smoke`, scene selection, altered rate, duration or statistical
rule is used. The original order is eleven scenes, five alternating E/F
pairs each, 110 windows. A new launch receipt must bind complete qualification,
all executable/tool hashes, command and process identity before the first
window. No other Oracle build, profiler or diagnostic load overlaps timing.

The unchanged controller keeps each active workload in its own process group
with a 100-second deadline. Its private temporary directory is under `/tmp`
because the frozen lifecycle helper requires that path. After every attempted
window, including failures, `archive_window` records every regular file hash,
creates the per-window tar archive, copies the full window into the external
private `runs` directory, verifies the copied hashes, and only then removes
that temporary window. No raw artifact or binary enters Git.

After all original windows finish, independently verify:

- Progress contains the exact 110 labels/order and expected side identities.
- Every tar digest, archive member set and regular-file content matches its
  per-window manifest and external `runs` copy; no unexpected link or unsafe
  archive path is accepted.
- Every frozen source/tool and both product identities remain unchanged.
- The unchanged analyzer rechecks each window's raw files, complete cohorts,
  CPU endpoints, resource samples and original statistics.
- All original failures remain visible. A tool-invalid pair supplement is
  considered only after the original 110, under the separately frozen
  symmetric one-replay rule; product failures never qualify for that rule.
- The controller and its owned workload processes have ended; all needed raw
  evidence is archived before any later cleanup of owned temporary copies.

Only small derived status/results transfer during a concurrent router run.
Raw archives remain on Oracle until the coordinator releases any transfer
restriction. This preparation is not a qualification or acceptance claim.
