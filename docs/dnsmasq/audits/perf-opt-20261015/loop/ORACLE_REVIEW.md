# Oracle runner and build-control review

Reviewed the root runner, frozen case script, validator, analyzer and retained
measurement binaries before the 110-window candidate run. This review accessed
no router. [Receipts](oracle-runner-review.json) bind the reviewed files and
the two explicitly authorized, excluded smoke windows.

## Confirmed blocker and fix

The unchanged `device_perf_lifecycle` calls `realpath` and rejects a working
directory outside `/tmp/`. The original Oracle runner placed all windows under
`/home/ubuntu/.../runs`, so its 40 lifecycle windows would fail. A `/tmp` symlink
pointing back into `/home` would still fail the realpath check.

Fix `ce87b715` uses a uniquely created actual `/tmp/dnsmasq-perf-oracle-*`
directory. Only the generated case script's output-directory assignment is
redirected there. Every completed or interrupted window is archived, copied
back to the private output root and checked against its complete raw-file hash
map before its scratch directory is removed. Exceptions from validation no
longer prevent a failed window's archive/progress record. Empty and partial
failed-window archive controls passed locally.

No measurement binary, source workload, rate, duration, iteration count,
statistical rule or product input changed. The original case allowlist remains
restricted to the runner's exact private output directory. The inherited
session/process-group leader survives `nice10` and `device_perf_netns` execs;
the shell's PID/starttime/PGID ownership checks therefore remain applicable.
The controller's 100-second deadline kills only its own process group. Oracle
uses an owned controller PID as the guard, not a claim of router health checks.

## Executed smoke and compatibility

The new `--smoke` mode ran one complete UDP-hit window and one complete
startup-small window, both using the original deployed `8472be5a…` artifact.
UDP warmup/measurement completed 1000/4000 requests without errors; lifecycle
completed all 20 iterations with 8 hosts and 6 leases. The unchanged helper
accepted the actual `/tmp` realpath. The result explicitly records
`smoke_only=true`, `complete=false`; none of its timing qualifies a candidate.

Both archives and all 43 + 15 raw members were verified locally. The lifecycle
and DNS daemons, all owned measurement executables and controller were absent
after completion; the archived scratch directory was removed. Root-owned
0600 daemon/stderr logs cannot be copied by ordinary recursive SCP. Their
already-created archives are readable and were copied, safely extracted and
rehashed; that is the recommended transfer path for the full suite.

Read-only Oracle checks found `/bin/sh -> dash`, `/usr/bin/time`, BusyBox and
all case utilities present; the script does not require BusyBox-only syntax.
`CLK_TCK=100` matches the analyzer assertion. The deployed artifact and all six
copied measurement tools are static AArch64 ELFs with the frozen manifest
hashes. Namespace setup uses direct syscalls, so it does not depend on `ip`
command syntax. Existing loopback checks fail closed. No further environment
blocker was found. The independent correctness agent owns the separate full
device-baseline raw/health audit.

The analyzer retains nearest-rank latency, no p99 below 10,000 samples,
five alternating pairs, full-range W, at least four agreeing pairs, CPU
10-tick minimum and greater-than-8-tick difference, and the 1-ms lifecycle
resolution. Smoke cannot produce its required 11 complete scene comparisons.

## Build-layout control

[Build identities](build-control-review.json) show that deployed `8472be5a…`
and source-baseline SDK control `2bf38171…` share accepted product digest
`10f7c0b1…`, but differ as files. The control is 2,128,667 bytes versus 2,124,571
bytes: +4096 bytes (+0.193%). Its executable LOAD extent is one page larger;
the RW LOAD's file/memory sizes are unchanged, with offset/address shifted by
one page. Both are AArch64 static PIE without an interpreter.

Current control and historical Oracle `50e591a9…` receipts have identical
Rust 1.98.1/LLVM 22.1.8 version text and all 106 SDK input hashes. Canonical CI
uses x86_64 Linux, while the current compiler receipt records native AArch64
Linux. Research paths, linker-map output and cache-retention settings also
differ. Exact deployed-CI compiler binary hashes were not recovered here, and
the cause of dnsmasq's LOAD-byte differences remains unproved. The older
httpd/ring host-kind investigation is not proof of a dnsmasq cause.

Keep `8472…` versus candidate as the primary 110-window comparison. A separately
labelled `2bf…` versus candidate series can isolate changes under the same
Oracle build process. Quantifying build-layout drift itself requires a
separate `2bf…` versus `8472…` measurement with the unchanged rules. No such
performance result exists in this review; source identity alone cannot
transfer or explain an artifact's measured qualification.
