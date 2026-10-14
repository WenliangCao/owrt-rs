# Frozen integrated candidate: 19bd6162

This candidate is **not accepted for complete resource-boundary closeout**.
Fresh validation found partial inotify publication without a held TCP connection.
The frozen source and ELF remain available for independent review; a successor
repair is being developed separately. No main merge, push, physical-router
operation, or task-branch deletion was performed by this repair session.

## Identity and preservation

- Source: `19bd6162e1b33c92a1e5ea26e864497800c7cfed`.
- Durable local tag: `audit/dnsmasq-full-19bd6162-20261014`.
- Oracle source: `/dev/shm/full-integrated-fix-20261014/private/source-final`.
- Oracle ELF: `/dev/shm/full-integrated-fix-20261014/private/release-final/dnsmasq-rs`.
- ELF SHA-256: `fbeabf4f5ffabfa5d6b5f4eec0c52540984fdabe882943ef165d5b990a9f7b4b`;
  2,089,440 bytes.

All 647 files under `components/dnsmasq`, `components/ubus`,
`packaging/openwrt/owrt-dnsmasq`, and `tools/dnsmasq` matched Git, with zero
missing or changed inputs. This is a scoped source archive, not provenance for
the other nine components in the broader integration audit. The downloaded
artifact archive was reopened locally and all 647 files plus the ELF were
independently rehashed against the same identity.

[Identity and test receipts](identity-19bd.json) include the build parameters,
test artifact identities, log hashes, and ignored local archive hashes. Source,
ELF, and complete logs are backed up under this worktree's
`private/final-candidate-19bd/`; no binary or raw device data is committed.

## Fresh source tests

| Test executable | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| Linux musl library | 789 | 0 | 20 |
| Linux musl binary | 78 | 0 | 3 |
| Native Linux allocator injection | 8 | 0 | 0 |

The musl test executables were freshly built from the frozen source using the
existing SDK build script, then run through `run_isolated.sh` with a private
tmpfs `/tmp`. Allocator tests used `cargo +1.98.1 test --frozen --test
hosts_allocations` in a separate target directory. Its first invocation failed
before compilation because the new target's parent directory was not writable;
that log is retained. After creating the task-owned directory, the same test
command passed. Ignored tests were not executed.

These tests do not cover all production incremental-publication allocation
boundaries. In particular, the old retained-owner test omits the no-held-TCP
incremental case and models ownership rather than calling the production
publication transaction. The runtime counterexample below takes precedence.

## Newly reproduced incremental boundary

With shared DHCP, no held TCP, 2,000 initial hosts, 6,000 replacement hosts,
and that process's VmSize plus 1,024 KiB as RLIMIT_AS, the first inotify update
reached source EOF and encountered allocation failures while assembling the
replacement. The old names disappeared; the first and middle new samples
existed but the final sample did not. Removing the limit without another file
event retained that partial view. A later successful close-write restored a
complete generation. The original repair-side case and three repetitions
showed the same failure. The independent audit also reproduced it.

The process exited normally, and configured/lease DNS, TCP and DHCP remained
healthy. This is a partial-publication failure, not evidence of a crash or
service outage. Exact C published both complete generations with zero ENOMEM
in the corresponding 6,000-row/+1,024 KiB case. Unrestricted C/Rust controls
also passed with zero ENOMEM.

Repair-side evidence is under
`/dev/shm/full-integrated-edge-20261014/private/inotify-no-held-6000/`.
The cause is the incremental loop's unchecked `Hosts::insert`: it folds
allocation failures into a false return, continues dropping affected staged
records, and can subsequently allocate a publication snapshot of the partial
generation. A separate allocator diagnostic demonstrates that the old
no-shared-owner recovery path can also lose the local view after consecutive
publication and restore failures; that diagnostic is not presented as a
second daemon runtime reproduction.

## Other boundaries

Same-ELF TCP and trial receipts are recorded alongside this report when their
fresh runs complete. Earlier reports for `e2b07561...` and `d57280b8...` remain
historical evidence and must not be counted as this candidate's validation.
The repeated-address rolling order difference is a separate pre-existing
compatibility issue: old/fixed Rust agreeing with each other does not establish
agreement with the exact C binary. Its attribution belongs to the rotation
investigation, not to this candidate's passed source-test count.
