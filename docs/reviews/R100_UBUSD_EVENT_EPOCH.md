# R100: event deduplication epoch wrap

Status: correctness repair accepted after physical reproduction, release differential and all six host gates passed. No optimization candidate accepted or deployed.

## Defect and repair

The accepted `5a19517` implementation increments a `u32` dispatch epoch with wrapping arithmetic. Zero also initializes every new object's `event_seen`. When the epoch wraps to zero, a matching, never-delivered object is mistakenly treated as already delivered. This predates the R98/R99 optimization candidates.

At wrap, clear all object stamps and restart at one. Merely skipping zero is insufficient: an object last delivered in epoch one could then collide. The repair allocates nothing and adds no object fields. It traverses the registry once per roughly 2^32 dispatches, adding an ordinary zero check per dispatch. It does not change the separately maintained wire sequence number.

The exact image's upstream C revision `24864e7840b3a02a9ef76284a373f6b2f00b8a9b` uses `static int obj_event_seq = 1` in `ubusd_event.c` and an `int event_seen` in `ubusd_obj.h`. We do not infer a physical C overflow failure from this source, or treat overflow behaviour as a compatibility requirement.

## Evidence and limits

The diagnostic sets the internal counter to `u32::MAX`; it does not execute four billion events. Each test installs two matching patterns for one live listener and verifies exactly one INVOKE, including its header sequence and peer. Cases cover unseen stamp zero, old stamp one, and recent stamp MAX.

On the physical router the old diagnostic fails only the unseen case (zero received versus one required): two pass, one expected failure. The fixed diagnostic passes all 32 unit tests. A separately built release artifact passes the seven C/old/fixed wire differentials: object events, events, monitor, release, UTF-8, monitor lookup, and method ACL. Its associated SDK unit binary also passes all 32 tests on the router.

Both physical windows verify stock production identity, unchanged boot/configuration/host mounts, and complete cleanup. No candidate was deployed. Native tests and clippy are supplementary; clippy reports existing unused-import warnings in examples.

Release SHA-256: `042610fd90e592f93bf31a30b088141dac19d96da627975ba8e8aadb364aaa79`.

R99's interrupted seven performance windows remain separate and yield no acceptance decision. Subsequent candidate comparisons must use fresh artifact identities and complete independently frozen plans. The allocation/event candidate is being rebased onto this repair, not folded into the correctness change.

All six host gates passed: root/user functional, ACL, protocol fuzz differential, resource limits, and recovery. Machine-readable identities and clean-router evidence are in `r100-event-epoch-results.json`.
