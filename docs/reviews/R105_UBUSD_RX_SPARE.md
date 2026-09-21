# R105: shared spare receive buffer — rejected

The per-message wrapper candidate `99dffae3…` is rejected and removed from the working runtime. Accepted production-candidate source remains R103. Production on the router remains original C.

The hypothesis was to retain only one empty 4096-byte read-ahead buffer across clients, keeping fragmented frames and descriptor marks with their client. It passed 41 physical-router tests, seven C/before/candidate protocol differentials, and all six supplementary host functional/recovery gates. The accepted control rebuilt byte-identically.

## Independent CPU recheck

Ten physical-router windows ran two independently started daemons pinned to CPU 1 and the exact-image libubus caller on CPU 0. Each scenario used one ABBA and one BAAB quartet, 5000 measured sends and 2000 warmup sends per segment. Four equal-size segments per side were aggregated into one ratio per window. Slots alternated across windows. Requests and segments are not independent statistical samples.

The 12 planned median intervals use exact binomial rank bounds with Bonferroni family coverage of at least 95%, under independent identically distributed block-ratio assumptions. At n=10 this selects minimum/maximum bounds (each marginal coverage 99.8047%). Values are candidate/R103 changes.

| Scenario | Daemon CPU median (interval) | Total CPU median (interval) |
|---|---:|---:|
| user_1_1 | +2.30% (+1.56% to +6.07%) | +1.12% (+0.52% to +4.21%) |
| user_8_1 | +1.22% (+0.81% to +1.92%) | +0.58% (+0.31% to +0.96%) |
| user_1_0 | +1.40% (-0.83% to +2.38%) | +0.70% (-1.72% to +1.56%) |

The one- and eight-object matched lanes exceed the frozen 1% median daemon-CPU limit, with every window adverse and both intervals entirely above zero. Total CPU also increased. The unmatched interval crosses zero and remains unresolved; it is not equality. Caller CPU and wall intervals cross zero in all scenarios. This independently confirms enough regression to reject this variant; there is no need to clear the remaining query recheck gates to retain it.

## Memory and matrix limits

The [held-connection series](r105-rx-spare-memory-results.json) reduced 64-connection RssAnon from R103 402 KiB to candidate 100 KiB; C/R89 were 118/82 KiB. Candidate VmData was 116 KiB versus C/R89 96/92 KiB. Idle/no-client anonymous residency also increased versus R103. The [query matrix](R105_UBUSD_RX_SPARE_MATRIX.md) retained lower daemon-CPU medians than C/R89, but end-of-matrix anonymous residency increased from R103 168 KiB to candidate 172 KiB (C 144 KiB). These proc snapshots do not establish precise PSS or peak superiority.

All ten recheck windows passed protocol, process identity, CPU masks, exact-image library identity, same boot/configuration/host mounts, stock production and cleanup checks. A prior attempt failed its initial SSH health check before creating any remote test directory; it was archived separately, then same-boot stock health and no test artifacts were verified before starting this fresh complete series. It contributes no sample.

Evidence: [preflight](r105-rx-spare-preflight.json), [matrix](r105-rx-spare-matrix-results.json), [initial event screen](r105-rx-spare-user-event-results.json), [frozen independent plan](r105-rx-spare-event-recheck-plan.json), [all recheck data](r105-rx-spare-event-recheck-results.json), [rejected patch](r105-rx-spare.patch).

Next: localize the extra receive cost before changing ownership granularity or code generation. The experiment rejects a per-message wrapper, not every shared-buffer design. Method storage, remaining receive allocations, precise C/Rust memory and combined-system validation are still open. No Rust/C language-limit inference is supported.
