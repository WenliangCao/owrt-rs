# Post185 original SDK execution

The frozen sequence completed once: 7c diagnostic SDK, original standalone
allocation fixture, original four parser tests, then 6ab combined SDK. All six
commands exited zero. Both outputs remain `built-unqualified`; performance,
runtime hardening and complete compatibility acceptance are pending.

| Source | SDK ELF bytes | SDK APK bytes | Original 2,200,000 / 1,200,000 budget |
| --- | ---: | ---: | --- |
| `7c5b4c586e571eae875a0cb0e1ebfc88e2e1e7db` | 2,366,235 | 1,264,206 | **FAIL both**, excluded allocation diagnostic only |
| `6ab0f064b69087add3be1cb2bf5604fbaf42dffa` | 2,145,051 | 1,167,196 | PASS both |

The original builder `f4540b1c…` and helper `f280b97d…` were unchanged.
Both builds used opt3, empty features, Rust 1.98.1 and the original allocator,
linker, strip and packaging recipe. The 359 source inputs, Git identities,
ELF/map/APK/prestrip outputs, payloads and SDK tools were rehashed. Both ELF
files are AArch64 static PIE with RELRO, BIND_NOW, NX stack and no writable
executable load. These are static observations; runtime protections remain
unverified.

The standalone host fixture reproduced the exact original JSON
`2b3f4a07…`, including its deliberate unscoped negative control. All four
unchanged parser tests passed. This establishes the original host GlobalAlloc
accounting controls, without claiming musl SDK runtime or performance results.
Real diagnostic windows must still meet their original nested/unscoped gates.

The original helper completed its recipe restoration; both temporary backups
are absent and SDK inputs are unchanged. The pre-existing recipe's current
two file hashes are recorded. No pre-build recipe hash snapshot is claimed.
The controller exited, the original research/exact-C process scan was empty,
and all three build locks were available. The existing idle SDK fakeroot
daemon was identified separately and left untouched. Accepted G artifacts
remain unchanged.

The immutable download contains 46 rehashed files. Complete artifact IDs,
source manifests, command outputs and paths are in
[the execution result](post185-sdk-execution-result.json). Private binaries,
maps, source archives and raw logs are excluded from Git.

Five setup/review issues remain recorded: initial local archive file modes,
the launcher's string-path SHA error, an overbroad process predicate, an
incorrect postflight assumption that the restored recipe must be absent,
and local Python's unsupported tar extraction option. None caused a build or
control rerun. The initial archive was never uploaded; the downloaded result
archive was reused after the local extraction error.

Next is independent SDK review and artifact pretransfer, then an explicit
quiet handoff to the original native240/owner32 sequence and original full
44/67 compatibility plus boundary corpus. DHCP owns the independent physical
count3 and G/6ab ten-window work. No timing, router access or deployment was
performed by this SDK task.
