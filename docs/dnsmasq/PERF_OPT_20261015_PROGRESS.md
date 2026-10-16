# Performance research continuation

Branch: `perf/dnsmasq-20261015`; worktree:
`/Users/USER/Developer/owrt-perf-opt-20261015`.
Starting main: `51b03959`. Do not merge main, push, or deploy.
Original main worktree has user prompt edits; leave them intact.

Current research status, 2026-10-16: G is accepted after complete correctness
and both110-window matrices. Its A53 UDP-hit CPU is138→116us versus E; a
separate direct C/G comparison remains82→114us.6ab has full functional PASS
but no discernible performance increment.803opt2 has actual957/SDK independent
PASS and awaits final quiet handoff to owner32/A53ten; bare1df is next.
See the latest section at the end for exact evidence and execution boundaries.
Production remains v0.2.0 SHA256
`8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7`.
The following sections retain the chronological evidence and superseded plans.
See `audits/perf-opt-20261015/FROZEN.md` and `frozen-inputs.json`.

Oracle initial observation: root 53 GiB used / 142 GiB free; `/dev/shm` empty,
12 GiB free. No cleanup needed to obtain space; no deletion performed. All
seven existing containers healthy, including vaultwarden/pocket-id/caddy,
with original September 24 start times. perf hardware counters available.
Matching SDK and exact image bases retained under `/home/ubuntu`.

Active directions (separate worktrees/branches):

- `perf/dnsmasq-dns-20261015`: DNS cache/name/answer allocation and copy cost.
- `perf/dnsmasq-loop-20261015`: UDP/TCP owner loop/syscalls/start-stop.
- `perf/dnsmasq-dhcp-20261015`: DHCP persistence/hosts loading and publication.
- `perf/dnsmasq-correctness-20261015`: immutable gates and independent review.

Root controls all router activity and Oracle timing reservations. Oracle task
root will be `/home/ubuntu/dnsmasq-perf-20261015`, separate agent subdirectories.
Raw artifacts/configuration/logs belong in ignored `private/` only.

Next: complete fresh base2 C/v0.2.0 suite; integrate screened DNS/DHCP/loop changes into candidate A, run independent complete correctness gates and Oracle full timing before device eligibility. Health baseline:125s,48 DNS samples,p95 0.753ms,max2.780ms;23 LuCI403 checks,max80.381ms;threshold200ms. F10 original reference fully restored to original raw SHA4021e120… and13 case SHAs without changing checker/qualifiers. Record every attempt in `PERF_OPT_20261015.md`.

## 00:32 CEST checkpoint

- Fresh device suite: `private/perf-opt-20261015/base2/`, controller stdout/stderr alongside. Tool exec session 68952. Prefix base2, all 110 planned windows; currently DNS mixed, prior hit/miss complete. Never mix old `baseline/` attempt (DISQUALIFIED.md) into acceptance.
- Router temp root `/tmp/dnsmasq-perf-20261015`; production daemon PID3086/starttime2115/hash8472…, PID3082 is ujail. Device guardian is per-scene with unique timestamp suffix. No production operation authorized.
- Candidate A product snapshot tag `perf/dnsmasq-candidate-a-20261015` at `a7164697ba8d27e8bea2e37a7f1c783533acb240`: DNS1/2, lease hex/canonical key, TCP framing, UDP borrowing and upstream poll scratch. No DNS3 stack, no hosts map removal.
- Oracle immutable A `/home/ubuntu/dnsmasq-perf-20261015/root/source-a`; baseline source `root/source-baseline`. SDK builds in progress: `root/private/sdk-baseline-control`, then `root/private/sdk-a` (tool exec88215). Unchanged recipe/profile, linker-only Map wrapper, stable `root/private/sdk-build-slot` and shared dependency cache `root/private/sdk-cargo-target`. Native-host baseline differs from canonical deployed ELF; preserve original8472 as primary. Need measure/record matching build control to separate build layout effects. First SDK exploratory run `sdk-baseline-native` retained as harness-failed after successful package because SDK autoremove deleted optional prestrip ELF; timestamp argument also was not source epoch. New run uses correct epoch and disables only build-cache deletion, no codegen change.
- Correctness agent has recovered original F10909279B JSON rawSHA4021e120…/canonicalc927… and original native Cbba5… exactly. Baseline ordinary/namespace/config/allocation924 tests, F10,368protocol,TCP all pass. Three44-family preflight groups complete; prepare all44 for exact candidate A SDK ELF+same-build map. Old native target metadata recovery still being handled without changing C expected stdout.
- First native Oracle micro timing completed: DNS1/2 up to15.2% local API improvement, DHCP D1 serializer46% instrumented micro improvement. Device gains unclaimed.
- Rejected/pending: DNS3 stack reduces common instructions but400configured-CNAME micro +2.43%, excluded A. Hosts D3 map removal load−23% but presence+37–83%, rejected. D3b representative-map deletion+7.43%, not accepted; D3c next-index chain in research. D5 batched prefix+22–27% instructions, rejected; single-sort subchange pending. Empty shared cache blocks rejected because first-insert infallible allocation moves OOM boundary. recvmmsg saves calls but preserving deferred error needs extra getsockopt and loses benefit.
- Second batch in progress: DNS agent `perf/dnsmasq-cache-20261015` worktree owrt-perf-cache-20261015 does blockwiseCache::clear (same COW/drop order, no new representation). Loop agent `perf/dnsmasq-loop-exit-20261015` does terminal pure-cache-memory retirement after all explicit cleanup (independent mechanism review passed; IO Drops retained). DHCP agent does D3c/D4publication/single-sort.
- Oracle timing is idle; agents currently allowed1-job compilation, correctness and counters. Root must reserve a globally quiet slot for full timing before any candidate reaches router. `tools/dnsmasq/perf_opt_oracle_run.py` mirrors all11 frozen scenes, fivepairs, CPU2, isolatedloopback. It is prepared but not run.
- Root offline analyzer `perf_opt_analyze.py` rechecks hashes/counts, nearest-rank latency, W/4-of-5/CPU precision, memory/FD and DORA (home6 not ranked). Reviewer checked formulas; full raw independent audit still required.

## Correctness hold / B build checkpoint

Candidate A is NOT qualified: unchanged `stale_metadata_diff` reported two of1100 observations differing only in stale metadata for `cname-nx-q1-at-110`, profiles finite/min-max (C T0 vs Rust T1). Reviewer is reproducing source51b03959 with the same C fixture; no expected result or exemption changed. A cannot go to device even though928other tests/F10/368/TCP pass. Full44 continues for breadth. B inherits A and is also unqualified until this is resolved and every frozen gate passes.

B product tag `perf/dnsmasq-candidate-b-20261015` = `9b91a192583282fa546811977ee124d5873dd2db`, epoch1792017878. Adds blockwise cache clear, reuse uniqueempty roots, terminal pure-cache-memory retirement, hosts count index, lease-publication key borrowing. Exact source snapshot `root/source-b`. Only use Git-bound SDK output `root/private/sdk-b-git-bound` once status is built-unqualified; previous sdk-b/sdk-b-verified/sdk-b-final are retained harness attempts (incorrect caller metadata, existing cache symlink, recipe-target shadowing respectively), never qualified artifacts. Source Git blob+epoch binding now checked before SDK work; frozen performance/correctness comparators remain unchanged.

DHCP plain quiet (4cases×5pairs) accepted D3d/D4: 8hosts−4.40%,1000hosts−9.50%,clone+remove+0.42% withinW1.81%,publication−6.36%. All old rejected variants remain separate. New C research uses actual SDK2bf/b353 profile: names_for~15% of instruction samples, exact380B function range; investigate repeated FNV+SipHash work without changing randomization/side effects. Loop metrics gating rejected at0.046–0.124%samples. DNS4 question validation skip rejected at~54instructions/query(<device variation).

Base2 device current51/110 completed valid (DNS5 groups complete, DHCP6 started). Main analyzer verifies raw hashes/counts independently; no production health failures. Per-window archive+hash copies retained. The root task must still finish baseline, all finalist gates, serialized full Oracle timing, qualified device comparison, stop-evidence research, and final cleanup/report.

## Pending user boundary decision (01:00 CEST)

Root drafted independent compatibility fix `b1136023050853e918a3671704d27c8687921356`: guard onlyNX terminal stale contribution withCache::is_valid; no earlyprune/LRU and no blanketNone reset. New finite/min-max unitpassed; independent fresh1100 corpus now1100/1100 (oldA/base1098/1100). Reviewer proved existingv0.2.0 external defect withlive exactC: afterexpiredNX+configuredTXT terminal, CemptyOPT/noextraquery;8472 emitsEDE3+extra backgroundquery. Therefore fix is NOT externally transparent. User has been asked via async tool whether to allow this independent C compatibility fix despite original “functionality completely unchanged”; reply pending. Do not silently adopt it or waiveC expectations. Rootmain currently contains draft fix, but frozenB tag/source-b remain pre-fix. Other optimization work and original-file device baseline remain authorized.

Git-boundB SDK completed: `root/private/sdk-b-git-bound/dnsmasq-rs`, SHAa6ad4f1c0091d4656a2d52af855eaafac9daf6356aedc0011a00fabb37d6ef0a,2128667B, same-build map/receipt. Earlier mislabeledB build producedsamebytes; onlyGit-boundreceipt may beused. It is unqualified because inheritingstale gate.

A928 shorttests plusF10/368/TCPpassed; full44 stillrunning. Correctness hasnew`run_family_gates.py` originalrunner-per-family scheduler, independentlyreviewed byroot with duplicatejobcount/Cidentity strengthening requested; PAUSE onlybeforefamilies. C additionaldirections: names_for safeephemeral lookuphint (Bfork, initialwholeAPI−10.31%hit/−18.45%miss but8RR+1.87%mustaddress); UDP source sockets create atomicNONBLOCK/CLOEXEC (actualAmiss5000each ioctl+fcntl proven, potentially2syscalls/query); LeaseNames inline-one index andimmutable sharing prototypes. No C candidatequalified yet.

## Resume, 2026-10-15 10:03 CEST

User explicitly authorized independent `b1136023` C compatibility fix and
continuing full qualification. The pending-boundary section above is superseded;
frozen C expectations remain unchanged.

Recovered detached base2 completion: all 110 windows completed at 01:20 CEST,
110 valid, all raw file hashes reverified, no parse failures. Complete derived
results in `audits/perf-opt-20261015/baseline-summary.json` and report table.
All 11 guard segments stopped normally; 252 external HTTPS checks passed. One
terminal HTTP probe was cancelled at requested guard shutdown, never a pass.
Original deployed PID3086/start2115/SHA8472 remains live. No active measurement
process on either host at resume. Oracle135GiB root free/12GiB shm free. No cleanup.

Four resumed agents own correctness, DNS cursor2, atomic socket/residual loop,
and lease D6/D7 publication. Root next: combine refinements after quiet micro
timing, freeze C with approved fix, Git-bound SDK build, full Oracle workloads
and immutable correctness gates, then device eligibility.
A full44 completed; independent review found original UBus checker registry
expects350 paired observations but suite hardcodes346. Investigating unchanged
inputs/history, no C expectation modified, no qualification claimed.

## Authorized UBus metadata correction

User explicitly approved the reviewed two-number registry repair350→346 during
this continuation. Applied exactly the proposed patch; C fixtures/comparators/
assertions/negative controls unchanged. Original freeze manifests remain intact;
`correctness/ubus-inventory-amendment.json` binds both hashes, patch and consent.
The fresh finalist still requires all44families; this is not a gate waiver or
retroactive A/B pass.

## Selected mechanisms and harness readiness, morning continuation

User authorized autonomous necessary research/bug/tool fixes with small commits;
continue performance mainline without repeated routine approval questions.
Original no deployment/main merge/push boundary remains.

Root integrated atomic UDPflags95403890 (six factory controls, independent
review), D6 f2c5ce8b and D7 b4532991 (combined complete ownerpublication15–18%
quiet improvement, no discernible lookup regression). Local all-target compile
passes;703lib tests pass/8existing ignored. These do not replace frozen Linux
and exactC gates.

Cursor2 rejected: configuredCNAME+8.54% versusW0.17 despite hit−13.12%/miss−21.92%.
Retain all timing, investigate allocating alias scan independently. DNS insertion
nonallocating size/clone variant under quiet screen; DHCP same-call hosts bucket
variant has a multi-record lookup counter concern and is not selected.

Oracle full runner lifecycle helper requires real /tmp directory. b6fcc0c9
uses owned /tmp scratch, verifies archived persistent copies before cleanup,
retains interrupted windows, and marks explicit2window smoke asnonacceptance.
Both full-duration baseline smoke windows passed. Correctness scheduler bd8eb22f
permits3 isolated families concurrently and preserves exact44families/67jobs;
full timing remains globally exclusive.

## Candidate C freeze and next execution

Tag `perf/dnsmasq-candidate-c-20261015` identifies the product snapshot after
this checkpoint. Includes all screened A/B mechanisms, separately authorized
stale fix, atomic UDP flags, D6/D7 immutable lease publication, D8 same-call
hosts hash, cache insertion discarded-copy removal, and alias-allocation removal
plus independently re-screened cursor3. Original cursor2 failure remains.
Local integrated lib:709pass/8existing ignored. Full Linux gates not transferred.

Oracle immutable snapshot: `/home/ubuntu/dnsmasq-perf-20261015/root/source-c`;
SDK output: `root/private/sdk-c`; shared build-slot/cargo-target unchanged.
Root creates Git archive plus exact Git blob inventory before calling
`perf_opt_sdk_build.py` with this tag's commit/epoch. Correctness agent builds
tests from same source while SDK builds, then all loads pause for full110window
Oracle timing. Afterwards fresh44families/67jobs use bounded3worker scheduler.
No device eligibility until full timing and complete correctness qualification.

Known frozen lease insertion corpus retains two documented originalC UID-reuse
wrong-target differences. Original comparator/raw/exit1 remain untouched. Under
user's broad repair authorization, reviewer is deriving a separate narrowly
bound contract audit with original-v0.2.0 equivalence, independent correct-target
assertions and adversarial controls. New/unclassified differences must fail.
Report must explicitly distinguish raw exactdiff from qualified C defect.

Baseline110completed router windows were copied and independently verified
(110archives/3430files), then their unchanged remote inventory was rechecked
and ONLY those owned /tmp window directories removed. Local archives and
extracted evidence remain. See baseline-prune-receipt.json. Production files,
configuration and processes were not modified.

Research is not at a stopping point: current full-cache insertion still scans
capacity. DNS agent will examine conservative expiry-bound direction locally
while C timings run, using current interfaces/mutators and historical EPS1
evidence without importing old implementation wholesale. No Oracle load during
exclusive timing.

## User priority and running C screen, 10:40 CEST

User reiterated C through complete Oracle timing +44families then fresh device
comparison is first priority. Only blocking or real-use bugs may be fixed;
no workflow expansion. The two existing UID-reuse C discrepancies are expressly
nonblocking and must only be recorded. No new qualifier/audit framework. Draft
qualifier work was retired unexecuted/uncommitted under private; original
comparators/rawexit1 retained. This supersedes earlier qualifier proposal.

C SDK SHA `b4c4a8e40698feb7aa57da09699bb2988ac1cf4bb54345474a9f659a12edcda1`,
2,136,859bytes (+12,288/+0.578%vs deployed), within existing budget. Exact build
manifest/map/ELF copied locally to private/perf-opt-20261015/sdk-c and hashchecked.
Source f7f7a2edd9f2ecfac72953e43cfc873a354b468b. Linux shortgates941passed/0failed:
824lib+81bin+17allocation+16ignorednamespace/config+3ignoredbin. Four frozen
corpus probes pending and will run after timing.

Full110window Oracle screen launched10:40CEST detached controllerPID4043998.
Output `/home/ubuntu/dnsmasq-perf-20261015/root/private/oracle-c`, stdout/stderr
and launchreceipt alongside. Baselineexact8472 vsCexactb4c4,CPU2; all other
research workloads paused. Initial3windowsvalid. Poll progress.json/failure.json/
complete.json, independently derive fullresults; never select replacement windows.

Immediately after timing release, correctness agent launches source-c's
`run_family_gates.py --jobs3 --source <root>/source-c --elf <root>/private/sdk-c/dnsmasq-rs
--link-map <root>/private/sdk-c/link.map --commit f7f7a2edd9f2ecfac72953e43cfc873a354b468b
--base-identity <task>/correctness/private/family-base-identity.json
--out <task>/correctness/private/c-families-attempt1`, plus existingF10/TCP/protocol/
fourcorpus probes. No new C differences permitted; knownUID2 explicitly recorded.
Then qualifiedC goes to router using same110window frozen B/N comparison.

D research paused until C device comparison completes. Exact preserved Dtip
9f2a905289c6c009edd747abc590a1d013b114e5, activeperf/dnsmasq-expiry-20261015
worktreeowrt-perf-expiry-20261015. Notintegrated;41localcachetests passed,
noOracle/Cdiff/perfqualification. OldDNSbranches archived/detached with private
evidence retained; cleanDworktree intact.

## Clarified bug policy during C timing

The user's latest clarification supersedes the narrower blocking-only wording:
any genuine product defect (C behavior mismatch, crash, leak, unbounded resource
use or incorrect error handling) should be fixed autonomously. Each fix needs
its own commit, reproducer and relevant correctness gates, and enters the NEXT
candidate for fresh timing. Never change frozen C during its run. Fixes and
performance changes remain separate in reports. C's own errors/already recorded
differences do not justify new audit rules/frameworks; testing tools stay limited
to acceptance needs. C full Oracle+44families+device comparison remains first
priority, then next optimization iteration resumes.

## C Oracle complete / full correctness running, 11:33 CEST

OracleC110/110valid, nofailure, all110archives and extractedfilehashes verified
locally. Raw+analyzer JSON in private/perf-opt-20261015/oracle-c*; derived summary
committed under audits/oracle-c-summary.json. No p50/p95/CPU regression meets
frozen discernibility criteria.150DHCP CPU732→544µs/op,−25.68%W24.59%,5pairs,
precisionpassed; all otherprimarymetrics inconclusive. No deviceclaim.

Correctness started immediately after complete marker:44family schedulerPID4064310
output`<task>/correctness/private/c-families-attempt1`,3workers. Fourth-slot batch
PID4068233,`c-remaining.log` and`c-remaining-state.json`: releaseprobe build,F10,
protocol,31existing checker tests,TCP3groups,fourcorpora. Exact sourcef7f7a2ed /
shippingELFb4c4a8e...; no new framework. KnownoriginalUID2rawexit1 recorded per
user; any newfailureblocks. Once fullcorrectnesspasses, stage C only under
router/tmp and run110fresh deployed/C pairs with original guard and workloads.

## C qualified and DEVICE running, 12:10 CEST

C complete44/44families and67/67uniquejobs passed with all rawresult hashes
reverified;941shorttests,F10,protocol,TCP,all4corpora complete. Original
UID2rawdifferences remain explicitlynonblocking; no newfailures/retries.
Finalgate evidence c-full44-gates.json; product/source/ELF remainf7f7/b4c4.

Root staged only owned/tmp comparator files after verifying qualification,
all9frozen tool/script hashes and productionPID/start/hash. Baseline c-side
is exactdeployed8472; rust-side exactCcandidateb4c4. DetachedLOCAL controller
PID14903, outputprivate/perf-opt-20261015/candidate-c; stdout/stderr and
launchreceipt alongside. Prefixcandidate-c, originalhealthbaseline/threshold200,
same110window protocol. Initial9windowsvalid, nofailure. Poll localprogress and
failure/complete JSON; controller itself maintains production/externalhealth.
Never touchproduction; firstfailurestopsownedgroup automatically. No deployment.

Fresh exactC counter-only profiles now run onOracle using existingtools and
separate loop/private/c outputs (UDP hit/miss/mixed,TCPmiss,misssyscalls).
Noextra routerload; elapsed diagnostic timing is excluded. D product remains
unintegrated; use C device results and fresh profiles before next iteration.

## C complete failed attempt / D fullscreen active

C110attempts109valid; original TCPmiss-r2-rust13busy-client scheduling skips
remain invalid, no wrong/timeouts on3987sent. WholeCacceptanceFAILED; no
selective replacement. Complete data private/candidate-c-summary.json and
publiccandidate-c-device-summary.json. Independent all110archive/3430file and
11guard/256externalHTTPS audit passed. Valid-scene diagnosticgains:DHCP150
CPU/p50−33.6%,configp50−15.46%,largeHUPp50−15.52%,home6p95−5.33%;DNSinconclusive.
Earlier9.49MB transfer overlap onlyUDPmiss-r1-rust remains flagged separately.
All110ownedrouterCwindowdirs pruned after local+remotehashverification; first
SSHverification/deletecommand reset,all110stillpresent onretry,stdin retry
reverifiedthenremoved. Localraw includingfailure retained; pruningreceiptcommitted.

D selected onlyfor complete screening, preserving incrementalCNAME caveats
(+0.754/+2.836%vsCmicro). Nativepressure/expiry/staleCPU−80.30/−71.82/−79.94%;
allocationcontrolsidentical,Cache216→224B. Product9f2a9052/tagD, fullsourceGit
9f2 tree recreatedOracle root/source-d fromsource-c archive+16,340BfullGitpatch
and16,708B179-inputidentity; no bulknetworkcopy.

D first SDK root/private/sdk-d FAILEDpreparesourcehashbeforecompile: staleC
cache.rs/tests dueunchangedSDKpreparemarkers. Builderfix5e6c41f6 externaltool
copy root/private/sdk-builder-5e6c41f6, sourceDuntouched. Successfulreproducer/
regressionrun root/private/sdk-d-fresh-prepare:SHA4167609f5fe1c17a480f0a395fba1e3c15142f6c2ad7c3998d133a04829965e8,
2136859B(equalC),samelinkmap/buildreceipt.943shorttestspassed,releaseprobe ready.

FULLDOracle110exclusive began13:16:46CEST, detachedPID4188061; output
/home/ubuntu/dnsmasq-perf-20261015/root/private/oracle-d (stdout/stderr/launch
alongside), original8472baseline,CPU2. Latest38/110valid,nofailure. Noother
Oracleworkloads untilcomplete. Then startD44family --jobs3 and F10/protocol/TCP/
4corpora immediately fromsourceD/SDKfreshpreparepath; knownUID2onlynonblocking.
Dartifactnotdownloadedlocallyyet (deferbulk untiltimingends). Afterallgates,
freshDdevice110pairs; no reuseCnumbers asacceptance.

## D Oracle complete / correctness active, 14:15 CEST

D full Oracle attempt completed 110/110 valid windows, no failure marker.
All 110 archive hashes and 3,430 extracted files verified locally; exact shipping
ELF, same-link map and the public build-receipt fields match downloaded artifacts.
Local raw: private/perf-opt-20261015/oracle-d; SDK: private/perf-opt-20261015/sdk-d.
Full derived summary committed as oracle-d-summary.json (SHA256
39f42344986bcb1f0c5190b3ef956d28ee9f4138bdf35b0fa932852d32e14b02).
No primary metric regresses beyond frozen criteria. Discernible improvements:
150-client DHCP p50 2.941464→2.693102 ms (−8.443%, W8.324%) and CPU
760→544 µs/op (−28.421%, W8.421%); mixed UDP p95 1.25653→1.23325 ms
(−1.853%, W1.703%). Other metrics remain inconclusive. Parent/tree FDs unchanged;
DNS RSS differences are mostly file-backed, with UDP-hit anonymous peak +4 KiB,
TCP-miss +4 KiB; large-HUP anonymous peak falls 1,432→1,172 KiB.
Oracle is screening evidence, never a device performance claim.

Correctness agent verified completion before launching D full44 scheduler
PID13199 (--jobs3) and serial boundary/corpus batch PID13200. F10/protocol/TCP
and all four original corpora completed without new failures; known UID2 raw
exit1 retained. Full44 remains active. Fourth slot released to the existing
narrow readiness-count screen. No D device launch until complete qualification.

## Readiness count screen retains a concrete next direction

The existing bounded screen completed all 21 predeclared Oracle cases after
D timing ended, using only the fourth research slot. Deferred 14-fd versus
1-fd controls add 9,424–9,758 instructions/iteration; all three observed 1,000
not-ready prechecks and voluntary context switches, with coalescing retained.
An optimistic all-increment projection against separate C TCP-hit counts is
18.1–18.7% of instructions, not a CPU saving or rigorous bound. It is too large
to dismiss as below noise. No product backend is selected. Commit 930f5140
retains the complete counts and interpretation. Original-tool exact D profiles
are now running in that one fourth slot, while full44 keeps three workers.
No bulk artifact transfers during future D device timing. The next mechanism
must preserve file/descriptor kinds, duplicate masks, fd reuse, runnable work,
error handling and all existing owner boundaries. D remains immutable.

The frozen most-scenes improvement goal is still unestablished: D Oracle has
three discernible primary metrics in only two scenes; C's failed device attempt
cannot supplement D. Updated experiments ledger retains every prior decision,
C failure, D CNAME micro caveats, pending device qualification and open research.

## D full correctness failure, device blocked, 14:46 CEST

Full44 attempt1 ended with 38 families attempted/37 passed, 54 jobs/53 passed.
One original service case failed: m5_interface_records-service,
hostsdir-dhcp-name-effects / initial-helper:helper. Exact C callback names were
original→empty→fromhosts; D emitted original→original. Later updated-name helper
events and all DNS replies match. Both artifact identities, startup, exit0 and
cleanup pass. This is new, not the documented UID2 difference; D cannot reach
the device. Scheduler stopped dispatch and let active families drain normally.
No attempt/window is replaced. Commit27a86caa records original failure evidence.

The original reused test root does not retain a separate final helper.log after
later cases; original phase rows remain intact. Correctness will run exactly
nine diagnostic single-case observations (deployed/C/D, three each, rotating
order), with original fixture/runner and independent retained output, to
separate an existing race from D changes. Diagnostics do not qualify failed D.
DHCP owner reviews helper/hosts publication source locally; no product change
yet and no root-cause claim. Any actual fix receives its own reproducer, commit
and relevant gates, then a new immutable candidate and fresh full timing.

Exact D five-scene profiling is complete and verified (root7d8eca98): insertion
self-instruction samples fall to about0.57% in both miss scenes, without implying
paired CPU gains. The next narrow TCP aggregation primitive completed16 controls;
its total deferred instruction saving projects only7.16–7.89% against D TCP-hit,
below current CPUprecision before productbookkeeping. Do not implement that
productfork based on the ideal14-to-1 projection; all new primitive evidence
will be retained. This does not establish allreadiness costsirreducible.

## D device release withdrawn before launch, 14:59 CEST

All67 original jobs are now covered (65rawpass, service+itsqualify rawfail),
but D remains BLOCKED. The provisional interpretation as the previously recorded
HUP mixed-chain difference was premature. Offline actual-mapping reconstruction
fits all6 Rust observations, yet exactC original-namebucket2 precedes static59
and C stillrenames. Initial startup may not contain the same retained DHCP
nodes as HUP. Correctness andDHCP independently reproduced this counterevidence
and are reading exactC initialization/publication order; no new samples/seedsearch.
Do not finalize a43+1 qualification receipt or treat this as an accepted waiver.

Root copied exactD4167609f andoriginal8472 onlytoowned/tmp comparator paths after
freshproduction/9toolhashchecks. NO devicecontroller or Dwindowwasstarted; D has
not been measuredondevice. ProductionPID/start[3086,2115] andoriginalhash remain
unchanged. Launch was withdrawn immediately on the counterevidence. Any actual
startupdefect will receive a separate deterministicreproducer/fixcommit andenter
a newfrozen candidate withfulltiming; D itself staysunchanged. The stagingstep
is retained here to avoid mistaking stagedartifact presence for an executedtest.

## Confirmed startup defect; separate E repair in progress

MatchingC source establishes the actual boundary: lease_init restores/prunes
andmarks dns_dirtywithoutpublishing; firstdo_script_run freezesoriginal;
EVENT_INIT executescache_reload→lease_update_from_configs→firstlease_update_dns.
Ruststep_dhcp_files→initialize→maintain(forceDNS=true) publishesoriginalearly;
initialhostsdirbulk theninheritsDHCPnodesandcan suppressrenamebybucketorder.
This is a genuine pre-existingRuststartupdefect exposedbyDlayout, nottheoldHUP
mixed-chainexception. No additionalrandomsamplesare needed. Dremainsfailed and
immutable; allrawservice/qualify failures remain. A separateEfix mustdeferonly
firstDNSpublication, keeptheoriginalpre-INIThelpercallback, preserveHUPmixedchain
semantics, andinclude deterministicregressioncoverage forbothrelativebucketorders.
DHCPownsfix innewworktreebasedonD, DNSreviewsRustchanges, correctnessbindsexactC
andrelatedgates. NootherproductoptimizationiscurrentlyselectedforE; behavior
repairwillbe reportedseparately fromD'sperformancemechanism andfreshwholeELFtiming.

## E frozen after independently verified startup repair, 15:14 CEST

Behavior-onlyrepair4f869c885b47dcf60d56c872e5b0b3c62237beea is tagged
perf/dnsmasq-candidate-e-20261015 (rootcherry-pick aca71a51). AgainstD itchanges
only17main lines andadds113lines ofdeterministicownerregression. Coldinitial
hosts bulk excludesprovisionalretainedleases usingtheexistinginitialization
latch, includingHUPbeforefirstpublication; runtimeHUPstillretainsleases. Itdoes
notdelayproviderinitialization orfirstfrozenoriginalhelpercallback, andadds
no state/API/heapallocation. LazyemptydefaultavoidsruntimeHUPwork.

Linuxbefore(afteraddingonlytest)fails exit101 exactlyin thetwoDHCP-firstcold
branches; all6sceneoutcomes retained. Fixedtestpasses plus existingmodules:
7hostsdirinit+1initialHUP+4TCPimport=12passed. IndependentDNS/codeandcorrectness
reviewscompleted, receipts c26de50b/874c572e. FrozenDremainsfailed, no retro-pass.

E source /home/ubuntu/dnsmasq-perf-20261015/root/source-e recreated independently
fromsourceD +8,975BfullGitpatch, all179inputGitblobs verified; identity16,708B.
LocalMacsystemPython3.9 failedimporttomllibbeforeanymutation; explicitinstalled
python3.14 preparationpassed. SDKbuild PID122516 outputroot/private/sdk-e
launched15:14 with externalfixedbuilderroot/private/sdk-builder-5e6c41f6,
originalSDKflags/build-slot/sharedcargo-cache. stdout/stderr/launchjsonalongside.
Correctnessowns Eshort/alloc/namespace/probe andthenfresh44 --jobs3 plusfourth
boundary/corpusbatches. Avoidduplicatinginterfacefamilyoutsidefull44. Afterall
correctnesscompletes, rootreservesOracleexclusivelyforfresh110-windowEtiming,
thenqualifiedEgoesdirectlytofreshexactdeployed/Edevicepairs. D/tmpstageisnotE
andneverran; restage exactEhashonlyaftertheseprerequisites.

## E artifact and short/boundary gates complete, full44 active

E SDK complete SHA8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27,
2136859B (equalD/C); mapcbf8655450a025a51be7a3c8630fa84ff48aba5ca5c641a9a3f53fd0bf4637fd.
Localprivate/sdk-e retainsELF/map/fullbuildreceipt. All179receiptinputSHA256s
matchedGit4f869c88; publiccandidate-e-build.json committed. Buildflags unchanged.
944freshshorttestspass (826lib+82bin+17alloc+16ignoredlib+3ignoredbin), receipts
1aed7843. Source-boundreuseddebugbinsverified; allocationfreshbuild. Eboundary
batchbe11bb2e:F10 13/704,protocol368/366,8lifecycles,5negativecontrols,TCP13/50,
cache764/164/382,transfer307,stale1100,leaseonlyknownUID2; nonewfailure.

Full44once-onlyschedulerPID125922, outputcorrectness/private/e-families-attempt1,
--jobs3, exactsource-e/sdk-e, startedabout15:17CEST. FourthslotbatchPID127963
finished; Oraclehasnootherresearchload. Latest5/44families,6/67jobs,no failures.
Afterall44/67 pass, rootmustverifynewreceiptandthenlaunchfull110exclusiveOracle
comparisonoriginal8472/E8b8082b9 atroot/private/oracle-e. NoE timingyet. Localand
router DstageisnotE; noDtestwaslaunched. Edevice followsfulltiming+qualification.

## E complete correctness; exclusive Oracle timing running, 15:54 CEST

E passed all44/44 originalfamilies and67/67uniqueoriginaljobs RAW, no failures,
pauses orretries (2065.11s). Independent hashesofall44family+67jobresults and
immutableinputs rechecked; rawresultSHA c132ab5c39517fbf72355eae9c97a64d781d66888e2208ece368458427d9f01a.
Originalinterface276service/qualified288/closeoutsallpass; originalfailedhelper
case exactC/Eoriginal→empty→fromhosts andlaterupdatedevents match. No startup
exception. Finalcorrectness receipt e-full44-gates.json (agentb5f68b57), plus
944shortandF10/protocol/TCP/4corpora complete. OnlyoriginalexplicitUID2 rawcorpus
boundary remains nonblocking. Eartifact8b8082b9, source4f869c88 unchanged.

Root launched detachedexclusiveOraclefull110 controllerPID225895 at15:54:31CEST.
Output /home/ubuntu/dnsmasq-perf-20261015/root/private/oracle-e; .stdout/.stderr/
.launch.json alongside. Original8472baseline versusE8b8082b9, CPU2, samefrozen
measurementtools/controllerhashes. Ebuildreceipt matchedlocalcopy; all6measurement
binaries matchedD'sfrozenidentity. Correctness/allotheragents idle; nobuilds,
profiles,testsorbulktransfers duringtiming. Poll onlysmall progress/failure/complete.

After110complete: copyallarchives/manifests/identity/progress/complete/controller
logs, verifyarchiveSHAandsafeextractedfiles; runoriginalanalyzer; independently
reviewallmetrics/resources. OnlythenrootstagesE (routercurrentlystillDartifact
fromabortedprelaunch, noDwindows) andrunsfresh110deployed/Edevicepairs. Nochange
toloads/thresholds/windowreplacement. AlllocalSDK-Efiles alreadydownloaded and
verifiedbeforetiming. Remainingreadinessaudit islocalonlyandunselected; do not
resumeOraclework untiltimingcomplete.

## User-authorized parallel E device/Oracle validation and active research

The user explicitly changed the scheduling and ownership boundary: start E
on the router now, concurrently with Oracle timing, delegate one agent per
measurement host, and use root plus two agents for local next-round research.
This supersedes the earlier root-only router and Oracle-before-device sequence;
the frozen workloads, statistics, health controls and production isolation stay
unchanged. Root does not access the router while the DHCP agent owns it.

Oracle owner: correctness; controller PID225895 and outputroot/private/oracle-e
continue unchanged. Latest48/110valid, nofailure. No CPU research workload during
timing. Aftercomplete, correctness releasesOracleCPU and runs existing analysis/
hash audit single-core atlowpriority. RawstaysOracle untildevicefinished; only
small summariesmaytransfer duringdevice timing.

Device owner: DHCP. LocaldetachedcontrollerPID43894, output
private/perf-opt-20261015/candidate-e, stdout/stderr/launchreceipt alongside.
Source4f869c88/ELF8b8082b9 versus original8472; full110 originalparameters, no
resume/sceneselection. FreshproductionPID/start[3086,2115], file/liveSHA8472,
9toolhashes, noactiveownedgroup/STOP, 113696KiBavailablememory verified. Ewas
stagedvia.new/hash/chmod/renameonlyinowned/tmp; productionunchanged. Original
125shealthbaseline/200msthreshold retained. Latest11/110valid (UDP-hit10/10),
30externalHTTPSchecks successful. Receiptbc93fd41. Onlytheoriginal per-window
archiveflow usesrouterlink; nobulkOracletransfers orotherrouteroperators.

Research: DNS owns lower-case insertion-key borrowing and avoiding an unused
reverse-insertionkey on perf/dnsmasq-insert-key-20261015; loopowns selective
readinessprototype onperf/dnsmasq-readiness-hybrid-20261015. BothbaseE4f869 and
remain separate fromfrozenE/rootproduct. Rootreviewsmechanisms andactualowner
boundaries. OracleCPU remainsofflimits untilcorrectnessreleasesit. Every
candidatevariation hasitsowncommits/evidence; no gainsclaimedfromallocation
counts orsamplepercentages. Localcompilation/counts are permitted bytheuser.

## E device attempt has a baseline-side invalid window; retain full run

DHCP owner reports candidate-e-udp-miss-r4-c invalid under the unchanged rule.
This is the original deployed8472 side, not E. All1000warmup+4000measurement
queries werecorrect, withno timeouts/wrong/skips; upstream5000/5000 total, but
steady3999+saturation1. Clienthas3999in-window and1after-window. The observation
is a phase-boundary overrun, not an established product or host rootcause.
No rule/expectedcount/windowchanges are permitted. Full110attempt continues with
originalhealthguard; no selective replacement. Atthatpoint19attempts18valid,
50externalHTTPSsuccessful, nohealthfailure. The wholeEdevice attempt therefore
cannotpass thefrozenvalid-window gate; validscene resultswillbe diagnostic only.
Nextcandidate research continues independently, not a repeat ofunchangedE.

OracleE remains separate andvalid:60/110completed, nofailure. Itscompletion/
verification owner stayscorrectness; rawbulkcopy waitsdevicecompletion. Root
andloop locallyreviewselectivepersistentwaitprototype; DNS localinsert-key
revision60c3bdf2 anditscounters are readyforpostOracle native screening. No new
researchCPU hasrun onOracle duringE timing, androot hasnot accessedrouter since
DHCPtook exclusiveownership. Fulloriginalfaileddeviceevidence willbe committed
bydeviceowner aftersource/data validation; nostop/cleanup withoutfullarchival.

## E accepted after authorized supplements; next-version tool fixes complete

User amendment7691e8aa (FROZEN_TOOL_WINDOW_SUPPLEMENT.md) was frozen before any
supplement: symmetric once-only complete-pair replay for demonstrated tool
invalidity, no response-error/response-timeout/crash waiver, all old raw retained.
OriginalE110/107valid had3baselineinvalids:udp-missr4phasecounter3999;tcp-missr3
25skips;dhcp-home6r2one skip. Afteroriginalcomplete, originalvalidator/tools ran
3wholepairs/6windows once inoriginalorder;6/6passed. Effectiveview110 contains
104original+6supplement, no mixedsides or116window pooling. FinalmappingSHA
96fee31a9be5612d0e2bf983c318017401fc8709b89d1520913e7034275c0361; analyzer summary
SHAe3a0e556b189f35cde0a5a48abab3aab23d7c76711d03689a8bd439b3411071b.
Independentfinalaudit4f544c3d(root90d3f021) verifiesallraw/35metrics/resources/
3938guard samples/262HTTPS. Sixof11scenes improve,0discernibleprimaryregression.
UDPmissCPU−14.79%,TCPmiss−19.92%,mixed−8.26%(narrowW8.00%,9ticks),DHCP150−32.99%;
configp50−16.73%,largeHUPp50−14.08%. E944short+44/67+boundary/corpora allpassed.
OracleE110/110valid/110tar3430files retainedlocallyundercorrectness/private/
oracle-e-transfer; rootprivate/oracle-e-summary-verified.json copied/hashverified.

Toolfixes forNEXTround only are integratedas a2dc1fa6(cohort) and0f8ced6c(queue).
Queue independentbranch9e6556cf+ab7f3695: original three delayed-cohort tests fail,
all5isolatedLinuxnetworktests passafter; DHCP6/150SDKstatic toolfunctionalcontrols
pass (ae3f5cf7/root207cdd88). Newloadgen SHA f7c7d8e94a96e5c23f06aec1396539c439516fa4408a3657835cf78bdceb618e;
oldb5inputs/routerunchanged. No Eretime usednewtool. Mainproductstill exactE4f869.

## Latest user priority: direct exact-C/E UDP/TCP hit accounting

User explicitly selected C/E hitgap as mainattack and asked four-agent parallel
research. Do not stop atE; nextoptimizationmusttarget largestverifieddifference.
Rootowns source/call-chain audit and coordination; loopowns whole-process-tree
syscall audit; DNSowns stat-only user/kernel PMU and separatefunctionsampling;
correctnessowns independentreview; DHCPissolephysicalrouteroperator.

Freshrouter diagnosticPID40801,rootprivate/c-e-hit-diagnostic,launchsameprefix.
ExactimageC097a9e21 versusE8b8082b9, twohit scenes×5pairs=20windows; oldEprivate
controller/analyzerfromGit4f869,oldb5measurementtool, originalhealth125s/200ms.
Latest11/20valid,32HTTPSsuccess. Prod[3086,2115]/8472unchanged. Only/tmp comparator
leftsidechangedtoexactC (notdeployed8472), rightEunchanged. Thisisdiagnosticnot
newcandidatequalification. BulktransfersagainforbiddenuntilDHCPdeclaresidle.

OracleloopfixedstraceplanCUDP→EUDP→CTCP→ETCP, -f/-v/trace=all, b5/01frozenloadgen/
upstream,5000correct+fixed1sgrace, Cchildrenincluded. FirstCUDPidentityprecheck
failed BEFOREprewarm/capture because readonlyTZifwasmisclassifiedasELF; retained.
Minimalidentityfix keepsC+4ELFexact, recordsnonexecutablereadonlyTZifdata separately;
newdriver/plan mustbehashedbeforefresh4attempt. No performancewindowsreplaced.
DNSthenowns12stat-onlywindows(3alternatingC/Epairs×2scenes) +4separateuser-sample
windows, same1sgrace; instructions:u/k andcycles:u/k group mustnot silentlyscale
multiplexedcounts. Csymbolsource verifiedvia originalsstrip-z reproducing097
byte-for-byte,22ALLOCsegments/332sizedfunctions. No foreignbinarymaps.
MatchingCsrc: /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/h1-3a/build/openwrt/build_dir/target-aarch64_cortex-a53_musl/dnsmasq-nodhcpv6/dnsmasq-2.93/src.
Rootsavedsmallhash-bound Csnippets inprivate/perf-opt-20261015/c-e-hit-source-snippets.json.

Priorinsert-keybranch60c3 rejectedafter150plainwindows (upperpressure+1.518%,
dynamicCNAME+0.475% beyondsmallW); allhistoryunderrefs/archive/perf-opt-20261015/dns/insert-key-rejected,
worktree/private retained. Readiness9ce prototype rejectedby110PMUready/runnable
counts(14steady+47.79%); successorstable-shapefastpathd83/e227 isparkedafter
functionaltests whiledirectC/Eevidence takespriority. No prototypeproductis
integratedintoE/root. LoopactiveC/Ediagnosticbranch perf/dnsmasq-c-e-hit-syscalls-20261015;
readinessbranch perf/dnsmasq-readiness-hybrid-20261015 remainspreserved.

## C/E attribution complete; next hit candidate screening

The fresh exact-image-C/E router diagnostic completed 20/20 valid windows.
UDP median CPU is 84 to 146 us/query; TCP 116 to 168 us/query. Production is
unchanged and the router is idle. These are direct pairs, separate from E's
accepted comparison against deployed v0.2.0.

All four whole-tree syscall captures, 12 PMU stat windows, four instruction
sample windows and four separately planned cycle sample windows completed.
UDP E adds one terminal EAGAIN receive and 32 bytes of IP_PKTINFO per query;
both have one completed ppoll and sendmsg per query. TCP E has many more ppoll
calls but fewer total syscalls than C including its children. Native UDP user
instructions are only 6.86% higher, while user cycles are 55.44% higher; do not
equate instruction count or the shared kernel with equal CPU cost. Local
answer functions account for 20.32% of E UDP cycle samples. Oracle Neoverse
counts do not quantitatively explain the router Cortex-A53 gap.

Three isolated exact-E-based candidates were prepared, not yet integrated:
UDP admission c1ea66f6, local address path 6f594d7b, static bound IPv4 pktinfo
5a03fffe. Admission removes one discarded 32-byte name allocation per query.
Its fixed quiet 50-window plain screen passed every checksum and five of five
pairs improve in each scene: hit -4.329%, uppercase -4.734%, miss -6.865%,
host -4.086%, malformed -2.166%; all exceed the measured within-side range.
The malformed instruction increase remains recorded separately. This is a
native public-call-chain result, not whole-daemon or device acceptance.

Local-address 15-scene allocation controls passed and its fixed 150-window
plain screen is running exclusively. Pktinfo's real API mechanism screen
completed 56/56: roughly 312--323 fewer kernel instructions per bound packet,
unchanged syscall counts, but 3--8 extra user instructions on generic controls.
Its fixed 40-window quiet plain screen follows local-address, before any
selection. Correctness independently reviews source boundaries. E remains
unchanged; all attempts and compiler/launcher failures remain preserved.

The next accepted-E/F increment will use the previously approved cohort and
queue tool repairs, with new identities frozen before measurements. The user's
explicit current goal makes discernible UDP-hit improvement the primary
incremental target; full eleven-scene no-regression/resource/correctness gates
and original statistical thresholds still apply. This does not relabel E/F
as a fresh deployed/F comparison or alter E's historical acceptance evidence.


## F frozen and SDK complete; fresh correctness started

F source `3a3d8e3e848b93b0309353acfa0033d0b01a7cd0`, tag
`perf/dnsmasq-candidate-f-20261015`, is exact E plus three separate performance
commits (admission b49f8ca3, local address 445f3a09, bound pktinfo 3a3d8e3e).
There are no new behavior repairs. Local address completed all 150 windows:
12 scenes improve beyond W, three inconclusive, no regressions. Bound pktinfo
completed all 40 windows: bound burst1/burst16 improve 2.310%/2.212%, five of
five pairs, while generic controls remain within W. All failed setup attempts
and original counter increases remain preserved.

The unchanged SDK recipe built F ELF
`b7926bcf39cd7f33b4f0c110315ddc1ad719b39427bec53430ea05aeacd781fc`,
2,136,859 bytes (same as E); same-link map
`75efe620d1455b6bdcee55fda5304f8a967faeff84ecb316e285c6bd48dec5ab`.
Root and correctness independently verified all 179 Git-bound inputs and full
build receipt `9e0339be8651258d9e56f1140c679de6849c60cc828d22e910badea7c7ef5c40`.
Public receipt is `candidate-f-build.json`; private ELF/map/build remain under
`private/perf-opt-20261015/sdk-f` and Oracle `root/private/sdk-f`.

Correctness fresh short runner PID310233 is active; no qualification claim
until short, original 44/67 and all boundary/corpus gates finish. Then loop
owns exclusive Oracle full E/F110 and DHCP owns simultaneous router full E/F110.
Tool identities and incremental criteria were fixed beforehand in
`F_E_NEXT_ROUND.md`. Router remains idle, production unchanged, old comparator
staging untouched. Root and DNS prepare later experiments only in isolated
F-based local worktrees; they must not mutate F or consume Oracle CPU now.

## F fully qualified; both performance controllers running

F completed 950 short tests, all 44 families/67 original jobs, F10/protocol/TCP
and the four source corpora. There are no new failures; the original explicitly
recorded differences remain separate. Qualification SHA
`84ca19157d7f40710715fc000d1491e8c9918961ce9600a67abcc92185b8a821` binds source
3a3d8e3e, SDK b7926bcf, map75efe620 and all original result identities.
The original complete family run took2064.10s. See `correctness/f-full44-gates.json`
and `correctness/f-correctness-qualification.json`.

Loop owns exclusive Oracle E/F110, started17:53:31UTC, PID416211,
`root/private/oracle-f-vs-e`. DHCP owns router E/F110, started18:18:41UTC,
local controller80604, `private/perf-opt-20261015/candidate-f-vs-e`. The device
handoff initially failed to wake the completed agent; root explicitly used
followup_task and corrected that delay before its fresh125s health/staging.
Production8472/PID3086/start2115 remained unchanged. No new Oracle CPU research
or raw bulk transfer is allowed during timing. The primary predeclared increment
is discernible UDP-hit CPU/query improvement, not latency-only improvement.

The user explicitly reopened terminal-EAGAIN scheduling and requires low/high
load costs, plus user-cycle/locality/layout evidence, before choosing the next
candidate. The user also instructed root to personally research and prototype
while agents execute acceptance, rather than repeatedly sleep/poll progress.
Root now owns the following independent F-based product prototypes:

- UDP read-one `4bd3c9a4`, worktree `owrt-perf-udp-read-one-20261015`: per-listener
  while becomes if; existing cross-listener true-result budget and service
  ordering remain. This is not C's entire global-first-event scheduling policy.
  Source/error/resend review and local Linux-musl all-target check pass; the new
  real queued-packet Linux test remains pending. Plan `UDP_READ_ONE_PLAN.md`
  declares separate low200/s/high-unpaced syscall, PMU and plain windows.
- Reply construction layout `2bd0d6b2`, worktree
  `owrt-perf-local-reply-layout-20261015`: the6045B owned-answer body moves intact
  behind inline(never). Mac714tests and15scene allocation controls pass. A local
  final Linux-target ELF (Rust bundled musl, not SDK) shows entry848→656B, but
  owned two-frame subtotal1264B, +416B. SDK/native cycle/timing remain pending.
- Address dispatcher layout `26aefa79`, worktree
  `owrt-perf-address-dispatch-20261015`:6779B general-record body moves intact
  behind a separate boundary. Mac714tests and15scene controls pass. Local final
  Linux-target disassembly shows the ordinary dispatcher inlined into its caller,
  removing the old1408B frame; the848B caller and512B address helper remain.
  General/raw/ANY paths retain their semantics; no CPU result is claimed.
- Singleton IDs `0a94e3b0`+`b1180f72`, worktree
  `owrt-perf-hit-singleton-20261015`: one64B allocation removed for ordinary hits;
  explicit drop restores the original fallback Vec release point. Source review,
  Mac63cache tests and Linux830library tests passed. Separate native instruction
  controls include a+0.962% host and+0.413% RRset change; no timing conclusion.

DNS's independent dotted-name prototype `c627927d` remains in
`owrt-perf-local-residual-20261015`; it saves a small name allocation but increases
the Mac entry frame240B. Its counter controls include configured-CNAME+0.073%.
The two allocation prototypes completed320 fixed native rows in the spare
correctness slot before F timing (80allocation/240instructions, all unscaled),
and are now idle. They are not automatically selected as the next candidate.
DHCP also prepared recipe-only A53 tuning `c076835d`, with evidence `eab6538d`;
fat LTO and codegen-units1 were already enabled. Compiler experiments stay
separate from product changes and require independent timing.

The existing diagnostic owner driver gained only the requested explicit rate,
uninstrumented mode, bound tool identity, full-cohort CPU endpoints and sender
CPU accounting (bec57a22/039de987/7c958af9). The frozen110 controllers are untouched.
Do not use the old C/E fixed5000 analyzer on unpaced/F-prototype data. No Linux
runtime, SDK or timing claim is attached to locally cross-linked ELF inspection.

## F completed; root continues the two requested mechanisms

F passed correctness but did not meet the predeclared UDP-hit CPU improvement
goal. Both complete Oracle and router comparisons have 110 valid windows and
all 33 primary comparisons inconclusive. The router retained its tool-memory
stop after 58 windows, recovered outside any started window and completed the
remaining 52 in original order. E remains accepted; F is not promoted. See
`F_E_DEVICE_RESULT.md` and `ORACLE_F_RESULT.md`. No production state changed.

Root owns the active independent UDP read-one screen2: four strace, twelve
grouped PMU and twenty plain windows, low200/s and high unpaced. The first
attempt's namespace-wrapper assertion occurred before daemon startup and is
retained separately. Loop only monitors failure/completion; no simultaneous
Oracle workload or raw bulk transfer is allowed. Read-one passed83 Linux bin
tests plus4 ignored-live checks; each independent layout passed829 library
tests plus18 ignored-live checks. The unchanged SDK builder reproduced F
exactly and built all three prototypes, each within the existing size budget.

Root prepared `dns/layout-screen-plan.json` and its dedicated replay runner
while read-one runs. It reuses the unchanged hot15 fixture, independently
compares each layout to F, and fixes three user instructions/cycles pairs plus
five no-observer CPU pairs. Counts are fixed before timing:200,000 for PMU;
plain2,000,000 except raw/configured-CNAME200,000, justified by retained
setup-inclusive durations of the prior counter screen. All native builds precede
measurement; source inputs and probe hashes are bound.32 independent original
SDK owner windows follow. Native frame/code-size reductions are mechanisms to
test, not evidence of a shipping performance improvement. No next candidate
is selected until both requested mechanisms have actual results.

## Read-one result rejects fixed mode; adaptive follow-up prepared

Read-one completed all36 windows. Low200/s recvmsg2→1/query and EAGAIN5000→0
confirm the mechanism; CPU28→24µs has only2ticks difference and is below W.
High unpaced ppoll rises~1/16→1/query, observed throughput213790.90→166067.75/s
(−22.322%) and CPU/query4.6747→6.0222µs (+28.826%), five adverse pairs beyond W.
Both sender and daemon approach one CPU, so this is a closed-loop pipeline
comparison, not isolated server capacity. Fixed read-one is not selected.
All raw/derived failures and counts remain; see `loop/UDP_READ_ONE_RESULT.md`.

Root's new independent F prototype1b934951 lives in
`owrt-perf-udp-idle-batch-20261015`. It reuses the existing poll-wait measurement:
≥1ms permits one true-result per ready listener, shorter waits restore the
original shared16 budget. The threshold is fixed before measurement and is only
a hint, including scheduler delay. The packet body/error/resend/service ordering
remains unchanged. New deterministic real-socket tests force1→16→1 across valid,
short-invalid and oversize packets. Local Linux-musl all-target check passed
after fixing the statistics usize/u64 mismatch; initial logs are retained.
Linux runtime and SDK build remain pending until the layout reservation ends.
Preparation inputs are local `private/perf-opt-20261015/idle-batch-inputs`;
correctness separately prepared its unchanged bin+4ignored-live runner.

The layout native480-window controller is running after read-one analysis ended.
Its fixed plan93381a06 has independent reviewfd1fec93. Loop only watches failures
or completion.32 SDK low-load windows follow before releasing Oracle for the
new UDP follow-up. The exact downloaded SDK ELF/maps independently confirm the
address chain2768→1360B and reply owned-answer chain848→1264B. Those observations
remain static reservations, not dynamic stack traffic or CPU evidence.

## A53 evidence and next prototypes, 2026-10-16

The excluded E stage diagnostic completed 50 valid physical windows. Fresh
same-round exact C/E CPU medians are 80/140 microseconds/query. Original E and
diagnostic full are both140. With the same diagnostic ELF, full/receive-cut is
136/70, full/before-answer is136/98, and full/skip-local is138/120. These are
coarse interventions with their own controls, not additive function costs or
candidate acceptance. Every mode retains1000 real prewarm requests; traffic,
mode counters, archives, health and restoration passed independent review.
See `loop/A53_UDP_STAGE_DEVICE_RESULT.md` and its independent audit. Production
was unchanged and the temporary slots restored.

The independent excluded count-only E diagnostic confirms exactly5 allocations,
5 frees,0 reallocations and270 requested/released bytes per cached hit, in all
15,600 physical hit requests. Whole cached-only owner turns agree; nested and
unscoped counts are zero. Source explains32+32+14+64+128 bytes, but no backtrace
histogram or allocator CPU cost was captured. The diagnostic exceeds the release
ELF budget and is never a candidate. See `loop/E_UDP_ALLOCATION_DEVICE_RESULT.md`.
Software perf is unavailable too: retained TASK_CLOCK probes return ENOSYS;
there is no reason to install perf or alter the router kernel for this work.

Completed independent screens remain separate:

- Fixed read-one removes the low-load EAGAIN but causes high-load pipeline CPU
  +28.826% and throughput−22.322%; rejected. Adaptive idle-batch preserves busy
  batching and removes4999/5000 low-load empty receives, but Oracle CPU28→26 is
  only1tick and inconclusive. A53 screening is queued after the current test.
- Reply-body layout has9 native regressions and no discernible gains; retired.
  Address-dispatch layout has small native signals but Oracle CPU28→28 and now
  A53 F126→prototype132 in10 valid windows: only3ticks, below the original
  precision gate. No demonstrated physical benefit; do not promote it.
- Dotted allocation removal has a configured-CNAME native regression+5.089%.
  Initial singleton has four native regressions. Preserve all480 windows and
  all15 scenes from their independent screen; neither is automatically combined.
- UDP decoded-name reuse `f404ed75` passes934 related Linux tests and the SDK
  budget. Oracle32 gives low CPU28→28 and high variable-N CPU−1.151%, while high
  throughput is inconclusive. A separate A53 F/name-buffer10 is running. The
  scratch is bounded by valid DNS input, but its capacity is not universally
  256: uneven labels retain380B with the pinned allocator growth behavior.

Root's independent fresh-single-address prototype `2a9d53b0` keeps the successful
single fresh A/AAAA answer out of the general cache state machine and removes
its64B IDs allocation. All fallback code is unchanged. Mac716 library tests,
musl checking and the unchanged SDK build pass; exact-source Linux runtime
qualification is in progress. Local15-scene count pairs confirm the intended
allocation change with equal checksums and zero retained bytes. No timing or
full44 claim follows. `dns/FRESH_ADDRESS_PLAN.md` freezes the next480-window
native screen, independently comparing this and singleton-slice refinement
`8ed0cfdf` against F, then a32-window exact-SDK low/high owner screen. Oracle
is reserved for those windows after gates/builds complete.

Root also investigates using the existing hosts forward index to reject a
published-generation name miss before C-style bucket hashing/walking. The
separate prototype preserves bulk/retained-lease lookup and original rotation;
it does not add an index or cache local-ownership decisions. It remains local
and unselected. PGO is separately prepared: existing release settings already
use fat LTO/codegen-units1, and Oracle has matching LLVM22.1.8 llvm-profdata.
Only a narrow static-PIE profile-emission smoke test is being prepared; training
and performance claims remain pending. Rust/C total ELF sizes do not establish
instruction working-set sizes.

Continue until an immutable next candidate has complete frozen-C correctness,
full Oracle/device matrices and a discernible A53 improvement over E. Tool
repairs, behavior repairs and performance patches remain separate commits and
separate report categories. No production deployment is part of these tests.

## Current continuation after independent physical screens

F/name-buffer10 completed all windows and independent audit: CPU130→132us,
one tick, no primary discernible change. F/adaptive-idle10 also completed:
126→126us, zero median ticks and no primary discernible change. These do not
prove either change has zero cost; neither earns promotion. Every original raw
window and all restoration evidence remain. Three retired branch heads
(fixed read-one, reply layout, address dispatch) now have durable annotated
`archive/perf-20261016/*` tags; their worktrees/private evidence remain in place.

The fresh-address/singleton-slice native480 completed with all486 commands and
1152 small raw metadata files verified. Fresh-address has4 gains,8 regressions,
3 inconclusive scenes: its hit classes improve8–10%, but miss/local/RRset/CNAME
paths worsen1–3%. Singleton-slice has6 gains,1 regression,8 inconclusive; synth
remains adverse. None of these results is pooled with its earlier version.
See `loop/FRESH_ADDRESS_NATIVE_RESULT.md`. Exact fresh-address related gates
pass935. Its immutable SDK owner32 is active under loop's Oracle reservation;
DHCP has downloaded both required SDKs in the inter-matrix gap and is preparing
the independent A53 fresh-address10 after idle-batch postflight.

Root prepared three further immutable, uncombined sources:

- `5d94139b`: existing hosts forward-index miss shortcut. Local715/8, musl
  checking and30 allocation controls pass; source review finds no blocker.
- `40cc86fe`: optional cache metadata. Measured local Entry/Option<Entry>
  shrinks72→32B. Each first metadata value costs one64B allocation; the
  two fields can coexist. Slot-content plus metadata requested bytes change
  by−40×capacity+64×metadata_entries, not an RSS promise. Shared64-block target
  update requests4650→2154B but makes one extra allocation. Snapshot/live and
  hot15 controls pass; the invalid initial64/64 long-name fixture is retained.
  See `dns/COLD_METADATA_LOCAL_REVIEW.md`.
- `b343df11`: fresh-address writer moved into a non-inline selected-hit helper.
  Exact parent SDK evidence shows shared caller frame592→720B relative to F;
  this helps explain why a separate refinement merits testing, not proof of
  causality. Local LTO caller frame is688/752/688B for F/parent/refinement,
  but refinement's selected-hit chain grows752→896B. Local716/8 and musl
  checking pass; writer/general source semantics are reviewed unchanged.

Each has a fixed independent240-window native plan using the same15 scenes and
original comparison rules. The runner's only new change derives its final row
count from the already fixed plan dimensions instead of literal480. Old active
and historical runner copies/hashes remain unchanged. Correctness has prepared
three179-file source manifests and the existing Linux gate runner locally;
none has been uploaded or run on Oracle yet. Wait for owner32 to release before
their gates/builds. PGO's narrowly scoped E-control/generate smoke controller is
being prepared locally; its two SDK builds need a continuous reservation over
the existing per-build lock. Generated instrumentation is excluded from release
budget decisions; exact control identity and all hardening checks remain gates.

No G is selected and no new physical performance win is claimed. Next decide
from the immutable fresh-address device result, then prioritize actual A53
evidence for compact metadata and the writer refinement. Keep the PGO smoke
separate, do not expand the test framework, and do not mutate active artifacts.

## Continuation through 01:16 local, 2026-10-16

Fresh-address parent completed exact-SDK owner32 and A53 ten windows. Oracle
low CPU28→30 remains inconclusive; high variable-N CPU/query−5.347%, throughput
+5.666%, response p50/p95 improve, but sender lag p50/p95 worsen beyond W.
A53 F130→124us has3tick difference and absolute change exactly equal to W,
so both strict precision and variation criteria reject promotion. All raw and
independent audits pass; this is a valid inconclusive outcome, not a tool failure.

The next three prototypes pass2803 related Linux tests in total and unchanged
SDK builds. All three artifact sets were downloaded before their timing. Cold
metadata's native240 has1 small gain,5 regressions (configured-CNAME+5.201%),
9 inconclusive scenes. Its A53 ten windows are134→130us,2ticks, inconclusive;
RssAnon peak medians520→472KiB are retained separately as memory evidence, not
USS or CPU attribution. Cold metadata is retired for the current performance
candidate and receives no SDK owner32 follow-up. The source remains archived.
Frame and hosts-index240 native and ten-window physical rounds continue with
independent F controls. All exact SDK code/frame differences are recorded in
`dns/NEXT_CACHE_SDK_CODEGEN.md`; no static reservation is called runtime cost.

PGO smoke1 stopped during Cargo compiler discovery before compilation. The
separate pinned-RUSTC repair passes its real empty-PATH regression. Smoke2
then built a hardened control but its hash did not reproduce E, so generate
and runtime never started. The difference is now traced to the prepared package
path: Cargo path-dependency metadata changes when that root moves, despite
corresponding source remaps. A real two-crate local regression confirms this.
Tool repair `3b4abe0b` restores the canonical E build-slot/control target and
binds them to the original receipt; smoke3 retains the exact-E identity gate.
All10 integrated local PGO tool tests pass when invoked with the existing tools
module path. The earlier missing-PYTHONPATH invocation is retained privately.
PGO is still unproved; there is no instrumented product/profile/training result.

Root prepared a more direct local ownership miss experiment:

- Source `1676fbb6` (product9617d93e) proves no local A/AAAA ownership or lookup
  side effects, then retains the original cache name hint and returns None
  before local reply machinery. Broad config/hosts/lease/bulk guards preserve
  the original fallback. Local715/8 plus two added/updated fixture tests pass.
  It adds one allocation on four fallback classes, retained in its hot15 data.
- Child `c44cd116` uses the existing bounded253B converter only inside the
  non-inline miss-check helper. Original general local/expiry functions remain
  unchanged. Local717/8 and musl checking pass. Hot15 now saves one21B fixture
  allocation on four hit classes, both misses, RRset and CNAME-with-leases;
  the parent's four extra allocation counts disappear. Host-localise varying
  reallocations/requested bytes remain explicitly reported, not attributed.
- Local integration `8d572ba1` cherry-picks fresh writer refinement and bounded
  local miss only. No conflicts/manual product edits; six files match the two
  original source variants byte-for-byte. Local719/8, musl checking and30 hot15
  controls pass. Ordinary hit4→2 allocations/245→160 requested bytes. This tree
  is not G, has no remote build or timing, and gains must not be added together.
  Source-interaction review finds no blocker; runtime/selection remain pending.

A review hypothesis about filterwin2k plus a missing Additional RR was disproved
by a reproducer and the helper's actual error boundary. Original and prototype
both return no local answer. The erroneous expected-error assertion is retained,
corrected regression passes, and no unnecessary product guard was committed.
This is not recorded as a product bug or changed C expectation.

Next non-timing reservation is conditionally authorized after loop's three
native rounds fully exit and release: correctness runs1676 then c44 related
Linux gates on CPU2 with separate179-file manifests; DNS runs canonical-path
PGO smoke3 under the SDK reservation. Completed agents must be awakened using
followup_task. Root's next two-SDK controller is prepared locally at
`private/perf-opt-20261015/local-miss-sdk-inputs/build-sdk.py`; it must wait for
both runtime gates and smoke3's SDK release. Integration is local only. Fixed
independent240-window plans for each local-miss variant are committed but not
started. Do not mutate or pool any already measured artifact/sample.

Retired standalone source heads now have annotated archive tags and detached
worktrees: read-one, reply layout, address dispatch, cold metadata, UDP name
buffer, adaptive idle batching, original fresh-address parent. All private
artifacts remain in place; active refinements/integration branches are intact.
E remains the only accepted optimization candidate; production is unchanged.

## Continuation through the cached-only and PGO screens, 2026-10-16

The complete A53 stage experiment passed50 windows. Independent exactC/E
controls measured80/140us; E/full diagnostic140/140; full/receive136/70;
full/before-answer136/98; full/skip-local138/120. These interventions are not
additive function costs. E's allocation diagnostic counted exactly5allocations,
5frees and270requested bytes per real cached hit. All physical work through
the standalone bounded local-miss round totals140 valid windows; production
and prior E/F slots were independently verified unchanged/restored.

The broad integration8d572 is not selected: native240 had7 gains and8
regressions, including hosts+14.25% and lease-address+29.77%. Its A53
138→126us is6ticks and belowW; the standalone bounded local-miss132→126us
is3ticks. Both CPU results are inconclusive despite distinguishable p50 gains.
The cold-metadata, writer-frame and hosts-index results remain independently
recorded. None is added to an expected combined speedup; no G is selected.

The narrowed54bd1e56 prototype checks local ownership only after finding an
eligible single fresh positive address, retaining original lease expiry and
the read-only cache hint. RelatedLinux938 pass. Child0161ad9c adds only the
previously reviewed synchronous decoded-name buffer; interaction review and
Linux939 pass. Both use the separate existing-fixture repair16a95086, whose
original intermittent failure was reproduced in F and traced to the intended
fixture's missing different-bucket precondition. No product or C expectation
changed. Reports and failed executables remain retained.

Local prepared-UDP counts are F4/245B,54bd2/160B,0161one/128B per call,
with equal checksums and no live-byte delta. This excludes socket/owner work.
Loop now owns sequential canonical SDK builds for54bd then0161. After all
postflight and artifact transfers, it will run54bd's frozen native240 vsF;
DNS will run0161's independent owner32 vsacceptedE in a separate CPU slot.
DHCP has frozen an independent A53ten comparison of0161 vsacceptedE and
completed read-only recovery checks; no new device windows have started.
Correctness is preparing exact0161 full44/67 and both full11-scene matrices,
without reusing old8d572 artifact bindings. Actual qualification remains open.

PGO smoke3 reproduced the exact E control and completed the fixed one-pass
11-scene training with50 normal-exit profiles. Default profile-use passed
hardening/CFG gates but failed original ELF/APK budgets. The one predeclared
hot-callsite250 build also fails: ELF2,267,939B andAPK1,282,729B. Its source,
50profiles and merged profile are unchanged; all failures are retained. No
parameter sweep, retraining, timing or qualification follows. SDK reservation
was explicitly released. E already had fatLTO/codegen-units1 before this work.

Root's next independent source03ace8ec recycles one<=512B cached UDP reply
after its final send. Mac721/8 and musl all-target checking pass; local prepared
counts reach zero steady allocations versus0161'sone/128B, same checksum.
This is not A53 CPU evidence and is not mixed into active builds. See
`dns/CACHED_REPLY_BUFFER_PLAN.md` for ownership bounds and the conditional
incremental screen. Existing no-subscriber metrics and upstream idle-clock
directions were already rejected/removed; do not reopen them as new findings.

## 0161 fails the original improvement gate;185 prepared, 2026-10-16

Both54bd and0161 SDK builds passed canonical source/size/hardening/postflight
checks. 0161 ELF isf4230f03137bd235489cda2cfa186e44aefe390d9a5f9afd8368c80e73658aff,
2,140,955B; mapb9a67ea6 and receipt972a6f3c. Its independent A53ten is complete
and independently audited: E136→122us/query,5/5 improving,7tick median delta,
absolute change belowW13.235%. CPU,p50,p95 all remain inconclusive. Every
window remains, including E's first152us sample.150 physical windows have now
completed in total. Production8472/[3086,2115] and E/F restoration are verified;
the router is idle. No0161 full44/110 has run, and those prepared recipes are
explicitly marked SCREEN_DID_NOT_SUPPORT_CONTINUATION.

54bd native240 completed6 gains/4 regressions/5withinW. Hits improve17.383–25.892%,
but miss+2.180%,miss-leases+2.101%,synth+0.797%,lease+0.622% each exceedW.
Its metadata has independent recomputation; original578 stdout/stderr/CSV files
remain remote until the current timing reservation ends. Do not describe that
as completed independent raw-byte verification. DNS continues0161/E owner32
in full under PID644847; its output isdns/private/cached-local-name-owner32,
plan3a0e6206. No build, transfer or other Oracle workload may overlap it.

Next source185db90c9cabd26c0af09765636ef15bf6d35f79 combines03ace8ec bounded
reply-buffer return witha8dcdacc narrowed local-frame extraction. It is a clean
cherry-pick: six changed files match their independent parents exactly. Mac721/8,
musl all-target checking and composition review pass. Its179-file identity is
0fdf69233a1c32cfe2ae3d1280801e1256b7542b4df68c732e028ddc29670762.
Fresh local prepared-UDP comparison gives E5/277B allocations per operation
versus185zero, equal checksum and no live-byte delta; this is not A53 evidence.
Source/worktree isowrt-perf-cached-zero-frame-20261016. No G is selected.

Rootb17f4010 freezes direct accepted-E comparisons: complete hot15/native240,
exactSDK owner32 and independent A53ten, original workloads/rules. Hot15 does
not recycle owner responses, so it primarily checks shared local/cache and
fallback effects. It cannot prove the buffer-return mechanism. No earlier
standalone effects are summed. After DNS explicitly releases, loop downloads
54bd578raw, correctness runs185's original four Linux gates once, then loop
builds its single canonical SDK. Actual receipts must bind before timing. All
transfers finish before native/owner timing; A53 can run concurrently after
new health/recovery checks. The two standalone children's gates/SDKs remain
prepared but unexecuted; the combination takes priority.

Additional root source722d2762 is a separate185 child, never part of the active
185 experiment. It removes disabled diagnostic elapsed-time reads from the
owner wait and avoids a fresh pre-poll clock when no deadline needs it. Active
deadlines and enabled diagnostic timing retain the original reads. Default and
m6b-feature musl all-target checks pass; local cross-codegen review is pending.
This differs from the already removed idle upstream timer work and has no
measured A53 invocation count or CPU benefit yet.

Completed PGO and superseded standalone source branches were archived under
exact annotated archive/perf-20261016 refs and detached; all worktrees/private
evidence remain. Current185, its722 child, accepted E/F and agent timing/gate
work remain intact. Future promotion still requires full44/67 and complete
Oracle/device11-scene matrices, with a fresh original-baseline comparison for
any new total v0.2.0 claim.

## 185 runtime screens begin, around03:12 local, 2026-10-16

0161/E owner32 completed all32 windows and independent metadata/raw-PMU audit.
Low CPU28→28us is inconclusive. High variableN CPU/query−10.103% and throughput
+11.160% pass W/direction diagnostically, but sendlagp50+300% andp95+56.790%
also exceedW adversely. All32 windows are retained. The1211 small files have
independent byte checks; the64 large latency/sendlag binaries and32 mappings
remain remote with their original digests, so local quantiles were not derived
again. Its failed A53 result still prevents promotion/full44/110.54bd's578
original raw files and90 PMU pairs now also have independent byte/CSV checks.

185 related Linux qualification passes940 (836+18+82+4), exact receipt
b5089b4b54bcde00a4d887453a1912965c10062066bb48323ea7607f2b651501.
The canonical SDK passed source/budget/hardening/postflight:
ELF9109e9871e83f652788621b2fbd5845f7d63e4bf7d05593b5098f741c31d7f99,
2,145,051B; mape1c8638fbb2ff229d736d697dae78a519a914beb975cbf017f7666dd1dbe314f;
builddfb42af12c623b3eb7551bd9e821ef6fb0d63922f02a8714e7475623b9483f10.
APK1,167,095B remains under1,200,000. Main source remains185db90c;722 is separate.

All DNS/DHCP artifact downloads and owner inputs were verified before timing.
Loop launched directE/185 native240 at01:11:48UTC, PID659491/start183772597,
planbeb36e4d, runner119d49a1. It owns Oracle through full postflight/collection,
then must usefollowup_task to awaken idle DNS for the authorized185/E owner32.
That32-window plan is frozen73ad729e/e05c8b0a; exactSDK,940gate,358source files,
driver/analyzer/modules were independently checked before pretransfer. Do not
start another Oracle workload/build/transfer during these timing reservations.

DHCP185/E A53ten plan76a34850 is fully artifact/gate/concept bound; it completed
transfers and is performing fresh125s health/recovery before the independent
ten windows. F remains only a restore role. Correctness prepared185 full44/67
and both11-scene110 recipes locally in893eed29, without uploading or running.
They still require supportive screens and the current owner32 reservation end.

Root's exact SDK inspection4f8054b4 confirms185 local entry4,508B/384B versus
0161's14,768B/848B. The actual record helper is12,132B/784B (different from the
standalone local cross-build). Fallback two-frame subtotal remains1,168B;
fresh writer1,088B/288B and UDP owner4,672B/1,056B grow slightly. These are
static observations, not CPU or cache-cost attribution. The original ambiguous
map match and Python basename-shadowing read-only errors remain retained.

Local64-unrelated-live-lease allocation control0ba6132a narrows the zero claim:
E5allocations/277B per prepared call becomes185one/21B, equalchecksum468800.
The original lease-expiry conversion remains. No-lease prepared calls still
reach zero after prewarm; neither scope covers the whole physical owner.
722 local final-codegen2f985631 confirms fewer static clock-call sites6→4,
same352B wait frame, with no runtime/A53 claim; source reviewc04e4d6a passes.

Completed54bd/0161 and standalone03ace/a8 branches now have exact durable
archive/perf-20261016 tags and clean detached worktrees. Their files, raw
evidence and all negative results remain. Active185/722 and operational agent
branches are intact. Accepted E and production remain unchanged; G is not yet
selected or qualified.

## 185 passes full functionality and A53 screening, 2026-10-16

The E/185 A53ten passes the original CPU improvement rule:138→114us/query,
69→57ticks,12tick delta>8,W8.772%,5/5 improving. p50 improves14.420%;p95
is inconclusive. All ten windows and430 archived files have independent
verification. This is a screen, not completed full performance qualification.
No new candidate has been selected or deployed. Production and E/F restored
identities remain unchanged;160 physical windows have completed overall.

The first health baseline failed before any performance window. Its apparent
last-probe cancellation remains a tool hypothesis, not a proven excuse. All
original logs and STOP were retained. The reviewed capture-before-stop repair
retains complete capture/final logs and qualifies all complete captured probes.
Fresh125s baseline passed without excluding a failed probe. Full110 runtime
validation separately preserves short-scene resume semantics; only the fresh
baseline imposes120s coverage. Final tool52a92e80 and independent48-test review
f95f83a4 bind controllerd2bb00f7/helper8e3367d9; the superseded runtime120s
version must never be used. Oracle tools and timed loops remain unchanged.

185 native240 has6 improvements,7 regressions,2 withinW; hit gains are
18.320–33.530%. Miss,miss-leases,raw,synth,lease,RRset and configured-CNAME
regressions all remain visible. The hot15 fixture does not recycle replies.
Owner32 low CPU is inconclusive; high variable-N CPU falls12.109% but sendlag
p50/p95 rises305.882%/75.309%. These diagnostics do not override original
full11/33 acceptance. All small raw files and PMU groups have independent
checks; owner large latency/sendlag binaries remain remote with original hashes.

Exact185 full functionality now PASS:957 short checks,44families/67jobs and
all original boundary corpora, receipt d76634eab46459a2a38e672da8e1eb86d79a250cf5b4b0c367ee79392fe2d4be.
Original28PTR,F39,2C defects and2UID lease differences remain unchanged. An
initial root-owned output-directory setup failure occurred before comparisons;
logs remain and only that directory ownership was repaired. Original corpora
then completed in a separate attempt. Source179/ELF/comparators were reverified.
The final quiet/lock audit released Oracle to DNS. DNS and DHCP are authorized
to execute the unchanged full11-scene110 matrices in parallel on separate
machines after their actual preflights. They are not yet complete.

Next source f3e0a145 contains5e67562f conservative lease-expiry bound plus
the separate hosts collision-fixture repair. With64 unrelated live lease names
the original5e local count gives185one/21B→zero allocations; no CPU claim.
Finalf3 Mac723/8ignored and musl all-target checks pass. The prior failed run,
its executable, and the independently reproduced fixture defect remain retained.
722d2762 owner-clock is another separate child; neither is part of185 timing.

## Complete110 matrices running; separate next work prepared, 2026-10-16

The original full Oracle E/18511scene110 started02:45:12UTC (PID776427),
and the independent router matrix started02:45:40UTC. Artifact/source/plan
identities and actual full functional PASS were bound before launch. The original
APK is now retained locally and hash-verified:5bb29803bceaf70eecc9a88d582e67a4440c53aa8ec498d3990b06eab82fe032.
Neither complete performance matrix is yet qualified. The first30 device
windows have independent verification of all1230 raw members and3guards.
In this formal round UDP-hit CPU138→116us passes the original rule, UDP-mixed
208→186us also passes, UDP-miss448→456us is inconclusive; none of these partial
results is a final33-comparison acceptance decision.

Root continued entirely locally. Independent0958f89c replaces repeated generic
cache validity traversal after positive A/AAAA selection with the identical
expiry predicate on the already fetched entry. Mac722/8ignored and musl
all-target checks pass; independent source review9cfd9649 verifies equivalence.
Local final codegen removes two is_valid call sites but grows the local/shared
entries32/80B; no SDK/runtime gain is claimed. Loop's independent99b519dc
delays the listener Arc clone until received packet work, preserving recv
counts,16packet budget,invalid/resend boundaries and pending-work ownership.
Its23bin/default+m6b checks and independent967ddae8 source/codegen review pass.

Combined sourcea15d3ca2 applies5e lease-bound,7c270 fixture,722 clock,0958
positive-validity and99 listener-borrow as five separate clean cherry-picks.
Local724lib/8ignored+23bin+default/m6b musl all-target checks pass; original
64live-lease prepared-query control remains185one/21B→zero with equal468800
checksum. Composition reviewad77431a passes; only the original five related
Linux groups are prepared (expected960, actual fresh listing still required).
No SDK or timing has run for this combination.

Compiler experiment80351142 is separate185+fixture+opt-level2; fatLTO and
codegen-units1 remain. Local.text decreases5.15% but shared cache/writer/wait
frames grow64/32/16B. ReleaseMac721/8ignored and musl checks pass; no IPC or
performance claim. Sourceb65e9a9c is another separate pending-review prototype:
record_at reuses the validated first question only atHEADER_LEN with a written
question; all other offsets retain original validation. Mac722/8ignored and
musl checks pass; local final-codegen work is pending. None alters185 timing.

Excluded diagnostic7c5b4c58 reuses the original E allocation meter/control
byte-for-byte on185; independent98367eec source review and original controls
pass. Its SDK and fixed three A53 count windows remain pending; whole-owner
zero-allocation and timing claims are explicitly absent. recvmmsg is deferred
after8dd138bd owner-boundary review: shared-pool tails add lifecycle/runnable
state, and partial-success errors cannot preserve currentresend classification
without another observation. No new batching implementation was made.

After DNS completes full110 raw checks/postflight/quiet, loop must independently
audit it before executing authorized C/185 profiling: original12stat+4cycles,
no instruction-sample repeat, exact original drivers/loadgen/symbol proof.
Planac6b2cf6 and independent2e5ff275 are frozen; no pretransfer yet. After device
full110 audit/restore/no-product-failure, DHCP is authorized for fresh exactC/185
UDP-hit five pairs, original thresholds and freshhealth/recovery. Plan8e56ce33
and independent8bcdfe38 pass locally. These two new diagnostics may run in
parallel on separate machines. Preserve pending timing exclusivity until the
actual releases, not just the last timed window.

## G accepted; next source and residual gap, 2026-10-16

Frozen185 is accepted as candidateG, tag
`perf/dnsmasq-candidate-g-20261016`. Its original SDK ELF is9109e987 and
APK is5bb29803; a build from the integrated main tree is not that measured
artifact. Functional qualification passed957short checks,44families/67jobs
and the original boundary corpora. Both full110matrices and independent
raw/statistical/health/postflight audits completed. Acceptance and source
integration receipts are in candidate-g-acceptance.json and
candidate-g-source-integration.json.

The formal A53 E/G matrix has110valid windows, no replacements,4/33 discernible
improvements and no discernible regressions. UDP-hit CPU138→116us/query
passesW/direction and11ticks>8; UDP-mixed208→186 also passes. Hit/mixed p50
improve14.214%/15.482%. TCP-hit164→152 and DHCP1500 2596→2564 remain
inconclusive. Oracle110 has no discernible primary change;26→24us UDP CPU
does not clear its variation/resolution. Resource ranges and all adverse
earlier native/owner-screen observations remain in the reports. The approved
CNAME behavior repair is common toE/G, not a new part of their delta.

Fresh direct exactC/G A53ten independently passes all10windows but still
findsG slower:82→114us/query,+39.024%,16ticks,5/5. This is a contemporaneous
comparison, not pooled with the formal E/G controls. Original C round4 p95
1.562003ms remains. E/F task slots and production identity were restored and
verified after both rounds. Oracle C/G profiling completed the original
12stat+4cycles captures: G UDP instructions−14.001%, user cycles+30.849%,
kernel cycles+1.09%. These are Oracle observations, not A53 PMU attribution.

Next product source6ab0f064 contains six separately committed optimizations:
lease expiry bound, disabled-diagnostic clocks, already-fetched positive-entry
validity, delayed UDP handle clone, first-written-question validation reuse,
and private UDP Rc ownership. The hosts collision fixture repair is separate
and test-only. Actual Linux961related checks pass; full44/corpora and timing
are pending. DNS owns the serial canonical SDK sequence for excluded G
allocation-meter source7c5b4c58, original controls, then6ab. No product source
or artifact is changed during a measured run. DHCP owns the reviewed fixed
three allocation windows followed by the separately bound G/6ab ten; loop
owns original native240/owner32 after actual artifacts and Oracle release.

The three-window meter permits zero or nonzero allocation counts and uses the
actual cached-hit denominator, including prewarm. Instrumented size/CPU/latency
are excluded from product acceptance. The first two launcher setup failures
occurred before any build and are retained; only launcher path/process checks
were repaired. Actual SDK sequence began with PID822120. This entry is a
checkpoint, not its completion receipt.

Independent local content-slice prototype2b4f8b16 removes one dependent storage
pointer and one allocation per content block. All16count controls and12ELF
function inspections have independent verification. Capacity1000 constructor
allocations99→83, but20snapshot root bytes rise2560 and peak detach bytes2240.
No runtime gain is claimed; full resource-tool representation adapters remain
unmodified. Separate803opt2 reduces local.text5.15% but grows selected frames;
its SDK/timing are pending. LTO/CGU1 already apply, and failed PGO size results
remain retired. Root is also examining conditional UBus doctor-metrics capture
in an isolated child of6ab; it is not part of the frozen SDK sequence.

## Exact6ab screening active; G allocation count complete, 2026-10-16

The canonical SDK sequence completed once with all six commands successful.
Independent94608544 verifies7c/6ab inputs, artifacts and original controls.
6ab ELFfeac49a0 is2145051B; APK37b2be86 is1167196B, both within original
budgets. Excluded7c count ELF92ba1353 is2366235B and APK1264206B: both
original budget failures remain, with no product promotion. Final quiet
receiptb596f6a0 explicitly released Oracle from DNS to loop.

Loop started original G/6ab native240 at05:20:33UTC, controller834343,
nativeplan968af9c4/runner241dd797/probe72d836d1. Independent original-protocol
and ready-binding reviews5aa27e67/800e726a pass. It then runs original owner32,
verifies raw/source/artifacts and releases to correctness for the prepared
original44families/67jobs and boundary corpora. Preparation1128afb4 and peer
reviewa052ce31 retain the same-source961receipt without rerunning those groups;
only the original fresh release-probe build precedes the remaining full gates.
No other Oracle workload or bulk transfer may overlap its measured windows.

The fixed G allocation three windows are complete and independently audited
by14c7e7e7:3archives/132files/95single-thread observations. Each window has
5200cached queries and exactly one128B allocation, with zero dealloc/realloc
in that classification; histogram0=5199/1=1. Cached-only whole-turn results
match this condition. All-owner totals remain separately reported, not a
process-lifetime allocation or leak conclusion. Instrumented timing is excluded.
All18000queries and health passed; E/F slots and production3086/2115 restored
and verified. The one prehealth stat-not-found tool failure remains retained.

DHCP started the independent exact G/6ab A53ten at05:24:20UTC, controller92747,
after fresh125s health and actual SDK/961/plan binding. It uses uninstrumented
9109/feac artifacts and original thresholds. Partial windows are not a result.
Keep transfers out of its windows; archive and restore precede release.

Root locally annotated existing G sample PCs without new profiling: original
cache-content/Record dependent-load sites and lease iterator state are concrete
code locations, not proven A53 cache stalls. Same-source child210801cf keeps
LeaseNames::lookup's API and original predicates but returns a direct slice
iterator. Mac726/8ignored and musl checks pass; independentb0d63b76 verifies
source/tests/codegen. The iterator is64→32B, its advancement code816→240B,
ownership frame368→336B, whole local ELF−888B; lookup/name_exists code growth
remains explicit. Linux/SDK/runtime qualification is pending. DNS is preparing
only original source/related/SDK inputs locally; execution awaits current
results and queue release.

Another isolated6ab child84912e54 moves the original conservative lease-expiry
guard to its sole caller and keeps the traversal in a separate non-inlined
frame. Mac725/8ignored+musl checks pass; codegen/source review is pending.
No current measured source changes. Local boolean-presence530 and conditional
metricsa2 prototypes were not selected: code-growth costs and evidence remain
under durable archive refs with detached worktrees/private files intact.

Separate803opt2 now has reviewed metadata-only builder copy08ccde52,
independentf26d9261. It verifies actual profile/compiler flags and rejects
ambient release-profile overrides; originalf454 builder stays unchanged.
No803 product SDK or timing has run. Its build remains after the active
native→owner32→full44 queue. AcceptedG and the original stopping rule remain;
this checkpoint is not task completion.

## 6ab screen closed; next compiler and inline-address sources, 2026-10-16

6ab is not promoted. Original A53ten and independent5a2263a1 pass10/10valid
but all three primary comparisons are inconclusive:122→116us CPU,5/5,3ticks,
change4.918% belowW6.897%. Oracle native240/owner32 and independentd68522c6
are complete. Native has9gains/2regressions/4within; synth-address+2.621% and
cname-config+4.765% remain. Owner32 plainCPU/throughput/latency/sendlag are all
inconclusive. All raw bins, including3.58GB independently replayed, remain.
Oracle release35dda22f passed to correctness; fullqualificatione1db339f is
running with originaljobs3, same-source961rehash and one fresh release probe.
Probe exit0/receipt402f9e93; original remaining/full families still pending.

After actual fullfunctional/audits/quiet, correctness must use followup_task
to wake DNS for authorized803originalfivegroups→reviewedopt2SDK. The disabled
package d7957509 and independentfb1cf84b are ready. Then actualSDK/gates/review/
transfers/quiet bind the original G/803 owner32 and independent A53ten in
parallel. Loop preparationb1efce28/7e344d5b and DHCP57ce2cc0 are reviewed.
There is no native240 for this compiler experiment: its original probe's
finalopt3 flags would not establish a profile2 single-factor comparison.

Root's next product source1df135dc is an independent6ab child, not combined
with210/849/2b/803. EntryDetails stores valid positive A/AAAA bytes inline;
Other retains separate CNAMEtarget and negativeauthority. OriginalArc<Record>
ownership remains. Source/count independent5ec04eed passes; Mac727/8ignored
and muslalltargets pass. Originalc43count16 has8pairs with every field equal
exceptside, including construction,20snapshots,COW,peak anddrop. Entry and
Option remain72/72B in actualhostcounts and purecompile-time Linuxtargetprobe.
Localcodegen removes the Record/RDATA dependence on the fresh address path,
but outlines eligibility384B; writer+56B,invalid+8B,wholelocalELF+976B remain.
No SDK, Linuxruntime, RSS/PSS or CPU improvement is claimed.

Bare1df originalrelated/SDK preparation0d90579d and independent0aca751f are
disabled/actualnull; expected963 is only a projection. It is the priority
product experiment after803, using originalG controls and unchanged full gates.
The live6ab/full44 and future803 artifacts must not be modified. DHCP's read-only
resource review finds no1df-specific representation blocker; actualoriginal
resource thresholds remain. Legacycompanion clockanchor drift and oldmemory
layout assumptions predate this change and are not called by currentfull44;
only recorded in844a797c, with no repair or new framework.

Other preserved local evidence:210directleaseiterator64→32B andguardframe
368→336B;84912e54 expirytraversal frame split passes source0a202a2b and725local
tests but remains unmeasured. G/A53target-cpu source478acea6 replays the original
F flag with a separatefixture fix. Local.text grows8.68%, not a demonstrated
SDK budget failure or runtime outcome; retain below803 priority. Local evidence
and Git refs are preserved; no new source has replaced acceptedG.
