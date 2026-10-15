# Performance research continuation

Branch: `perf/dnsmasq-20261015`; worktree:
`/Users/USER/Developer/owrt-perf-opt-20261015`.
Starting main: `51b03959`. Do not merge main, push, or deploy.
Original main worktree has user prompt edits; leave them intact.

Status: frozen protocol; first algorithm directions screened. Device baseline initial attempt was excluded after a controller archive incompatibility and overwritten guard segment. All completed/interrupted raw windows retained; fresh entire 110-window baseline uses prefix base2. No selective replacement. Current best remains
deployed v0.2.0 SHA256 `8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7`.
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
