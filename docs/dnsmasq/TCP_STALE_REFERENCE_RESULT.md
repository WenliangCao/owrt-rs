# Private stale TCP differential result

The private candidate `2a773f8` matches the exact native C daemon in **41/41
observations** across all five stale TCP profiles. The fresh C-first paired run
passes **164/164 C checks** and **154/154 candidate checks**, with no comparison
or infrastructure failures. Both run in real foreground `-k` mode with private
ubusd inside the Linux isolation wrapper. This is private correctness evidence;
it is not a product merge or a performance result.

The [calibrated C baseline](TCP_STALE_C_BASELINE.md) establishes the expected
behavior before implementation. The paired gate covers finite stale success,
finite stale refresh EOF, explicit forever policy, a finite retention cutoff,
and ordinary empty OPT with EDE 3. In particular:

- The old TCP connection retains its accepted clock and the original cached
  TTL after wall-clock expiry.
- The later stale connection returns the old value with TTL 0 and flags
  `0x8180`. Its downstream EOF is observed before the controlled upstream
  refresh is released. An empty OPT yields EDE 3.
- The active TCP slot remains occupied while refresh is blocked, then closes
  after the one refresh. Success writes the new value into the parent cache;
  upstream EOF does not insert a value.
- Parent TCP-derived local/stale counters remain unchanged. All 30 real UBus
  fields match at every paired observation, including insertion and active
  TCP counts.
- After finite retention expires, the later connection waits for upstream,
  receives a fresh answer, and remains reusable. There is no premature stale
  answer or downstream EOF.

The comparison preserves packet flags, section counts, ordered records, EDE
data and ordered upstream queries/replies. Upstream transaction IDs are
normalized. Only designated fresh cached TTLs allow a one-second difference
between runs; stale TTL, EDE, flags, refresh count and EOF/release order remain
exact. C's child PID and pipe structure are checked only on C, since the private
candidate uses threads. The ten inapplicable checks are exactly two C process-
shape checks in each of five profiles; they are not counted as candidate passes
or silently included in 154. Active-slot metrics and cleanup remain required on
both. The 41 explicit paired observations are separate from these auxiliary
calibration totals.

Comparison calibrations accept an identical trace and reject missing
observations, changed RCODE, changed stale TTL, and reversed downstream
EOF/upstream-release order. The original C-only positive and negative
calibrations and their earlier harness failures remain preserved separately.

| Artifact | Identity |
| --- | --- |
| Exact native C ELF | `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431` |
| Private candidate ELF | `012448b55401f3ca5e0550751b1cd695dc4b137f948c624a366afa6886233e4a` |
| Private candidate source | `2a773f8` |
| Paired tool commit | `bdecb33` |

The JSON records tool, result, archive and individual C/candidate trace hashes.
Raw evidence is retained in the independent stale-gate worktree's ignored
`private/stale-tcp-evidence/paired-01-evidence.tar.gz` and on oracle under
`/home/ubuntu/tcp-stale-gate-20261001/private/paired-01/`.

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/tcp_stale_oracle.py \
  --reference-build /home/ubuntu/dnsmasq-rewrite-20260929/c-native-01 \
  --rust "$PRIVATE_CANDIDATE" \
  --out private/stale-tcp-paired
```

The private implementation replaces the old stale-policy rejection with a
deliverable cached packet plus the engine's observed stale flag. Only a
successful downstream send of an actual stale answer triggers shutdown and
close. The same worker then forwards the original query once, retaining its
accept clock and writeback pipe, discards the refreshed downstream result and
exits. A failed send does not refresh; a stale observation with no answer
remains an ordinary forward miss. Tests separately pin expiry equality (TTL 0
without stale), finite cutoff, and a positive-TTL answer marked stale by the
CNAME/NXDOMAIN pre-scan, so TTL is never used as the stale classifier.

The borrowed cache policy was reconciled before the stale implementation:
private `319a3e2` incorporates `7f60791`, and `ee5f279` adapts `ddac95d` through
the capture wrapper. Unsupported metadata, extraction without ordinary commit,
and normal commit remain distinct; independent bogus transactions keep their
own commit boundary. TCP uses the restored request CD rather than UDP raw reply
CD. This interface alignment is **not** an actual TCP CD/bogus or CD-prefix
qualification; those combinations remain outside this gate.

The same frozen native candidate passes the ordinary TCP regression (32/32),
UBus daemon integration (69/69 paired observations, 585 checks), namespace-
isolated Linux tests (398 library + 7 main passed, 16 ignored), and native plus
aarch64-musl all-target Clippy with warnings denied. The ignored drivers are
not passes. Tests ran through `run_isolated.sh` as the build user; no library
test was run in the ordinary oracle namespace for this stale task. Regression
raw files and logs are under ignored `private/stale-reference-evidence/` in the
private reference worktree and oracle
`/home/ubuntu/dnsmasq-tcp-stale-reference-20261001/2a773f8/`.

The complete cache clone and typed pipe codec remain private references. No
snapshot representation has passed the existing resource guards, and this code
must not be merged into the default product cache as a `Clone` implementation.
Capture/encode/decode allocation failure, abnormal partial EOF effects, typed
codec byte-size/backpressure differences from C, and resource cost remain
unqualified. The earlier ordinary private report remains frozen at its old
source, including its then-explicit stale exclusion and known gaps.

This run does not cover DO/CD combinations, CNAME stale/no-answer service
cases, EDE size boundaries, malformed partial frames, or OOM. Deliberately
reversing worker exit and cache-pipe EOF belongs to the separate slot gate.
The forever profile is representative, not an unbounded-duration proof.
There is no throughput, memory, latency, target-musl or router acceptance here.
No physical router was accessed.
