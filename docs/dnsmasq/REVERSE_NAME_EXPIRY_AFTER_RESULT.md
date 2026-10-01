# Shared name index closes the bounded reverse-expiry gap

Final private candidate `0eaaef8` passes all **27/27** frozen same-name expiry
observations against the saved exact-C baseline. The [six before differences](REVERSE_NAME_EXPIRY_BEFORE_RESULT.md)
are resolved. No C baseline, workload, comparator or expected row changed.

| Profile | After observations | Differences |
| --- | ---: | ---: |
| Same-name forward lookup, RD=1 | 5/5 | 0 |
| Same-name forward lookup, RD=0 | 5/5 | 0 |
| Same-name forward insertion | 6/6 | 0 |
| Read-only name existence control | 5/5 | 0 |
| Live forward/reverse coexistence control | 6/6 | 0 |

The three formerly failing profiles now remove the expired PTR and miss on
the rollback-time PTR query. The existence predicate stays read-only, live
records retain both directions, original PTR target case is preserved, and
all insertion/eviction counters match. The run exits 0 with no fixture failure.
Counter-mutation and missing-row comparator calibrations remain enabled.

An independent source review covered every `names` consumer. Committed records
of both directions now enter and leave the shared index; pending records stay
unindexed. Forward lookup removes invalid entries of either direction before
selecting or promoting only forward entries. Direction-aware conflicts protect
live reverse entries during forward insertion, victim removal and DHCP name
publication. The existence predicate excludes reverse records without mutation,
and DHCP publication records each dynamic row's direction. The existing guards
against CNAME-to-reverse links and forward local matching during reverse import
remain intact. No additional source issue was found in those consumers.

The final observed source is **`0eaaef8`**, not intermediate `adf3977`. Its cache
source hash was independently checked before execution and again through the
append-only build identity. Tests belonging to the intermediate source are not
substituted for this result.

## Original 125-row primitive regression

Because the index change affects direction selection, coexistence, expiry and
eviction, the original primitive comparator was then run unchanged against its
saved C baseline: **125/125**, zero differences, zero unsupported rows and no
fixture failure. This reused the exact same `0eaaef8` observation ELF built for
the 27-row addon; it did not rebuild the probe or execute C.

The 44-row multi-process C ordering cohort remains C-only. It was not replayed,
sorted or accepted as Rust behavior. Existing multi-PTR ordering gaps remain
open. The 27-row addon and 125-row regression retain separate denominators.

The actual regression command, run from the isolated build-host work directory,
is retained in ignored `private/primitive125-after-01.command.json`:

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/reverse_cache_rust_gate.py run \
  --build private/build-0eaaef8-01 \
  --c-baseline /home/ubuntu/dns-reverse-cache-20261001/work01/private/native-baseline-01 \
  --out private/primitive125-after-01
```

Each profile preserves its original commands, stdout, stderr, observations and
difference file. The original comparator still rejects missing rows and detects
one changed TTL. There were no failed after attempts or fixture revisions.

## Identity and evidence

| Artifact | Identity |
| --- | --- |
| Final candidate source | `0eaaef813893ac71954f56c379f8fc6b5eb24064` |
| Source archive SHA-256 | `80f8729926e16b0a630dfbaba19941bd4527fe534484a0617115d168e555c315` |
| Cache source SHA-256 | `5d62b11382abcb2c59cef411a060365f1675ebeca839101c1cb194d26e9160d2` |
| Shared observation ELF SHA-256 | `434171de6d85a0d78347a72b76defb12cf387eaee31a1d49b1e68989eec8bfff` |
| Unchanged addon tool SHA-256 | `c52d0d212a138bb411ff6154855bd8465ddb619e153538c6532f4b108f27a260` |
| Saved addon C result SHA-256 | `225cd87342a0719a37f026b8f792a51810b4e904ee9f0161206802e17fd5349a` |
| Saved original C result SHA-256 | `63e97d2c01e391036f9b71de7ea3bff47030816043b2aaecdcf308c406ae396f` |

The [derived JSON](REVERSE_NAME_EXPIRY_AFTER_RESULT.json) includes both sets of
counts, matrix identities, the invocation and append-only instrumentation.
The ignored `private/reverse-name-expiry-after-01.tar.gz` archive preserves the
final source, probe, saved addon C evidence and all after observations; all
168 files were individually verified after download. Archive SHA-256:
`bc9426e5182a1904dc7a1115a1b658df9dabb7dc0e48af8d40788f2ffccb9436`.
The separate `private/primitive125-after-01.tar.gz` archive preserves another
88 verified files, SHA-256:
`46d5b45938bfa03cad793abe2b04f12bc2da78054be17facb5df89f46bc9d906`.
Original before evidence and its six differences remain preserved. Remote
originals are under `/home/ubuntu/dns-reverse-name-expiry-20261001/work01/private/`.

All execution used `run_isolated.sh`. This is native-source primitive evidence,
not stock-image or service acceptance. Equal/case-equivalent names establish
the tested shared C bucket; collisions between different names remain outside
this gate. No router, resource/performance qualification or product promotion
is claimed. The extra name-index storage has no new allocation acceptance here.
