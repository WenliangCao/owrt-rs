# Local/reverse precedence and metadata addon before result

The independently frozen [three-profile addon](REVERSE_LOCAL_ADDON_PLAN.md)
calibrates **28/28 observations against native C** and **28/28 against the
actual image**. The saved C observations also compare 28/28 without another
execution. Each C variant passes 42 auxiliary DHCP checks and 121 fixture/UBus
checks, separate from the 28 observations.

Private Rust source `0eaaef8` completes all 28 native comparison observations:
**24 match, four differ, zero fixture failures**. All four differences occur
in the existing-CNAME-before-lease scenario. No after implementation is claimed.

| Profile | Native C | Image C | `0eaaef8` native before |
| --- | --- | --- | --- |
| Address-owner CNAME before real lease publication | 8/8 | 8/8 | 8 compared / 4 differences |
| Local plus dynamic PTR/ANY with RD/DO/CD | 14/14 | 14/14 | 14/14 match |
| Stale dynamic entry visited by ANY, local-only reply | 6/6 | 6/6 | 6/6 match |
| **Total** | **28/28** | **28/28** | **28 compared / 4 differences** |

This addon has 19 recipient DNS responses, six real DHCP exchanges, two held
request observations and one background-refresh observation. It does not add
28 rows to the old 62-event service gate. The single stale wait is functional
expiry control, not a performance window.

## Reachable CNAME precedence difference

The complete C daemon first receives an upstream CNAME from the address-form
PTR owner to a non-address terminal, with PTR at that terminal. It commits the
forward CNAME/Generic(12) chain because no direct PTR matched the original owner.
A real DHCP OFFER/ACK then publishes the lease for the address. The ordinary
short-name A probe proves that publication is visible.

On the next ordinary PTR, C still returns the cached CNAME followed by the
terminal PTR and clears AA. Rust instead returns the lease FQDN directly with
AA set. RD0 and empty-OPT/DO PTR requests must reject that dynamic CNAME and
forward; C receives the controlled SERVFAIL, while Rust again answers with the
local lease PTR. A final ordinary query shows that C's original chain remains
cached; Rust still selects the local lease. These four answer differences also
carry the RD0/DO forwarding/local-answer metric differences into later rows.

The evidence matches the earlier independent source audit: rfc1035.c:1753-1814
visits CNAME/NXDOMAIN before local PTR selection, and rejection of a dynamic
CNAME does not permit fallback to the original address's local PTR. The current
local-first query entrypoint hides that prior cached chain. A correction should
preserve the one initial lookup's expiry/LRU/stale effects and pass its result
through the common query path; merely modifying the already-built local packet
would not preserve this branch or prevent duplicate lookup effects.

## Independent metadata controls which already match

A genuine direct PTR query is held upstream, then real DHCP ACK publishes the
lease before the reply is delivered. The resulting cache state is reached
through actual callers, not a synthetic local blocker.

Once local and dynamic reverse entries coexist, C evaluates RD/DO admission
using the first local entry. PTR includes the local FQDN followed by the dynamic
target even with RD0 or DO; it clears AA. ANY includes only the local PTR and
retains AA. RD1/RD0 crossed with plain/DO questions, plus DO+CD controls for each
qtype, all match on `0eaaef8` across the 14-observation profile. Original-case
targets, each TTL, flags, OPT metadata, no-upstream behavior and counters remain
part of comparison. These passing controls bound the CNAME fix's scope.

The separate fresh stale profile holds PTR, publishes the lease, delivers a
TTL1 dynamic answer and waits 2.1s. ANY with empty OPT then returns only the
local FQDN, with AA and EDE3, before the observer supplies a refresh response.
The dynamic entry is stale and visited even though it is omitted from output.
The daemon increments its stale-answer counter and makes exactly one background
ANY request. The observer replies NOERROR with no answers, avoiding SERVFAIL
retry semantics; no second recipient reply or additional upstream request is
observed after the completion check. `0eaaef8` matches all six observations.
This is a logical response-before-refresh-answer check, not a claim about the
kernel arrival order of two sockets or indefinite absence of later traffic.

## Identities, controls and boundaries

- Frozen plan: `7022440`; frozen tool: `140b889`.
- Tool SHA-256:
  `42bf3d66bb6ade586cfe37277f251889c178ab6e252240f0eaf493db584e8eb0`.
- Unchanged real-DHCP helper SHA-256:
  `76e97c4dedc1026411e80ef985764050d8f0808c20f10588a5582530251146ee`.
- Rust before source: `0eaaef813893ac71954f56c379f8fc6b5eb24064`.
- Rust native daemon ELF:
  `217bace9b1a231d0a008842365239085ad21353fb75750d70103325699d3888a`.
- Recorded source archive SHA-256:
  `191e841a8989884d8509652c1aa406b92008aae8097dab76cb3c0526ad1de601`.
- Native C ELF:
  `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
- Actual-image C ELF:
  `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`;
  runner, musl loader and dependencies are checked before execution.

Both C calibrations finish before the Rust before comparison. No matrix or
predicate revision is needed, and no failed attempt is discarded. Every C
profile detects one changed saved DNS flag and rejects a missing observation.
A standalone paired negative awaits a fully passing source. Compression may
differ; cached upstream CNAME/PTR TTL phase may differ by at most one second.
Local/DHCP TTLs, case, ordered records, flags, durable lease relationships,
upstream sequence and counters remain checked.

Raw evidence is retained as `local-addon-native-baseline-01`,
`local-addon-image-baseline-01` and `local-addon-native-before-01` under
`private/dnsmasq-rewrite/reverse-cache-gate-20261001/private/`, mirrored from
`/home/ubuntu/dns-reverse-cache-20261001/work01/private/`.
`local-addon-before-evidence-sha256.json` covers 185 files, including the frozen
ELF and its original source/verification identities. The source build's broader
verification belongs to its own report and is not counted as addon observations.

All experiments use run_isolated.sh and private real lease files. The old 62
and config5 results remain attributed to `a4a38bc`; they are not relabelled as
`0eaaef8`. No multi-target-order, arbitrary EDNS/DNSSEC, transfer, resource or
production/deployment acceptance is added by this bounded addon.
