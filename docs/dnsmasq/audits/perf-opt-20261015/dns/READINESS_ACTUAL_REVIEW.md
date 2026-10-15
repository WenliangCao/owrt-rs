# Independent review of the actual selective readiness prototype

Reviewed source: `9ceab58d`, after initially examining `f404337f` (including
`7f9c09d6`). This is an actual-code review of `owner_readiness.rs`, its main
owner integration and the module/caller tests; it supersedes neither the
earlier proposal review nor future runtime qualification. Immutable E is not
changed by this separate fork.

Two concrete wait-budget issues were reported and fixed in `9ceab58d`:

1. Successful waits previously used the full incoming relative timeout after
   allocation and registration reconciliation. They now subtract preparation
   time before both direct epoll waiting and the mixed outer poll, matching
   the existing remaining-budget fallback.
2. An aggregate wake followed by an empty extraction could return zero before
   the caller's idle interval elapsed. A mixed internal wake with no expanded
   ready entry now waits through the remaining interval using direct poll.
   This preserves the DHCP probe's distinction between traffic and a complete
   quiet timeout. Existing EINTR retry policy is retained.

No further concrete blocker was found in this static review:

- Listener identity uses a monotonic listener token and transport role;
  accepted downstream TCP uses its own checked generation, preserved through
  vector moves. Signal and RouteWatch descriptors are installed once in the
  production owner. Retired registrations are removed before additions and
  each registration gets a separate checked monotonic event token.
- A downstream stream closed for stale refresh is no longer tagged in the
  forwarding phase. New accepts begin with zero ready events. Deferred listener
  Arc ownership keeps the same owned fd alive; the backend does not duplicate
  source fds or extend their ownership.
- Reconciliation rebuilds the exact normal/probe eligible subset. Forwarding,
  MAC waits, log-only clients and unclassified descriptors remain direct.
  Removal after close tolerates the expected absent/invalid source registration;
  unrelated control failure permanently disables optional acceleration.
- Duplicate logical slots merge requested IN/OUT interests but expand results
  through each slot's own requested mask plus ERR/HUP. Negative descriptors
  stay zero and no longer force an otherwise unnecessary outer wait. Final
  ready count uses expanded original entries, preserving downstream consumers'
  indices and readiness categories.
- Event storage covers the entire eligible set. All new vector growth uses
  `try_reserve` before pushes/resizes; checked arithmetic/identity exhaustion
  falls back. More than 64 tagged entries selects direct poll for that call
  and removes prior optional registrations, without limiting TCP capacity.
- Optional creation failure leaves direct poll available. Successful creation
  holds one additional descriptor from owner construction, so normal connection
  cleanup can return to that owner's initial FD set. This is a measured resource
  cost; it is not identical numeric FD-exhaustion headroom.

Reviewed file SHA-256 values:

| File | SHA-256 |
| --- | --- |
| owner_readiness.rs | `5d14a78758d05caa542c4056b91490e7f9f02ab6f8fb5a94d91ade8e8e7d51a3` |
| main.rs | `a686adb7ae506a4a587d5bd5c2c52b531bdc1c255ee440d5cef964bab759dd0f` |
| owner_readiness_tests.rs | `70179d43ea63f0445fcb8f68d4ac75682b3a9f54003d0aa4363d397babf86682` |
| main_readiness_hybrid_tests.rs | `582bc6d22db45a2c17ded5054382a10edfb3e614d5b9d471b8c8057df7d0782f` |

This reviewer ran no readiness runtime workloads. The loop owner retains its
earlier eight-plus-two test results on their original revision and is validating
the corrected nine-plus-two revision separately. Existing owner phase/partial
I/O tests, FD pressure and cleanup, allocation failures, full exact-C gates and
performance/resource controls remain necessary. No test pass or candidate
qualification is inferred from this static review.
