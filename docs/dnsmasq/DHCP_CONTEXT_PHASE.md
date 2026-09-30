# DHCPv4 dynamic context completion

`dhcp/context.rs` implements the dynamic IPv4 portion of exact `dhcp.c`'s
`guess_range_netmask()` and `complete_context()` (`567–687`). It consumes parsed
ranges, persistent context state and ordered interface snapshots. It returns
the current range list, broadcast addresses and source configuration indices.
Allocation epochs retain that source mapping when the current list reorders.

| C contract | Rust boundary |
| --- | --- |
| Guess an omitted mask when either endpoint shares an interface's subnet | Guess for all enumerated interfaces, including other interfaces |
| Explicit zero mask stays zero and cannot form a current context | `None` and `Some(0.0.0.0)` remain distinct |
| Link each qualifying context once, on the receiving interface only | Preserve its first matching local/router address during a packet |
| Each linked context prepends to `current` | Reverse insertion order; do not substitute the first configured range |
| A later interface may still change a linked context's guessed mask/broadcast | Construct returned ranges after the complete enumeration |
| Keep explicit broadcast; otherwise use a same-subnet interface broadcast or computed fallback | Preserve zero and unusual explicit broadcast addresses too |
| Inferred fields survive packet boundaries | Keep `ContextState` through interface changes and disappearance |

The caller owns primary-address and listen-address admission. C obtains the
primary address with `SIOCGIFADDR`; if the primary fails admission, its secondary
search chooses the last enumerated matching address, completes it first, and
then enumerates every address again (`dhcp.c:353–364`, `check_listen_addrs()`).
The pure function accepts exactly that ordered callback sequence, including a
preferred-secondary prepass. It does not infer a primary from the first address
or from packet destination metadata. The integration layer must supply the
admission result and enumeration order.

The dedicated `dhcp_context_diff.py` oracle extracts both function bodies
verbatim from hash-pinned `dhcp.c`, then links them against the audited native C
objects/dependencies. The extraction SHA256 is
`06cbb38390dde4f2d795f205fe71d20eb6132a65b6e03c57a20f4d40b329336a`.
The extracted C bodies and driver are compiled with ASan and UBSan; previously
built dependency objects are not retroactively sanitizer-instrumented. No OS
interface or socket operation supplies expected state. C warnings are suppressed
in the driver, so warning logs are explicitly outside this comparison.

A C-only baseline froze 145 scenarios and 402 state transitions: 120 transitions
produce at least one current context, 282 produce none, and 162 contexts are
selected in total. The final C/Rust comparison matches all 145 scenarios with
zero mismatches or sanitizer failures. It compares ordered selected contexts
and all persistent mask/broadcast/router/local/epoch fields, including contexts
not selected in the current step. The corpus has 17 directed scenarios and 128
deterministic generated multi-step scenarios. Generated direct state inputs also
exercise combinations a configuration parser would reject; they do not claim
configuration acceptance. The comparator/counter calibration reports one
success and two deliberate errors. Six local Rust regression tests pass.

```sh
python3 tools/dnsmasq/dhcp_context_diff.py \
  --source "$REFERENCE_SOURCE" \
  --reference-build "$REFERENCE_BUILD" \
  --out private/dnsmasq-rewrite/dhcp-context-diff
cargo test --manifest-path components/dnsmasq/Cargo.toml --lib dhcp::context::tests
```

Ignored `private/dnsmasq-rewrite/dhcp-context-20260930/` retains the C-only
baseline and every attempted differential build. `diff-01` failed to build
because the standalone Rust probe omitted its lease-file module dependency;
`diff-02` passed after fixing the probe, and `diff-03` is the final recorded
source/artifact identity run. No failure was counted as a pass.

This phase excludes shared networks, relay context selection, primary/listen
admission, log output, real interface discovery and packet-level option
construction. Those contracts require their own integration evidence. The
algorithm retains the C `interfaces × ranges` cost and adds bounded per-call
selection vectors; this phase makes no performance improvement claim.
