# OpenWrt ubus contract: real C baseline

This phase is a functional baseline, not complete Rust integration, performance
evidence or production acceptance. No physical router was accessed. The exact
patched C daemon and image-matching libubus/ubusd run on the Linux build host in
a fresh network/mount/PID namespace containing only loopback. The runner mounts
a private `/run` before either daemon starts; every ubus client uses its private
UNIX socket explicitly.

## Reference and observed contract

The reference ELF remains
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
Its source and native dependencies are the audited artifacts described in
[REFERENCE_AUDIT.md](REFERENCE_AUDIT.md). The runner requires this supplied
digest, records the ubusd/client/tool identities, and links its subscriber to
that build's libubus/libubox. It does not replace C handlers or inject counters.

| Source | Contract / evidence |
| --- | --- |
| `ubus.c:56-85,111-147,213-234` | `<name>` has only the no-argument `metrics` method. `<name>.dns` has no methods. Both have assigned object types. Source type names remain `dnsmasq` / `dnsmasq.dns`; type names are not transmitted in this wire registration. |
| `metrics.c:20-52`, `metrics.h` | Exactly 30 ordered u32 fields, including unavailable-feature counters and `dhcp_lease_actve`. The live DNS and DHCP engines change their own counters. Unknown `set_connmark_allowlist` returns method-not-found, status 3. |
| `rfc2131.c:1918-1962`, `ubus.c:411-429` | Only ACK and RELEASE are emitted here. Fields retain `mac`, `ip`, optional `name`, `interface` order; RELEASE passes NULL for name even when the lease has a hostname. `quiet-dhcp` suppresses notifications unless `log-dhcp` or a logged error bypasses its early return. |
| patch 200, `rfc1035.c:457-503,525-583` | `dns_result` fields are `name`, u32 `ttl`, `type`, `address`, in that order. A same-family string address replaces RDATA and clears AA, even if the address is unchanged. Invalid/wrong-family/wrong-type replies leave the original address and AA. |
| `ubus.c:396-408` | One synchronous notification has a 100 ms completion budget. Immediate/no-data responses return promptly; silent and 180 ms delayed subscribers produce the original reply after that budget. This is a per-record budget, not an unconditional delay on every DNS query. |
| `rfc1035.c:458-470` | The last response containing a string `address` wins. A later invalid string cancels an earlier valid rewrite; arrival order is preserved. Two subscriber processes with controlled response delays verify this. |
| `forward.c:806`, cache extraction | A rewritten UDP answer is cached with its replacement address. The immediate cache hit does not forward again or notify again; its TTL is retained with only the one-second wall-clock boundary allowed. |
| `dnsmasq.c:2187-2189` | TCP child drops ubus; its answer is not rewritten and emits no DNS event. The parent's next UDP query still uses its live subscription. |

The baseline uses normal daemon mode (`--keep-in-foreground`), including the
real TCP fork path. Debug `--no-daemon` is unsuitable for this TCP boundary:
patch 200 also drops the caller's ubus connection on that nonforked path.

## Observed reference defect: DNS object after ubusd restart

On a private ubusd restart, metrics reconnects and preserves all 30 counters,
but the DNS object's lookup returns status 0 **without DATA**. The source
explains why: `ubus_destroy` resets only the main object's/type's IDs. The DNS
type ID survives into the replacement ubusd, where it is unknown.
`ubusd_create_object` accepts a path with a NULL type, while `ubusd_send_obj`
omits objects lacking a type. Therefore the DNS path exists but cannot be
resolved by ordinary lookup or subscribed to by name.

This is recorded reference behavior, not a desired Rust compatibility rule.
Rust must register both objects and their types from fresh connection state.
The C baseline counts the observed defect separately in `reference_defects`;
a passing baseline does not imply the C implementation has no known defects.

The first test client exposed an additional harness error: libubus's
`ubus_lookup_id` can return 0 with no DATA and leave the caller's output untouched.
The client now initializes the ID and returns NO_DATA if lookup supplied none.
The original failing runs are retained. An initial expected RELEASE name was
also corrected against the actual callsite and real observed omission.

## Calibration and evidence

The final C-only corpus is frozen at **256 checks**. Positive calibration
passes **256/256**, exit 0. Negative calibration changes the expected address
of a real unsubscribed DNS answer: **255 pass, 1 fail**, exit 1. It exercises
the actual semantic comparator and result accounting, not a fake forced error
counter. Every run retains its checks, raw typed payloads, DNS packets,
subscriber logs, daemon logs, upstream requests, tool hashes and failures under
ignored `private/dnsmasq-rewrite/ubus-20261001/`.

| Run | Result | Meaning |
| --- | --- | --- |
| `baseline-01` | 157 pass / 1 exception | Restart subscription failure exposed; initial client had uninitialized missing lookup ID. |
| `baseline-02` | 173 pass / 1 exception | Exact missing lookup DATA established; initial “listed object” hypothesis disproved. |
| `baseline-03` | 239 pass / 2 fail | RELEASE lacks hostname; erroneous initial fixture expectation retained. |
| `baseline-04` | 255 pass / 0 fail | Full C corpus before frozen-count guard. |
| `baseline-05` | 256 pass / 0 fail | Final positive calibration including frozen count. |
| `calibration-negative` | 255 pass / 1 fail | Deliberately incorrect DNS expected address rejected. |

Reproduce on an isolated Linux build host, with a new ignored output directory:

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/ubus_contract_diff.py \
  --reference-build "$EXACT_C_BUILD" \
  --c-sha256 bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431 \
  --out private/ubus-baseline
```

Add `--inject-error` and use a different output directory for the negative
calibration. The native build's library path stays private to the test process.

## Remaining integration gates

The production Rust daemon does not yet publish these objects or notify these
subscribers. A standalone `metrics` object with fabricated zero values would
not satisfy this gate. The new controller boundary is being verified separately;
it requires its caller's real `Metrics` and does not manufacture counters.

Still pending: synchronous multi-subscriber DNS transport and main-loop
integration; complete C/Rust paired metrics increment/reload windows; DHCP
error notifications and all optional-field callers; ACL allow/deny under the
dnsmasq identity; subscriber pressure, FD/memory exhaustion, partial frames and
long-run growth; reconnect during a notification; helper/hotplug/ujail/procd
and rpcd/LuCI integration. Process termination and disappearance are checked,
but no peak-memory, FD-peak or performance claim is made by this corpus.
