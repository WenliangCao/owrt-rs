# UBus queued metrics ordering and opaque object names

This phase adjusts the standalone controller contract; product UBus activation
and live aggregate metrics publication remain separate gates. Tests used Rust
1.98.1 and the exact C ELF
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`
with its matching native libubus/ubusd. All network tests used the private
loopback-only network/mount/PID namespace runner. No physical router was used.

## Calls received during a synchronous DNS notification

The matching `libubus.c:99-124` queues INVOKE, NOTIFY and UNSUBSCRIBE while
`stack_depth` is nonzero. `libubus-req.c:151-200` decrements that depth at the
end of `ubus_complete_request` and invokes the pending-message timer before
returning when the socket is not registered with uloop. dnsmasq uses its own
poll integration (`ubus.c:143-206`), so this condition holds. The deferred
`metrics` handler therefore runs before `do_doctor` returns its replacement
and before the DNS reply's cache transaction is committed.

`ubus_order_diff.py` verifies this with the real C daemon. After receiving
`dns_result`, a real libubus subscriber invokes `metrics` from inside its
callback before completing that callback. C reaches the 100 ms notification
timeout, then answers the deferred metrics request. The snapshot shows
`dns_queries_forwarded=1` and `dns_cache_inserted=0`; after the DNS response,
the latter is 1. This baseline passes **24/24**.

The old Rust controller returned before servicing that request. An explicit
test fixture increments its supplied cache counter immediately after the hook
returns; this detects the old ordering as **39/40**, exit 1. The controller now
accepts `&Metrics` and drains already queued/buffered messages before returning
the selected address. The same comparison passes **40/40**. A deliberate wrong
C pre-commit expectation still reports **39/40**, exit 1. The Rust fixture's
counter is synthetic test input; these passes do not prove production cache
or aggregate-counter integration.

The caller must fetch a genuine pre-hook snapshot before locking ParentDns.
The controller receives only that borrow and never calls a provider callback.
Integration must preserve lock order `event -> provider -> parent`, avoiding
a parent-to-provider lock acquisition during the synchronous hook. It must
also drain ordinary messages before the hook so subscription state is current.
The existing clean-timeout, cancellation and transport-error rules remain in
force. The notification budget remains 100 ms; deferred handler work follows
that budget, as in C.

## Object path bytes

The [configuration phase](UBUS_CONFIG_PHASE.md) preserves opaque bytes.
`UbusService::connect_bytes` and `Connection::add_object_bytes` now register
them directly, using C's first-NUL length and appending `.dns` to the main
name. Existing string callers delegate to the byte API. No lossy conversion
or DNS-name normalization occurs.

`ubus_name_diff.py` completes all real C registrations before Rust. Six names
cover ordinary ASCII, leading/trailing spaces, comma/colon/slash characters,
non-UTF-8 bytes, quotes/backslash, and a 1,024-byte name. A libubus client emits
hex paths and verifies both assigned types and signatures. The paired corpus
passes **105/105**. A new Linux socket-pair regression independently verifies
the exact outgoing byte path and first-NUL termination.

## Regression evidence and limits

- Shared UBus tests: **65/65**, including all 64 existing tests.
- Standalone controller/metrics policy tests: **5/5** on Linux.
- Existing controller/payload corpus: **83/83**.
- Existing DNS doctor corpus: **473/474**, exit 1. The unchanged failure is the
  already documented C receive-buffer lifetime difference; it is not waived.

The first controller-corpus rerun used only the baseline JSON and omitted its
subscriber logs, producing **82/83** because the C event list was empty. That
failed harness setup is retained. Supplying the complete original C baseline
and its logs restores **83/83**; no expected payload was changed.

Raw observations, binaries, logs and failure runs remain ignored under
`private/dnsmasq-rewrite/ubus-lifecycle-20261001/`. ACL, full daemon pressure,
failure recovery and live main-loop integration remain untested by this phase.

After building the standalone fixture as in
[UBUS_CONTRACT_PHASE.md](UBUS_CONTRACT_PHASE.md), use fresh output directories:

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/ubus_order_diff.py \
  --reference-build "$EXACT_C_BUILD" --c-sha256 "$EXACT_C_SHA256" \
  --probe private/ubus-service-probe --out private/ubus-order

sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/ubus_name_diff.py \
  --reference-build "$EXACT_C_BUILD" --c-sha256 "$EXACT_C_SHA256" \
  --probe private/ubus-service-probe --out private/ubus-names
```

Omit `--probe` for the C-only ordering baseline. Use `--inject-error` and a
separate output directory for the ordering negative calibration.
