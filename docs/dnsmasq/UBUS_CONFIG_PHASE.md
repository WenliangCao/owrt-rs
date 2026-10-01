# UBus configuration state and activation boundary

`config::ubus::UbusConfig` preserves the exact `option.c:2271-2277` state:
disabled by default; `enable-ubus` selects `dnsmasq`; a supplied nonempty
argument is an opaque byte string decoded by `opt_string_alloc`. It is not a
DNS name and is not restricted to UTF-8. The existing loader applies C's
once-per-origin repetition and file-over-CLI precedence rules.

An explicit empty argument, including `enable-ubus=""`, leaves the C name
pointer NULL (`option.c:682-697`). C's `--test` accepts it. `ubus_init` later
calls `strlen` on that pointer after establishing a bus connection. Rust keeps
the accepted typed state `Enabled { name: None }`, while `object_name()`
explicitly rejects activation with `empty enable-ubus object name`. This is a
documented safety boundary, not a default-name substitution or full runtime
equivalence claim. The unsafe C activation path was not executed.

The native oracle links the unmodified exact C objects and runs `read_opts`;
it does not open listeners. All C observations precede Rust probe invocation.
The frozen corpus has 33 cases and checks state and `--test` independently:
omitted/empty arguments, quoting, whitespace, metacharacters, opaque bytes,
embedded-NUL line termination, long names, CLI optional-argument behavior,
repeated options and cross-origin precedence.

With Rust 1.98.1, the positive run passes **66/66**. The negative calibration
changes the disabled case's expected state and reports **65/66**, exit 1.
Raw configurations, logs and linked binaries remain ignored under
`private/dnsmasq-rewrite/ubus-lifecycle-20261001/`. No physical router was used.
The parser does not activate UBus or supply metrics. Product publication still
requires the real engine metrics and main-loop integration gates.

```sh
python3 tools/dnsmasq/ubus_config_diff.py \
  --reference-build "$EXACT_C_BUILD" --source "$EXACT_C_SOURCE" \
  --rustc "$RUST_1_98_1" --out private/ubus-config
```

Use a fresh output directory and `--inject-error` for the negative calibration.
