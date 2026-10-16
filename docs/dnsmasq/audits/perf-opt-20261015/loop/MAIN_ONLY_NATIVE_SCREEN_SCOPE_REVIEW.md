# Native probe scope for 025 and 5c

The original 162-file native protection manifest includes `main.rs` and seven
binary probe sources; it is not a library dependency-only list. Exact Git
hash comparison shows 025 and 5c each differ from 6ab only in `main.rs` among
those 162 files. The other 161 files are byte-identical. Their complete Git
diffs from 6ab also change only `main.rs`.

The unchanged native runner at `run_post185_combined_native.py:117–123` builds
`--lib`, then compiles the original external hot15 probe with
`--extern dnsmasq_rs`. `Cargo.toml` explicitly sets the library entry to
`src/lib.rs`; it does not include the daemon's `main.rs`. Neither extracted
owner helper is reached by this probe. This matches the previously recorded
scope in [the 6ab native result](POST185_COMBINED_NATIVE_RESULT.md).

Repeating native240 for these main-only changes would not measure their new
owner paths. If selected later, retain the existing 6ab native evidence,
including both regressions, and use original related/SDK plus owner32/device
screens for the changed owner. The existing
`tools/dnsmasq/audit_20261011_runtime_signals.py` already exercises two SIGUSR1
dump requests and SIGALRM maintenance followed by a dump. It is a frozen
independent audit, not an entry called by the original 44-family registry or
runner. A future selected 5c must explicitly run that existing audit through
its original isolated entry; no coverage is inherited from full44 and no new
test rules are needed. Full acceptance gates remain separate. This scope
review changes no current bare 1df native240 window, threshold or queue.

[Exact input checks](main-only-native-screen-scope-review.json) retain the
three source identities, differing hashes and original entry/probe bindings.
The review used local existing source only: no compilation, target execution,
new measurement or remote access.
