# Preserve address-line boundaries in staged hosts reads

The matching C `cache.c:read_hostsfile` checks its 1,000-accepted-name growth
threshold at the start of each address line, before iterating that line's names
(around lines 1480–1486). It also rehashes at file completion. It does not rehash
between aliases on the same line. The ordinary Rust streaming reader performs
the equivalent transition after each completed line; the staged source helper
previously advanced after every accepted record.

This mechanism difference is observable. A bounded source-level probe builds
one crossed-name bucket, then reads a single line containing 1,001 unique
aliases followed by a duplicate `x.test`, all at one address. Under one process
seed and identical initial state, the frozen `ce04a28d` source returns opposite
A and PTR orders depending on whether it uses streaming or staged loading:

| Path | A x.test | PTR 192.0.2.1 |
| --- | --- | --- |
| Streaming / actual line boundary | 192.0.2.1, 192.0.4.1 | selected, x.test |
| Previous staged / each record boundary | 192.0.4.1, 192.0.2.1 | x.test, selected |
| Fixed staged / endpoint `[1002]` | 192.0.2.1, 192.0.4.1 | selected, x.test |

`selected` is found from a fixed bounded name pool using that process's actual
hash. Each comparison uses the same process and seed; it is not a comparison
of arbitrary C/Rust startup orders. The test demonstrates ordering differences,
not lost records or a service interruption. [result.json](result.json) retains
the failing old-source run, the fixed run, binary hashes and source/tool hashes.
This is a source-level regression test, **not an exact-image daemon runtime
measurement**.

The fix preserves cumulative accepted-record endpoints as source metadata in
the staged reader. Endpoints include duplicate and expanded names; they cross
read-chunk boundaries and are retained only when the accepted count increases.
Metadata reservations are fallible and share the existing incomplete-source
failure path. The source transaction advances bulk hash growth only at those
endpoints and file completion. Ordinary incremental loading still has no bulk
reverse hash or bulk growth accounting.

The `hosts.rs` unit feeds the 1,002-alias line in 4,096-byte chunks through the
production parser, checks endpoint `[1002]`, and compares full entries plus A/PTR
orders between streaming and fixed staged paths. The standalone
`tools/dnsmasq/hosts_line_boundary_probe.rs` also retains the old per-record
placement as an explicit negative control and checks that it differs.

Replay the fixed source probe locally:

```sh
rustc --edition=2024 -Awarnings tools/dnsmasq/hosts_line_boundary_probe.rs \
  -o private/staged-line-probe/fixed-probe
private/staged-line-probe/fixed-probe
```

The frozen old `hosts.rs`, its failed probe executable and stdout/stderr are
retained in ignored `private/staged-line-probe/before/` and the parent directory.
No frozen Oracle candidate was modified or relabeled by this test.
