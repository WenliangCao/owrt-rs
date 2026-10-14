# Proposed source-bound contract: six-host-record .1 PTR initial order

**Proposed for review; not activated and not final acceptance.** The unchanged observed manifest remains 11 tracks / 23 states. This proposal adds exactly one source-derived contract with four states and eight target observations. The checker refuses a source entry unless its review status is explicitly approved. No real candidate has been reclassified with this proposal.

The exact source is OpenWrt 25.12.5 dnsmasq 2.93-r1, recipe revision `f0a60eee2fe051741c643ea6118718aae1ef17fb`. Its retained identity file hashes all three source files used here. Exact C ELF SHA-256 is `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`; the executable is AArch64 PIE. Source hashes and line anchors are in [source-evidence.json](source-evidence.json).

| Source anchor | Relevant contract |
| --- | --- |
| `cache.c:38–43`, `295–309` | `typestr` contains name pointers and supplies raw bytes to the name hash; pointer placement can change bucket placement between process starts. |
| `cache.c:312–341`, `1174–1231` | Hash chains preserve reverse/immortal classes, and forward rotation only moves records within the same class. |
| `cache.c:1262–1317` | PTR lookup walks bucket/chain order. It changes temporary result links, not the hash-chain order. |
| `cache.c:1322–1385`, `1640–1666` | Configured host-records use the bulk insertion path involved in this six-row fixture. |
| `rfc1035.c:1939–1989` | PTR records are emitted in that lookup order. |
| `dnsmasq.c:2104–2197` | Non-debug TCP handling forks the current parent state before servicing the connection. |

The scope is only the six configured host-records corresponding to the original six-line fixture. Fixture SHA-256 is `6601edabfe74502710720d990897b6c1559d76d39b9214b71dc431f40da10791`. Full service options, initial files, mutation list and all 28 query inputs are bound by `1fcbdc9c0dc1baa90c91fff0a1ad875cb95eb081d984afdb105eca5128767411`. The reference document and reference case hashes are also fixed. Candidate paths and executable names are excluded from the service-options comparison; no configuration option or query input is excluded.

Only question `1.2.0.192.in-addr.arpa`, IN PTR, is qualified. Its full C records are fixed: two answer records with TTL 37 and targets `x.test` and `y.test`. All owner/type/class/TTL/section fields, DNS header and other records stay unchanged. The four states are:

- `udp-ptr-before-192.0.2.1`, repetitions 0 and 1.
- `udp-ptr-after-192.0.2.1`, repetitions 0 and 1.
- `tcp-ptr-before-192.0.2.1`, repetitions 0 and 1.
- `tcp-ptr-after-192.0.2.1`, repetitions 0 and 1.

The permitted transformation is one consistent initial permutation across **all eight observations and both transports**: either every answer is `[x.test, y.test]` or every answer is `[y.test, x.test]`. This is inferred from the exact source's process-dependent initial namehash placement, not from the candidate's response. There are exactly two records, so there are only those two initial permutations.

Within this fixture, the only multi-address forward query is `y.test`. Its .1 record is reverse-owned and its .2 record is not; forward lookup cannot rotate them across their different reverse flag classes. `x.test` has one address. Neither `x.test` nor `a.test` is forward-queried; the readiness name is also a singleton. There is no DHCP, reload, hostsdir event or other generation mutation. Therefore a later phase, repeated reply or TCP child must not select another permutation. The source rationale does not apply to the separate five-line query-induced PTR-order bug or any other case.

The [proposal entry](entry.proposed.json) was generated from exact C, the explicit fixture and source hashes only; the generator accepts no candidate argument. The [combined proposed manifest](manifest.proposed.json) preserves all existing observed entries unchanged. Validation uses a synthetic uniform reversal of the C records, never a real candidate, and confirms that a proposed entry is inactive. Twenty checker unit tests pass, and 11 actual-C-derived negative controls reject transport/phase/repeat splicing, changed input, unknown case, header/TC/TTL/count/RRset and forward-order changes. See [negative-controls.json](negative-controls.json).

This is a narrowly scoped source inference for independent review. The retained 4ff6 run remains `passed=false`, exit 1, under the observed-only manifest. No additional C process was run and no raw result was altered.
