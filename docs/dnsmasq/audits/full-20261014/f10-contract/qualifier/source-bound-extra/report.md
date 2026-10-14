# Three proposed source-bound PTR contracts

**Proposed only; not activated.** These entries apply individually to the exact C source and fixed inputs below. They add no general PTR-order exemption. No real candidate was evaluated with the proposal, no original result changed, and no C process was rerun.

| Fixed case | Question | Bound DNS queries | States / repeated targets | Uniform initial owner orders |
| --- | --- | ---: | ---: | --- |
| six-hostsdir-initial | 192.0.2.1 reverse PTR | 28 | 4 / 8 | `[y.test,x.test]` or `[x.test,y.test]` |
| leases-dhcp | 192.0.2.1 reverse PTR | 46 | 6 / 12 | `[y.test,x.test]` or `[x.test,y.test]` |
| ipv6-repeated-ptr | 2001:db8::1 reverse PTR | 28 | 4 / 8 | `[x6.test,y6.test]` or `[y6.test,x6.test]` |

Every entry binds the complete C reference document and case hashes; full service options; every initial file byte; the mutation list; all labeled DNS requests and transports; and both complete PTR records including owner/type/class/TTL/section. The DHCP entry additionally binds the DHCP request wire and its position after `restored-lease-ptr` and before `live-lease-a`. DHCP decoded output remains strictly compared. Exact hashes and state lists are in [entries.proposed.json](entries.proposed.json) and [summary.json](summary.json).

Only one of the two initial permutations may be selected for the entire case. It must remain uniform across UDP/TCP before/after and, for `leases-dhcp`, both after-DHCP phases. The other DNS responses, headers, TTLs, counts, TC bits and forward orders must exactly match C. Changed inputs or query phases are outside the declaration. The existing five-line query-induced ordering regression is a different case and remains default-denied.

The exact source is OpenWrt 25.12.5 dnsmasq 2.93-r1, recipe revision `f0a60eee2fe051741c643ea6118718aae1ef17fb`, matched to C ELF SHA-256 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`. The source identity and full source-file hashes are checked during generation. [source-evidence.json](source-evidence.json) records the following anchors:

- `cache.c:38–43,295–309`: the name hash reads `typestr` bytes containing relocated pointers, permitting different initial bucket order between processes.
- `cache.c:312–341,1174–1231,1262–1317`: insertion preserves class regions; forward lookups rotate only matching reverse/immortal classes; PTR enumeration does not reorder hash links.
- `cache.c:1436–1541,1716–1720` and `inotify.c:193–253`: hosts parsing sets the address-family flags, and initial hostsdir scanning passes the bulk reverse table into the loader. The exact hostsdir fixture has one file and no later file mutation; initialization and any loading-time rehash finish before the query track.
- `cache.c:1742–1755`: DHCP refresh removes only `F_DHCP` nodes. Existing static x/y nodes retain their relative order.
- `cache.c:1758–1836`, `1846–1912`, and `lease.c:564–618`: DHCP publication queries the new lease names/addresses, adds nodes, and maintains name-suffix nodes. This path does not rehash or permute unrelated static x/y nodes.
- `rfc1035.c:1939–1989` and `dnsmasq.c:2104–2197`: output preserves reverse enumeration order and TCP inherits the current parent state by fork.

For both IPv4 fixtures, y.test has one reverse-owned .1 address and one non-reverse .2 address; x.test is a singleton. Only y.test is queried as a multi-address forward name, so its records cannot cross-rotate between flag classes. No x.test or a.test forward query occurs. The readiness name is also a singleton.

For `leases-dhcp`, the restored name is `restored`/`restored.test` at 127.0.0.31 and the live name is `lease`/`lease.test` at 127.0.0.30. Neither names nor addresses overlap x/y. Removing/reinserting those DHCP nodes cannot reverse the order of two existing static nodes, even if they share a hash bucket. Suffix maintenance affects the new names and `test` nonterminal, not address-bearing x/y records. The post-DHCP PTR track therefore retains the same initial permutation as the pre-DHCP and TCP tracks. This reasoning is restricted to this precise disjoint-name fixture.

For IPv6, the fixed file uses `::1`/`::bc` and `::2`/`::bb` address-hash relationships. The resulting two ::1 owners and mixed reverse status of y6.test are fixed by the C records. AAAA lookup matches `F_IPV6` and the same reverse/immortal class rule; x6.test is a singleton. No mutation or other multi-address forward query occurs.

Independent review found no counterexample within these fixed schedules. The proposal generator takes only the C archive, the matching source and the unchanged observed manifest; it accepts no candidate input. Validation uses synthetic uniform reversal of C records. Twenty-three unit tests pass, and 38 C-derived negative controls reject unknown cases with otherwise identical input, transport/phase/repeat splicing, after-DHCP splicing, changed DHCP request, options/mutations, header/TTL/TC/count/RRset and A/AAAA order. See [negative-controls.json](negative-controls.json).

The combined [manifest.proposed.json](manifest.proposed.json) retains the original 11 observed tracks / 23 states and adds only these three proposed entries. It does not include or activate the separate host-record proposal. Every source entry remains `review_status=proposed`; the checker rejects such entries until explicitly approved. The retained final238e observed-only failure remains unchanged pending independent review.
