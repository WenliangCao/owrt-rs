# Approved fixed source contracts: offline final qualification

The independent audit/root source-contract review explicitly approved the four exact entries from `d72ca9d9` and `3ae4030d`. This is a source-derived compatibility contract, not a user waiver. The unified [manifest](manifest.json) retains the original 11 observed tracks / 23 states and adds only these four approved source entries:

| Exact case and question | States | Target answers | Full bound DNS schedule |
| --- | ---: | ---: | ---: |
| six-host-record / 192.0.2.1 PTR | 4 | 8 | 28 |
| six-hostsdir-initial / 192.0.2.1 PTR | 4 | 8 | 28 |
| leases-dhcp / 192.0.2.1 PTR | 6 | 12 | 46, plus bound DHCP request position and strict decoded output |
| ipv6-repeated-ptr / 2001:db8::1 PTR | 4 | 8 | 28 |

Each entry permits one uniform two-record initial permutation across its complete case, including both transports and all repeated/before/after phases. Configuration, files, mutations, requests, record fields, header/TTL/count/TC, forward answers and other states remain bound. Unknown cases, query-induced phase changes and the separate five-line stateful regression receive no allowance.

[review.json](review.json) records the approval authority and scope. The additional exact-ELF DT_RELR/typestr evidence is **reported by the independent auditor**, not reproduced here: typestr VA `0x3e388`, pointer addends `0x32862/0x3509a/0x31c6c/0x31b68`, and 26 observed load biases with predicted orders in both directions. The original two six-line C runs' predicted `[x,y]` order matched their actual answers. No additional reverse-order C daemon was run.

Both retained final results pass offline requalification:

| Actual | ELF SHA-256 | Cases / DNS observations | Unqualified failures | Source-bound / observed-qualified differences |
| --- | --- | ---: | ---: | ---: |
| final238e | `2692c760be3719b15f4bcadb6c5a1445a9f37993a11c1369619550218e4c76eb` | 13 / 704 | 0 | 28 / 16 |
| SDK final | `50e591a9d9dc1e6578888b14690b5b38415a9db886a492a2960a0c75b3eeb57c` | 13 / 704 | 0 | 28 / 16 |

SDK `ipv6-three-duplicate` and `mixed-sources` are covered by the existing observed C/C entries. No new source entry was added for either. SDK needed the approved host-record, hostsdir and lease entries; final238e needed hostsdir, lease and the approved IPv6 entry.

The manifest file SHA-256 is `57da7fe59de8de504cb77f5982b8e15a3d599a083b1387e1a7451936f64a8f78`; its canonical document SHA-256 is `c2f99f2ae778fe87311fed2b211e4ae4af06f1244d69a6457b58c38e6b24a309`. The input reference raw SHA is `4021e120f447aa54e7fad49146837c01fd8752f7e9184b67e42f31ba79bcae94`.

| Actual | Original raw JSON SHA-256 | Canonical actual document SHA-256 |
| --- | --- | --- |
| final238e | `911a149bd897b6e6fba8aafc79ec14fe658671339f0a07d13a3c2d32667c8517` | `8440855fed8829d00fa16023c90dcb41a918fc1197237619bfcf28d915b07c0f` |
| SDK final | `f066b0da9f3291b98d3d6c3defa6fc31c956d3c77c674fb1fd94723cc2f4c88e` | `123058f26e2d49a060c9e896cf8a286153e84c8f1f0300f5d52c25b6cd5664a9` |

The checker SHA-256 used offline is `fecf70b5730f1dc7f76d710fe50d611f5f18a1a7adf3767c5e5bf235a3774c62`. Twenty-four unit tests pass, including the added approval-scope control and strict DHCP decoded-output rejection. [validation.json](validation.json) and [unit.log](unit.log) record this check. The existing 38 source-proposal negative controls remain in their original evidence.

No daemon, Cargo build or product modification occurred. Original observed/proposed manifests and raw results remain unchanged, including their original observed-only failure status. These separate approved-manifest rechecks record the later engineering contract decision; they do not rewrite the earlier evidence.

Artifacts: [summary](summary.json), [final238e recheck](final238e-recheck.json), [SDK recheck](sdk-final-recheck.json), [review](review.json), [derivation](derive.py). The derivation reads the original private archives and SDK JSON, creates a new output directory and does not mutate its inputs.
