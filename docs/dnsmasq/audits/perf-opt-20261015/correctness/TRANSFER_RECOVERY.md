# Frozen cache-transfer fixture recovery

**The original 36-case C transfer behavior is restored unchanged.** Both native
and target runtime, three repeats each, produced 307 observations per repeat:
1,842 observations in total. The complete 216-file stdout digest is exactly the
pre-existing comparator constant
`6624663c148bea679075197a0a3d0847673513893620a217094c7fb66e5eb43b`.
No C case, driver, expected output, comparator or allocation policy was changed.
[Receipt](transfer-recovery-receipt.json) records the independent verification.

The missing original native C executable was rebuilt byte for byte. Inside a
private mount namespace only, a task-owned tree was mapped to its original
`/home/ubuntu/dnsmasq-rewrite-20260929` path; the unchanged `build_reference.sh`
then used the unchanged matching libubox/ubus sources. The resulting hashes match
all three historical values:

| Artifact | SHA256 |
| --- | --- |
| Native C dnsmasq | `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431` |
| libubox | `792322b91310f50ffcea8b177e7a077529cf92dd5048ecb05d50ef5778b63243` |
| libubus | `9e8f940a55e285ae379a01fec9977ec0e21c9e3837b99cb717770c1987ee9293` |

All 148 patched C source files and the complete original source identity JSON
were also recovered to SHA256
`62cec0e9dda0265cb9c4f6af27f7d23067aed967afab3c74e37370149a8326e9`.
An explicit post-run assertion separately checked actual `cache.c` against
`cache_transfer_diff.CACHE_SHA`,
`51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c`.
The build already enforced the same condition through the recovered source
identity. No mount remained at the compatibility path in the host namespace;
that path is only a newly created empty mountpoint directory.

The historical target-runtime metadata JSON with SHA `fb873b9a…` remains missing.
Its contents were not guessed or presented as recovered. The five actual image
ELF/library files remain available and match every original pinned byte hash.
The [recovery builder](recover_transfer_c.py) therefore records fresh build
metadata, verifies those five hashes individually, keeps the original native
ELF/source pins, imports the original case generator and C driver unchanged,
and requires the original complete stdout digest before producing a receipt.
The root coordinator independently reviewed this builder before acceptance.

The existing, unchanged `c_primitive_receipt.freeze/validate_fresh` and
`cache_transfer_rust_diff.py --fresh-c-receipt` entry point bind the new paths and
compiler/artifact receipts. This is the already supported source-oracle path;
it does not impersonate execution of the stock C daemon. Exact-image daemon
qualification remains separately mandatory in F10, TCP and the 44 families.

Oracle outputs:

- `correctness/private/native-reference-compat/`: recovered original source,
  native C executable, libraries and objects.
- `correctness/private/transfer-c-recovered/`: new compiler commands, source
  before/after hashes, two primitive ELF identities, all 216 transcripts and
  `fresh-c-receipt.json`.
- `correctness/private/transfer-recovery-receipt.json`: explicit original source,
  native/library and complete stdout equality checks.

Paths above are relative to `/home/ubuntu/dnsmasq-perf-20261015/`. Raw files stay
outside Git. Future candidate tests must run their own source-bound Rust probe;
recovering this C fixture is not a candidate pass.
