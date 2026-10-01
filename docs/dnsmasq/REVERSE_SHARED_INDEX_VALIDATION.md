# Final private reverse candidate integration checks

Frozen private source `0eaaef813893ac71954f56c379f8fc6b5eb24064` passes native
and SDK-linked musl library **397 passed / 16 ignored**, main **7 passed**,
all-target Clippy with warnings denied, and formatting. Both runtimes also
pass the original forward transfer **307/307** against its saved, hash-verified
C traces. Test executables were built unprivileged and run inside isolated
Linux network namespaces; ignored tests are not ordinary-suite passes.

The independently reported final-source checks are:

- [Same-name expiry and original reverse primitives](REVERSE_NAME_EXPIRY_AFTER_RESULT.md):
  27/27 and 125/125, respectively, using one unchanged observation binary.
- [Ordinary allocation and layout](REVERSE_SHARED_INDEX_ALLOCATION_RESULT.md):
  all five cases retain their allocation/deallocation vectors, layouts and
  zero outstanding bytes after drop.
- [Reverse transfer](REVERSE_SHARED_INDEX_TRANSFER_RESULT.md): 184/184
  deterministic observations; the separate 12 ordering observations still
  differ, and the complete comparator exits 1.
- [Real DHCP/reverse service](REVERSE_LEASE_SERVICE_RESULT.md): the preceding
  `a4a38bc` source passes native/image 62/62. Those results retain their own
  identity and are not relabelled as final-source runs.

The ordinary forward corpus completed **22,571 commands with zero mismatches**
on intermediate `adf3977`, reusing its original C inputs and outputs. Its 138
previously allowed cross-generic-type order variations remain separately
recorded. The writer then amended two readability details before announcing
the final freeze: comment wrapping and binding the same immutable Copy `Kind`
once in the publication closure. No operation, branch or state mutation changed.
An independent reviewer checked that exact diff. The corpus was not rerun;
its executed source remains `adf3977`, while final suites and both 307-row
transfer replays use `0eaaef8`.

The first `adf3977` verification completed its tests, Clippy, formatting and
release build, then its strict directory-identity check **exited 1**. The
concurrent forward-replay Python import had created one `__pycache__` file
inside the tool directory. A retained audit confirms every original archived
file was unchanged and records the added file's hash. The failure, generated
file, complete logs and both source identities remain archived. The fresh
final-source validation passes the strict check; subsequent Python replays
disable bytecode generation. No test expectation or source check was weakened.

The final native daemon ELF is
`217bace9b1a231d0a008842365239085ad21353fb75750d70103325699d3888a`.
The original transfer comparator receives verified prebuilt library artifacts
through the previously used replay shim; the actual build commands and binary
hashes are retained. It does not build under sudo or substitute observations.

[Derived identities and counts](REVERSE_SHARED_INDEX_VALIDATION.json) link the
full evidence, including the later independent main FQDN build. The 1,349-file
archive was downloaded and checked file by file. Archive SHA-256:
`188738bbc8d51d2677e78778088ee7bef4eef87368e3ddbbe7cc01e22e84d973`.
The ignored mirror is
`private/dnsmasq-rewrite/reverse-final-validation-20261001/mirror-01/`.

Reverse code remains private. Multi-PTR ordering and its state effects,
dynamic CNAME/local precedence, reverse index heap cost, OOM, full TCP service
and performance acceptance remain open. No target package or router claim
follows from these host checks.
