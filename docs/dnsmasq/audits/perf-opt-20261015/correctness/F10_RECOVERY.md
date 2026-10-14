# Exact F10 reference recovery

**The missing original C reference was recovered without changing any golden
expectation.** The recovered file is 909,279 bytes, raw SHA256
`4021e120f447aa54e7fad49146837c01fd8752f7e9184b67e42f31ba79bcae94`, and canonical
JSON SHA256 `c927b1cef7fcf3ee13583080260d038354f5bbdc793d41b64507a3e7624c50b9`.
These match the pre-existing raw index and the unchanged approved manifest.
All 13 individual case JSON byte lengths and hashes also match their original
entries. This is exact data recovery, not a replacement C measurement.

The old archives were absent from the local Developer tree and prior Oracle
scratch directories. A fresh, unchanged `f10_contract_probe.py` run against the
exact image C completed all 13 cases in a private Oracle namespace. That new run
remains separate under
`/home/ubuntu/dnsmasq-perf-20261015/correctness/private/f10-recovery-c/`.

The recovery used only previously committed identities and fixed fixtures:

1. Restore each `argv` root to the original recorded
   `/dev/shm/full-f10-contract-20261014/private/repeat-c/stage/rootfs`.
2. Restore original PTR observations from the first recorded reference sequence
   of each approved observed track and the original `reference_records` of the
   four source-bound entries. Corresponding raw uncompressed PTR RDATA and
   derived fields are reconstructed together. No other record is transformed.
3. Recover the synthetic lease's one absolute expiry timestamp by searching
   2026-10-13 through 2026-10-15 UTC against the original lease-file SHA256.
   Exactly matching value: `1791991133`; lease-file SHA256
   `47249e275172974132e181d857b45e64fd61f5272f371a2dba30d10a6997a893`.
4. Restore the original, already recorded driver identity
   `e42e2f3fd3e82e322ce9d3048ff2fd24a63897eb722b23b2f63948bf7baa477a`.
5. Require all old per-case file hashes, full raw-file hash and canonical hash
   before writing a recovered output. The helper aborts without producing a
   reference if any equality fails. Unmatched working data is not evidence.

[Recovery helper](recover_f10_reference.py) is independent of the unchanged
probe/checker. The original approved manifest remains SHA256
`57da7fe59de8de504cb77f5982b8e15a3d599a083b1387e1a7451936f64a8f78`.
Reproduce from the separately retained new C observation:

```sh
python3 docs/dnsmasq/audits/perf-opt-20261015/correctness/recover_f10_reference.py \
  --fresh-c private/perf-correctness-20261015/f10-recovery-c.json \
  --contract-directory docs/dnsmasq/audits/full-20261014/f10-contract \
  --output private/perf-correctness-20261015/f10-original-c-recovered.json
```

The recovered JSON remains ignored under `private/`. This does not recover the
old archive's process mappings/logs or claim a new observation at the old time;
it restores exactly the already indexed comparator input. Original hashes and
prior C comparison results are unchanged. Candidate gates must still run fresh.
