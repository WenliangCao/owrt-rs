# v0.2.2 research tool archive

This directory preserves the otherwise untracked execution tools from the
retired DNS safety worktree before its private build/results directories are
removed. It is an archive, not another validation runner or a release input.
Several files intentionally preserve failed or superseded attempts.

`manifest.json` accounts for all **72 source paths**:

| Preservation | Paths | Stored source files |
| --- | ---: | ---: |
| Existing committed device-tool generator | 5 | 0 |
| Committed startup shell template plus one root substitution | 8 | 0 |
| Otherwise unique execution tools / preparation note | 59 | 54 |

The 54 stored files total 255,797 bytes. Identical copies share one archive
path. Every row retains the original relative path, original SHA256 and size.
Archived rows also identify their stored SHA256 and path substitutions.
No result JSON, logs, profiles, binaries, rootfs, user configuration or secrets
are included. The sole historical preparation note is
`sources/oracle-v022/final-b8617f57/pgo-input-tools/PREPARATION.md`.

## Source reconstruction

For `existing-generator` rows, check out the recorded commit and run its
existing local-only generator into a new private directory:

```sh
python3 tools/dnsmasq/prepare_safe_v022_device.py --out private/reconstructed-tools
```

Select the row's `output` file. All five outputs were reproduced byte for byte
before archiving; this operation does not build a binary or contact a device.
The generator itself records the older source commits and input identities.

For `git-template` rows, obtain `git show COMMIT:PATH`, then replace the
`replace_literal` value with the selected runtime root. Each original file was
verified to differ from that exact Git version only by this replacement.

For `archived` rows, copy `archive_path` to the row's relative source location.
The `/srv/owrt-archive/` and `/tmp/owrt-archive-v022-slot-*` paths are neutral
placeholders, not live machine locations. `path_bindings` gives each a stable
identifier; bind the required work root, SDK, image base, Cargo/Rustup home and
isolated runtime slots explicitly before any reuse. Keep different runtime
slots distinct. One private session filename in the preparation note is also
replaced with a neutral label.

For audit-only reconstruction of the original bytes, the maintainer's protected
main worktree retains the non-raw
`private/backup/v0.2.2-tool-archive/restore-bindings.json`. Reverse its placeholder
substitutions for archived rows, or use its original root for template rows,
then check `original_sha256`. Every such inverse was verified during archiving.
The public manifest never contains the old machine home/work paths; the private
receipt contains only bindings and source hashes, no test results or firmware.

## Reuse boundaries and inputs

These scripts retain their original expected source commits, ELF hashes,
source-file counts, warning checks, namespace boundaries and failure behavior.
They also refer to per-run input manifests, build receipts, helper binaries,
image fixtures and output directories which are **not** part of this archive.
Reconstruct source/tool dependencies from the recorded commits and the retained
Git branches/tags; obtain the matching firmware/SDK from the retained recovery
and build infrastructure. The native runners require their pinned Rust toolchain
and matching source snapshot. The PGO preparation note documents the training
input closure and workload build commands.

To repeat an experiment, first prepare new input identities and fresh output
directories, and review the applicable current protocol. Path substitution alone
does not qualify a new run or recreate deleted raw evidence. Some historical
scripts execute at module import; do not import them as a convenience library.
They may build, create namespaces or stop their owned test processes when run.
The router snapshot script is preserved as code only; its output is not public.

## Preservation checks

All 72 source hashes were checked before copying. The 13 generated/template
copies were reconstructed exactly; all 59 archived-path mappings round-trip to
their original bytes. Python sources were parsed and shell sources checked with
`sh -n`; no archived entrypoint was run. Static review found no credential
literal, private key, token, email address or real client/server IP literal.
The original machine paths were replaced reversibly. Only loopback and
documentation-network synthetic fixtures remain.

## Deployment tool supplement

`deployment-manifest.json` preserves two additional scripts found alongside the
final deployment raw files. Neither exact script nor its generator was found in
Git. They live under `sources/deployment/` and are not raw observations:

- `observation600/daemon-snapshot.sh` requires explicitly supplied `DNSMASQ_PID`,
  `HTTPD_PID`, `LOGD_PID`, `NETIFD_PID`, `PROCD_PID`, `RPCD_PID` and `UBUSD_PID`.
  Its process-stat, executable-hash, status and FD-count observations are
  unchanged; the script contains no recorded results or actual observed PIDs.
- `router-cleanup/disarm-command.sh` requires `TRIAL_ROOT`, `EXPECTED_BOOT_ID`,
  `EXPECTED_GUARD_SHA256`, `ROLLBACK_MARKER` and `GUARD_LOCK`. The accepted-boot,
  guard identity, rollback/bridge absence, owned process identity and normal
  disarm checks are retained. It still removes the armed marker when explicitly
  run; archiving it does not authorize or perform that operation.

The exact original bindings are retained only in main's protected non-raw
`private/backup/v0.2.2-tool-archive/deployment-restore-bindings.json` (0600).
Both inverse substitutions reproduce their recorded original SHA256. Both
scripts passed `sh -n`; neither was executed during preservation. No actual
boot UUID, process PID, guard digest, private deployment path or token remains
in their public script bodies. Historical source-file digests in the manifest
are retained solely for provenance.

## Final core controller supplement

`core-manifest.json` accounts for 33 otherwise untracked paths found during the
final core worktree retirement check. Four have the exact original SHA256 of
an existing archive entry; six startup shell copies are reconstructed from the
recorded Git template and one runtime-root substitution. The remaining 23 paths
share 21 newly stored files under `sources/core/`, totaling 94,741 bytes:
14 Python controllers/collectors and seven preparation or release notes.

This includes the `core-ci/d644eda4/collect_verify.py` collector and the R92
continuation controller; their only local copies therefore survive retirement.
Source/SDK/rootfs/cache copies were excluded. Identical Git-backed scripts need
no additional copy. Draft cleanup and release notes retain their historical
pending-state wording; they neither describe current status nor authorize work.

All original source hashes, archive mappings and exact inverse checks are
recorded. Original host/work paths and the one observed prior-runner PID live
only in main's 0600 non-raw receipt:
`private/backup/v0.2.2-tool-archive/core-restore-bindings.json`.
The R92 continuation script now requires `OWRT_PRIOR_RUNNER_PID` explicitly;
its existing check that the prior executor has exited is retained. The old
SSH alias is represented as `owrt-build-host`. GitHub repository URLs and
historical build/source hashes remain public provenance.

All 14 new Python files were parsed without executing them. The six template
copies were reconstructed byte for byte, and all 23 archived-path mappings
reverse to their original bytes. No raw results, logs, configuration, binaries,
credentials, actual process identifiers or machine home paths were added.
