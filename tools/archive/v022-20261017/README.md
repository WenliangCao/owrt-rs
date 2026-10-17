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
