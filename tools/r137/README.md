# R137 fixed-path Oracle build stage

This removes the source-path confound identified in
[R136_BUILD_IDENTITY.md](../../docs/reviews/R136_BUILD_IDENTITY.md). It is build
identity tooling, not a performance improvement or a new candidate screen.
The frozen R135/R136 tools and runtime sources remain unchanged.

Each candidate gets a private Linux mount namespace and a private empty parent
bound over `/tmp/owrt-build/r135` **inside that namespace only**. The unchanged
R135 builder then creates `/tmp/owrt-build/r135/r136-combined-01` and copies the
candidate there. Every Cargo package therefore has the same absolute path.
Output and target directories remain independent. Existing host sources and
artifacts are hidden only in the child namespace and are never overwritten.

The wrapper must run as `ubuntu`, with passwordless `sudo` for namespace setup.
Cargo runs as `ubuntu` in `/home/ubuntu`. The builder SHA-256 is pinned to
`da5692bb202c7ee10ce7d1f56966dfc06262101e8e96ef4e133c745db90c3bc5`.
Toolchain, SDK, profile, linker flags, path remapping and `sstrip` are inherited
verbatim from that builder. This also needs Python 3.11+ and util-linux unshare.
The mount parent must already exist. Sources, tools and outputs must be outside
that parent. Inputs must be clean snapshots with no symlinks or target files.

Before any build starts, `frozen-plan.json` records every source-file hash,
wrapper/recipe hashes, the fixed source root and each expected ELF identity (if
known). Inputs are checked again before/after compilation. Output directories,
plans and logs are created exclusively; an existing run cannot be overwritten.
Do not modify source snapshots or scripts while a run is in progress.

```json
{
  "schema": 1,
  "variants": [
    {
      "label": "control-a",
      "components": "/home/ubuntu/r136/sources-02/combined/components",
      "expected_sha256": "ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330"
    },
    {
      "label": "control-b",
      "components": "/home/ubuntu/r136/sources-02/combined/components",
      "expected_sha256": "ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330"
    }
  ]
}
```

```sh
python3 tools/r137/build_batch.py /path/to/control-plan.json \
  --build-script /home/ubuntu/r136/tools/build_variant.sh \
  --jobs 2 --output /home/ubuntu/r137/control-new
```

The root shell unmounts on exit. The private PID namespace and `--kill-child`
ensure its processes and mounts disappear if the namespace supervisor dies;
temporary source directories are removed by the outer wrapper on normal or
failed builds. No mount is propagated back to the host. Abruptly killing the
outer Python process may leave ordinary temporary files, never a host mount.
Per-candidate logs/results survive failures for diagnosis. `results.json`
records effective build UID, mount namespace identity and Cargo dependency
fingerprints. This stage does not start a daemon, measure latency or access a
router.
