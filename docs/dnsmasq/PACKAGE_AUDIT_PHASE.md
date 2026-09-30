# Inert target package build audit

The package wrapper now requires a fresh output directory below ignored
`private/`. It snapshots only the Rust/package build inputs, records each file's
SHA256, explicitly runs the package `prepare` target, and checks the prepared
copies before compiling. Both the package build directory and APK output live
inside the task output. It accepts exactly the expected newly generated APK;
it does not search the SDK's historical output for a matching filename.

The package recipe no longer deletes or reuses the shared
`/tmp/owrt-build/owrt-dnsmasq` directory. Cargo builds the checked prepare output
with `--frozen`, a fixed Rust channel and remapped source paths. The SDK recipe
is temporarily replaced under an advisory per-package lock and restored on
success or a handled failure. A killed build can leave the clearly named
`.dnsmasq-backup-OUTPUT_NAME` recovery directory; the tool refuses to overwrite
an existing recovery backup. This lock coordinates this wrapper, not arbitrary
external SDK commands.

`build_package.py` verifies the SDK archive against the pinned release manifest
and records hashes of the actual SDK configuration, packaging rules, musl
header/runtime, compiler wrappers, underlying `.bin` tools and host loader.
Archive verification does not by itself prove an extracted SDK has never been
modified; the recorded working-file identities make the actual inputs explicit.
It records Cargo/Rust/compiler versions, source commit provenance, source digest,
both make commands and complete logs. Any `runas.so`/loader preload warnings stay
in those logs and are copied into the manifest's warnings field, including failed
attempts. They must not be silently described as warning-free validation.

After extraction, the only allowed regular payload files are
`/usr/libexec/dnsmasq-rs` and the SDK-generated APK ownership list. Symlinks and
additional payload files fail the audit. The ownership list must contain only
the inert executable path. `readelf` verifies AArch64 ELF64 with target musl or
static linkage; the manifest records both packaged ELF and APK hashes/sizes.
The artifact remains `activation=inert`: it does not own `/usr/sbin/dnsmasq`,
an init script or UCI configuration. This tool never assembles an image or invokes
a router command.

```sh
sh tools/dnsmasq/build_package.sh "$MATCHING_SDK" \
  private/dnsmasq-rewrite/package-NEW_RUN
python3 tools/dnsmasq/test_build_package.py
```

For a copied checkout without `.git`, supply `--source-commit`,
`--source-date-epoch` and `--expected-source-digest` from the frozen original
checkout. The digest is SHA256 over the JSON-serialized sorted map returned by
`build_package.inputs(ROOT)`, using separators `(',', ':')`. The tool checks
this digest before SDK mutation and verifies that all inputs remain unchanged
through completion. A caller-declared commit is labeled as such; file hashes
remain the artifact's authoritative source identity.

At this tooling stage, four local failure-boundary tests pass: restoring the
prior recipe after build/copy failure, rejecting unexpected or symlink payloads,
and rejecting paths unsafe for the SDK Make layer. Python compilation and shell
syntax checks pass. The existing older inert APK was inspected to validate the
SDK extraction interface. The current parallel source has **not** been compiled
by this wrapper yet; a frozen-source SDK run must validate the updated Make
integration and produce a new artifact/manifest before claiming target-build
success. Bit-for-bit reproducibility across independent builds is not established.
