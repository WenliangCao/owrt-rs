# Canonical x86 PGO builds for a97edbc1

The product stays at a97edbc1, 193 inputs, digest
`c47f95e99a966ec6433f37e0a7d36a8d8a7e9b360f63de6e905e0993e1bfc671`.
The original Oracle-host profile and its frozen candidate manifest remain intact.
One x86 CI toolchain now produces both instrumentation and profile-use artifacts;
Oracle executes only the original frozen training workload between them.

After the tooling commit is present on the validation branch, generate with:

```sh
gh workflow run dnsmasq-pgo-candidate.yml \
  --repo WenliangCao/owrt-control-plane-rs \
  --ref validation/dnsmasq-fork-pgo-a97edbc1-20261017 \
  -f stage=generate -f spec=manifests/dnsmasq-pgo-generate-a97edbc1.json
```

The same workflow defaults to the original `frozen-use` manifest. It has no push
trigger. Dispatch stage and manifest stage must agree. Every run uses the same
absolute package slot, source archive, SDK, Rust and unchanged package recipe.

`generate` takes no input profile. Its ELF is `dnsmasq-rs` in the artifact and
its manifest has `status=built-instrumented-training-only`,
`artifact_purpose=instrumented-training-only`, `release_qualified=false`.
The temporary budgets are ELF 6,000,000 B / APK 3,500,000 B. Oracle must override
`LLVM_PROFILE_FILE` for its excluded smoke and each original training scene.
Restore executable permission after downloading the artifact if necessary.

After training, create a **new** manifest for `candidate-use` from the generation
manifest. Remove `instrumentation_budget`; set `pgo_stage` to `candidate-use`;
replace `pgo.profile_output_dir` with the immutable, uniquely named profile URL,
SHA256 and byte count (`profile_url`, `profile_sha256`, `profile_bytes`). Keep
`pgo.build_slot` and `pgo.retain_link_map=true`. Add `pgo.training` with these
SHA256 fields:

- `generator_manifest_sha256`: downloaded generation manifest.
- `generator_elf_sha256`: that manifest's actual ELF.
- `training_receipt_sha256`: successful frozen-workload training receipt.

Do not include `reference_elf_sha256` or `reference_elf_bytes` in first-use specs.
Dispatch the same command with `stage=candidate-use` and the new manifest path.
This reports `created-unqualified-pgo-candidate`; it keeps the strict 2,500,000 B
ELF / 1,400,000 B APK, static PIE layout, zero compiler-warning and zero
missing/mismatched-profile gates. Freeze its actual ELF and send that artifact
to runtime/performance qualification. No extra reproduction build is required
in this research round. Later `frozen-use` specs add the actual reference hash
and size; normal accepted-release builds retain mandatory hash equality.

Every PGO build preserves original compilation logs and selected host/target
Cargo fingerprints/build-script output. New pipeline builds additionally retain
`pgo-compilation/link.map`, `dnsmasq-prestrip`, and `map-cc`. The map wrapper adds
only `-Wl,-Map` to the actual static PIE link, after Cargo/rustc identity selection;
it does not alter source or Rust flags. `manifest.json.link_map` binds the map,
wrapper and actual SDK compiler. No stage grants deployment acceptance.

Diagnostic run `39045487550` used added Cargo `-vv` and failed the unchanged
warning gate on two rustix ignored-hint advisories. That failed record remains
intact. Generate/use now preserve normal recipe verbosity, `-Dwarnings` and the
same warning scanner without exemptions. Cargo `-vv` also changes dependency
`--cap-lints allow` to `warn`; therefore the two runs must not be described as
having identical actual rustc flags. Compare the generated ELF and retained
crate identities when checking the normal-verbosity rerun.
