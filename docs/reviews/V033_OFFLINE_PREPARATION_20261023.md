# v0.3.3 / OpenWrt 25.12.6 offline preparation

Status: official inputs verified; final canonical candidate image and its eight
qualification groups remain pending. No router was contacted or flashed.

The [new release input record](../../manifests/release-25.12.6.json) preserves the
existing `inputs.sdk` / `inputs.imagebuilder` format without copying historical
release output claims. The intake adds a dated SDK verification and retains the
previous 2026-10-22 unverified state in that entry's history.

The 252,756,332-byte SDK was downloaded from the official release URL and hashed
against both the freshly retrieved official `sha256sums` and the prior pinned
value: `1c04ac47bdfc361d6aab299eb520d570e368013dedcb8d29cf39dc7168ae642e`.
Existing stock image and ImageBuilder archives were independently rehashed and
match the new release record. Signature verification is not claimed.

All private evidence below is under Oracle
`/home/ubuntu/owrt-v033-25126-release-20261023/private/`.
Official SDK bytes remain untouched. `tooling/sdk-view-02` wraps its x86 tools
with QEMU for diagnostic fixtures only; GCC reports `r33311-981c978eff`, and an
AArch64 static C smoke program compiled and executed successfully. Canonical
product builds remain on the x86 GitHub Actions path. The initial wrapper view
incorrectly wrapped an SDK hidden ELF behind its existing runas launcher; that
failed view remains separate and is not used.

`tools/check_ax3000t_fit.py` now accepts the reviewed OpenWrt version and passes
the repository argument required by the current CI FIT block. An optional
explicit native `mkimage` supports Oracle diagnostics without changing official
ImageBuilder files. The default version remains 25.12.5; historical pins are
unchanged. Two CLI boundary tests pass. Four actual 25.12.6 runs yielded identical
FIT SHA-256 `abc43bdc4368f888277164ef39e6214cea9080998473bd8c6ed9bd507c39dafb`,
each rejecting both malformed-metadata controls. Using 25.12.5 with the 25.12.6
inputs fails the original-FIT identity check. This does not qualify a final image.

## Retained NAND scripts

The stock AX3000T branch adds `CI_DATA_UBIPART=ubi`. The retained `nand.sh` now
selects the data UBI separately for `rootfs_data` creation and configuration
restoration. Existing PID1 handoff tests stop at an inert `upgraded` recorder,
so they cannot cover this decision. `tools/test_upgrade_25126.py` adds a focused
check of the exact scripts inside private chroots and mount/network/PID
namespaces. `/dev`, `/proc` and `/sys` contain no host devices or mounts; external
command lookup is disabled. NAND operations, mount/unmount and backup moves are
recording functions.

Five cases pass: kernel/root/data selection, restoration to `rootfs_data`,
fallback to `rootfs`, missing-volume refusal and mount-failure refusal. Removing
only the new data-partition override from a private script copy produces the
expected wrong target and is rejected. All original script hashes remain
unchanged. No NAND write, real stage2, reboot or physical recovery is tested.
The initial fixture's `set -u` conflicted with stock shell conventions; its
failed run remains in `upgrade-script-gate-01`, separately from the successful
final run.

## Final image gates to run

Use the downloaded canonical image and manifest, matching source snapshot, all
eleven accepted ELF hashes and the exact 25.12.6 stock recovery files. Extract
the candidate rootfs once and retain its identity before and after all groups.
Disable Python bytecode creation for the runner and every child command.

| Group | Entry and required input |
| --- | --- |
| FIT | `native_image.verify_ax3000t_fit`: extracted candidate FIT against the **25.12.6 stock FIT**, with manifest metadata; preserve its kernel payload and exactly two DTB insertions. |
| Boot | `native_boot_check.sh ROOTFS OUT`: actual PID1/services and synthetic IPv4/IPv6 clients. |
| Image / restore | `native_image_check.py ROOTFS OUT --apk-dir APKDIR --image IMAGE`, plus `test_upgrade_25126.py ROOTFS OUT`: configuration migration, exact C recovery, metadata refusal and retained NAND decisions. |
| APK ownership | `native_package_reinstall_selftest.py ROOTFS APKDIR OUT`: two actual reinstalls and eight no-op negative controls. |
| Guard | `native_trial_guard_selftest.py ROOTFS BOUNDED OUT`: all 23 existing branches. |
| PID1 handoff | `native_trial_handoff_check.py ROOTFS ROLLBACK BOUNDED OUT --image-sha256 SHA`: ordinary and 70-second delayed shutdown. |
| Backup bundle | `native_trial_prepare.py` with an explicitly obsolete offline backup and the verified v0.3.2 rollback image; compare original members/metadata and all 13 recovery payloads. Never deploy its output. |
| Log settings | `check_log_settings_migration.py ROOTFS SCRIPT KEEP OUT`: all 16 C/Rust red/green cases. |

Ten unsigned stock-owner APK fixtures were rebuilt from exact 25.12.6 installed
metadata and payloads in `stock-apk-fixtures`. They are not signed upstream APKs
and are only for `--no-scripts` offline ownership tests. `netifd`, `rpcd` and
`uhttpd` versions change; every other payload is also bound to the new image.
Once the canonical native APK is available, copy these into a new gate directory
and build an index containing that exact APK. Do not reuse the 25.12.5 fixture set.

The v0.3.2 rollback image was rehashed: 14,151,968 bytes,
`9f8e4b10225ca9c49e0e08d096cf645667c5687b1b42784adab50d3751a3e179`.
It is distinct from the 25.12.6 stock FIT used to verify the candidate kernel.

| Evidence file relative to private root | SHA-256 |
| --- | --- |
| `upstream/25.12.6/inputs.json` | `9f5a834e296201773579591499360e6934a37706f0cbd1bf8e2edfb229ba5794` |
| `fit-check-25126-01/result.json` | `9c3b21176cb22c1ec4ba6674a7116b454e7afcb2ed61ea00734801d013c0ce2a` |
| `upgrade-script-gate-final/result.json` | `2800ff927bea87514825178d9e8460df19571c9da36ef886e821c6a0e7572d3b` |
| `stock-apk-fixtures/fixture-provenance.json` | `b96aa2cadc01978b7891920c5b24422ea9d47b4876c818ea6f367f17ae7d90b7` |
