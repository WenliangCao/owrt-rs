# Native eleven-component image

`native-25.12.5.json` fixes the standard executable paths, original file owners
and exact stock hashes for the AX3000T image. The original packages continue to
supply configuration, libraries and execution-plane helpers. The accepted
dnsmasq init script and ubus ACL are the only two integration-file replacements;
their original and replacement hashes are pinned in the image specification.
`owrt-control-plane 0.3.0-r1` owns eleven executable paths and these two files through APK v3 `replaces`
and `replaces-priority`; its stock package dependencies are pinned to the
versions whose recovery copies were verified. The older `owrt-*` switch packages
conflict with this package and are excluded from the final image.

The eleventh program is scoped `odhcpd-rs` at `/usr/sbin/odhcpd`. Its original
`odhcpd-ipv6only` package still supplies init, defaults and `odhcpd-update`.
The exact accepted SDK ELF is pinned like the other programs. Historical
native-ten manifests and complete twelve-file recovery sets remain supported.

The current release target is v0.3.0 because it adds a new component. The user
authorized one idle/Renew fix and one limited device comparison; both metrics
passed. The recipe now pins SDK ELF
`589226a178668c0e53fa8db5ff726e2b4e69464f9521355fad229b1862c3043e`
from source `162d9ba8`, SDK CI `39122603394` (802936 bytes, static).
The latest shipping gate requires one full device comparison of all metrics on
this final SDK before the authorized image build, deployment and publication
can continue. That gate is pending; see the [full comparison plan](../../docs/reviews/ODHCPD_FINAL_FULL_AB_PLAN_20261018.md).
Image CI `39123811190` (source `346470cd`) was cancelled, with no new physical
trial or flash. The two-metric PASS remains valid; no new product optimization
or recipe identity change is part of this gate.
PR #1 remains draft; production is unchanged at v0.2.3 with C odhcpd.
See the [limited comparison](../../docs/reviews/ODHCPD_IDLE_RENEW_RESULT_20261018.md).
The [first batch's stop result](../../docs/reviews/ODHCPD_DEVICE_AB_RESULT_20261018.md)
remains historical evidence; other metrics were not remeasured.
Existing v0.2.4 candidate images, measurements
and qualification reports keep their original versions and hashes; they are not
renamed or treated as v0.3.0 build evidence.

The canonical workflow builds the existing SDK artifacts and runs
`tools/ci_build_dnsmasq.py` with the unchanged, accepted dnsmasq SDK recipe, then
`tools/ci_integrate_image.sh`. It creates one native APK and rebuilds the image
from the pinned original stock image with the official services enabled and without boot-enable flags,
trial collectors or per-component activation scripts. Final deliverables are
under `work/native/out/`; `work/out/` contains intermediate build evidence. Final assembly uses an offline APK install and the exact ImageBuilder squashfs, sysupgrade-tar and fwtool tools. It never resolves rolling feeds for the final rootfs. Four Chinese catalogs are rebuilt from the pinned matching LuCI source, checked against production hashes, and delivered as four ordinary translation APKs.

The dnsmasq build locks all 212 frozen source, shared-platform, toolchain and recipe inputs by
their digest. `dnsmasq-build-manifest.json` records the fresh CI ELF, static PIE
checks and its comparison with the previously accepted SDK ELF. A different
canonical-host ELF does not inherit runtime qualification merely from matching
source; final image acceptance is a separate gate. The intermediate standalone
dnsmasq APK is audited but not installed into the final rootfs or released for
live installation. The unified package depends on the original dnsmasq package
for its configuration, users and unchanged helpers.

From v0.2.2, the other nine programs also carry individual reference ELF hashes.
Every canonical image rebuild must reproduce every qualified binary. v0.3.0
adds the functionally qualified odhcpd reference without changing the other ten. The
DNS product commit and packaging epoch remain distinct from the final image's
build commit, so report/version changes do not retrain PGO or change its inputs.

Upgrade the complete firmware using sysupgrade with selected configuration
retention. The native APK is an image construction input, not a supported live
PID1/bus upgrade mechanism. Do not mix it with the old layered deployment tools.

On first migration, `05-owrt-native` removes the old log/rpcd/uhttpd disable
commands from sysupgrade's generated `10_disable_services`. These names now
start Rust. It records `native-nine-v1` in `/etc/owrt-control-plane-layout`, which
the package's keep.d entry preserves. Later native-to-native upgrades therefore
honor the user's service-disable choices. The v0.2.0 ten-component layout keeps
this migration marker's name; it is not a component-count assertion. No trial
collector is added.

`owrt-recover-c` verifies all eleven stock recovery programs plus the exact stock
dnsmasq init script and ACL under `/usr/libexec/owrt-stock/`, prepares all thirteen
replacement files with their original modes, and stages them at
their standard paths. It leaves reboot to the operator and works from failsafe
after `mount_root`. `/rom/sbin/procd` is Rust in this image and is not a C recovery
source. Factory reset discards overlay changes, including a staged C recovery,
and restores the image's Rust defaults.

Image assembly and offline checks never authorize flashing a physical router.
Firmware installation still requires the project's explicit request and recovery
gate. Hardware boot, Wi-Fi and actual configuration migration remain deployment
acceptance checks.
