# Native nine-component image

`native-25.12.5.json` fixes the standard executable paths, original file owners
and exact stock hashes for the AX3000T image. The original packages continue to
supply configuration, libraries, init scripts and execution-plane helpers.
`owrt-control-plane` owns all nine replacement files through APK v3 `replaces`
and `replaces-priority`; its stock package dependencies are pinned to the
versions whose recovery copies were verified. The older `owrt-*` switch packages
conflict with this package and are excluded from the final image.

The canonical workflow builds the existing SDK artifacts first, then runs
`tools/ci_integrate_image.sh`. It creates one native APK and rebuilds the image
from the pinned original stock image with the official services enabled and without boot-enable flags,
trial collectors or per-component activation scripts. Final deliverables are
under `work/native/out/`; `work/out/` contains intermediate build evidence. Final assembly uses an offline APK install and the exact ImageBuilder squashfs, sysupgrade-tar and fwtool tools. It never resolves rolling feeds for the final rootfs. Four Chinese catalogs are rebuilt from the pinned matching LuCI source, checked against production hashes, and delivered as four ordinary translation APKs.

Upgrade the complete firmware using sysupgrade with selected configuration
retention. The native APK is an image construction input, not a supported live
PID1/bus upgrade mechanism. Do not mix it with the old layered deployment tools.

On first migration, `05-owrt-native` removes the old log/rpcd/uhttpd disable
commands from sysupgrade's generated `10_disable_services`. These names now
start Rust. It records `native-nine-v1` in `/etc/owrt-control-plane-layout`, which
the package's keep.d entry preserves. Later native-to-native upgrades therefore
honor the user's service-disable choices. No daemon or trial collector is added.

`owrt-recover-c` verifies all nine stock recovery programs under
`/usr/libexec/owrt-stock/`, prepares all replacement files, and stages them at
their standard paths. It leaves reboot to the operator and works from failsafe
after `mount_root`. `/rom/sbin/procd` is Rust in this image and is not a C recovery
source. Factory reset discards overlay changes, including a staged C recovery,
and restores the image's Rust defaults.

Image assembly and offline checks never authorize flashing a physical router.
Firmware installation still requires the project's explicit request and recovery
gate. Hardware boot, Wi-Fi and actual configuration migration remain deployment
acceptance checks.
