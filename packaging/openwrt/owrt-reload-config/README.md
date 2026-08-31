# OpenWrt package

This recipe packages `components/reload-config` for the pinned
OpenWrt 25.12.5 `mediatek/filogic` SDK.

Installation is inert: it adds `/usr/sbin/reload_config_rs` and
`/usr/sbin/owrt-reload-config-switch`, but does not change any caller or mount.

Activation is explicit and reboot-volatile:

```sh
owrt-reload-config-switch enable
owrt-reload-config-switch status
owrt-reload-config-switch disable
```

`enable` first verifies the exact deployed `/sbin/reload_config` SHA-256, then
bind-mounts the candidate over that path. `disable` unmounts it and verifies
that the exact original is visible again. A reboot also removes the bind mount.
Live post-install/post-upgrade and pre-removal scripts all force the disabled
state or fail closed. Offline rootfs installation does not run this action.

V1 builds this recipe with Rust 1.94.0, matching the release-pinned packages
feed, and the official `aarch64_cortex-a53` GCC 14.3.0/musl SDK toolchain.
The gate and exact input arguments are documented in
`reports/ax3000t-stock-openwrt-25.12.5/V1_VALIDATION.md`.
