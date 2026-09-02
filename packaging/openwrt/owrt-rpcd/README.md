# owrt-rpcd

Rust `rpcd-rs`: the rpcd plugin-layer objects `file` and `luci` (contract C5,
decision 0011) as a standalone ubus object server. The original rpcd keeps
`session`, `uci`, `rc` and the `iwinfo`, `luci-rpc`, `rpc-sys`, `network.rrdns`
plugins.

Installation is inert. `owrt-rpcd-switch`:

- `enable`: starts the `owrt-rpcd` procd service (which bind-mounts a copy of
  `/usr/lib/rpcd` without `file.so`/`ucode.so` over `/usr/lib/rpcd` and runs
  `rpcd-rs`), restarts rpcd so it loads the trimmed plugin set, verifies the
  objects answer, otherwise reverts.
- `disable`: stops `rpcd-rs`, unmounts, restarts rpcd with its original plugins
  (sha256 pinned).
- `boot-enable on|off|status`: whether `/etc/init.d/owrt-rpcd` (S11, before
  S12 rpcd) applies the mount at boot.

Offline evidence: 63 `file`/`luci` requests answered identically to the
original plugins in the exact-rootfs sandbox (`tools/r13_rpcd_check.py`).
