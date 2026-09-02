# owrt-uci

Rust replacement for `/sbin/uci` (contract [C6](../../../docs/contracts/uci.md), decision
[0012](../../../docs/decisions/0012-uci-library-and-cli-in-rust.md)). Installs `/usr/sbin/uci-rs`,
`/usr/sbin/owrt-uci-switch` and `/etc/init.d/owrt-uci`; installation changes nothing until
`owrt-uci-switch enable`.

- `owrt-uci-switch gate` — read-only: `export`, `show`, `changes` for every package must be
  byte-identical between `/sbin/uci` and `uci-rs`, with `/tmp/.uci` untouched.
- `enable` — verifies the original's sha256, runs the gate, bind-mounts `uci-rs` over `/sbin/uci`.
- `disable` — unmounts; the original binary was never modified.
- `boot-enable on|off|status` — flag file `/etc/owrt-uci.boot-enable`; the S00 init script
  re-applies the mount before the first init script that calls `uci`.

`libuci.so` and its library users (netifd, rpcd, odhcpd, ucode, iwinfo) are untouched; both
implementations share `/etc/config`, `/tmp/.uci` and `/var/state`.
