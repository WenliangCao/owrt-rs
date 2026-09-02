# owrt-fw4

Rust replacement (`fw4-rs`) for the firewall4 ucode generator behind `/sbin/fw4`
(contract C4, decision 0010). Same command surface as `/sbin/fw4`:
`start|stop|flush|restart|reload|check|print|reload-sets|network|device|zone`.

Installation is inert. `owrt-fw4-switch`:

- `gate` renders the live configuration with both implementations and reports
  whether the output is byte-identical (no change to the system).
- `enable` runs the gate and, only when identical, bind-mounts `fw4-rs` over
  `/sbin/fw4` (reboot-volatile). The kernel ruleset is untouched by enabling.
- `disable` unmounts; the original `/sbin/fw4` (sha256 pinned) is back.
- `boot-enable on|off|status` controls whether `/etc/init.d/owrt-fw4` (S18,
  before S19 firewall) re-applies the mount at boot.

Offline evidence: all 31 upstream firewall4 test files pass byte-for-byte
(`tools/r09_fw4_check.py`), and the AX3000T configuration renders identically
(`tools/r09_device_fixtures.py`).
