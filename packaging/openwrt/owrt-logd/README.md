# OpenWrt package: owrt-logd

Packages `components/logd` (with `components/ubus`) for the pinned OpenWrt
25.12.5 `mediatek/filogic` SDK as `/usr/sbin/logd-rs`.

Installation is inert: the stock `log` service keeps running. The init script
`/etc/init.d/owrt-logd` starts the Rust daemon only when either the persistent
flag `/etc/owrt-logd.boot-enable` or the volatile marker
`/var/run/owrt-logd.enabled` exists.

```sh
owrt-logd-switch enable        # stop stock logd instance, start logd-rs, wait for ubus "log"
owrt-logd-switch status        # enabled (0) / disabled (3)
owrt-logd-switch disable       # stop logd-rs, start stock log service again
owrt-logd-switch boot-enable on|off|status   # swap the rc.d links of log/owrt-logd
```

`enable` fails closed: if the candidate does not publish `log` within ten
seconds the stock service is restarted. Removing the package turns boot-enable
off and re-enables the stock `log` service.
