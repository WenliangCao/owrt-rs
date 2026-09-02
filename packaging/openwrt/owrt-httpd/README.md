# OpenWrt package: owrt-httpd

Packages `components/httpd` (with `components/ubus`) for the pinned OpenWrt
25.12.5 `mediatek/filogic` SDK as `/usr/sbin/httpd-rs`. The binary accepts
uhttpd's command line; `/etc/init.d/owrt-httpd` builds it from
`/etc/config/uhttpd` exactly like the stock init script and adds
`--call-log /tmp/owrt-httpd-calls.txt` (the `/ubus` object/method inventory
used by stage 5).

Installation is inert. `owrt-httpd-switch enable` stops the stock `uhttpd`
service, starts `httpd-rs` on the same ports and fails closed (restarts uhttpd)
if nothing answers on the HTTP port within 20 s. `disable` swaps back.
`boot-enable on|off` swaps the rc.d links of `uhttpd` and `owrt-httpd`.

TLS uses rustls with the ring provider and the existing DER certificate/key
(`/etc/uhttpd.crt`, `/etc/uhttpd.key`). It is the only third-party dependency
in this project (decision 0009).
