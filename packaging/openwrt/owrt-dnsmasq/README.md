# owrt-dnsmasq

This SDK package is a staging artifact for the Rust dnsmasq rewrite. It
installs `dnsmasq-rs` at `/usr/libexec/dnsmasq-rs` and intentionally leaves the
stock OpenWrt `dnsmasq` package, `/usr/sbin/dnsmasq`, init script, UCI files,
and ownership unchanged. It must not be included in a production image yet.

The package becomes a replacement only after the DNS/DHCPv4/TFTP integration,
OpenWrt lifecycle, target build, and frozen performance gates in
`docs/dnsmasq/REPORT.md` pass. Keeping this package inert prevents an SDK build
from being mistaken for a deployable daemon.
