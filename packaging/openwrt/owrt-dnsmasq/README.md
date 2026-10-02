# owrt-dnsmasq

This is the M4 deployment-candidate recipe for the AX3000T `dnsmasq` package.
It keeps the package identity `dnsmasq` at version 2.93-r2, provides
`dnsmasq-any`, and declares conflicts/replacement for the stock DHCPv6/full
variants. The candidate installs the daemon at `/usr/sbin/dnsmasq`
and carries the stock package's init script, UCI conffiles, hotplug helper,
dhcp-script, migration scripts, default data and ubus ACL paths.

The recipe is a packaging candidate, not production acceptance. The matching
SDK build, exact-image install/upgrade/uninstall/rollback checks, complete
M5 contract, and M6 performance gate must pass before deployment is considered.
