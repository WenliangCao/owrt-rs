# owrt-dnsmasq

This is the M4 replacement recipe for the AX3000T `dnsmasq` package.
It keeps the package identity `dnsmasq` at version 2.93-r2, provides
`dnsmasq-any`. Same-name replacement uses APK version ordering. Mutual
exclusion with the stock DHCPv6/full variants needs a solver test with their
actual APKs; the recipe does not emit a conflicts field. It installs the daemon at `/usr/sbin/dnsmasq`
and carries the stock package's init script, UCI conffiles, hotplug helper,
dhcp-script, migration scripts, default data and ubus ACL paths.

The recipe does not establish deployment readiness. The matching
SDK build, exact-image install/upgrade/uninstall/rollback checks, complete
M5 contract, and M6 performance gate must pass before deployment is considered.

For activation and automatic recovery, follow the
[guarded deployment runbook](../../../docs/dnsmasq/DEPLOY_RUNBOOK.md).
This recipe builds a package artifact; APK installation alone is not a rollback
mechanism. The guarded procedure keeps stock C on disk and activates a separate
candidate through temporary runtime mounts, with recovery from `/rom`.
