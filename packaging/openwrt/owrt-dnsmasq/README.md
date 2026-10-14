# owrt-dnsmasq

This is the M4 replacement recipe for the AX3000T `dnsmasq` package.
It keeps the package identity `dnsmasq` at version 2.93-r4, provides
`dnsmasq-any`. Same-name replacement uses APK version ordering. Mutual
exclusion with the stock DHCPv6/full variants needs a solver test with their
actual APKs; the recipe does not emit a conflicts field. It installs the daemon at `/usr/sbin/dnsmasq`
and carries the stock package's init script, UCI conffiles, hotplug helper,
dhcp-script, migration scripts, default data and ubus ACL paths.

Release r4 orders after the accepted M5 r2 and M6b r3 packages. The build and
lifecycle tools still accept explicit releases 2 and 3 for historical replay.

The init instance tracks both the generated configuration and the executable
through procd's `file` parameter. APK's normal post-install/post-upgrade `start`
therefore replaces a running instance when the executable changes. Returning to
the original stock package also changes this tracked-file set and activates C.
Reinstalling identical bytes is idempotent; no extra post-install restart runs.
Package acceptance checks the live `/proc/PID/exe` identity and client answers,
not just the installed version or executable on disk.

The recipe does not establish deployment readiness. The matching
SDK build, exact-image install/upgrade/uninstall/rollback checks, complete
M5 contract, and M6 performance gate must pass before deployment is considered.

For activation and automatic recovery, follow the
[guarded deployment runbook](../../../docs/dnsmasq/DEPLOY_RUNBOOK.md).
This recipe builds a package artifact; APK installation alone is not a rollback
mechanism. The guarded procedure keeps stock C on disk and activates a separate
candidate through temporary runtime mounts, with recovery from `/rom`.
