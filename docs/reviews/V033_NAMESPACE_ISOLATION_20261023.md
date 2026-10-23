# v0.3.3 offline fixture isolation

The reviewed tools execute only disposable image copies on Oracle. No physical
router is accessed. The product ELFs, firmware, and extracted source rootfs are
not changed by the isolation fixes.

Two concrete gaps were closed before running the final image gates:

- Handoff and configuration/APK fixtures now bind an empty ordinary file over
  `/proc/kmsg`, as the boot fixture already did. All three verify that the exposed
  file has the same device and inode as the empty fixture, both before chroot
  and inside it. Type and size alone are insufficient: native `/proc/kmsg` also
  reports a regular, zero-length file. Host-side `stat` records mode and size;
  the exact OpenWrt image has no `stat` command, so the runtime checks use shell
  `test -ef`, `test -f`, and `test ! -s`. Each repeated configuration/APK call
  removes its previous isolation evidence before starting.
- Boot and handoff copies use `[]` for `/etc/hotplug.json`. Their real procd and
  udevtrigger remain in place. A fresh read-only sysfs prevents udevtrigger from
  writing `uevent`, but unrelated physical events without a network namespace
  tag can still reach these netns sockets. The exact image's original rules
  would create device nodes for any event containing major/minor numbers.
  Disabling those rules in the copy closes that path. Both tools verify the
  original source rules' hash before/after and explicitly exclude hardware
  hotplug behavior from their results.

The remaining reviewed boundaries are:

| Gate | Isolation and execution scope |
| --- | --- |
| FIT | File extraction, hash and DTB comparison against exact 25.12.6 stock FIT. |
| Boot | Private mount, network, PID, UTS and IPC namespaces; private root mount; fresh proc and read-only sysfs; only null/zero/urandom devices; synthetic network interfaces. Selected actual init services run. |
| Image/configuration and APK | Private mount/network/PID/UTS/IPC namespaces and minimal devices. Restore mounting hooks are stubbed. APK runs with `--no-network --no-scripts`; no daemons start. |
| Guard | Disposable chroot with ordinary fake proc files; health, clock, sysupgrade and reboot commands are stubbed. Exact C recovery only replaces fixture files. |
| Handoff | Same namespaces as boot, read-only sysfs and minimal devices; empty rc.d. Real PID1/service stop/sysupgrade validation execute; a static recorder replaces upgraded, so stage2 and flashing never execute. |
| Rollback bundle | Archive/file processing only; the historical backup is explicitly a non-current, do-not-deploy fixture. |
| Log migration | Disposable chroot, only null device, no proc/sys mounts. UCI and the exact config generator run; only the read-only keep collector is extracted from sysupgrade. |
| NAND extension | Empty proc/sys/dev, no external commands on PATH, recording functions for all NAND/UBI/mount/backup-move operations. No stage2 or reboot. |

UTS isolates hostname changes. The reviewed netifd/client writes affect
network-namespaced sysctls on synthetic interfaces. The fresh sysfs has no
cgroupfs submount, so procd's cgroup-root existence check fails; read-only sysfs
also prevents writes. Procd interprets the rcS inittab action using its internal
queue, so the absence of an executable `/etc/init.d/rcS` is expected.

PID-namespace reboot terminates that namespace; unsupported reboot operations,
including CAD changes, fail there. `kill(-1)` cannot target ancestor PID
namespaces. Exact recovery and shutdown paths still call `sync()`, which requests
global filesystem writeback. Consequently these are isolated functional tests,
not a claim of zero shared-kernel effects or a hostile-code security sandbox.

The minimum Oracle validation passed two masked launches and rejected two
missing-bind controls before chroot. It deliberately never read kernel logs or
started PID1. Both valid launches changed their private hostname and IPv4
forwarding value, while the host values remained unchanged; they also verified
the absent cgroup root and the handoff's read-only sysfs. Original hotplug rules
remained SHA256 `5bdcecd7029d08c50bcc10c5a5cf7e71067010591b1fa9f446f546ae508701a6`.

Evidence is under
`/home/ubuntu/owrt-v033-25126-release-20261023/private/namespace-isolation-smoke-02`;
`result.json` SHA256 is
`858ce75e99714a2c0125a7f130999af9dfc93db190cad9f82101be731dc0a989`.
The initial `namespace-isolation-smoke-01` failure (`stat: not found` inside the
stock image) remains preserved. It was a fixture assumption, not a product
failure. The final image's eight groups and NAND extension are recorded separately.

References: [Linux kobject event delivery](https://github.com/torvalds/linux/blob/v6.12/lib/kobject_uevent.c),
[OpenWrt udevtrigger](https://github.com/openwrt/procd/blob/master/plug/udevtrigger.c),
[Linux reboot semantics](https://man7.org/linux/man-pages/man2/reboot.2.html),
and [sync semantics](https://man7.org/linux/man-pages/man2/sync.2.html).
