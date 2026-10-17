# v0.2.3 single-batch fw4 measurement fixture

The parent owns the only router run, recovery gate, schedule, noise policy and
decision. These tools do not deploy, schedule repetitions or compare versions.
All development/build/fixture checks run on Oracle. No product code changes.

Build `exec_sample.c` and `../benchmark/ns_exec.c` with the image SDK using
`-Os -static -Wall -Wextra -Werror`; verify AArch64 and no ELF `INTERP` segment.
`prepare.py CAPTURE V022_ELF V023_ELF HELPERS OUTPUT` assembles a private bundle.
It pins the captured v0.2.2 and canonical SDK v0.2.3 ELF SHA256s, the captured
firewall config, two WAN6 input snapshots, and the existing comments-only include.
The bundle contains private runtime inputs and must not be committed.

After the parent approves the fixed batch, launch once as root:

```sh
sh "$bundle/driver.sh" / "$bundle" "$output" > "$driver_log" 2>&1 &
driver=$!
# Wait for $output/READY and keep checking the driver/outer lifetime guard.
printf 'unchanged A cal-unchanged-01\n' > "$output/control"
# Wait for $output/cal-unchanged-01/COMPLETE, or report an exited driver.
# Read measurement.json; do not resubmit a failed or timed-out request.
printf 'stop\n' > "$output/control"
wait "$driver"
```

`bundle` and `output` are absolute paths; output must not exist before launch.
The image root argument `/` binds the currently running userspace read-only into
a private chroot. For Oracle use the exact extracted image path instead.
The launcher isolates mount, net, PID, IPC and UTS namespaces, owns all child
lifetimes, hides production configuration/sockets/devices and mounts private
sysfs/proc. Two empty bridges named `wan` and `br-lan` model existing interface
names without requiring dummy/veth modules or physical links. A private ubusd
and a small ucode provider supply `network.interface.dump` and `service.get_data`.
The measured process uses real input paths and real nft; `FW4_MOCK_DIRS` is unset.

Legal commands are `SCENE SIDE ID`, where SCENE is `unchanged`, `changed`, `start`,
`check` or `print`; SIDE is `A` (v0.2.2) or `B` (v0.2.3); ID contains only ASCII
letters, digits, `_` and `-`. Every command has a fresh deterministic starting state:

| Scene | Untimed preparation | Expected measured effect |
| --- | --- | --- |
| unchanged | Empty table/state/cache; same side `start + reload`; select captured WAN6 variant | A rebuilds; B retains every rule/flowtable handle |
| changed | Same baseline `start + reload`; change DHCP-Renew port 68 to 41001 in the isolated config | Both rebuild and install port 41001 |
| start | No fw4 table, state or reload cache | Both install the first table; this is cold firewall state, not a claim of cold CPU/page cache |
| check | Same baseline `start + reload` | Validate without changing handles |
| print | Same baseline `start + reload` | Print to `/dev/null`, without changing handles |

The script takes pre-state snapshots, then waits the frozen **1 second** before
calling the timer. All preparation, probes, verification and output-file setup
are outside the measured interval. No nft wrapper, strace or cache eviction is
used. The timer directly execs the requested ELF. Wall time spans fork to reap;
CPU is `wait4` user+system for fw4 and descendants it reaped (including nft),
excluding the separate ubusd/ucode provider and timer parent. JSON records the
monotonic clock resolution and 1 µs rusage output quantization, which are not
claims about scheduler noise. `maxrss_kib` is a maximum, not a summed tree peak.

Oracle validation is `sudo python3 verify_oracle.py ROOTFS BUNDLE OUTPUT`. It
issues exactly one functional request per side/scene, checks all ten effects and
helper fields, and makes **no timing comparison or candidate selection**. The
final v3 bundle passed these ten commands with the exact image. Resident helper
daemons were 920 + 1484 KiB RSS; largest child/reaped-child RSS was 3332 KiB.
These are Oracle observations, not a router RSS acceptance result. Bundle size
was 2,773,042 bytes and ten sample outputs totaled 129,799 regular-file bytes.

The parent froze calibration `ABBAAB` and formal `ABBABAAB` for each scene in
the listed order, within a single combined fw4/netifd batch limited to 600 s.
No repetition or statistical rule is encoded in this driver; the parent applies
the frozen per-scene wall/CPU noise gate and reports any regression without
extra samples, optimization rounds or PGO.
