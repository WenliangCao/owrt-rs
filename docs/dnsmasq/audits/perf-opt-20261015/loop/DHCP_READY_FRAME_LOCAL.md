# Keep ready DHCP work out of the shared owner frame

Independent6ab child025c2f2c inserts eight lines at the existing readiness
boundary. Helper processing, reload gates, input detection and maintenance
clock checks remain in step_dhcp. Only after they authorize work does the
owner call non-inlined process_ready_dhcp(input_pending). Its complete body
is byte-for-byte original; no cold annotation or new readiness state is added.
Source review fc446c16 proves deletion of the eight lines restores all main.rs.

The parent local AArch64 ELF emits step_dhcp inside SinglePoll::step. The
shared step is17,608B with a2,400B frame even on an ordinary UDP-only turn.
The prototype emits13,436B/1,312B plus a4,408B/2,016B ready-DHCP helper.
Whole bundled-musl/lld ELF shrinks424B; wait_for_files stays7,192B. This removes
4,172B from the common function, but does not prove a smaller dynamically
executed working set or CPU/cache benefit. Actual DHCP now pays an extra call
and nests the helper frame under step, so maximum stack need can increase.

Mac executable tests23pass and musl all-target compilation pass. The extracted
Linux-only work is not executed by those Mac tests: original Linux related
gates and DHCP/probe/reload coverage are mandatory before any timed screen.
No SDK, remote gate, full qualification or CPU result is claimed. Keep this
local candidate after803opt2 and bare1df; do not alter their measured sources.

[Exact source, logs, ELF and codegen receipt](dhcp-ready-frame-local.json).
