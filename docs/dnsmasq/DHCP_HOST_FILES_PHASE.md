# DHCP host-file reload contract

Ordinary-selector `dhcp-hostsfile` paths now connect to daemon startup and the
main-loop SIGHUP transaction. Their live C/Rust leasefile/DNS gate passes the
stated fixture. This is not complete host-file or DHCP service equivalence:
hosts-derived addresses, name fallback and other selectors remain open.

| Exact C reference | Contract |
|---|---|
| `option.c:2405-2429` | Store repeated `dhcp-hostsfile` paths in reverse directive order. |
| `option.c:5471-5614,5630-5718` | Apply the normal quote/comment scanner to each whole line as a host argument, including ordinary `=` bytes. Blank/comment lines are skipped. Bad rows are logged and skipped; valid later rows survive. Open failure is nonfatal. Unlike main includes, repeated files are not deduplicated by inode. |
| `option.c:5721-5843` | Expand directory paths with C-locale alphabetical order; skip dotfiles, trailing `~`, `#…#` names and directory-derived nonregular files. Preserve the expanded list across reloads, moving rediscovered entries to the end. Explicit file/directory overlap affects this ordering. |
| `option.c:5867-5949` | Clear only `CONFIG_BANK` rules before rereading files. Missing/deleted files remove prior file rules. Main/CLI rules remain. |
| `dnsmasq.c:1835-1851` | SIGHUP reloads data, then runs host-address/config-name updates, lease-file maintenance and forced DHCP DNS publication. It does not reparse the main configuration. |
| `lease.c:256-275,1062-1102` | Apply a configured name only when its fixed address is absent or matches the lease. Removing a rule does not delete the lease or its old name. Renaming dirties the lease file; changing lease duration in a rule does not itself renew the existing expiry. |

`HostFiles` retains only file-list expansion state; each `reload(main_hosts)`
returns a fresh complete rule list plus line/open diagnostics. It does not retain
stale rules when a file disappears. `lex_argument_line` shares the audited
scanner with ordinary main directives, preserving quoting without splitting an
unquoted `=` in a client ID into a directive.

`LocalProvider::reload_host_files(now)` preserves main-rule DECLINE state,
rebuilds file-rule state and reservations, applies configured-name updates, then
performs file maintenance and synchronous forced DNS publication. The returned
`MaintenanceReport::host_files` contains its diagnostics. Startup performs the
same file read before the first name publication. The main owner must call this
after DNS hosts reload and finish it before exposing the new reload generation.
It must not hold the DNS-parent mutex while calling this method because the
publisher locks that parent synchronously.

Unsupported but C-valid tags, wildcards and name-only selectors are distinct
from C syntax errors. `HostReload::ready()` is false for those selectors; the
daemon adapter pauses DHCP admission rather than applying a partial rule set.
A later supported reload resumes it. This deliberate unsupported boundary is
not counted as functional equivalence. Empty/stdin paths and `dhcp-hostsdir`
remain rejected. The latter has a separate inotify append/update contract, not
the SIGHUP file-bank replacement behavior.

## Evidence

All raw configurations, files, packets and native artifacts remain below ignored
`private/dnsmasq-rewrite/dhcp-static-20261001/`. No physical router was accessed.

- `hostfiles-c-baseline-01/`: the exact native C `reread_dhcp` implementation,
  linked from the hash-pinned objects, establishes **7 scenarios / 20 reloads**.
  It includes replacement/deletion/recreation, multiple-file priority, retained
  main rules, duplicate addresses, malformed rows, quoted IDs, embedded NUL,
  directory order/filtering and explicit-path overlap.
- `hostfiles-diff-01/`, `hostfiles-diff-02/`: **7/7 scenarios and every one of
  their 20 reloads match**, including all parsed fields, rule order and error
  counts. C-derived per-phase counts are frozen in the tester.
- `hostfiles-calibration-01/`: changing one decoded Rust address yields **6
  matching scenarios / 1 failed**, exit 1. Unmodified raw output is retained.
- `hostfile-lifecycle-c-baseline-01/`, `hostfile-lifecycle-c-baseline-02/`:
  namespace-isolated real C baseline, with **13 ordered event snapshots**, **5
  DHCP replies** and **8 × 21 DNS replies**. The second round also records
  leasefile-write occurrence using its private inode's modification timestamp.
  Rename/recreate write the file; address-only changes, empty and missing host
  files do not. Existing expiry and rows remain visible in every snapshot.
  These are C baseline observations, not Rust service passes.

The live fixture proves that a fixed-address change takes effect for a new ACK,
while deleting the rule retains the old lease/DNS name. Main-file domain and
inline-rule edits are ignored by SIGHUP; restart adopts the new domain. A fresh
addn-hosts marker bounds each reload: subsequent DHCP-name observations cannot
be delayed until an incorrect intermediate state disappears.

The nine focused typed-DHCP configuration tests, the affected DHCP tests and
library clippy passed. The explicit unsupported-selector regression checks that
a C-valid scoped `ignore` rule cannot be silently discarded as an ordinary bad
row. Host-derived addresses (`dhcp_update_configs`), hosts-name fallback, inotify directories,
tags, file reload under resource pressure and performance remain open.

## Integrated ordinary-file gate

The main owner added one parent-event read/write gate. UDP processing/polling,
TCP acceptance snapshots and DHCP transactions take its read side; SIGHUP takes
its write side until DNS hosts/cache work and DHCP rule/file/DNS publication
finish. Lock order is event gate → DHCP provider → DNS parent. This keeps the
fresh reload marker from being visible before DHCP names have been republished,
and avoids holding the parent lock across a publisher callback.

After that connection, the temporary `validate_ready` host-file gate was removed.
The independently archived native Linux build and all new raw evidence are in
`private/dnsmasq-rewrite/dhcp-hostfile-integration-20261001/`:

- `lifecycle-diff-01/`: **41 passed, zero failed**. All 13 C/Rust event snapshots
  match, including 168 DNS answers, five DHCP replies, ordered lease rows,
  original expiry and actual lease-file write/no-write behavior. The snapshots
  immediately follow the new marker response; no later convergence is accepted.
- `lifecycle-calibration-01/`: corrupting one decoded DNS flag yields **40
  passed, one failed**, exit 1, with the raw packet unchanged.
- `unsupported-boundary-01/`: **11 Rust-only checks pass**. A C-valid scoped
  rule that Rust cannot implement pauses existing-client renewal and other
  clients, preserves the lease bytes, emits a diagnostic, and resumes after a
  supported reload. These checks are explicitly excluded from C parity counts.
- `source-01.tar.gz`, `source-01-head.txt`, `source-01-diff.patch`,
  `source-identity-01.json` and `dnsmasq-rs-01` retain the dirty-source snapshot
  and native ELF used by these runs. This is host evidence, not a target-router
  deployment or performance measurement.
