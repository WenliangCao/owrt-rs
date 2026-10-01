# Lease persistence, expiry and DNS publication contract

This phase starts from the matching C implementation; it is not yet a Rust
persistence/DNS/service equivalence claim.

| Reference | Required behavior |
|---|---|
| `lease.c:174-254` | Open the configured file once as `a+`, rewind and restore before serving. Open/read failure and capacity exhaustion are startup-fatal. Parsing warnings alone do not discard all valid records. Clear file dirtiness, prune expired records, and mark DNS dirty after normal restore. |
| `lease.c:181-210,225-248` | `leasefile-ro` does not read the configured file. Without a script it starts with an empty DB and clean file/DNS flags. With a script it reads `<command> init` stdout and checks the process exit status. |
| `lease.c:286-413` | When dirty and a stream exists: rewind, truncate, serialize newest-first basic rows followed by extension rows, flush and fsync. Flush failure skips fsync. Dirty clears only when every required stage succeeded. An earlier error still permits flush/fsync; a later flush/fsync error replaces the reported error. |
| `lease.c:415-453`; `config.h:38` | Schedule the earliest finite expiry. On write error also consider `now + 60`; log and retain dirty state. A missing writable stream does not itself create a retry error. |
| `dnsmasq.c:1420-1431` | `send_alarm(0, nonzero_now)` leaves the prior alarm alone. A due event or `now==0` queues an immediate callback; a future event replaces the alarm. |
| `dhcp.c:372-380`; `dnsmasq.c:1607-1613` | Packet and alarm paths both prune, update file and update DNS. The packet path does these before deciding whether to send. File-write failure must not undo the committed lease or suppress an otherwise valid ACK. |
| `lease.c:564-620` | DNS enabled plus dirty/force triggers a full DHCP-only unhash and newest-first rebuild, FQDN before short name. FQDN-only mode omits the short name. DNS disabled leaves the dirty flag set. |

The binary default is **`/var/lib/misc/dnsmasq.leases`**, confirmed by the
matching native C `--help` and `config.h:211-220`. OpenWrt's init recipe
instead always emits an explicit **`--dhcp-leasefile=/tmp/dhcp.leases`**
default, creates the file if missing and grants its jail a writable mount
(`dnsmasq.init:1067,1103-1104,1282`). The recipe does not override the compiled
LEASEFILE macro. These are separate CLI and OpenWrt-init contracts.

The same reference also fixes `MAXLEASES=1000` (`config.h:41`,
`option.c:5978`); the init script only passes a user `dhcpleasemax` value and
does not replace that default. Rust's pre-existing default of 150 has been
corrected to 1000 by this integration. Tests that intend a
150-lease budget must configure it explicitly on both implementations.

Every daemon experiment must set an absolute lease path under its private
output directory. A network/mount namespace created by `run_isolated.sh`
does not isolate the caller's `/var/lib` or `/tmp` directories. The tracked
DHCP daemon smoke fixture now supplies its own path before persistence is
enabled; parser-only probes and socket tests do not construct this adapter.

## Existing reusable code and boundaries

`lease_file::parse` already preserves scanf field widths, partial records,
byte-oriented names, typed hardware IDs and extension association.
`LeaseStore::restore` preserves the C newest-first order and startup flags,
then prunes and marks DNS dirty. It deliberately rejects ambiguous duplicate
addresses; this existing recovery-policy difference remains explicit.
`write_leases` only proves that a `Write` accepted bytes. Its caller must
flush and sync the held inode before `file_written`; `dns_updated` requires
the corresponding publication to have completed.

The persistence adapter will keep the file descriptor and buffering rather
than reopen or rename the path on each update. Its narrow `LeaseIo: Write`
boundary exposes rewind, truncate and sync for deterministic failure tests.
An update returns a report containing any error and the next event; it does
not return early and lose an already committed outcome. Periodic maintenance
owns pruned leases and lost-name notifications until their cleanup consumers
take them, even when persistence fails.

DNS publication requires its own explicit sink and completion boundary.
Ordinary hosts entries cannot stand in for DHCP entries: `cache.c:1742-1842`
preserves hosts/config precedence, reverse-record choice and DHCP expiry;
`rfc1035.c:1661` selects DHCP/local TTL and bounds it by remaining lease time.
FQDN ancestors also carry non-terminal semantics. The sink must become visible
to DNS readers before ACK transmission; enqueueing an asynchronous message
without acknowledgment does not establish that ordering. Until the DHCP DNS
source is connected, pending publication and dirty state must remain visible.

## C baseline evidence

`tools/dnsmasq/dhcp_persistence_diff.py` extracts `ourprintf`,
`lease_update_file`, `lease_update_dns` and `send_alarm` from hash-pinned
sources, with instrumented file calls. The C-only baseline calibrated
**314 inputs** covering clean/dirty, stream absent, DNS disabled/force/FQDN,
rewind/truncate/partial-write/flush/fsync faults, retry versus earlier expiry,
and alarm keep/immediate/replace behavior. The comparator's pass/fail and
missing/extra-output paths are calibrated before use.

Evidence is under ignored
`private/dnsmasq-rewrite/dhcp-persistence-20261001/c-baseline-02/`, with the
matching C help output in the parent directory. The first oracle attempt
incorrectly supplied expired active leases to an error branch that real
callers enter only after prune; its sanitizer rejection is retained in
`c-baseline-01/`, and the generated schedule now preserves that precondition.
This instrumented stream records accepted text and operation order; it does
not emulate all libc buffering details or prove bytes durable on real media.
Rust differential, real file failures and full DORA/renew/release/restart
service comparisons remain pending at this checkpoint.

## Reusable adapter checkpoint

`dhcp::persistence` now implements the held-inode `LeasePersistence`, the
`LeaseIo` failure boundary, `PersistReport`/`AlarmAction` and the synchronous
`DnsPublisher::replace` handoff. Its writer uses a bounded 1 KiB buffer.
The C comparison now covers **317/317** inputs, including combined faults
and the exact error code selected when flush/fsync replaces an earlier error;
evidence is `diff-02/`. The real-file unit check confirms that replacing a
pathname does not redirect the held descriptor's writes. Read-only/no-script
ignores even an unopenable path. Missing or failed DNS sinks retain dirty
state and never claim successful publication.

Startup parsing now consumes a buffered reader with a record-capacity limit,
so it does not allocate the complete database file before checking capacity.
Its whitespace matcher includes vertical tab as C scanf does; the previous
Rust ASCII-whitespace predicate omitted it. A tiny-buffer regression and a
C-derived vertical-tab fixture accompany this correction. The broader
primitive oracle passed **2,016/2,016** after being updated to link the actual
crate (its previous standalone module import broke after context integration).
The failed adapter build is retained in `parser-stream-01/`; the passing run
is `parser-stream-02/`. Real-file unit checks and library clippy passed.
Daemon/config/tick wiring and a live dedicated DNS source are still pending
at this adapter checkpoint.

## Local daemon and filesystem checkpoint

`DhcpConfig` now accepts `dhcp-leasefile`/`dhcp-lease` and `leasefile-ro`,
including the C empty-path fallback and empty lease-max value of zero.
`LocalProvider::new` opens/restores before listener startup; `initialize` and
`tick` perform file maintenance and offer pending data to `DnsPublisher`.
Packet resolution performs state → file → DNS sink before returning the
committed outcome. I/O errors stay in `MaintenanceReport`; an otherwise valid
ACK is sent. Periodic maintenance returns owned removals and lost names.

The provider uses a monotonic deadline for C's relative alarm delay, computed
from `event - caller_now`. This matters when caller time predates an ICMP wait
or file operation. A prior alarm that expired during work remains pending
when a new alarm is installed, and `Keep` does not cancel an earlier timer.
The main-loop owner calls `tick(fresh_epoch_seconds)` before polling packets
and consumes packet/periodic reports. No new DHCP traffic is needed for expiry
or the 60-second failed-write retry.

Before real serialization, the client-name boundary was corrected:
`Packet::client_hostname` follows option-81 precedence, target no-IDN
`check_name`/`legal_hostname`, and short-name extraction. Client-provided
domain text is not promoted to a configured DNS domain. BOOTP does not use
this DHCP name parser. The C primitive run now passed **5,516/5,516**,
including 500 direct legal/invalid hostname cases; FQDN precedence/encoding
has focused source-derived regressions. Full FQDN reply flags/options and
configured domain policy remain separate work.

A normal full-daemon header discrepancy was also closed: `do_options` sets
`siaddr` to the selected context's local address. `NetworkOptions::next_server`
now supplies that header value, while NAK and missing-context paths retain
zero. The lifecycle comparison checks that address rather than dropping it
during normalization.

`tools/dnsmasq/dhcp_lease_lifecycle.py` runs the exact C and Rust daemons with
the same explicit private configuration, a 150-lease limit and loopback-only
DHCP traffic. Evidence under the phase directory records:

- `lifecycle-01/`: **114 passed, zero failed** checks across DORA, unicast
  renewal, broadcast rebinding, release, restart, no-traffic expiry and
  read-only/no-script. The file is inspected after ACK, and restart must retain
  the exact prior rows before another request.
- `enospc-01/`: **38 passed, zero failed** checks. A private 4 KiB tmpfs is
  filled, both daemons still ACK, the filler is removed, and each daemon waits
  its real 60-second retry without receiving more DHCP packets. The resulting
  lease expiry remains tied to the original ACK; retry does not extend it.
- `calibration-01/`: deliberately corrupting one decoded lease TTL produced
  **71 passed, one failed**, exit 1; original response bytes remain untouched.
- `source-identity.json`: source and ELF identities for these runs. The
  generated configs, lease files, packets, logs and binaries remain ignored.

Renewal T1/T2 randomness is checked against C's common-subtraction and bounded
fuzz rules, with all observed timer values retained. Every finite leasefile
expiry is checked against its corresponding request time, allowing only the
whole-second observation boundary; expiry is not silently erased from the
acceptance gate. DNS publication remains explicitly **unchecked** in these
daemon runs until the dedicated DNS source is connected. These counts are
checks within the stated scenarios, not a claim of complete DHCP equivalence.

The expanded exact-C configuration gate has **105 matching contract cases**
and **9 explicit unsupported-boundary cases**, with no failure. It preserves
exit codes as well as state. In particular `bootp-dynamic` with tag parameters
is rejected instead of widening scoped permission to all clients; bare
`bootp-dynamic` remains available. The authoritative, ignore-client-id,
sequential and no-ping switches are verified no-argument options. This does
not establish BOOTP/PXE service equivalence.
