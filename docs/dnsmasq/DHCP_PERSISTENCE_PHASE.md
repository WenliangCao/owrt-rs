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
does not replace that default. Rust's pre-existing default of 150 is a known
configuration defect to correct with this integration. Tests that intend a
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
