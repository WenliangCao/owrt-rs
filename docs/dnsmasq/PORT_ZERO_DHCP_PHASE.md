# DHCP with DNS disabled and startup failure classes

The ordinary `port=0` DHCP daemon now passes the scoped native C comparison.
This does not establish every disabled-DNS configuration, full DHCP equivalence,
resource improvement or router acceptance. All listeners ran in isolated Linux
network namespaces with private configurations and lease paths.

| Exact reference | Required behavior |
|---|---|
| `dnsmasq.c:300-318,411-435,462-463` | DHCP lease initialization and its socket remain independent of DNS; DNS cache, forwarding pools and DNS sockets are conditional on a nonzero DNS port. |
| `dnsmasq.c:851-861,985,1091,1835-1851` | Disabled DNS does not read its hosts/resolver data or run DNS cache reload. SIGHUP still rereads DHCP file banks and updates lease-file state. |
| `lease.c:564-620` | A disabled DNS port leaves `dns_dirty` pending; it does not announce successful publication. |
| `util.c:48-57`, `dnsmasq.h:211-217` | Entropy open/read failure is `EC_MISC=5`. C reads 32 seed words and 12 input words before initialization succeeds. |
| `lease.c:132-134,207-223` | Lease file open/read failure is `EC_FILE=3`; exceeding the stored-lease capacity is `EC_MISC=5`. |
| `dhcp.c:48-97,119-123` | DHCP socket creation, socket option and bind failures are `EC_BADNET=2`. Configuration errors remain `EC_BADCONF=1`. |

`LocalProvider::new` now returns the small typed `StartupError` with lease-file,
restore, socket and entropy variants. Its `exit_code()` follows the operation
boundary instead of guessing from errno. The bounded file parser retains a
typed `CapacityExceeded` cause inside `io::Error`, so an ordinary I/O error with
the same kind/text cannot accidentally acquire the capacity exit class.

The DHCP entropy source now completes the C-sized 176-byte startup read before
lease-file creation. Merely opening it would accept an unreadable or short
source and could mutate the lease pathname before reporting that failure.
This keeps the OS entropy source for subsequent Rust random values; it does not
claim bitwise equivalence to C's SURF generator or complete process-wide entropy
startup equivalence outside the DHCP provider.

The main owner prepares all listeners and the provider, completes startup file
maintenance and synchronous lease publication, and only then starts workers.
When DNS is disabled it does not construct the DNS daemon or read its inputs,
and it does not attach a DHCP DNS publisher. DHCP domain/name configuration,
file maintenance, idle ticks and SIGHUP remain active.

## Evidence and boundaries

Raw files, packets, process socket observations, exit stderr, source snapshot
and ELF are retained under ignored
`private/dnsmasq-rewrite/port-zero-dhcp-20261001/`:

- `c-baseline-01/`: **25 C-only checks pass**, establishing DHCP allocation,
  ACK/file commit, host-file rename on SIGHUP, INFORM, release, and restored
  lease expiry with zero DHCP packets in the expiry scenario. Real negative
  startup cases establish exit codes 3/5/2/1 for missing lease parent,
  capacity exhaustion, occupied DHCP port and invalid configuration.
- `diff-01/`, `diff-02/`: **72 checks pass, zero fail** in each C/Rust round.
  The extended checks require no owned DNS/other TCP socket, stable UDP socket
  counts, no option-6 DNS server in OFFER/ACK, unchanged expiry during rename,
  and no private DNS hosts/resolver file open or read at startup or reload.
- `calibration-01/`: **70 passed / 2 failed**. One is the intentionally changed
  ACK lifetime. The other exposed the tester's overly strict INFORM comparison:
  remaining lifetime and the matching lease expiry were 599 in C and 600 in
  Rust across a whole-second observation boundary. Raw values remain retained.
- `calibration-02/`: after binding INFORM's wire lifetime to each run's own
  expiry/send time and retaining a one-second cross-run bound, the injected
  ACK corruption gives **71 passed / 1 failed**, exit 1. OFFER/ACK configured
  lifetime still compares exactly. Further positive/missing/incorrect-TTL
  comparator calibration is part of the tool and was run independently.
- `linux-library-01.log`: **318 passed, zero failed, 14 ignored** in a fresh
  namespace. The ignored oracle-dependent tests were not counted as passed.
  The new Linux startup-origin/capacity unit passed; the five lease-file tests
  and Linux musl library clippy also passed.
- `source-01.tar.gz`, HEAD/diff records, `source-identity-01.json` and
  `dnsmasq-rs-01` identify the source/build. Native Rust ELF SHA-256 starts
  `3b3d8044972086d0`; the complete digest is in every paired result.

The canary detector first observes a controlled OPEN/ACCESS and then an untouched
file; the owned-socket detector also calibrates a known socket. Readiness uses
the daemon's owned UDP port 67 from `/proc`, not a sleep or a DNS connection.
Lease expiry is observed without DHCP traffic after readiness. Raw expiry and
wire timers are retained, including the accepted whole-second differences.

The unchanged persistence implementation's existing **317/317** instrumented
C/Rust gate (`dhcp-persistence-20261001/diff-02/`) remains valid for disabled-DNS
dirty-state retention. That private-state evidence is separate from the real
daemon socket/file gate; no successful DNS publication is inferred from silence.

The socket snapshots show one C DHCP UDP socket and two Rust UDP sockets: Rust
retains its existing additional interface-control UDP descriptor. This is an
explicit resource difference, not a gain; these snapshots are not full FD peaks
or a performance benchmark. Global DNS/TFTP entropy initialization, broader
configuration acceptance, pressure failures and complete resource accounting
remain outside this scoped gate. No physical router was accessed.
