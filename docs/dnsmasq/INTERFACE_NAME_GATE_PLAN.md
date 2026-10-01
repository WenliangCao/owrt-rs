# Frozen interface-name configuration and snapshot service gate

This first gate follows [the source review](INTERFACE_NAME_SOURCE_REVIEW.md).
It adds an independent tool and leaves all existing fixtures unchanged. Exact
native C and verified image C complete their schedules before main Rust is
observed. C supplies ordered packet/state expectations; do not sort records or
silently reinterpret a surprising configuration or runtime outcome.

## Twelve syntax cases

Accept plain `name,lo`, `/4`, `/6`, mixed-case name, repeated same-name `/4` plus
`/6`, and a nonexistent interface. Also observe an empty name with `,lo`:
`canonicalise_opt` explicitly accepts an allocated empty name, so its source
expectation is acceptance. Reject missing interface, empty interface, suffix
`/5`, an empty interior name label and an IPv4 prototype before the interface.
The prototype form belongs to dynamic-host, which is outside this gate. Each
case is a separate real `--test` process; compare acceptance and preserve exact
stdout/stderr/exit without treating executable-name text as a byte contract.

## Two service profiles: 25 DNS observations

Run both implementations in normal foreground mode **`-k`**, preserving C's
forked TCP handling. Debug `--no-daemon` would serialize an open TCP connection
and is forbidden for this fixture. Start with an isolated namespace containing
only loopback and verify loopback has 127.0.0.1 and permanent ::1. No temporary,
tentative or deprecated IPv6 state is introduced or qualified.

**Static family and priority profile (14):** Configure first and second names
for plain lo, separate `/4` and `/6` names, a joined name declared once per
family, a nonexistent-interface name, an explicit PTR colliding with loopback's
IPv4 address, and a configured CNAME targeting the first interface name.
Query, in order: first A/AAAA/ANY; second A; v4 A/AAAA; v6 A/AAAA; joined ANY;
IPv4 PTR; IPv6 PTR; missing-interface A; a missing-interface name's child TXT;
the configured alias A. The first interface name wins PTR before explicit PTR.
Wrong-family/missing-interface forward requests use controlled upstream
NXDOMAIN so C determines their local-existence/NODATA behavior. Record order,
flags, TTL and original PTR case remain observable.

**Accepted-TCP snapshot profile (11):** Configure one plain-lo DNS name.

1. Query UDP A, then connect TCP0 and query A with the initial addresses.
2. Add fixed IPv4 address 192.0.2.77/32 to this namespace's lo only.
3. Query UDP A, UDP PTR for the added address, TCP0 A, then newly accepted TCP1 A.
4. Remove that exact namespace-local address.
5. Query UDP A, UDP PTR for the removed address, TCP0 A, TCP1 A, then new TCP2 A.

TCP0 must retain its pre-add snapshot; TCP1 retains the added address across
deletion; new TCP and parent UDP use current snapshots. The listener and all
client connections use 127.0.0.1, which is never removed. Adding an address on
lo independently of the explicitly selected listener also exercises C's
interface-name enumeration outside the listener-address set.

For each connection record connect start/completion, the first observed parent
`tcp_connections` count reaching 1/2/3, and the first query send/reply times.
C increments this metric only after fork and the child's netlink-close pipe
handshake. These are observed bounds and barriers, not fabricated timestamps
of the accept syscall. Complete the first query before the next address change.
Close all connections and require the count to return to zero before teardown.

Address changes are successful `ip address add/del ... dev lo` operations inside
run_isolated.sh, followed by saved `ip -j address` verification and a completed
parent readiness request/UBus barrier. The next dynamic UDP query is a separate
parent event and itself calls interface enumeration. No fixed sleep constitutes
proof of refresh. All mutation commands, kernel snapshots, acceptance bounds,
barriers and query timelines remain raw evidence; they are not additional DNS
rows. Loopback IPv6 unavailability or an unsuccessful mutation is a fixture
failure, never a product pass or a reason to silently remove a row.

## Comparison and limits

Use local TTL 17, no-round-robin and no-negcache. Compare all decoded DNS
headers/records in order, PTR case, question bytes, ordered upstream activity
and all 30 UBus counters. Normalize only upstream transaction IDs and valid DNS
compression differences. Compare the full C schedule before allowing a Rust
comparison. If Rust cannot start, retain its configuration and logs and report
startup failure with zero completed service rows, not successful equivalence.
Missing/reordered rows must fail; one altered decoded flag must be detected.

Every process executes in the isolation wrapper with a private /run mount.
All interface inspection and mutation stays in that network namespace; never
change host or physical-router interfaces. Raw configs, packets, snapshots,
logs and artifacts stay ignored under private paths. IPv6 address-state flags,
interface-label aliases/IF_NAMESIZE limits, localisation, wildcard semantics,
dynamic-host, enumeration failure, resource/performance and complete option
acceptance remain outside this bounded gate.
