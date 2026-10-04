# M5 DHCP relay implementation plan

Planning only. Product implementation and Oracle execution wait for the main agent to close the current integration batch. Nothing in this plan closes an option.

The authoritative, source-derived boundary checklist is
`private/dnsmasq-rewrite/evidence/M5/relay/checklist.json` in the main worktree:
43 pending boundaries for `dhcp-relay`, `dhcp-split-relay`, and
`dhcp-alternate-port`. Audits check these boundaries and their case evidence.
C source identity is OpenWrt 25.12.5 dnsmasq 2.93-r1 nodhcpv6, recipe
`f0a60eee2fe051741c643ea6118718aae1ef17fb`; the checklist pins source hashes.

## Existing interface and callers

| Boundary | Exact C caller and behavior | Current Rust gap |
| --- | --- | --- |
| Configuration | `option.c:4644-4658,4731-4807` produces server/client ports and ordered relay rules. IPv6 relay is excluded by this image. | Option metadata exists, main rejects the three options; no typed relay config. |
| Startup | `dnsmasq.c:304-327` initializes DHCP socket for ranges OR relay, but leases only for ranges. | `main.rs:537-615` constructs provider/socket only for nonempty ranges and binds port 67. Constructing an empty-range provider would incorrectly create/open lease storage. |
| Poll | `dnsmasq.c:1146-1152,1316-1323` schedules the same DHCP descriptor for local server and relay. | Existing `SocketListener::process_once_local` is already nonblocking but parses through a BOOTREQUEST-only local packet view. |
| Receive | `dhcp.c:174-177,246-264,305-316` receives a raw packet of at least 236 bytes, normalizes all-ones giaddr and checks relay replies before request admission. | `service::receive_once` rejects BOOTREPLY or malformed local DHCP before relay could consume it; 16,384-byte buffer is below C legal UDP datagram capacity. |
| Request admission | `dhcp.c:318-366` obtains primary/selected secondary address, applies DHCP/interface exclusions, enumerates context and return-ifindex state, then forwards. | Reuse `interface_admission::InterfacePolicy` but do not force lease/context allocation. Relay requires an admitted interface/address snapshot even with zero ranges. |
| Forward upstream | `rfc2131.c:3060-3227` mutates an opaque packet per rule, selects source and upstream port, then restores it for local DHCP. | New small relay module; existing `DatagramSocket::send` supplies explicit IPv4 source without forced interface but needs a one-attempt variant for owner policy. |
| Forward reply | `rfc2131.c:3229-3264`, then `dhcp.c:305-316,417-469`, selects learned downstream interface and existing ciaddr/broadcast/yiaddr+ARP branch. | Need raw BOOTREPLY destination selection without calling local lease allocator. Reuse ARP and send primitives, with configured client port and correct C ciaddr route semantics. |
| Network changes | `network.c:1778-1796` clears ordinary relay return-ifindex cache. | Main network-change handler must invalidate relay cache before processing subsequent replies. |

State is one small record per configured rule: local/server/uplink IPv4,
optional interface pattern, upstream port, split flag, cached downstream
interface and duplicate-address warning state. C has no request-XID table,
expiry timer, retry queue or socket per upstream. Do not add them.

## File ownership and integration handoff

The family branch is `m5/relay`, worktree
`private/dnsmasq-rewrite/worktrees/m5-relay`. No product changes have been made.

1. Family owner adds `config/dhcp_relay.rs` for parsing and a small
   `dhcp/relay.rs` for opaque-byte request/reply selection. Keep wire mutation
   safe, explicit and bounded, with C offsets named once.
2. Family owner changes the listener/service and destination helpers only
   after root confirms file ownership. Existing local-only APIs remain
   wrappers where that keeps callers clear. The listener receives once,
   handles a relay reply first, then applies request admission and forwards
   upstream, finally allowing the restored packet into the local server if
   one exists.
3. Root owns `main.rs`, `config/dhcp.rs`, `dhcp/daemon.rs`,
   `dns/daemon.rs` and module registration. Handoff typed fields
   `relay rules` and `DHCP server/client ports`; create a listener for
   ranges OR relay, and make the provider optional for relay-only service.
   Root plugs fresh interface snapshots and address-change invalidation into
   the existing single owner. Ordinary DHCP/leasequery destinations consume
   the configured ports too.
4. Family owner adds one `tools/dnsmasq/m5_relay.py` family harness.
   Build a candidate after root integration, run exact-image C paired
   evidence, then mark individual checklist entries. Only after all required
   boundaries pass (or an explicit recorded reference-defect disposition)
   does root merge the family, record ELF SHA/size/delta, and close options.
   The batch-wide regression is separate and must not delay that closure.

No thread, sleep, polling loop inside a callback, unbounded received-packet
queue or per-XID tracking is required. Each owner step receives at most one
packet; each configured rule performs at most one send attempt. A UDP-sized
fixed receive/scratch buffer makes the maximum allocation explicit. The
split relay append bound still follows C's 548-byte struct boundary, not the
larger receive capacity.

## One image-C harness

Run under `run_isolated.sh` with a family-specific Oracle job directory.
Create a relay namespace with downstream `client0` at 10.77.0.1/24 and
upstream `server0` at 10.78.0.1/24, a client namespace at 10.77.0.2, and an
upstream namespace at 10.78.0.2. Add a second downstream/interface only for
selector cases. Namespaces are private to this family, so other families can
run in parallel without sharing ports, routes or device names.

Use the same topology and interface indices while running C and Rust
sequentially for a given configuration. This keeps the split remote-id bytes
directly comparable without masking a routing error. Start the exact image
C using the pinned rootfs/musl loader already used by `m5_leasequery.py`;
validate `STOCK_SHA256`. Capture upstream and downstream with deterministic
scripted UDP peers (and packet capture/neighbor queries for broadcast and
ARP cases); the reference daemon is the relay, not a Python relay emulator.
Run representative normal DHCP-server cases with the candidate to cover the
alternate-port integration.

For every checklist case, save input config, both `--test` exit/output,
startup outcome, request/upstream/downstream packet bytes and endpoints,
daemon stderr, PID/thread/FD observations, neighbor state when needed,
exit status and cleanup. Use exact byte comparison for forwarding; mask no
DHCP field. Compare sets only where the socket receive ordering is genuinely
unobservable, retaining the original sequence in raw evidence. A no-packet
result is valid only when the daemon is alive, its DNS heartbeat works, and
an adjacent positive control proves the path is connected.

The harness manifest lists every checklist ID and expected concrete cases;
the summary fails for missing cases, skipped cases, tool errors or mismatched
stock identity. Negative controls corrupt recorded hops, giaddr, ports,
option82, or packet presence/destination to prove the comparison fails.
Deterministic seeded malformed packets supplement the listed boundary
cases; they do not replace them.

Evidence paths: `evidence/M5/relay/<run>/manifest.json`,
`cases/<id>/c.json`, `cases/<id>/rust.json`, `result.json` and raw logs.
Record candidate SHA256, build input identity, ELF byte count, preceding
family ELF byte count, and exact delta. Keep raw artifacts ignored.

## C edges to reproduce before choosing compatibility behavior

- C's numeric parser accepts some empty numeric fields; relay `#bad`
  silently falls back to 67, whereas alternate-port bad values fail.
  Pin these with parser and startup evidence instead of designing a new grammar.
- Ordinary relay intentionally forwards opaque packets that a local DHCP
  parser would reject, including hlen outside local-client limits. This is
  distinct from permitting unsafe memory access.
- Two split rules share an `endopt` pointer. C restores `sz=orig_sz` on
  every rule but computes the appended size only on the first. Later rules
  may emit truncated option82. Preserve an exact minimal reproduction and
  record the actual image behavior; do not silently normalize it away.
- C strips split option82 before checking whether its remote-id/interface
  yields an accepted return route, which can affect later relay rules.
  Capture the ordered-rule case explicitly.
- `dhcp-relay=<local>,0.0.0.0` has no guaranteed interface for C's
  broadcast ioctl, and zero/empty split uplink values need image evidence.
  If C exhibits an unsafe defect, keep a minimal reproduction and separate
  it from the implementation's explicit disposition.

The family is not implemented or tested yet. All 43 checklist entries are
pending; no option count is reduced by this planning commit.
