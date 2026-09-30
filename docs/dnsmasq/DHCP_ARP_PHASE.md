# DHCPv4 Linux ARP and unicast-send boundary

This phase implements the local unconfigured-client send dependency. It does
not establish complete DHCP service equivalence or production acceptance.
All network mutations were confined to build-host network namespaces.

| Exact C reference | Rust boundary | Evidence |
|---|---|---|
| `network.c:21-35`; `dhcp.c:244-267` | Capture the original ingress name through `SIOCGIFNAME` on the existing DHCP descriptor before provider/state work; retain it across bridge/context work and ICMP delay | Snapshot-before-provider regression and actual interface rename during the snapshot/send gap |
| `dhcp.c:446-466` | `ArpEntry`: IPv4 sockaddr including client port/address; hardware family and bounded bytes; `ATF_COM` without `ATF_PERM`; original device name | Extracted C field assignments, Linux header size/offset/constant assertions and 1,027 field cases |
| `dhcp.c:464-466,520-528` | Try `SIOCSARP` once; retain an error event and still send with the original receiving interface; no broadcast fallback or lease rollback | Runtime event ordering and real `CAP_NET_ADMIN` removal followed by client receipt |
| `util.c:718-749` | One send retry loop: EAGAIN sleeps 10 microseconds and allows at most 1,001 attempts; EINTR resets the EAGAIN count; terminal errors stop | 18 exact-C retry schedules, including the retry limit and EINTR reset, with ARP success/failure |

`DatagramSender::interface_name` captures the name before `OutcomeProvider`
runs. An absent interface stops before lease pruning or commit, matching C's
admission order. `ArpRequest` carries the name snapshot. After reply build,
`prepare_destination` attempts the ioctl; the report contains `ArpInjected`
or `ArpInjectionFailed { kind, raw_os_error }` before the send result. The
caller must log the latter even when sending succeeds. Send failure retains
the committed outcome and the earlier ARP warning. Fake senders may supply
their own name/preparation boundary without opening sockets.

`net::ArpEntry` owns an initialized, four-byte-aligned 68-byte Linux request.
The unsafe boundary is limited to byte views of initialized fixed storage,
`SIOCGIFNAME`'s bounded 40-byte ifreq and the synchronous `SIOCSARP` call.
The kernel receives no borrowed pointers after ioctl returns. Resolving the
name reuses the listener descriptor, as C does; it does not open a temporary
libc control socket. `send_on_interface_once` exposes EINTR/EAGAIN to the DHCP
runtime. Other protocols retain their previous interrupted-send behavior.

C leaves unused arpreq storage uninitialized. The comparator preserves all
defined protocol/hardware/flag/device fields while excluding the hardware
tail beyond `hlen` and the unused netmask field. Rust zero-initializes them.
This is **not** a claim that an anomalously short hardware address produces
the same complete kernel MAC as C's indeterminate stack bytes: the live
Ethernet cases use the correct six-byte hardware length. The raw constructor
rejects zero hardware type, lengths outside 1..14, empty/oversized device
names and embedded NUL; normal DHCP dispatch already broadcasts invalid
hardware forms rather than entering this path.

`tools/dnsmasq/dhcp_arp_diff.py` pins `dhcp.c`, `network.c` and `util.c`,
extracts the C assignments/`indextoname`/`safe_strncpy`/`retry_send`, compiles
with ASan/UBSan, and compares C with the Rust adapter. Its final run passed
**1,045/1,045**, including missing/extra-output counter calibration. The C
header assertions cover arpreq size/alignment, all relevant offsets,
`SIOCSARP`, `SIOCGIFNAME`, `ATF_COM`, IFNAMSIZ and ifreq layout.

`tools/dnsmasq/dhcp_arp_linux.py` creates a private veth pair and a separate
client namespace, which permits actual UDP delivery checks beyond a dummy
interface's neighbour-table check. The final run passed **88/88** checks:
eight repeated injections per implementation, matching kernel neighbour
states and MACs, receipt at the client, ioctl permission failure with continued
delivery, interface rename after name capture, removed-interface errors,
stable per-probe descriptors and exit reclamation. Dynamic neighbour entries
survive socket close in both implementations and remain kernel-managed;
they are not permanent entries and are not deleted during daemon shutdown.
Both probe processes held three descriptors after each command; the observed
kernel neighbour state was `DELAY` for both C and Rust. Rename produced
`ENODEV` from ARP injection while the subsequent UDP send and receipt succeeded.

All generated C, inputs, outputs, binaries and source/artifact SHA256 values
are under ignored `private/dnsmasq-rewrite/dhcp-arp-20261001/`:
`diff-02/`, `live-02/` and `source-identity.json` are the final evidence;
`diff-01/` and `live-01/` are retained earlier runs. The affected host DHCP
regression passed **89/89**, and aarch64-musl library clippy passed. Full DHCP ACK/lease/DNS/script
integration, alternate-port wiring, relay/PXE, package privilege policy and
physical-device validation remain separate gates. No performance improvement
is claimed from these correctness/resource observations.
