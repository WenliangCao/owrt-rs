# odhcpd-rs

Scoped replacement for the OpenWrt 25.12.5 `odhcpd-ipv6only` daemon, referenced
against C commit `5d7be43f8b9dec0eb47e245cfab81108bb131273`. The historical Fable fix
SDK ELF passed all 129 packet checks and a new guarded device trial with 123.739
seconds of continuous client health. The guard restored C; the router still
runs v0.2.3. That v0.2.4 candidate image and its qualification retain their
original identities; see the [Fable result](../../docs/reviews/ODHCPD_FABLE_RESULT_20261018.md).
The next release is v0.3.0 (`0.3.0-r1`) because it adds this new component.
The user-authorized single idle/Renew fix and limited device comparison passed.
The current recipe pins SDK ELF
`589226a178668c0e53fa8db5ff726e2b4e69464f9521355fad229b1862c3043e`
from source `162d9ba8` and SDK CI `39122603394` (802936 bytes, static). Idle CPU
medians were C 18.858681 µs/s and Rust 0 measured increment; Renew medians were
544.46225/288.5715 µs, with all four pairs improved. The idle result covers seven
three-second Rust windows; it is not a zero-cost claim for all workloads.
The latest shipping gate requires one full device comparison of all metrics on
this final SDK before the authorized v0.3.0 image build, deployment and
publication can continue. That gate is pending; the two-metric PASS above
remains valid. Image CI `39123811190` (source `346470cd`) was cancelled, with no
new physical trial or flash. The SDK and recipe stay fixed without additional
product optimization; see the [full comparison plan](../../docs/reviews/ODHCPD_FINAL_FULL_AB_PLAN_20261018.md).
PR #1 remains draft and production v0.2.3 with C odhcpd is unchanged. See the
[limited comparison](../../docs/reviews/ODHCPD_IDLE_RENEW_RESULT_20261018.md);
the [first batch's failure](../../docs/reviews/ODHCPD_DEVICE_AB_RESULT_20261018.md)
and all historical artifacts retain their original results and identities.

Supported: RA/SLAAC, DHCPv6 IA_NA/IA_PD, lease and hosts exports, `leasetrigger`,
the `dhcp` ubus object, UCI, and netifd/kernel prefix updates. The original init,
`odhcpd-update`, dnsmasq and protocol scripts remain the callers/consumers.

NDP proxy, relay/hybrid and odhcpd DHCPv4 modes fail configuration validation.
Shared `dhcpv4=server` with `maindhcp=0` remains dnsmasq input. Reconfigure is not
advertised or implemented; current observed clients do not request it. Other
unused extensions and the exact compatibility boundary are documented in the
[control](../../docs/contracts/odhcpd-control.md),
[RA](../../docs/contracts/odhcpd-ra.md) and
[DHCPv6](../../docs/contracts/odhcpd-dhcpv6.md) contracts.

The protocol loop owns sockets, kernel snapshots and leases. A bounded ubus
worker reconnects without holding up packet processing. RA history is committed
only after a successful send. PD route ownership is recorded only after a kernel
ACK; failed removals remain pending. Every refreshed kernel snapshot is compared
with its predecessor so concurrent address changes cannot be lost.

Lease files are exports, not a restart database. A restart retains the previous
export until the next relevant state event, matching C. PIO history is restored
from its state file. Intentional C differences include ubus reconnection, removal
of old managed PD routes, rejection of routes larger than their source pool,
and immediate export cleanup when a finite lease expires.

Build and test on Linux (Oracle or CI), never on the development Mac:

```sh
cargo test --locked --manifest-path components/odhcpd/Cargo.toml
cargo clippy --locked --manifest-path components/odhcpd/Cargo.toml --all-targets -- -D warnings
```

The two ignored tests require an explicitly prepared private ubus or network
namespace. `tools/odhcpd_baseline.py` drives real packets against the exact image
and a candidate ELF in private namespaces; raw results stay outside Git.
`OWRT_CORE_INCLUDE_ODHCPD=1` enables the SDK candidate in `ci_build_core.sh`.
The v0.3.0 recipe pins the functionally qualified odhcpd ELF and retains the other
ten v0.2.3 ELFs. Existing v0.2.4 images and measurements are historical artifacts,
not v0.3.0 build or performance acceptance.

Acceptance and outstanding work are tracked in
[the prototype report](../../docs/reviews/ODHCPD_PROTOTYPE_20261018.md).
