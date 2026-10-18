# odhcpd-rs

Scoped replacement for the OpenWrt 25.12.5 `odhcpd-ipv6only` daemon, referenced
against C commit `5d7be43f8b9dec0eb47e245cfab81108bb131273`. The final Fable fix
SDK ELF passed all 129 packet checks and a new guarded device trial with 123.739
seconds of continuous client health. The guard restored C; the router still
runs v0.2.3. That v0.2.4 candidate image and its qualification retain their
original identities; see the [Fable result](../../docs/reviews/ODHCPD_FABLE_RESULT_20261018.md).
The next release is v0.3.0 (`0.3.0-r1`) because it adds this new component.
The single device A/B batch failed the performance gate: all four idle CPU pairs
regressed, and one Renew pair exceeded calibrated noise. The decision is
`stop_and_report`; work is stopped for the user's decision, with no optimization
or repeat batch. The v0.3.0 image build, merge, flash and publication remain on
hold, and PR #1 remains draft. Production v0.2.3 and C odhcpd are unchanged;
see the [A/B result](../../docs/reviews/ODHCPD_DEVICE_AB_RESULT_20261018.md).

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
