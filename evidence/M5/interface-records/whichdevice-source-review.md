# Exact DHCP device gate

Reference: matching dnsmasq 2.93 `dhcp-common.c:558-641`, `network.c:113-149,243-274,491-585`, `option.c:2894-2921`, `dnsmasq.c:380-397,1027-1028,1134-1145`.

`whichdevice()` requires a nonempty `if_names` list. Every non-NULL declared name must already have INAME_USED and contain no `*`. NULL declaration names do not veto. It scans selected `irec` rows where **dhcp4_ok OR dhcp6_ok** and returns a copy only if all those rows have one byte-identical actual `irec.name`. Multiple address/alias rows for the same actual link remain one device.

The OR is not conditional on HAVE_DHCP6. The exact no-DHCPv6 image still stores `dhcp6_ok`; no-dhcpv4-interface therefore does not necessarily remove a row from this gate. `no-dhcp-interface` clears both flags; no-dhcpv4 clears only 4 (`option.c:2918-2920`). Root can derive the two exclusion sets from the existing `no_dhcp_interfaces` and all-family `no_tftp_interfaces`, until explicit per-family configuration is warranted.

Selection inputs must follow the existing enumeration, rather than packet-only admission:

- `iface_check()` marks **all address-label** name matches USED before considering except-interface. Explicit listen-address matches bypass except-interface.
- `network.c:502-520` auto-adds actual loopback names as USED when an interface list exists. Loopback's DHCP4 and DHCP6 flags are both zero (`264`), so it contributes no candidate.
- Alias labels can mark an explicit alias declaration USED. The stored `irec.name` and resulting SO_BINDTODEVICE value are the real link name from SIOCGIFNAME, never the alias label.
- DNS-unselected addresses never become `irec` candidates. The gate considers IPv6 `irec` rows too; both flags start at 1 for non-loopback rows independently of address family.
- There is no extra IFF_UP exclusion in this selection. Do not replace the C snapshot with the DHCP packet IPv4-up-only snapshot.

The added small pure API is `config::dhcp_device::which_device(&[DeclaredInterface], &[DeviceInterface]) -> Option<&[u8]>`. The owner supplies USED flags and selected rows with both DHCP-family flags. It performs no I/O and adds no socket abstraction. Two targeted tests cover absent/NULL/unused/wildcard declarations, alias collapse, loopback exclusion and retained DHCP6 candidacy after a DHCP4 veto.

Caller/failure boundaries remain Root-owned:

- The startup selection and SO_BINDTODEVICE attempt run only under NOWILD or CLEVERBIND (`dnsmasq.c:380-397`). An ordinary wildcard listener does not attempt this bind.
- `bindtodevice()` passes `min(strlen(name)+1, IFNAMSIZ)` bytes. Success and EPERM each return bit 1; another error returns bit 2. Startup bit 2 is EC_BADNET; bit 1 produces the exclusive-interface notice at `1027`.
- DHCP4's port-67 socket is skipped when relay4 exists. Enabled PXE port 4011 still gets the bind. No active DHCP/PXE socket means return 0 and no notice.
- The startup `bound_device` string is retained. The later loop retries that same value at `1136`; it does not call whichdevice again. A initially missing interface under bind-dynamic therefore stays without a selected bound_device even after it appears. A later bind failure is logged once and retry continues.

These are source-reviewed contracts. The pure tests do not qualify kernel SO_BINDTODEVICE behavior; Root's actual socket C/R gates must establish it.
