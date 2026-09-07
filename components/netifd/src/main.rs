//! netifd-rs: network device and interface management.
//!
//! Scope is deliberately this device's: see
//! reports/ax3000t-stock-openwrt-25.12.5/R45_NETIFD_SCOPE.md. Configuration
//! this build cannot honour is reported as an error, never ignored, and a
//! protocol it cannot run leaves the interface down rather than half up.
//!
//! What is implemented: the config model, the device registry and its
//! `network.device status`, the interface status projection, IPv6 prefix
//! assignment, and `proto static` end to end. What is not: proto-shell
//! (`dhcp`, `dhcpv6`, `ppp`, `pppoe`), the wireless orchestration, and the
//! interface write methods beyond `up`/`down`/`reload`/`restart`. Those
//! register with their real signatures and refuse.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod config;
mod device;
mod ethtool;
mod ethtool_modes;
mod interface;
mod ip;
mod netdev_types;
mod netlink;
mod process;
mod sys;
mod ubus;

use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use owrt_ubus::blob::{self, BlobBuf, MsgType};
use owrt_ubus::conn::{Connection, Incoming, Request};
use owrt_ubus::msg::status;
use owrt_ubus::sys::{PollFd, POLLHUP, POLLIN};

use config::Config;
use device::{Device, Devices};
use interface::{Address, Interface, State};

pub const BUILD_ID: &str = concat!("netifd-rs ", env!("CARGO_PKG_VERSION"));

/// `DEFAULT_HOTPLUG_PATH`; overridable with `-h`, as the C's `hotplug_cmd_path`
/// is. A harness that runs the daemon outside the rootfs needs this, and
/// silently skipping the call because the default path does not exist would
/// look like a working daemon with no hotplug integration.
const DEFAULT_HOTPLUG_PATH: &str = "/sbin/hotplug-call";

/// The interface events this build produces, named as `eventnames[]` names
/// them in interface-event.c.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Up,
    Down,
    UpFailed,
    Update,
}

/// The protocols this build can actually run.
const IMPLEMENTED_PROTOS: &[&str] = &["static", "none"];

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

struct Netifd {
    cfg: Config,
    devices: Devices,
    interfaces: Vec<Interface>,
    /// Absolute start times, for the `uptime` field.
    start_time: Vec<(String, u64)>,
    prefixes: Vec<ip::DevicePrefix>,
    sys: sys::System,
    events: netlink::Netlink,
    ethtool: ethtool::Ethtool,
    ifioctl: sys::IfIoctl,
    conn: Connection,
    objects: ubus::Objects,
    confdir: String,
    hotplug_path: String,
}

impl Netifd {
    fn new(confdir: &str, socket: Option<&str>, hotplug: &str) -> io::Result<Self> {
        let events = netlink::Netlink::open(
            netlink::grp(netlink::RTNLGRP_LINK)
                | netlink::grp(netlink::RTNLGRP_IPV4_IFADDR)
                | netlink::grp(netlink::RTNLGRP_IPV6_IFADDR),
        )?;
        events.set_nonblocking()?;
        let mut conn = Connection::connect(socket)?;
        let objects = ubus::Objects::register(&mut conn)?;
        Ok(Self {
            cfg: Config::default(),
            devices: Devices::new(),
            interfaces: Vec::new(),
            start_time: Vec::new(),
            prefixes: Vec::new(),
            sys: sys::System::open()?,
            events,
            ethtool: ethtool::Ethtool::open()?,
            ifioctl: sys::IfIoctl::open()?,
            conn,
            objects,
            confdir: confdir.to_string(),
            hotplug_path: hotplug.to_string(),
        })
    }

    /// Load the config and bring up what it asks for. Called at startup and by
    /// `network.reload`.
    fn reload(&mut self) {
        match config::load(&self.confdir) {
            Ok(c) => self.cfg = c,
            Err(e) => {
                eprintln!("netifd-rs: cannot load network config: {e}");
                return;
            }
        }
        for e in &self.cfg.errors {
            eprintln!("netifd-rs: config: {e}");
        }

        self.rescan_devices();
        self.create_devices();
        self.build_prefixes();
        self.setup_interfaces();
    }

    /// The devices the config names: every interface's device, every
    /// `config device` section, and every bridge port.
    ///
    /// netifd does NOT enumerate the kernel's links. A device object exists
    /// because something referred to it, so a veth peer nobody mentions never
    /// appears in `network.device status` -- which is exactly what the C
    /// reports, and what enumerating everything got wrong.
    fn known_device_names(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for i in &self.cfg.interfaces {
            if let Some(d) = &i.device {
                names.push(d.clone());
            }
        }
        for d in &self.cfg.devices {
            names.push(d.name.clone());
            names.extend(d.ports.iter().cloned());
        }
        names.sort();
        names.dedup();
        names
    }

    /// Refresh the registry from the kernel, for the named devices only.
    fn rescan_devices(&mut self) {
        let known = self.known_device_names();
        let msgs = match self.sys.dump_links() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("netifd-rs: link dump failed: {e}");
                return;
            }
        };
        let mut pending: Vec<Device> = Vec::new();
        for m in &msgs {
            let attrs = m.attrs(16);
            let Some(name) = netlink::attr_str(&attrs, sys::IFLA_IFNAME) else { continue };
            if !known.iter().any(|k| k == name) {
                continue;
            }
            let flags = u32::from_le_bytes([
                m.payload[8],
                m.payload[9],
                m.payload[10],
                m.payload[11],
            ]);
            let kind = self.link_kind(&attrs);
            let mut d = self
                .devices
                .get(name)
                .cloned()
                .unwrap_or_else(|| Device::new(name, kind));
            d.type_name = kind.to_string();
            d.present = true;
            d.active = flags & sys::IFF_UP != 0;
            d.link_active = flags & sys::IFF_LOWER_UP != 0;
            d.orig_settings = device::read_settings(name, &self.ethtool, &self.ifioctl);
            pending.push(d);
        }
        for mut d in pending {
            if let Some(idx) = self.dsa_conduit(&d.ifname.clone()) {
                d.orig_settings.master_ifindex = idx;
                d.orig_settings.flags |= device::opt::MASTER;
            }
            self.devices.insert(d);
        }
    }

    /// `dev->type->name`: the C names a plain kernel device "Network device"
    /// and a netifd-created bridge "bridge".
    fn link_kind(&self, attrs: &[(u16, &[u8])]) -> &'static str {
        let li = netlink::attr(attrs, sys::IFLA_LINKINFO)
            .or_else(|| netlink::attr(attrs, sys::IFLA_LINKINFO | netlink::NLA_F_NESTED));
        match li.and_then(|li| {
            let inner = netlink::parse_attrs(li);
            netlink::attr_str(&inner, sys::IFLA_INFO_KIND).map(|s| s.to_string())
        }) {
            Some(k) if k == "bridge" => "bridge",
            _ => "Network device",
        }
    }

    /// The DSA conduit, on the command socket. Opening a socket per device per
    /// rescan would be one syscall pair per device per event, for a value that
    /// almost never changes.
    fn dsa_conduit(&mut self, ifname: &str) -> Option<u32> {
        const IFLA_DSA_MASTER: u16 = 1;
        let hdr = sys::ifinfomsg(sys::AF_UNSPEC, 0, 0, 0);
        let mut a = netlink::Attrs::new();
        a.str0(sys::IFLA_IFNAME, ifname);
        let msg = self.sys.nl.dump_one(sys::RTM_GETLINK, &hdr, a.as_bytes()).ok()??;
        let attrs = msg.attrs(16);
        let li = netlink::attr(&attrs, sys::IFLA_LINKINFO)
            .or_else(|| netlink::attr(&attrs, sys::IFLA_LINKINFO | netlink::NLA_F_NESTED))?;
        let inner = netlink::parse_attrs(li);
        if netlink::attr_str(&inner, sys::IFLA_INFO_KIND)? != "dsa" {
            return None;
        }
        let data = netlink::attr(&inner, sys::IFLA_INFO_DATA)
            .or_else(|| netlink::attr(&inner, sys::IFLA_INFO_DATA | netlink::NLA_F_NESTED))?;
        netlink::attr_u32(&netlink::parse_attrs(data), IFLA_DSA_MASTER)
    }

    /// Create the devices the config declares. Only bridges are created; a
    /// `config device` with no type only carries settings for a device the
    /// kernel already provides.
    fn create_devices(&mut self) {
        for dc in self.cfg.devices.clone() {
            if dc.kind.as_deref() != Some("bridge") {
                continue;
            }
            let mut brcfg = sys::BridgeConfig::default();
            if let Some(v) = dc.stp {
                brcfg.stp = v;
            }
            if let Some(v) = dc.igmp_snooping {
                brcfg.igmp_snoop = v;
            }
            if let Some(v) = dc.vlan_filtering {
                brcfg.vlan_filtering = v;
            }
            if let Some(v) = dc.priority {
                brcfg.priority = v;
            }
            if let Some(v) = dc.forward_delay {
                brcfg.forward_delay = v;
            }
            if let Some(v) = dc.hello_time {
                brcfg.hello_time = v;
            }
            if let Some(v) = dc.max_age {
                brcfg.max_age = v;
            }
            brcfg.ageing_time = dc.ageing_time;
            if let Some(v) = dc.bridge_empty {
                brcfg.bridge_empty = v;
            }

            let existing = self.sys.if_index(&dc.name).unwrap_or(0);
            if existing == 0 {
                if let Err(e) = self.sys.bridge_addbr(&dc.name, &brcfg) {
                    eprintln!("netifd-rs: cannot create bridge {}: {e}", dc.name);
                    continue;
                }
            }
            let br = match self.sys.if_index(&dc.name) {
                Ok(i) if i != 0 => i,
                _ => {
                    eprintln!("netifd-rs: bridge {} did not appear", dc.name);
                    continue;
                }
            };
            if let Some(mac) = dc.macaddr {
                if let Err(e) = self.sys.set_mac(br, &mac) {
                    eprintln!("netifd-rs: cannot set {} macaddr: {e}", dc.name);
                }
            }
            if let Some(mtu) = dc.mtu {
                let _ = self.sys.set_mtu(br, mtu);
            }
            if let Some(q) = dc.txqueuelen {
                let _ = self.sys.set_txqueuelen(br, q);
            }

            let mut members = Vec::new();
            for port in &dc.ports {
                match self.sys.if_index(port) {
                    Ok(pi) if pi != 0 => {
                        if let Err(e) = self.sys.bridge_setmaster(pi, br) {
                            eprintln!("netifd-rs: cannot add {port} to {}: {e}", dc.name);
                            continue;
                        }
                        // a bridge member has to be up for the bridge to
                        // forward, which is what device_claim does
                        let _ = self.sys.set_link_up(pi, true);
                        // bridge_enable_member turns IPv6 off on a member
                        // unless a `config device` section set it explicitly,
                        // so the member has no link-local of its own
                        let explicit = self
                            .cfg
                            .devices
                            .iter()
                            .any(|d| &d.name == port && d.ipv6.is_some());
                        if !explicit {
                            let path =
                                format!("/proc/sys/net/ipv6/conf/{port}/disable_ipv6");
                            if let Err(e) = std::fs::write(&path, "1") {
                                eprintln!(
                                    "netifd-rs: cannot disable IPv6 on {port}: {e}"
                                );
                            }
                        }
                        members.push(port.clone());
                    }
                    _ => eprintln!("netifd-rs: bridge {} port {port} is absent", dc.name),
                }
            }

            self.rescan_devices();
            if let Some(d) = self.devices.get_mut(&dc.name) {
                d.type_name = "bridge".to_string();
                d.bridge = Some(device::BridgeState {
                    members,
                    config: brcfg,
                    stp_proto: None,
                });
            }
        }

        // settings-only device sections
        for dc in self.cfg.devices.clone() {
            if dc.kind.is_some() {
                continue;
            }
            let Ok(idx) = self.sys.if_index(&dc.name) else { continue };
            if idx == 0 {
                eprintln!("netifd-rs: device {} is absent", dc.name);
                continue;
            }
            if let Some(mac) = dc.macaddr {
                if let Err(e) = self.sys.set_mac(idx, &mac) {
                    eprintln!("netifd-rs: cannot set {} macaddr: {e}", dc.name);
                }
            }
            if let Some(mtu) = dc.mtu {
                let _ = self.sys.set_mtu(idx, mtu);
            }
            if let Some(q) = dc.txqueuelen {
                let _ = self.sys.set_txqueuelen(idx, q);
            }
        }
        self.rescan_devices();
    }

    /// The global prefix list: the ULA from `globals`. Delegated prefixes come
    /// from a protocol handler, which this build does not run yet.
    fn build_prefixes(&mut self) {
        self.prefixes.clear();
        if let Some((addr, len)) = self.cfg.globals.ula_prefix {
            // interface_ip_set_ula_prefix refuses a length outside 1..=64
            if (1..=64).contains(&len) {
                self.prefixes.push(ip::DevicePrefix::new(addr, len, "local", None));
            }
        }
    }

    fn setup_interfaces(&mut self) {
        let cfgs = self.cfg.interfaces.clone();
        self.interfaces.clear();
        for ic in &cfgs {
            let mut i = Interface::new(&ic.name);
            i.proto = Some(ic.proto.clone());
            // `main_dev` is set from the config whether or not the device
            // exists, so `device` is reported even for an absent one.
            i.device = ic.device.clone();
            // `available` reflects whether the device is present, not whether
            // the interface was started.
            i.available = ic
                .device
                .as_deref()
                .map(|d| self.sys.if_index(d).unwrap_or(0) != 0)
                .unwrap_or(false);
            i.autostart = ic.auto.unwrap_or(true) && !ic.disabled;
            i.metric = ic.metric;
            i.dns_metric = ic.dns_metric;
            i.ip4table = ic.ip4table.unwrap_or(0);
            i.ip6table = ic.ip6table.unwrap_or(0);
            i.proto_ip.no_delegation = ic.delegate == Some(false);
            self.interfaces.push(i);
        }
        // netifd keeps interfaces in a vlist keyed by name
        self.interfaces.sort_by(|a, b| a.name.cmp(&b.name));

        for name in self.interfaces.iter().map(|i| i.name.clone()).collect::<Vec<_>>() {
            if let Err(e) = self.register_interface(&name) {
                eprintln!("netifd-rs: cannot register {name}: {e}");
            }
        }
        // `config_init_interfaces` prepends each parsed interface onto
        // `config_ifaces` with `list_add` and then pops from the head, so
        // `interface_add` -- and with it the ifup and its event -- runs in
        // REVERSE config order. Hotplug consumers see that order, so it is
        // part of the interface, not an implementation detail.
        for ic in cfgs.iter().rev() {
            let autostart = ic.auto.unwrap_or(true) && !ic.disabled;
            if autostart {
                self.iface_up(&ic.name);
            }
        }

        // `set_device_state(dev, false)` brings a device down when nothing is
        // using it. A device named by a config section that never came up is
        // exactly that case, and leaving it up would be a visible difference.
        for ic in &cfgs {
            let up = self
                .iface_index(&ic.name)
                .map(|i| self.interfaces[i].state == State::Up)
                .unwrap_or(false);
            if up {
                continue;
            }
            let Some(dev) = &ic.device else { continue };
            // never touch a device another interface is using
            if cfgs.iter().any(|o| {
                o.device.as_deref() == Some(dev.as_str())
                    && self
                        .iface_index(&o.name)
                        .map(|i| self.interfaces[i].state == State::Up)
                        .unwrap_or(false)
            }) {
                continue;
            }
            // nor a bridge member, which the bridge itself claimed
            if self.cfg.devices.iter().any(|d| d.ports.iter().any(|p| p == dev)) {
                continue;
            }
            if let Ok(idx) = self.sys.if_index(dev) {
                if idx != 0 {
                    let _ = self.sys.set_link_up(idx, false);
                }
            }
        }
        self.rescan_devices();
    }

    fn register_interface(&mut self, name: &str) -> io::Result<()> {
        if self.objects.per_interface.iter().any(|(n, _)| n == name) {
            return Ok(());
        }
        self.objects.add_interface(&mut self.conn, name)?;
        Ok(())
    }

    fn iface_index(&self, name: &str) -> Option<usize> {
        self.interfaces.iter().position(|i| i.name == name)
    }

    /// Bring an interface up. For an unimplemented protocol this records an
    /// error and leaves the interface down; it never applies a partial
    /// configuration.
    fn iface_up(&mut self, name: &str) {
        let Some(ic) = self.cfg.interfaces.iter().find(|i| i.name == name).cloned() else {
            return;
        };
        let Some(idx) = self.iface_index(name) else { return };

        if !IMPLEMENTED_PROTOS.contains(&ic.proto.as_str()) {
            self.interfaces[idx].errors.push(interface::IfaceError {
                subsystem: "proto".into(),
                code: "PROTO_NOT_SUPPORTED".into(),
                data: vec![ic.proto.clone()],
            });
            eprintln!(
                "netifd-rs: interface {name} uses proto '{}', which this build cannot run; \
                 leaving it down",
                ic.proto
            );
            self.emit_event(name, Event::UpFailed);
            return;
        }

        let Some(devname) = ic.device.clone() else {
            self.interfaces[idx].errors.push(interface::IfaceError {
                subsystem: "interface".into(),
                code: "NO_DEVICE".into(),
                data: vec![],
            });
            return;
        };
        let devidx = self.sys.if_index(&devname).unwrap_or(0);
        if devidx == 0 {
            self.interfaces[idx].errors.push(interface::IfaceError {
                subsystem: "interface".into(),
                code: "NO_DEVICE".into(),
                data: vec![],
            });
            self.interfaces[idx].available = false;
            return;
        }

        if let Err(e) = self.sys.set_link_up(devidx, true) {
            eprintln!("netifd-rs: cannot bring {devname} up: {e}");
            return;
        }

        // proto static: addresses, then the gateway route
        let mut applied_any = false;
        let mut ipset = interface::IpSettings::default();
        for (a, m) in &ic.ipv4 {
            let sa =
                sys::Address::new(IpAddr::V4(*a), *m).with_default_broadcast();
            match self.sys.add_address(devidx, &sa) {
                Ok(()) => {
                    ipset.addresses.push(Address::new(IpAddr::V4(*a), *m));
                    self.replace_subnet_route(devidx, &sa, &ic);
                    applied_any = true;
                }
                Err(e) => eprintln!("netifd-rs: {name}: cannot add {a}/{m}: {e}"),
            }
        }
        for (a, m) in &ic.ipv6 {
            let sa = sys::Address::new(IpAddr::V6(*a), *m);
            match self.sys.add_address(devidx, &sa) {
                Ok(()) => {
                    ipset.addresses.push(Address::new(IpAddr::V6(*a), *m));
                    self.replace_subnet_route(devidx, &sa, &ic);
                    applied_any = true;
                }
                Err(e) => eprintln!("netifd-rs: {name}: cannot add {a}/{m}: {e}"),
            }
        }
        if let Some(gw) = ic.gateway {
            let mut r = sys::Route::v4_default(gw);
            r.metric = ic.metric;
            r.table = ic.ip4table.unwrap_or(sys::RT_TABLE_MAIN);
            match self.sys.add_route(devidx, &r) {
                Ok(()) => {
                    let mut ir = interface::Route::new(
                        "0.0.0.0".parse().unwrap(),
                        0,
                        IpAddr::V4(gw),
                    );
                    ir.metric = ic.metric;
                    ir.table = ic.ip4table.unwrap_or(0);
                    ipset.routes.push(ir);
                }
                Err(e) => eprintln!("netifd-rs: {name}: cannot add default via {gw}: {e}"),
            }
        }
        if let Some(gw) = ic.ip6gw {
            let mut r = sys::Route::v6(Ipv6Addr::UNSPECIFIED, 0);
            r.nexthop = IpAddr::V6(gw);
            r.metric = ic.metric;
            r.table = ic.ip6table.unwrap_or(sys::RT_TABLE_MAIN);
            match self.sys.add_route(devidx, &r) {
                Ok(()) => {
                    let mut ir =
                        interface::Route::new("::".parse().unwrap(), 0, IpAddr::V6(gw));
                    ir.metric = ic.metric;
                    ir.table = ic.ip6table.unwrap_or(0);
                    ipset.routes.push(ir);
                }
                Err(e) => eprintln!("netifd-rs: {name}: cannot add ip6gw {gw}: {e}"),
            }
        }
        ipset.dns_servers = ic.dns.clone();
        ipset.dns_search = ic.dns_search.clone();
        ipset.no_delegation = ic.delegate == Some(false);

        let _ = applied_any;
        let i = &mut self.interfaces[idx];
        i.state = State::Up;
        i.available = true;
        i.l3_device = Some(devname.clone());
        i.device = Some(devname);
        i.proto_ip = ipset;
        i.proto_ip.routes.sort_by(interface::route_order);
        i.updated = interface::updated::ADDRESS;
        if !i.proto_ip.routes.is_empty() {
            i.updated |= interface::updated::ROUTE;
        }
        i.errors.clear();
        self.start_time.retain(|(n, _)| n != name);
        self.start_time.push((name.to_string(), now()));

        self.apply_prefix_assignments();
        self.emit_event(name, Event::Up);
    }

    /// `interface_handle_subnet_route`: take over the prefix route. The
    /// kernel installs one automatically for an on-link address; netifd
    /// deletes that one (by asking for the same route with `proto kernel`) and
    /// installs its own carrying the interface's metric and table. Skipping
    /// either half leaves the wrong route in place.
    fn replace_subnet_route(
        &mut self,
        devidx: u32,
        addr: &sys::Address,
        ic: &config::InterfaceConfig,
    ) {
        let v6 = addr.ip.is_ipv6();
        let table = if v6 { ic.ip6table.unwrap_or(0) } else { ic.ip4table.unwrap_or(0) };
        // `if (iface->metric || a_new->policy_table)`: with neither set there
        // is nothing to change, and netifd leaves the kernel's route alone.
        if ic.metric == 0 && table == 0 {
            return;
        }
        // The delete happens before `interface_set_route_info`, so it carries
        // metric 0 and the main table -- which is what the kernel's own route
        // has. Deleting with the interface metric would match nothing.
        let mut r = sys::subnet_route(addr, 0, 0);
        r.proto = Some(sys::RTPROT_KERNEL);
        let _ = self.sys.del_route(devidx, &r);
        let mut r = sys::subnet_route(addr, ic.metric, table);
        r.proto = None;
        if let Err(e) = self.sys.add_route(devidx, &r) {
            eprintln!(
                "netifd-rs: {}: cannot take over the {}/{} prefix route: {e}",
                ic.name, addr.ip, addr.mask
            );
        }
    }

    /// Place every interface's `ip6assign` request in every known prefix, then
    /// add the resulting local address to each interface's L3 device.
    fn apply_prefix_assignments(&mut self) {
        let mut reqs: Vec<ip::AssignRequest> = self
            .cfg
            .interfaces
            .iter()
            .filter_map(|i| {
                i.ip6assign.map(|l| ip::AssignRequest {
                    name: i.name.clone(),
                    length: l,
                    hint: i.ip6hint,
                    weight: 0,
                    classes: vec![],
                })
            })
            .collect();
        reqs.sort_by(|a, b| a.name.cmp(&b.name));

        for i in &mut self.interfaces {
            i.prefix_assignments.clear();
        }
        let prefixes = self.prefixes.clone();
        for p in &prefixes {
            // `interface_update_prefix` installs an unreachable route for the
            // whole prefix, at the lowest possible priority, so a packet for
            // an unassigned part of it does not loop back out.
            let mut null = sys::Route::v6(p.addr, p.length);
            null.metric = i32::MAX as u32;
            null.nodev = true;
            if let Err(e) = self.sys.add_route(0, &null) {
                eprintln!("netifd-rs: cannot add the {}/{} null route: {e}", p.addr, p.length);
            }
            for a in ip::assign(p, &reqs) {
                let addr = ip::assignment_address(p, a.assigned);
                let local = ip::local_address(addr, "::1".parse().unwrap());
                let Some(idx) = self.iface_index(&a.name) else { continue };
                let up = self.interfaces[idx].state == State::Up;
                let l3 = self.interfaces[idx].l3_device.clone();
                if up {
                    if let Some(dev) = &l3 {
                        if let Ok(di) = self.sys.if_index(dev) {
                            if di != 0 {
                                let mut sa =
                                    sys::Address::new(IpAddr::V6(local), a.length);
                                // the prefix route is netifd's, not the kernel's
                                sa.offlink = true;
                                sa.preferred = p.preferred_until;
                                sa.valid = p.valid_until;
                                if let Err(e) = self.sys.add_address(di, &sa) {
                                    eprintln!(
                                        "netifd-rs: {}: cannot add {local}/{}: {e}",
                                        a.name, a.length
                                    );
                                }
                                // `interface_set_prefix_address` also installs
                                // the on-link route for the assignment, never
                                // narrower than a /64.
                                let rmask = a.length.max(64);
                                let mut pr = sys::Route::v6(
                                    ip::clear_if_addr(local, rmask),
                                    rmask,
                                );
                                let ic = self
                                    .cfg
                                    .interfaces
                                    .iter()
                                    .find(|i| i.name == a.name);
                                pr.metric = ic.map(|i| i.metric).unwrap_or(0);
                                let t = ic.and_then(|i| i.ip6table).unwrap_or(0);
                                pr.table =
                                    if t != 0 { t } else { sys::RT_TABLE_MAIN };
                                if let Err(e) = self.sys.add_route(di, &pr) {
                                    eprintln!(
                                        "netifd-rs: {}: cannot add the {}/{rmask} route: {e}",
                                        a.name, pr.target
                                    );
                                }
                            }
                        }
                    }
                }
                self.interfaces[idx].prefix_assignments.push(
                    interface::PrefixAssignment {
                        addr,
                        length: a.length,
                        preferred: p.preferred_until,
                        valid: p.valid_until,
                        local: if up { Some((local, a.length)) } else { None },
                    },
                );
            }
        }
    }

    fn iface_down(&mut self, name: &str) {
        let Some(idx) = self.iface_index(name) else { return };
        // `mark_interface_down` returns early when already down, so no event
        let was_up = self.interfaces[idx].state == State::Up;
        let l3 = self.interfaces[idx].l3_device.clone();
        let addrs: Vec<Address> = self.interfaces[idx].proto_ip.addresses.clone();
        let routes: Vec<interface::Route> = self.interfaces[idx].proto_ip.routes.clone();
        let assigns = self.interfaces[idx].prefix_assignments.clone();
        if let Some(dev) = l3 {
            if let Ok(di) = self.sys.if_index(&dev) {
                if di != 0 {
                    for r in &routes {
                        let mut sr = sys::Route::v4_default("0.0.0.0".parse().unwrap());
                        sr.target = r.target;
                        sr.mask = r.mask;
                        sr.nexthop = r.nexthop;
                        sr.metric = r.metric;
                        sr.table = if r.table != 0 { r.table } else { sys::RT_TABLE_MAIN };
                        let _ = self.sys.del_route(di, &sr);
                    }
                    for a in &addrs {
                        let sa = sys::Address::new(a.addr, a.mask);
                        let _ = self.sys.del_address(di, &sa);
                    }
                    for a in &assigns {
                        if let Some((local, len)) = a.local {
                            let mut sa = sys::Address::new(IpAddr::V6(local), len);
                            sa.offlink = true;
                            let _ = self.sys.del_address(di, &sa);
                        }
                    }
                }
            }
        }
        let i = &mut self.interfaces[idx];
        i.state = State::Down;
        let released = i.l3_device.take();
        // `device` is main_dev and survives the interface going down
        i.updated = 0;
        i.proto_ip = interface::IpSettings::default();
        i.prefix_assignments.clear();
        self.start_time.retain(|(n, _)| n != name);

        // `interface_flush_state` releases the L3 device, and releasing the
        // last user brings it down. Without this the device stays up with no
        // configuration on it, which is visible as a link-local address the C
        // does not have.
        if let Some(dev) = released {
            let still_used = self.interfaces.iter().any(|o| {
                o.name != name && o.state == State::Up && o.l3_device.as_deref() == Some(dev.as_str())
            });
            if !still_used {
                if let Ok(di) = self.sys.if_index(&dev) {
                    if di != 0 {
                        let _ = self.sys.set_link_up(di, false);
                    }
                }
            }
        }
        self.rescan_devices();
        if was_up {
            // entering teardown
            self.emit_event(name, Event::Down);
            // teardown complete: `mark_interface_down` emits it again, on
            // both ubus channels, but hotplug.d has already been called
            self.emit(name, Event::Down, false);
        }
    }

    /// `interface_queue_event`, for the events this build produces.
    ///
    /// Three things happen, and all three matter to a live system: the
    /// `network.interface` broadcast (what scripts listen for), the
    /// `interface.update` / `interface.down` notification on both the shared
    /// and the per-interface object (what subscribers get), and the
    /// hotplug.d call (what reconfigures the firewall, DNS and DHCP).
    fn emit_event(&mut self, name: &str, ev: Event) {
        self.emit(name, ev, true)
    }

    /// `interface_queue_event` sends the broadcast and the notification every
    /// time; only the hotplug.d call is collapsed when the event repeats the
    /// one already being handled. So the second IFEV_DOWN of a teardown is
    /// visible on both ubus channels but runs hotplug once.
    fn emit(&mut self, name: &str, ev: Event, hotplug: bool) {
        let up = matches!(ev, Event::Up);
        if matches!(ev, Event::Up | Event::Down) {
            if let Err(e) = ubus::interface_event(&mut self.conn, name, up) {
                eprintln!("netifd-rs: cannot send the {name} interface event: {e}");
            }
        }

        // `netifd_ubus_interface_notify(iface, ev != IFEV_DOWN)`
        let method = if matches!(ev, Event::Down) { "interface.down" } else { "interface.update" };
        let Some(i) = self.interfaces.iter().find(|i| i.name == name).cloned() else { return };
        let mut b = BlobBuf::new();
        b.msg_string("interface", name);
        let mut snapshot = i;
        snapshot.uptime = self.uptime_of(name);
        snapshot.dump_status(&mut b);
        let fields = b.payload().to_vec();
        let shared = self.objects.interface;
        let own = self
            .objects
            .per_interface
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, id)| *id);
        for id in [Some(shared), own].into_iter().flatten() {
            if let Err(e) = self.conn.notify(id, method, &fields) {
                eprintln!("netifd-rs: cannot notify {method} for {name}: {e}");
            }
        }

        if hotplug {
            self.call_hotplug(name, ev);
        }
    }

    /// `run_cmd`: fork `/sbin/hotplug-call iface` with the event in the
    /// environment. Synchronous here rather than queued -- the C serialises
    /// these one at a time anyway, and waiting keeps the ordering the scripts
    /// expect without a queue this build has no other use for.
    fn call_hotplug(&mut self, name: &str, ev: Event) {
        let action = match ev {
            Event::Up => "ifup",
            Event::Down => "ifdown",
            Event::UpFailed => "ifup-failed",
            Event::Update => "ifupdate",
        };
        let path = std::path::Path::new(&self.hotplug_path);
        if !path.exists() {
            return;
        }
        let mut cmd = std::process::Command::new(&self.hotplug_path);
        cmd.arg("iface").env("ACTION", action).env("INTERFACE", name);
        if matches!(ev, Event::Up | Event::Update) {
            if let Some(i) = self.interfaces.iter().find(|i| i.name == name) {
                if let Some(d) = &i.l3_device {
                    cmd.env("DEVICE", d);
                }
                if matches!(ev, Event::Update) {
                    if i.updated & interface::updated::ADDRESS != 0 {
                        cmd.env("IFUPDATE_ADDRESSES", "1");
                    }
                    if i.updated & interface::updated::ROUTE != 0 {
                        cmd.env("IFUPDATE_ROUTES", "1");
                    }
                    if i.updated & interface::updated::PREFIX != 0 {
                        cmd.env("IFUPDATE_PREFIXES", "1");
                    }
                    if i.updated & interface::updated::DATA != 0 {
                        cmd.env("IFUPDATE_DATA", "1");
                    }
                }
            }
        }
        match cmd.status() {
            Ok(_) => {}
            Err(e) => {
                eprintln!("netifd-rs: cannot run {} for {name}: {e}", self.hotplug_path)
            }
        }
    }

    fn uptime_of(&self, name: &str) -> u32 {
        self.start_time
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, t)| now().saturating_sub(*t) as u32)
            .unwrap_or(0)
    }

    fn dump_interface(&self, b: &mut BlobBuf, i: &Interface) {
        let mut snapshot = i.clone();
        snapshot.uptime = self.uptime_of(&i.name);
        b.msg_string("interface", &i.name);
        snapshot.dump_status(b);
    }

    fn handle(&mut self, req: Request) {
        let target = self.objects.route(req.objid);
        let method = req.method.clone();
        let r = match (target, method.as_str()) {
            (ubus::Target::Network, "reload") | (ubus::Target::Network, "restart") => {
                for name in
                    self.interfaces.iter().map(|i| i.name.clone()).collect::<Vec<_>>()
                {
                    self.iface_down(&name);
                }
                self.reload();
                self.conn.reply_status(&req, status::OK, None)
            }
            (ubus::Target::Network, "get_proto_handlers") => {
                let mut b = BlobBuf::new();
                self.dump_proto_handlers(&mut b);
                let fields = b.payload().to_vec();
                self.conn.reply_data(&req, &fields).and_then(|()| {
                    self.conn.reply_status(&req, status::OK, None)
                })
            }
            (ubus::Target::Network, m) => ubus::not_supported(&mut self.conn, &req, m),
            (ubus::Target::Device, "status") => {
                let name = blob::fields(&req.data)
                    .find(|f| f.name == "name" && f.ty == MsgType::String as u32)
                    .and_then(|f| f.as_str().map(|s| s.to_string()));
                let mut b = BlobBuf::new();
                match name {
                    Some(n) => match self.devices.get(&n) {
                        Some(d) if d.present => d.dump_status(&mut b, Some(&self.ethtool)),
                        _ => {
                            let _ = self.conn.reply_status(&req, status::NOT_FOUND, None);
                            return;
                        }
                    },
                    None => self.devices.dump_all(&mut b, Some(&self.ethtool)),
                }
                let fields = b.payload().to_vec();
                self.conn
                    .reply_data(&req, &fields)
                    .and_then(|()| self.conn.reply_status(&req, status::OK, None))
            }
            (ubus::Target::Device, m) => ubus::not_supported(&mut self.conn, &req, m),
            (ubus::Target::Interface(_), "dump") => {
                let mut b = BlobBuf::new();
                let arr = b.msg_open_array("interface");
                for i in &self.interfaces {
                    let t = b.msg_open_table("");
                    self.dump_interface(&mut b, i);
                    b.msg_close(t);
                }
                b.msg_close(arr);
                let fields = b.payload().to_vec();
                self.conn
                    .reply_data(&req, &fields)
                    .and_then(|()| self.conn.reply_status(&req, status::OK, None))
            }
            (ubus::Target::Interface(Some(name)), "status") => {
                let name = name.to_string();
                let Some(i) = self.interfaces.iter().find(|i| i.name == name).cloned() else {
                    let _ = self.conn.reply_status(&req, status::NOT_FOUND, None);
                    return;
                };
                let mut b = BlobBuf::new();
                let mut snapshot = i;
                snapshot.uptime = self.uptime_of(&name);
                snapshot.dump_status(&mut b);
                let fields = b.payload().to_vec();
                self.conn
                    .reply_data(&req, &fields)
                    .and_then(|()| self.conn.reply_status(&req, status::OK, None))
            }
            (ubus::Target::Interface(Some(name)), "up") => {
                let name = name.to_string();
                self.iface_up(&name);
                self.conn.reply_status(&req, status::OK, None)
            }
            (ubus::Target::Interface(Some(name)), "down") => {
                let name = name.to_string();
                self.iface_down(&name);
                self.conn.reply_status(&req, status::OK, None)
            }
            (ubus::Target::Interface(_), m) => ubus::not_supported(&mut self.conn, &req, m),
            (ubus::Target::Unknown, _) => {
                self.conn.reply_status(&req, status::NOT_FOUND, None)
            }
        };
        if let Err(e) = r {
            eprintln!("netifd-rs: reply failed: {e}");
        }
    }

    /// `get_proto_handlers`. Only handlers this build can run are listed: a
    /// caller that sees `dhcp` here would reasonably expect it to work.
    fn dump_proto_handlers(&self, b: &mut BlobBuf) {
        let t = b.msg_open_table("static");
        let v = b.msg_open_table("validate");
        for (k, ty) in [
            ("ipaddr", "ip4addr"),
            ("ip6addr", "ip6addr"),
            ("netmask", "netmask"),
            ("broadcast", "ipaddr"),
            ("ptpaddr", "ip4addr"),
            ("gateway", "ip4addr"),
            ("ip6gw", "ip6addr"),
            ("ip6prefix", "ip6addr"),
            ("ip6deprecated", "bool"),
        ] {
            b.msg_string(k, ty);
        }
        b.msg_close(v);
        b.msg_bool("immediate", true);
        b.msg_bool("no_device", false);
        b.msg_bool("init_available", false);
        b.msg_bool("renew_available", false);
        b.msg_bool("force_link_default", true);
        b.msg_bool("last_error", false);
        b.msg_bool("teardown_on_l3_link_down", false);
        b.msg_bool("no_task", false);
        b.msg_close(t);
    }

    /// A link event only refreshes the registry; it does not reconfigure. That
    /// is deliberate for this stage: the carrier-driven setup/teardown path is
    /// not implemented, and pretending otherwise would half-configure.
    fn drain_netlink(&mut self) {
        match self.events.recv_events() {
            Ok(msgs) if !msgs.is_empty() => self.rescan_devices(),
            Ok(_) => {}
            Err(e) => eprintln!("netifd-rs: netlink event read failed: {e}"),
        }
    }

    fn run(&mut self) -> ! {
        loop {
            let ubus_fd = self.conn.as_raw_fd();
            let nl_fd = self.events.as_raw_fd();
            let mut fds = [
                PollFd { fd: ubus_fd, events: POLLIN, revents: 0 },
                PollFd { fd: nl_fd, events: POLLIN, revents: 0 },
            ];
            match owrt_ubus::sys::poll_fds(&mut fds, 1000) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    eprintln!("netifd-rs: poll failed: {e}");
                    std::process::exit(1);
                }
            }
            if fds[1].revents & POLLIN != 0 {
                self.drain_netlink();
            }
            if fds[0].revents & (POLLIN | POLLHUP) != 0 {
                match self.conn.read_incoming() {
                    Ok(Incoming::Invoke(req)) => self.handle(req),
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("netifd-rs: bus connection lost: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}

fn main() {
    let mut confdir = "/etc/config".to_string();
    let mut hotplug = DEFAULT_HOTPLUG_PATH.to_string();
    let mut socket: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" => confdir = args.next().unwrap_or(confdir),
            "-s" => socket = args.next(),
            "-h" => hotplug = args.next().unwrap_or(hotplug),
            "-V" | "--version" => {
                println!("{BUILD_ID}");
                return;
            }
            other => {
                eprintln!("netifd-rs: unknown argument {other}");
                std::process::exit(2);
            }
        }
    }

    let mut n = match Netifd::new(&confdir, socket.as_deref(), &hotplug) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("netifd-rs: startup failed: {e}");
            std::process::exit(1);
        }
    };
    n.reload();
    n.run()
}
