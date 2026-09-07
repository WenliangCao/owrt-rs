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
mod proto;
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

/// Where the shell protocol handlers live; overridable with `-p`.
const DEFAULT_PROTO_DIR: &str = "/lib/netifd/proto";

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

/// `netifd_ubus_reconnect_timer`'s `int t = 2`.
const BUS_RETRY_SECS: u64 = 2;

/// A blobmsg array of strings, or a single string as a one-element list.
fn string_list(f: &blob::Field) -> Vec<String> {
    if f.ty == MsgType::Array as u32 {
        return f.children().filter_map(|c| c.as_str().map(|s| s.to_string())).collect();
    }
    f.as_str().map(|s| vec![s.to_string()]).unwrap_or_default()
}

/// Whether a config change needs the interface reloaded. This is
/// `interface_change_config`'s `reload` decision: the device, the protocol
/// and the protocol's own parameters. `raw` is deliberately not compared --
/// `uci_blob_check_equal` only looks at the parameters the protocol declares,
/// so an option nothing reads changing is not a reason to bounce the link.
fn config_changed(a: &config::InterfaceConfig, b: &config::InterfaceConfig) -> bool {
    let strip = |c: &config::InterfaceConfig| {
        let mut c = c.clone();
        c.raw.clear();
        c
    };
    strip(a) != strip(b)
}

/// One entry of a protocol's `state->deps`.
struct HostDep {
    /// The interface whose protocol declared the dependency.
    owner: String,
    /// `dep->interface`: an interface that must be up, if given.
    interface: String,
    /// `dep->host`: a host that must be reachable, if given.
    host: Option<IpAddr>,
    /// `dep->any`: an interface dependency with no host.
    any: bool,
    /// The interface that satisfies it, or `None` while it does not.
    satisfied_by: Option<String>,
}

/// Whether `addr` falls inside `prefix/len`.
fn in_prefix(addr: IpAddr, prefix: IpAddr, len: u8) -> bool {
    match (addr, prefix) {
        (IpAddr::V4(a), IpAddr::V4(p)) => {
            let (a, p) = (u32::from_be_bytes(a.octets()), u32::from_be_bytes(p.octets()));
            let m = if len == 0 { 0 } else { u32::MAX << (32 - len.min(32)) };
            a & m == p & m
        }
        (IpAddr::V6(a), IpAddr::V6(p)) => {
            let (a, p) = (u128::from_be_bytes(a.octets()), u128::from_be_bytes(p.octets()));
            let m = if len == 0 { 0 } else { u128::MAX << (128 - len.min(128)) };
            a & m == p & m
        }
        _ => false,
    }
}

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
    /// `/lib/netifd/proto`; the scripts there are run with it as cwd.
    protodir: String,
    /// One hotplug.d call at a time, as `interface_queue_event` does.
    hotplug: process::Slot,
    hotplug_current: Option<(String, Event)>,
    hotplug_queue: Vec<(String, Event)>,
    /// `state->deps`: what each interface's protocol said it depends on
    /// being able to reach. An unsatisfied dependency makes the interface
    /// unavailable.
    host_deps: Vec<HostDep>,
    /// Interfaces whose `remove` timer is armed.
    remove_pending: Vec<String>,
    /// The bus socket, kept so the connection can be remade.
    socket: Option<String>,
    /// Set when the bus connection is gone; the loop keeps running on netlink
    /// and retries the connection.
    bus_down: bool,
    /// Seconds-since-boot at which to try connecting again.
    bus_retry_at: u64,
    /// `iface->link_state`: whether the interface's main device has carrier.
    link_state: Vec<(String, bool)>,
    /// `dev->sys_present`: the device names the kernel currently has.
    present: Vec<String>,
    /// A child's exit wakes the loop through this, rather than waiting for
    /// the poll timeout.
    sigchld: process::ChildSignal,
    /// Every device netifd has an object for. An entry means `device_init`
    /// has run -- its state was cleared once -- and it means the device is
    /// reported by `network.device status`, which lists every present object,
    /// not just the ones the config names.
    device_objects: Vec<String>,
    /// `dev->active`: how many users have claimed each device. The link state
    /// follows this count, not any single interface's state.
    claims: Vec<(String, i32)>,
    /// `dev->parent`: the device a claimed device claimed in turn.
    parents: Vec<(String, String)>,
    /// `iface->main_dev` and `iface->l3_dev`, the two claims an interface
    /// holds, so each is released exactly once.
    claimed_main: Vec<(String, String)>,
    claimed_l3: Vec<(String, String)>,
    handlers: Vec<proto::Handler>,
    /// Per-interface protocol state, for the shell handlers only.
    protos: Vec<(String, proto::ProtoState)>,
}

impl Netifd {
    fn new(
        confdir: &str,
        socket: Option<&str>,
        hotplug: &str,
        protodir: &str,
    ) -> io::Result<Self> {
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
            host_deps: Vec::new(),
            remove_pending: Vec::new(),
            socket: socket.map(|s| s.to_string()),
            bus_down: false,
            bus_retry_at: 0,
            link_state: Vec::new(),
            present: Vec::new(),
            sigchld: process::ChildSignal::install()?,
            device_objects: Vec::new(),
            claims: Vec::new(),
            parents: Vec::new(),
            claimed_main: Vec::new(),
            claimed_l3: Vec::new(),
            ethtool: ethtool::Ethtool::open()?,
            ifioctl: sys::IfIoctl::open()?,
            conn,
            objects,
            confdir: confdir.to_string(),
            hotplug_path: hotplug.to_string(),
            protodir: protodir.to_string(),
            hotplug: process::Slot::default(),
            hotplug_current: None,
            hotplug_queue: Vec::new(),
            handlers: Vec::new(),
            protos: Vec::new(),
        })
    }

    /// Load the config and bring up what it asks for. Called at startup and by
    /// `network.reload`.
    fn reload(&mut self) {
        let first = self.interfaces.is_empty();
        let old = self.cfg.clone();
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

        if self.handlers.is_empty() {
            self.handlers = proto::discover(std::path::Path::new(&self.protodir));
            let names: Vec<&str> = self.handlers.iter().map(|h| h.name.as_str()).collect();
            eprintln!("netifd-rs: shell protocol handlers: {}", names.join(" "));
        }

        if first {
            for (_, st) in &mut self.protos {
                st.script.terminate();
                st.task.terminate();
            }
            self.protos.clear();
        }

        self.clear_new_device_state();
        self.rescan_devices();
        self.present.clear();
        for name in self.known_device_names() {
            if self.sys.if_index(&name).unwrap_or(0) != 0 {
                self.present.push(name);
            }
        }
        self.create_devices();
        self.build_prefixes();
        if first {
            self.setup_interfaces();
        } else {
            self.apply_config_change(&old);
        }
    }

    /// `vlist_update` over the interface tree: a section that is gone is
    /// removed, a new one is created and started, and one that is still there
    /// is reloaded only if its config actually changed.
    ///
    /// This is the difference between a reload and a restart. Rebuilding
    /// everything reaches the same final state, so the state afterwards
    /// cannot tell the two apart -- but every interface bounces, and anything
    /// watching hotplug.d or the ubus events sees it.
    fn apply_config_change(&mut self, old: &config::Config) {
        let new = self.cfg.interfaces.clone();

        // gone
        for oc in &old.interfaces {
            if new.iter().any(|n| n.name == oc.name) {
                continue;
            }
            eprintln!("netifd-rs: Remove interface '{}'", oc.name);
            self.set_down(&oc.name);
            self.mark_interface_down(&oc.name);
            self.interfaces.retain(|i| i.name != oc.name);
            if let Err(e) = self.objects.remove_interface(&mut self.conn, &oc.name) {
                eprintln!("netifd-rs: cannot unregister {}: {e}", oc.name);
            }
            self.link_state.retain(|(n, _)| *n != oc.name);
            self.protos.retain(|(n, _)| *n != oc.name);
        }

        // new, then changed -- both in name order, as the vlist walk is
        let mut names: Vec<String> = new.iter().map(|c| c.name.clone()).collect();
        names.sort();
        for name in names {
            let nc = new.iter().find(|c| c.name == name).cloned().unwrap();
            match old.interfaces.iter().find(|o| o.name == name) {
                None => {
                    eprintln!("netifd-rs: Create interface '{name}'");
                    let i = self.new_interface(&nc);
                    self.interfaces.push(i);
                    self.interfaces.sort_by(|a, b| a.name.cmp(&b.name));
                    if let Err(e) = self.register_interface(&name) {
                        eprintln!("netifd-rs: cannot register {name}: {e}");
                    }
                    if nc.auto.unwrap_or(true) && !nc.disabled {
                        self.iface_up(&name);
                    }
                }
                Some(oc) => {
                    if !config_changed(oc, &nc) {
                        // the cheap fields are updated in place, as
                        // `interface_change_config` does for everything that
                        // does not need a reload
                        if let Some(i) = self.iface_index(&name) {
                            let iface = &mut self.interfaces[i];
                            iface.metric = nc.metric;
                            iface.dns_metric = nc.dns_metric;
                            iface.ip4table = nc.ip4table.unwrap_or(0);
                            iface.ip6table = nc.ip6table.unwrap_or(0);
                        }
                        continue;
                    }
                    eprintln!(
                        "netifd-rs: Reload interface '{name}' because of config changes"
                    );
                    self.do_reload(&name);
                }
            }
        }
    }

    /// `interface_do_reload`: down, then up again with the new config.
    fn do_reload(&mut self, name: &str) {
        let Some(nc) = self.cfg.interfaces.iter().find(|c| c.name == name).cloned() else {
            return;
        };
        // `interface_do_reload` is a teardown, not an ifdown: autostart
        // survives it, which is what brings the interface back up
        self.set_down(name);
        self.mark_interface_down(name);
        if let Some(i) = self.iface_index(name) {
            let fresh = self.new_interface(&nc);
            self.interfaces[i] = fresh;
        }
        self.link_state.retain(|(n, _)| n != name);
        if nc.auto.unwrap_or(true) && !nc.disabled {
            self.iface_up(name);
        }
    }

    /// `device_init` runs `system_if_clear_state` once per device object, so
    /// every device netifd names for the first time is brought down and has
    /// its addresses, routes and permanent neighbours flushed. Tracking which
    /// names have already been through this keeps a reload from re-clearing a
    /// device that is up and configured.
    fn clear_new_device_state(&mut self) {
        for name in self.known_device_names() {
            if self.device_objects.contains(&name) {
                continue;
            }
            self.device_objects.push(name.clone());
            // a bridge this daemon is about to create is cleared when it
            // exists; one left over from a previous run is deleted
            self.sys.clear_state(&name, false);
        }
    }

    /// `proto_ext_checkup_timeout_cb`: the setup script finished but the
    /// interface never came up, so tear it down again. Cancelled whenever the
    /// state machine leaves SETUP, exactly as the C cancels the timeout.
    fn pump_checkups(&mut self) {
        let names: Vec<String> = self
            .protos
            .iter()
            .filter(|(_, st)| st.checkup_at.is_some_and(|at| now() >= at))
            .map(|(n, _)| n.clone())
            .collect();
        for name in names {
            self.proto_state(&name).checkup_at = None;
            let Some(idx) = self.iface_index(&name) else { continue };
            if !self.interfaces[idx].autostart || self.interfaces[idx].state == State::Up {
                continue;
            }
            eprintln!("netifd-rs: Interface '{name}' is not up after the checkup interval");
            self.proto_cmd(&name, proto::Cmd::Teardown);
        }
    }

    /// `__device_free_unused`: a device object with no users and no config
    /// section of its own is freed. Without this, an object created by
    /// `set_alias` for a device nothing references would linger and keep
    /// showing up in `network.device status`.
    fn free_unused_devices(&mut self) {
        let configured = self.known_device_names();
        let claimed: Vec<String> = self.claims.iter().map(|(n, _)| n.clone()).collect();
        let parents: Vec<String> = self.parents.iter().map(|(_, p)| p.clone()).collect();
        // "no users" also covers an interface still pointing at the device,
        // even one whose config section has just gone: dropping the object
        // out from under it made the interface look like it had lost its
        // device, and it churned up and down.
        let used: Vec<String> = self
            .interfaces
            .iter()
            .flat_map(|i| [i.device.clone(), i.l3_device.clone()])
            .flatten()
            .collect();
        let doomed: Vec<String> = self
            .device_objects
            .iter()
            .filter(|n| {
                !configured.contains(n)
                    && !claimed.contains(n)
                    && !parents.contains(n)
                    && !used.contains(n)
            })
            .cloned()
            .collect();
        for name in doomed {
            self.device_objects.retain(|n| *n != name);
            self.devices.remove(&name);
            self.present.retain(|n| *n != name);
        }
    }

    /// `device_claim`: one more user of a device. The device is brought up
    /// only by the first claim, and `simple_device_set_state` claims its
    /// parent first -- `iflink`, which is the DSA conduit for a user port and
    /// the peer for a veth. The count is what makes a mutual parent
    /// relationship terminate instead of recursing.
    fn device_claim(&mut self, name: &str) {
        let count = match self.claims.iter_mut().find(|(n, _)| n == name) {
            Some(slot) => {
                slot.1 += 1;
                slot.1
            }
            None => {
                self.claims.push((name.to_string(), 1));
                1
            }
        };
        if count != 1 {
            return;
        }
        if let Some(p) = self.sys.parent_of(name) {
            if !self.device_objects.contains(&p) {
                self.device_objects.push(p.clone());
                self.sys.clear_state(&p, false);
            }
            self.parents.push((name.to_string(), p.clone()));
            self.device_claim(&p);
        }
        if let Ok(i) = self.sys.if_index(name) {
            if i != 0 {
                let _ = self.sys.set_link_up(i, true);
            }
        }
        // `DEV_EVENT_UP` -> `interface_set_enabled(iface, true)`
        self.set_enabled(name, true);
    }

    /// `interface_set_enabled` for every interface whose main device this is.
    /// The C re-checks the state from here; this build re-checks it at the
    /// explicit call sites instead, which covers every case it reaches.
    fn set_enabled(&mut self, dev: &str, enabled: bool) {
        for name in self.ifaces_using(dev) {
            if let Some(i) = self.iface_index(&name) {
                if self.interfaces[i].enabled != enabled {
                    self.interfaces[i].enabled = enabled;
                    eprintln!(
                        "netifd-rs: Interface '{name}' is {}",
                        if enabled { "enabled" } else { "disabled" }
                    );
                }
            }
        }
    }

    /// `device_release`: the device goes down when the last user lets go, and
    /// its parent is released before it does.
    fn device_release(&mut self, name: &str) {
        let Some(pos) = self.claims.iter().position(|(n, _)| n == name) else { return };
        self.claims[pos].1 -= 1;
        if self.claims[pos].1 > 0 {
            return;
        }
        self.claims.remove(pos);
        if let Some(pp) = self.parents.iter().position(|(c, _)| c == name) {
            let (_, p) = self.parents.remove(pp);
            self.device_release(&p);
        }
        if let Ok(i) = self.sys.if_index(name) {
            if i != 0 {
                let _ = self.sys.set_link_up(i, false);
            }
        }
        // `DEV_EVENT_DOWN`
        self.set_enabled(name, false);
    }

    /// Claim `dev` on `iface`'s behalf, as its main or L3 device. Re-claiming
    /// the same device in the same slot is not a second claim.
    fn iface_claim(&mut self, iface: &str, dev: &str, l3: bool) {
        let held = if l3 { &self.claimed_l3 } else { &self.claimed_main };
        if held.iter().any(|(i, d)| i == iface && d == dev) {
            return;
        }
        // a slot that held a different device releases it first
        self.iface_unclaim(iface, l3);
        let slot = if l3 { &mut self.claimed_l3 } else { &mut self.claimed_main };
        slot.push((iface.to_string(), dev.to_string()));
        self.device_claim(dev);
    }

    fn iface_unclaim(&mut self, iface: &str, l3: bool) {
        let slot = if l3 { &mut self.claimed_l3 } else { &mut self.claimed_main };
        let Some(pos) = slot.iter().position(|(i, _)| i == iface) else { return };
        let (_, dev) = slot.remove(pos);
        self.device_release(&dev);
        // `device_remove_user` ends with `device_free_unused()`. That is the
        // only ordinary place the C collects them -- NOT periodically, and
        // not after a successful `set_alias`, which is why a device named
        // there stays visible until some user goes away.
        self.free_unused_devices();
    }


    fn handler_for(&self, proto: &str) -> Option<&proto::Handler> {
        self.handlers.iter().find(|h| h.name == proto)
    }

    fn proto_state(&mut self, name: &str) -> &mut proto::ProtoState {
        if !self.protos.iter().any(|(n, _)| n == name) {
            self.protos.push((name.to_string(), proto::ProtoState::new()));
        }
        let i = self.protos.iter().position(|(n, _)| n == name).unwrap();
        &mut self.protos[i].1
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
        // every device object, not just the config-named ones: a parent
        // claimed through `iflink` has an object too, and the C's
        // `network.device status` lists it
        let known = self.device_objects.clone();
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
            // `device_refresh_present`: present is the kernel's view minus
            // anything `set_state {"defer":true}` has held back
            d.sys_present = true;
            d.present = !d.deferred;
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
                        // forward, which is what device_claim does -- and
                        // claiming it also claims its parent, which is how a
                        // DSA conduit comes up behind its user ports
                        let _ = pi;
                        self.device_claim(port);
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

    /// One interface's bookkeeping, from its config section.
    fn new_interface(&mut self, ic: &config::InterfaceConfig) -> Interface {
        let mut i = Interface::new(&ic.name);
        i.proto = Some(ic.proto.clone());
        // `main_dev` is set from the config whether or not the device
        // exists, so `device` is reported even for an absent one.
        i.device = ic.device.clone();
        // `available` reflects whether the device is present, not whether
        // the interface was started.
        i.available =
            ic.device.as_deref().map(|d| self.sys.if_index(d).unwrap_or(0) != 0).unwrap_or(false);
        i.autostart = ic.auto.unwrap_or(true) && !ic.disabled;
        i.metric = ic.metric;
        i.dns_metric = ic.dns_metric;
        i.ip4table = ic.ip4table.unwrap_or(0);
        i.ip6table = ic.ip6table.unwrap_or(0);
        i.proto_ip.no_delegation = ic.delegate == Some(false);
        i
    }

    fn setup_interfaces(&mut self) {
        let cfgs = self.cfg.interfaces.clone();
        self.interfaces.clear();
        for ic in &cfgs {
            let i = self.new_interface(ic);
            self.interfaces.push(i);
        }
        // netifd keeps interfaces in a vlist keyed by name
        self.interfaces.sort_by(|a, b| a.name.cmp(&b.name));

        for name in self.interfaces.iter().map(|i| i.name.clone()).collect::<Vec<_>>() {
            if let Err(e) = self.register_interface(&name) {
                eprintln!("netifd-rs: cannot register {name}: {e}");
            }
        }
        // `interface_start_pending` walks the interface vlist, which is an
        // avl tree keyed by name, so the startup order is ALPHABETICAL -- not
        // config order and not its reverse. Four independent static
        // interfaces come up in name order, which is how r54 caught this;
        // earlier harnesses agreed by accident because their interfaces
        // finished coming up in a different order anyway.
        for name in self.interfaces.iter().map(|i| i.name.clone()).collect::<Vec<_>>() {
            let autostart = self
                .cfg
                .interfaces
                .iter()
                .find(|ic| ic.name == name)
                .map(|ic| ic.auto.unwrap_or(true) && !ic.disabled)
                .unwrap_or(false);
            if autostart {
                self.iface_up(&name);
            }
        }

        // `set_device_state(dev, false)` brings a device down when nothing is
        // using it. A device named by a config section that never came up is
        // exactly that case, and leaving it up would be a visible difference.
        for ic in &cfgs {
            // An interface still setting up is using its device: taking it
            // down here left udhcpc with no link and the interface stuck in
            // SETUP until the lease attempt timed out.
            let in_use = self
                .iface_index(&ic.name)
                .map(|i| self.interfaces[i].state != State::Down)
                .unwrap_or(false);
            if in_use {
                continue;
            }
            let Some(dev) = &ic.device else { continue };
            // never touch a device another interface is using
            if cfgs.iter().any(|o| {
                o.device.as_deref() == Some(dev.as_str())
                    && self
                        .iface_index(&o.name)
                        .map(|i| self.interfaces[i].state != State::Down)
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
                    let _ = idx;
                    // never claimed, so `system_if_clear_state` already left
                    // it down; releasing an unclaimed device is a no-op
                    self.device_release(dev);
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
    /// `interface_set_up`: claim the main device, then let
    /// `interface_check_state` decide. The bring-up is carrier-driven -- the
    /// claim brings the link up, and the interface only follows once the
    /// device reports carrier -- which is why an interface whose peer is down
    /// stays in DOWN rather than sitting in SETUP forever.
    fn iface_up(&mut self, name: &str) {
        let Some(idx) = self.iface_index(name) else { return };
        // autostart is set by every caller, before the state check
        self.interfaces[idx].autostart = true;
        if self.interfaces[idx].state != State::Down {
            return;
        }
        self.interfaces[idx].errors.clear();
        let main = self
            .cfg
            .interfaces
            .iter()
            .find(|i| i.name == name)
            .and_then(|ic| ic.device.clone());
        let error = if !self.interfaces[idx].available {
            Some("NO_DEVICE")
        } else {
            match main {
                Some(dev) => {
                    self.iface_claim(name, &dev, false);
                    self.rescan_devices();
                    // `device_add_user` replays the device's current state to
                    // a new user. Without that, an interface whose device was
                    // already claimed by someone else -- a bridge member's
                    // parent, say -- never sees DEV_EVENT_UP, so `enabled`
                    // stays false and `interface_check_state` refuses to
                    // bring it up.
                    let up = self.devices.get(&dev).map(|d| d.active).unwrap_or(false);
                    if let Some(i) = self.iface_index(name) {
                        self.interfaces[i].enabled = up;
                    }
                    // Complete here rather than waiting for the carrier
                    // event. Leaving it to the event path was tried and is
                    // worse: a later event re-read a device as momentarily
                    // without carrier and tore the interface straight back
                    // down. The cost is the startup ifup ORDER -- the C comes
                    // up in the order its carrier events arrive, this build
                    // in the order the walk starts them. See R45.
                    self.update_link_state(name);
                    self.check_state(name);
                    None
                }
                // no device at all: nothing to claim, so go straight to setup
                None => {
                    self.set_up_now(name);
                    None
                }
            }
        };
        if let Some(e) = error {
            self.iface_error(name, "interface", e, &[]);
        }
    }

    /// `__interface_set_up`: the protocol's own setup.
    fn set_up_now(&mut self, name: &str) {
        let Some(ic) = self.cfg.interfaces.iter().find(|i| i.name == name).cloned() else {
            return;
        };
        let Some(idx) = self.iface_index(name) else { return };

        if !IMPLEMENTED_PROTOS.contains(&ic.proto.as_str()) {
            if self.handler_for(&ic.proto).is_some() {
                self.proto_setup(name);
                return;
            }
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

        // `interface_set_up`: `device_claim(&iface->main_dev)`
        self.iface_claim(name, &devname, false);
        // static has no protocol script, so the main device is the L3 device
        self.iface_claim(name, &devname, true);

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
        // only what was actually applied: an interface that came up with no
        // addresses has `updated` empty, and the status omits the key
        i.updated = 0;
        if !i.proto_ip.addresses.is_empty() {
            i.updated |= interface::updated::ADDRESS;
        }
        if !i.proto_ip.routes.is_empty() {
            i.updated |= interface::updated::ROUTE;
        }
        i.errors.clear();
        self.start_time.retain(|(n, _)| n != name);
        self.start_time.push((name.to_string(), now()));

        self.apply_prefix_assignments();
        self.emit_event(name, Event::Up);
    }

    /// Run one protocol command for an interface, honouring the state machine.
    fn proto_cmd(&mut self, name: &str, cmd: proto::Cmd) {
        let Some(ic) = self.cfg.interfaces.iter().find(|i| i.name == name).cloned() else {
            return;
        };
        let Some(handler) = self.handler_for(&ic.proto).cloned() else { return };
        let plan = {
            let st = self.proto_state(name);
            proto::plan(st, cmd, &handler)
        };
        match plan {
            proto::Action::Nothing => {}
            proto::Action::Refuse => {
                eprintln!("netifd-rs: {name}: {cmd:?} refused in this state");
            }
            proto::Action::Abort => {
                // SIGTERM both children and wait for them; the abort completes
                // in `reap_children`.
                let st = self.proto_state(name);
                let _ = st.script.signal(process::SIGTERM as u32);
                let _ = st.task.signal(process::SIGTERM as u32);
            }
            proto::Action::Run { action, env } => {
                if action != "setup" {
                    // `uloop_timeout_cancel(&state->checkup_timeout)` on
                    // teardown and on abort
                    self.proto_state(name).checkup_at = None;
                }
                // `proto_ext_clear_host_dep` runs when a SETUP starts, not on
                // teardown -- so a dependency that went unsatisfied keeps the
                // interface unavailable until the protocol is set up again.
                if action == "setup" {
                    self.host_deps.retain(|d| d.owner != name);
                }
                let opts: Vec<(String, Vec<String>)> =
                    ic.raw.iter().map(|r| (r.name.clone(), r.values.clone())).collect();
                let config = proto::config_json(&handler, &opts);
                let argv = proto::argv(
                    &handler,
                    action,
                    name,
                    &config,
                    ic.device.as_deref(),
                );
                let dir = self.protodir.clone();
                let st = self.proto_state(name);
                // the scripts source ../netifd-proto.sh, so cwd matters
                if let Err(e) = st.script.start_in(&argv, &env, &dir) {
                    eprintln!("netifd-rs: {name}: cannot run {action}: {e}");
                }
            }
        }
    }

    /// Begin setup for a shell protocol: the interface goes pending, and the
    /// script decides when (and whether) it comes up.
    fn proto_setup(&mut self, name: &str) {
        let Some(ic) = self.cfg.interfaces.iter().find(|i| i.name == name).cloned() else {
            return;
        };
        let devidx = ic.device.as_deref().map(|d| self.sys.if_index(d).unwrap_or(0)).unwrap_or(0);
        if devidx == 0 {
            if let Some(idx) = self.iface_index(name) {
                self.interfaces[idx].errors.push(interface::IfaceError {
                    subsystem: "interface".into(),
                    code: "NO_DEVICE".into(),
                    data: vec![],
                });
                self.interfaces[idx].available = false;
            }
            return;
        }
        let dev = ic.device.clone().unwrap_or_default();
        let _ = devidx;
        self.iface_claim(name, &dev, false);
        if let Some(idx) = self.iface_index(name) {
            self.interfaces[idx].state = State::Setup;
            self.interfaces[idx].available = true;
            self.interfaces[idx].errors.clear();
        }
        self.proto_cmd(name, proto::Cmd::Setup);
    }

    /// `proto_shell_notify`: the eight callbacks a handler script uses.
    ///
    /// A missing or unknown `action` is `INVALID_ARGUMENT`, and actions 0, 1
    /// and 6 are `PERMISSION_DENIED` during teardown or abort -- a script that
    /// reports success after netifd decided to tear down must not be able to
    /// bring the interface back up.
    fn notify_proto(&mut self, name: &str, data: &[u8]) -> i32 {
        // `netifd_iface_notify_proto`: `if (!iface->proto->notify) return
        // NOT_SUPPORTED`. Only an external protocol has a notify callback, so
        // every action on a built-in one -- static, none -- is refused,
        // whatever the action number says.
        let external = self
            .cfg
            .interfaces
            .iter()
            .find(|i| i.name == name)
            .map(|ic| {
                !IMPLEMENTED_PROTOS.contains(&ic.proto.as_str())
                    && self.handler_for(&ic.proto).is_some()
            })
            .unwrap_or(false);
        if !external {
            return status::NOT_SUPPORTED;
        }
        let fields: Vec<blob::Field> = blob::fields(data).collect();
        let find = |n: &str| fields.iter().find(|f| f.name == n).copied();
        let Some(action) = find("action").and_then(|f| f.as_u32()) else {
            return status::INVALID_ARGUMENT;
        };
        let sm = self.proto_state(name).sm;
        let tearing = matches!(sm, proto::Sm::Teardown | proto::Sm::SetupAbort);

        match action {
            0 => {
                if tearing {
                    return status::PERMISSION_DENIED;
                }
                // "link-up", with a hyphen: `notify_attr` in proto-ext.c.
                // `link_up` matches nothing, so every update the scripts sent
                // came back INVALID_ARGUMENT.
                let Some(link_up) = find("link-up").and_then(|f| f.as_bool()) else {
                    return status::INVALID_ARGUMENT;
                };
                if !link_up {
                    self.link_lost(name);
                    return status::OK;
                }
                self.apply_proto_link(name, &fields)
            }
            1 => {
                if tearing {
                    return status::PERMISSION_DENIED;
                }
                let Some(argv) = find("command").map(|f| string_list(&f)) else {
                    return status::INVALID_ARGUMENT;
                };
                if argv.is_empty() {
                    return status::INVALID_ARGUMENT;
                }
                let env: Vec<(String, String)> = find("env")
                    .map(|f| string_list(&f))
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|e| {
                        e.split_once('=').map(|(k, v)| (k.to_string(), v.to_string()))
                    })
                    .collect();
                let st = self.proto_state(name);
                match st.task.start(&argv, &env) {
                    Ok(()) => status::OK,
                    Err(e) => {
                        eprintln!("netifd-rs: {name}: cannot run {}: {e}", argv[0]);
                        status::UNKNOWN_ERROR
                    }
                }
            }
            2 => {
                let sig = find("signal").and_then(|f| f.as_u32()).unwrap_or(u32::MAX);
                let st = self.proto_state(name);
                if st.task.is_running() {
                    let effective = if sig > 31 { process::SIGTERM as u32 } else { sig };
                    if effective == process::SIGTERM as u32
                        || effective == process::SIGKILL as u32
                    {
                        st.task_killed = true;
                    }
                    let _ = st.task.signal(sig);
                }
                status::OK
            }
            3 => {
                let Some(list) = find("error").map(|f| string_list(&f)) else {
                    return status::INVALID_ARGUMENT;
                };
                if list.is_empty() {
                    return status::INVALID_ARGUMENT;
                }
                let subsystem = self
                    .cfg
                    .interfaces
                    .iter()
                    .find(|i| i.name == name)
                    .map(|i| i.proto.clone())
                    .unwrap_or_default();
                if let Some(idx) = self.iface_index(name) {
                    self.interfaces[idx].errors.push(interface::IfaceError {
                        subsystem,
                        code: list[0].clone(),
                        data: list[1..].to_vec(),
                    });
                }
                status::OK
            }
            4 => {
                if let Some(idx) = self.iface_index(name) {
                    self.interfaces[idx].autostart = false;
                }
                self.proto_state(name).block_restart = true;
                status::OK
            }
            5 => {
                let Some(av) = find("available").and_then(|f| f.as_bool()) else {
                    return status::INVALID_ARGUMENT;
                };
                if let Some(idx) = self.iface_index(name) {
                    self.interfaces[idx].available = av;
                }
                self.proto_state(name).available = av;
                status::OK
            }
            6 => {
                if tearing {
                    return status::PERMISSION_DENIED;
                }
                self.add_host_dependency(name, &fields)
            }
            7 => match sm {
                proto::Sm::Idle => {
                    self.iface_down(name);
                    self.proto_cmd(name, proto::Cmd::Teardown);
                    status::OK
                }
                proto::Sm::Setup => {
                    self.proto_cmd(name, proto::Cmd::Teardown);
                    status::OK
                }
                _ => status::PERMISSION_DENIED,
            },
            _ => status::INVALID_ARGUMENT,
        }
    }

    /// The address, route and DNS half of action 0.
    fn apply_proto_link(&mut self, name: &str, fields: &[blob::Field]) -> i32 {
        let find = |n: &str| fields.iter().find(|f| f.name == n).copied();
        let Some(ic) = self.cfg.interfaces.iter().find(|i| i.name == name).cloned() else {
            return status::NOT_FOUND;
        };

        // `keep` asks netifd to add to what is already applied rather than
        // replace it. It is forced off unless the interface is already up with
        // an L3 device, and forced off again if the script named a device.
        let mut keep = find("keep").and_then(|f| f.as_bool()).unwrap_or(false);
        // `address-external` only changes how the L3 device is looked up
        // (`dev_create` 2 rather than 1, i.e. create it as an external
        // device). This build does not create devices on demand here, so it
        // has no further effect and is accepted rather than refused.
        let _addr_ext = find("address-external").and_then(|f| f.as_bool()).unwrap_or(false);
        if find("tunnel").is_some() {
            eprintln!("netifd-rs: {name}: proto-created tunnels are out of scope");
            return status::NOT_SUPPORTED;
        }
        let already_up = self
            .iface_index(name)
            .map(|i| self.interfaces[i].state == State::Up && self.interfaces[i].l3_device.is_some())
            .unwrap_or(false);
        if !already_up {
            keep = false;
        }

        // the script may name its own L3 device (ppp0); otherwise main_dev
        let named = find("ifname").and_then(|f| f.as_str().map(|s| s.to_string()));
        if named.is_some() {
            keep = false;
        }
        let l3 = named.or_else(|| ic.device.clone());
        let Some(l3) = l3 else { return status::INVALID_ARGUMENT };
        let devidx = self.sys.if_index(&l3).unwrap_or(0);
        if devidx == 0 {
            eprintln!("netifd-rs: {name}: proto reported device {l3}, which does not exist");
            return status::INVALID_ARGUMENT;
        }
        if !keep {
            let _ = devidx;
            self.iface_claim(name, &l3, true);
        }

        // `interface_update_start(iface, keep)`
        let mut ipset = if keep {
            self.iface_index(name)
                .map(|i| self.interfaces[i].proto_ip.clone())
                .unwrap_or_default()
        } else {
            interface::IpSettings::default()
        };

        // proto_apply_ip_settings: `ipaddr`/`ip6addr` are arrays of tables,
        // each carrying its own mask. A rejected item abandons the remaining
        // IP settings but still lets the interface come up, because
        // proto_ext_update_link ignores this function's return value.
        let mut counts = [0usize, 0usize];
        let mut bad = false;
        for (key, v6) in [("ipaddr", false), ("ip6addr", true)] {
            let Some(list) = find(key) else { continue };
            for item in list.children() {
                let Some(a) = proto::parse_addr_item(&item, v6) else {
                    eprintln!("netifd-rs: {name}: proto sent an address this build rejects");
                    bad = true;
                    break;
                };
                let mut sa = sys::Address::new(a.ip, a.mask);
                sa.broadcast = a.broadcast;
                sa = sa.with_default_broadcast();
                // v6 carries the lifetimes the protocol reported, and
                // `offlink` becomes IFA_F_NOPREFIXROUTE -- netifd manages the
                // prefix route itself. Without the flag the kernel adds its
                // own host route for a /128, which is visible in `ip -6
                // route` and is how r56 found this.
                sa.preferred = a.preferred;
                sa.valid = a.valid;
                sa.offlink = a.offlink;
                if let Err(e) = self.sys.add_address(devidx, &sa) {
                    eprintln!("netifd-rs: {name}: cannot add {}/{}: {e}", a.ip, a.mask);
                    continue;
                }
                if !a.offlink {
                    self.replace_subnet_route(devidx, &sa, &ic);
                }
                let mut ia = Address::new(a.ip, a.mask);
                ia.point_to_point = a.point_to_point;
                ia.class = a.class.clone();
                ia.preferred = a.preferred;
                ia.valid = a.valid;
                ipset.addresses.push(ia);
                counts[v6 as usize] += 1;
            }
            if bad {
                break;
            }
        }
        // `gateway`/`ip6gw` are applied only when that family got an address
        if !bad {
            for (key, v6) in [("gateway", false), ("ip6gw", true)] {
                if counts[v6 as usize] == 0 {
                    continue;
                }
                let Some(gw) = find(key).and_then(|f| f.as_str()) else { continue };
                let Ok(nexthop) = gw.parse::<IpAddr>() else {
                    eprintln!("netifd-rs: {name}: proto sent a bad {key} '{gw}'");
                    self.iface_error(name, "proto", "INVALID_GATEWAY", &[gw]);
                    break;
                };
                if nexthop.is_ipv6() != v6 {
                    break;
                }
                let target: IpAddr = if v6 {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                } else {
                    IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                };
                // parse_gateway_option sets neither DEVROUTE_METRIC nor
                // DEVROUTE_TABLE, so neither field is printed
                let mut r = interface::Route::new(target, 0, nexthop);
                r.metric = ic.metric;
                let t = if v6 { ic.ip6table } else { ic.ip4table };
                if let Some(t) = t.filter(|t| *t != 0) {
                    r.table = t;
                    r.flags |= interface::devroute::SRCTABLE;
                }
                self.add_iface_route(name, devidx, &r, &mut ipset);
            }
        }

        // `routes`/`routes6`: tables parsed by interface_ip_add_route
        for (key, v6) in [("routes", false), ("routes6", true)] {
            let Some(list) = find(key) else { continue };
            for item in list.children() {
                let Some(r) = proto::parse_route_item(&item, v6) else { continue };
                self.add_iface_route(name, devidx, &r, &mut ipset);
            }
        }
        // `neighbor`/`neighbor6`: permanent entries the protocol asks for
        for (key, v6) in [("neighbor", false), ("neighbor6", true)] {
            let Some(list) = find(key) else { continue };
            for item in list.children() {
                let Some(n) = proto::parse_neighbor_item(&item, v6) else { continue };
                let sn = sys::Neighbor {
                    addr: n.addr,
                    mac: n.mac,
                    proxy: n.proxy != 0,
                    router: n.router != 0,
                };
                if let Err(e) = self.sys.neighbor(devidx, &sn, true) {
                    eprintln!("netifd-rs: {name}: cannot add the neighbour {}: {e}", n.addr);
                    continue;
                }
                ipset.neighbors.push(n);
            }
        }

        for d in find("dns").map(|f| string_list(&f)).unwrap_or_default() {
            match d.parse::<IpAddr>() {
                Ok(a) => ipset.dns_servers.push(a),
                Err(_) => eprintln!("netifd-rs: {name}: proto sent a bad dns '{d}'"),
            }
        }
        ipset
            .dns_search
            .extend(find("dns_search").map(|f| string_list(&f)).unwrap_or_default());
        ipset.no_delegation = ic.delegate == Some(false);

        // `data` is one table; each member is stored under its own name in an
        // avl tree, so the status prints them sorted, not in arrival order.
        let mut newdata: Vec<(String, owrt_ubus::json::Json)> = Vec::new();
        if let Some(t) = find("data") {
            for m in t.children() {
                let j = owrt_ubus::convert::field_to_json(&m);
                newdata.push((m.name.to_string(), j));
            }
        }

        // `IFPEV_UP`: the interface only completes its bring-up from SETUP.
        // One that is already up gets an IFEV_UPDATE; one that is DOWN --
        // because something took it down while the protocol was still
        // talking -- keeps what was applied but does NOT come up. Setting the
        // state unconditionally brought an unavailable interface back up.
        let prev_state = self.iface_index(name).map(|i| self.interfaces[i].state);
        if prev_state != Some(State::Setup) {
            if let Some(idx) = self.iface_index(name) {
                let i = &mut self.interfaces[idx];
                i.proto_ip = ipset;
                i.proto_ip.routes.sort_by(interface::route_order);
                i.updated = 0;
                if !i.proto_ip.addresses.is_empty() {
                    i.updated |= interface::updated::ADDRESS;
                }
                if !i.proto_ip.routes.is_empty() {
                    i.updated |= interface::updated::ROUTE;
                }
                let update = i.state == State::Up && i.updated != 0;
                if update {
                    self.emit_event(name, Event::Update);
                }
            }
            self.proto_state(name).sm = proto::Sm::Idle;
            return status::OK;
        }
        if let Some(idx) = self.iface_index(name) {
            let i = &mut self.interfaces[idx];
            i.state = State::Up;
            i.available = true;
            i.l3_device = Some(l3.clone());
            i.device = ic.device.clone();
            i.proto_ip = ipset;
            i.proto_ip.routes.sort_by(interface::route_order);
            i.updated = 0;
            if !i.proto_ip.addresses.is_empty() {
                i.updated |= interface::updated::ADDRESS;
            }
            if !i.proto_ip.routes.is_empty() {
                i.updated |= interface::updated::ROUTE;
            }
            if !newdata.is_empty() {
                for (k, v) in newdata {
                    // avl_find_element + replace: same name replaces
                    match i.data.iter_mut().find(|(n, _)| *n == k) {
                        Some(slot) => {
                            if slot.1 != v {
                                slot.1 = v;
                                i.updated |= interface::updated::DATA;
                            }
                        }
                        None => {
                            i.data.push((k, v));
                            i.updated |= interface::updated::DATA;
                        }
                    }
                }
                i.data.sort_by(|a, b| a.0.cmp(&b.0));
            }
            i.errors.clear();
        }
        self.start_time.retain(|(n, _)| n != name);
        self.start_time.push((name.to_string(), now()));
        self.proto_state(name).sm = proto::Sm::Idle;
        self.apply_prefix_assignments();
        self.emit_event(name, Event::Up);
        eprintln!("netifd-rs: Interface '{name}' is now up");
        status::OK
    }

    /// `IFPEV_LINK_LOST`. Only an interface that is already up loses
    /// anything: `dhcp.script` reports link-up false from its `deconfig` case
    /// before the lease exists, and that must be a no-op, not a teardown. When
    /// it does fire, the interface goes back to SETUP -- not DOWN -- because
    /// the helper is still running and may get a lease.
    fn link_lost(&mut self, name: &str) {
        let Some(idx) = self.iface_index(name) else { return };
        if self.interfaces[idx].state != State::Up {
            return;
        }
        eprintln!("netifd-rs: Interface '{name}' has lost the connection");
        self.mark_interface_down(name);
        if let Some(idx) = self.iface_index(name) {
            self.interfaces[idx].state = State::Setup;
        }
    }

    /// Apply one route to the kernel and record it for the status.
    fn add_iface_route(
        &mut self,
        name: &str,
        devidx: u32,
        r: &interface::Route,
        ipset: &mut interface::IpSettings,
    ) {
        let mut k = match r.target {
            IpAddr::V4(a) => sys::Route::v4(a, r.mask),
            IpAddr::V6(a) => sys::Route::v6(a, r.mask),
        };
        k.nexthop = r.nexthop;
        k.metric = r.metric;
        k.table = if r.table != 0 { r.table } else { sys::RT_TABLE_MAIN };
        k.mtu = (r.flags & interface::devroute::MTU != 0).then_some(r.mtu);
        if r.flags & interface::devroute::ONLINK != 0 {
            k.onlink = true;
        }
        if r.flags & interface::devroute::TYPE != 0 {
            k.ty = Some(r.ty as u8);
        }
        if r.flags & interface::devroute::PROTO != 0 {
            k.proto = Some(r.proto as u8);
        }
        if r.sourcemask != 0 {
            k.source = Some(r.source);
            k.sourcemask = r.sourcemask;
        }
        if let Err(e) = self.sys.add_route(devidx, &k) {
            eprintln!("netifd-rs: {name}: cannot add the route to {}/{}: {e}", r.target, r.mask);
            return;
        }
        ipset.routes.push(r.clone());
    }

    fn iface_error(&mut self, name: &str, subsystem: &str, code: &str, data: &[&str]) {
        if let Some(idx) = self.iface_index(name) {
            self.interfaces[idx].errors.push(interface::IfaceError {
                subsystem: subsystem.into(),
                code: code.into(),
                data: data.iter().map(|s| s.to_string()).collect(),
            });
        }
    }

    /// Poll both slots of every protocol state and apply the effects.
    /// Log what the children have printed so far. The C reads each process's
    /// pipe from uloop and logs whole lines as they arrive; without this a
    /// helper that never exits -- `udhcpc -f -t 0` is the normal case -- keeps
    /// everything it printed, errors included, in an unread pipe.
    fn poll_child_output(&mut self) {
        for line in self.hotplug.poll_lines() {
            eprintln!("netifd-rs: hotplug: {line}");
        }
        let names: Vec<String> = self.protos.iter().map(|(n, _)| n.clone()).collect();
        for name in names {
            let lines = {
                let st = self.proto_state(&name);
                let mut l = st.script.poll_lines();
                l.extend(st.task.poll_lines());
                l
            };
            for line in lines {
                eprintln!("netifd-rs: {name}: {line}");
            }
        }
    }

    fn reap_children(&mut self) {
        self.poll_child_output();
        if let Some((_, _, output)) = self.hotplug.reap() {
            for line in output.lines().filter(|l| !l.trim().is_empty()) {
                eprintln!("netifd-rs: hotplug: {line}");
            }
            self.hotplug_current = None;
            self.pump_hotplug();
        }
        let names: Vec<String> = self.protos.iter().map(|(n, _)| n.clone()).collect();
        for name in names {
            for which in [proto::Which::Script, proto::Which::Task] {
                let exited = {
                    let st = self.proto_state(&name);
                    match which {
                        proto::Which::Script => st.script.reap(),
                        proto::Which::Task => st.task.reap(),
                    }
                };
                let Some((argv0, status, output)) = exited else { continue };
                for line in output.lines().filter(|l| !l.trim().is_empty()) {
                    eprintln!("netifd-rs: {name}: {line}");
                }
                if status != 0 {
                    eprintln!("netifd-rs: {name}: {argv0} exited {status}");
                }
                if which == proto::Which::Task {
                    let st = self.proto_state(&name);
                    if matches!(st.sm, proto::Sm::Idle | proto::Sm::Setup) {
                        st.last_error = status;
                    }
                }
                let Some(ic) = self.cfg.interfaces.iter().find(|i| i.name == name).cloned()
                else {
                    continue;
                };
                let Some(handler) = self.handler_for(&ic.proto).cloned() else { continue };
                // `proto_ext_checkup_attach` reads `checkup_interval` out of
                // the config blob handed to the protocol -- which carries
                // only the parameters the handler declares. No handler on
                // this device declares it, so the timer is never armed, and
                // setting the option in UCI has no effect. Reading it
                // straight from UCI instead armed a teardown the C never
                // performs, and the interface then retried in a loop.
                let declared = proto::IFACE_ATTRS.iter().any(|(n, _)| *n == "checkup_interval")
                    || handler.config.iter().any(|(n, _)| n == "checkup_interval");
                let checkup =
                    if declared { ic.checkup_interval.unwrap_or(0) } else { 0 };
                let effects = {
                    let st = self.proto_state(&name);
                    proto::task_finish(st, which, &handler, checkup)
                };
                for e in effects {
                    match e {
                        proto::Finish::LinkLost => {
                            self.link_lost(&name);
                        }
                        // teardown is complete: this is the second IFEV_DOWN,
                        // and hotplug.d already ran on the first
                        proto::Finish::Down => {
                            self.mark_interface_down(&name);
                            self.handle_config_change(&name);
                        }
                        proto::Finish::Teardown => {
                            self.proto_cmd(&name, proto::Cmd::Teardown);
                        }
                        proto::Finish::Renew => {
                            self.proto_cmd(&name, proto::Cmd::Renew);
                        }
                        proto::Finish::SignalTask(sig) => {
                            let st = self.proto_state(&name);
                            st.task_killed = true;
                            let _ = st.task.signal(sig);
                        }
                        proto::Finish::ArmCheckup => {
                            let at = now() + checkup as u64;
                            self.proto_state(&name).checkup_at = Some(at);
                        }
                    }
                }
            }
        }
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

    /// `__interface_set_down`, followed by the teardown completing. Static
    /// interfaces have nothing asynchronous to wait for, so both halves happen
    /// here.
    fn iface_down(&mut self, name: &str) {
        let Some(idx) = self.iface_index(name) else { return };
        // `interface_set_down` clears autostart first, which is what stops
        // `interface_handle_config_change` bringing it straight back up.
        // `interface_set_down(NULL)` -- what a restart uses -- does not, so
        // that path goes through `set_down` instead.
        self.interfaces[idx].autostart = false;
        self.set_down(name);
    }

    /// `__interface_set_down`, without touching autostart.
    fn set_down(&mut self, name: &str) {
        let Some(idx) = self.iface_index(name) else { return };
        let prev = self.interfaces[idx].state;
        // "case IFS_DOWN / case IFS_TEARDOWN: break" -- nothing to do
        if prev == State::Down || prev == State::Teardown {
            return;
        }
        // IFEV_DOWN on entering teardown, and only from IFS_UP
        self.begin_teardown(name, prev == State::Up);
    }

    /// The teardown half of `__interface_set_down`, also reached from
    /// `interface_check_state` when the carrier goes -- which does NOT emit
    /// IFEV_DOWN on the way in, so a carrier loss produces one ifdown where
    /// an explicit ifdown of an up interface produces two.
    fn begin_teardown(&mut self, name: &str, emit_down: bool) {
        let Some(idx) = self.iface_index(name) else { return };
        self.interfaces[idx].state = State::Teardown;
        if emit_down {
            self.emit_event(name, Event::Down);
        }
        // A shell protocol's teardown is a script, so the interface stays in
        // TEARDOWN until it exits and `Finish::Down` arrives. Without this the
        // helper -- udhcpc, pppd -- would outlive an ifdown.
        // An interface whose protocol has settled sits in S_IDLE, and S_IDLE
        // is exactly the state the teardown command runs from, so the state
        // machine must not be part of this test.
        let shell = match self.cfg.interfaces.iter().find(|i| i.name == name) {
            Some(ic) => {
                !IMPLEMENTED_PROTOS.contains(&ic.proto.as_str())
                    && self.handler_for(&ic.proto).is_some()
            }
            None => false,
        };
        if shell {
            self.proto_cmd(name, proto::Cmd::Teardown);
            return;
        }
        // the second IFEV_DOWN comes from mark_interface_down; hotplug.d has
        // already been called, so it goes out on the ubus channels only
        self.mark_interface_down(name);
        self.handle_config_change(name);
    }

    /// `_device_set_present`, for every device this daemon has an object for.
    /// A device that disappears takes its claims with it, so a device that
    /// comes back under the same name is claimed again rather than being
    /// assumed to still be up.
    fn update_presence(&mut self) {
        let mut watch: Vec<String> = self.known_device_names();
        for (n, _) in &self.claims {
            if !watch.contains(n) {
                watch.push(n.clone());
            }
        }
        for name in watch {
            let now = self.sys.if_index(&name).unwrap_or(0) != 0;
            let was = self.present.contains(&name);
            if now == was {
                continue;
            }
            if now {
                self.present.push(name.clone());
                eprintln!("netifd-rs: device '{name}' is now present");
                self.device_added(&name);
            } else {
                self.present.retain(|n| *n != name);
                eprintln!("netifd-rs: device '{name}' is no longer present");
                self.device_removed(&name);
            }
        }
    }

    /// `DEV_EVENT_ADD` reaching the interfaces that use this device.
    fn device_added(&mut self, dev: &str) {
        for name in self.ifaces_using(dev) {
            self.set_available(&name, true);
        }
    }

    /// `DEV_EVENT_REMOVE`, followed by `device_release_cb` over every user.
    fn device_removed(&mut self, dev: &str) {
        for name in self.ifaces_using(dev) {
            self.set_available(&name, false);
        }
        // the claims cannot be released through the kernel any more, so drop
        // them without trying to change a link that no longer exists
        self.claims.retain(|(n, _)| n != dev);
        self.claimed_main.retain(|(_, d)| d != dev);
        self.claimed_l3.retain(|(_, d)| d != dev);
        if let Some(pos) = self.parents.iter().position(|(c, _)| c == dev) {
            let (_, p) = self.parents.remove(pos);
            self.device_release(&p);
        }
        self.parents.retain(|(_, p)| p != dev);
    }

    fn ifaces_using(&self, dev: &str) -> Vec<String> {
        self.cfg
            .interfaces
            .iter()
            .filter(|ic| ic.device.as_deref() == Some(dev))
            .map(|ic| ic.name.clone())
            .collect()
    }

    /// `interface_set_available`. Losing the device is a forced teardown: the
    /// state is flushed at once rather than waiting for the script, because
    /// there is nothing left to tear down on.
    fn set_available(&mut self, name: &str, avail: bool) {
        let Some(idx) = self.iface_index(name) else { return };
        if self.interfaces[idx].available == avail {
            return;
        }
        self.interfaces[idx].available = avail;
        if avail {
            if self.interfaces[idx].autostart {
                self.iface_up(name);
            }
            return;
        }
        let prev = self.interfaces[idx].state;
        if prev == State::Up || prev == State::Setup {
            self.begin_teardown(name, prev == State::Up);
            // `if (force) interface_flush_state(iface)`: release the L3
            // device and drop the protocol's data, but leave the interface in
            // TEARDOWN. Marking it down here instead collapsed the two
            // IFEV_DOWNs into one hotplug call, because the second landed
            // while the first was still running.
            self.iface_unclaim(name, true);
            if let Some(i) = self.iface_index(name) {
                self.interfaces[i].data.clear();
            }
        }
        self.link_state.retain(|(n, _)| n != name);
    }

    /// Refresh every interface's link state from its main device's carrier.
    /// Used on netlink events, where the C is also reacting to whatever the
    /// kernel just reported.
    fn update_link_states(&mut self) {
        for name in self.interfaces.iter().map(|i| i.name.clone()).collect::<Vec<_>>() {
            self.update_link_state(&name);
        }
    }

    /// The same for one interface. A device event in the C reaches only that
    /// device's users, so claiming one device must not re-evaluate every
    /// interface: doing that let a later interface come up during an earlier
    /// one's bring-up, which reordered the startup ifup sequence.
    fn update_link_state(&mut self, name: &str) {
        let Some(idx) = self.iface_index(name) else { return };
        let Some(dev) = self.interfaces[idx].device.clone() else { return };
        let active = self.devices.get(&dev).map(|d| d.link_active).unwrap_or(false);
        self.set_link_state(name, active);
    }

    /// `interface_set_link_state`. `carrier_loss_delay` is not configured on
    /// this device, so there is no grace window: the check runs immediately.
    fn set_link_state(&mut self, name: &str, new_state: bool) {
        // `iface->link_state` starts false, so the first time a link is seen
        // up that IS a transition -- swallowing it left the interface waiting
        // for a second carrier event that never came.
        let prev = self.link_state.iter().find(|(n, _)| n == name).map(|(_, s)| *s);
        if prev.unwrap_or(false) == new_state {
            return;
        }
        match self.link_state.iter_mut().find(|(n, _)| n == name) {
            Some(slot) => slot.1 = new_state,
            None => self.link_state.push((name.to_string(), new_state)),
        }
        eprintln!(
            "netifd-rs: Interface '{name}' has link connectivity {}",
            if new_state { "" } else { "loss" }
        );
        self.check_state(name);
    }

    /// `interface_check_state`: losing the link tears the interface down, and
    /// getting it back brings the interface up again if it is still set to
    /// autostart.
    fn check_state(&mut self, name: &str) {
        let Some(idx) = self.iface_index(name) else { return };
        let link =
            self.link_state.iter().find(|(n, _)| n == name).map(|(_, s)| *s).unwrap_or(false);
        let enabled = self.interfaces[idx].enabled;
        match self.interfaces[idx].state {
            State::Up | State::Setup => {
                if !enabled || !link {
                    self.begin_teardown(name, false);
                }
            }
            State::Down => {
                if !self.interfaces[idx].available {
                    return;
                }
                if self.interfaces[idx].autostart && enabled && link {
                    self.set_up_now(name);
                }
            }
            State::Teardown => {}
        }
    }

    /// `netifd_handle_set_state`.
    fn device_set_state(&mut self, data: &[u8]) -> i32 {
        let fields: Vec<blob::Field> = blob::fields(data).collect();
        let find = |n: &str| fields.iter().find(|f| f.name == n).copied();
        let Some(name) = find("name").and_then(|f| f.as_str()).map(|s| s.to_string()) else {
            return status::INVALID_ARGUMENT;
        };
        if self.devices.get(&name).is_none() {
            return status::NOT_FOUND;
        }
        if let Some(defer) = find("defer").and_then(|f| f.as_bool()) {
            if let Some(d) = self.devices.get_mut(&name) {
                d.deferred = defer;
                // `device_refresh_present`
                d.present = d.sys_present && !d.deferred;
            }
        }
        if let Some(a) = find("auth_status").and_then(|f| f.as_bool()) {
            if let Some(d) = self.devices.get_mut(&name) {
                d.auth_status = a;
            }
        }
        status::OK
    }

    /// `netifd_handle_alias`.
    fn device_set_alias(&mut self, data: &[u8]) -> i32 {
        let fields: Vec<blob::Field> = blob::fields(data).collect();
        let Some(alias) = fields.iter().find(|f| f.name == "alias") else {
            return status::INVALID_ARGUMENT;
        };
        for a in alias.children() {
            if a.ty != MsgType::String as u32 || a.as_str().is_none_or(|s| s.is_empty()) {
                // the C's `error:` path is the one that collects
                self.free_unused_devices();
                return status::INVALID_ARGUMENT;
            }
        }
        if let Some(dev) = fields
            .iter()
            .find(|f| f.name == "device")
            .and_then(|f| f.as_str())
            .map(|s| s.to_string())
        {
            // `device_get(name, true)` creates the object, and `device_init`
            // clears the device's kernel state exactly once
            if !self.device_objects.contains(&dev) {
                self.device_objects.push(dev.clone());
                self.sys.clear_state(&dev, false);
            }
            self.rescan_devices();
        }
        status::OK
    }

    /// `netifd_add_dynamic`: an interface created at runtime rather than from
    /// the config, with the request itself as its config.
    fn add_dynamic(&mut self, data: &[u8]) -> i32 {
        let fields: Vec<blob::Field> = blob::fields(data).collect();
        let Some(name) = fields
            .iter()
            .find(|f| f.name == "name")
            .and_then(|f| f.as_str())
            .map(|s| s.to_string())
        else {
            return status::INVALID_ARGUMENT;
        };
        if self.interfaces.iter().any(|i| i.name == name) {
            return status::OK;
        }
        // `get_proto_handler`: no `proto` in the config means the "none"
        // handler, and the status prints that name
        let mut ic = config::InterfaceConfig {
            name: name.clone(),
            proto: "none".to_string(),
            ..Default::default()
        };
        for f in &fields {
            match f.name {
                "proto" => ic.proto = f.as_str().unwrap_or_default().to_string(),
                "device" | "ifname" => ic.device = f.as_str().map(|s| s.to_string()),
                "auto" => ic.auto = f.as_bool(),
                "metric" => ic.metric = f.as_u32().unwrap_or(0),
                _ => {}
            }
        }
        self.cfg.interfaces.push(ic.clone());
        // `interface_claim_device`: `device_get(iface->device, true)` creates
        // the device object -- and with it its parent's -- so both show up in
        // `network.device status`
        if let Some(dev) = ic.device.clone() {
            if !self.device_objects.contains(&dev) {
                self.device_objects.push(dev.clone());
                self.sys.clear_state(&dev, false);
            }
            self.rescan_devices();
        }
        let mut i = self.new_interface(&ic);
        i.dynamic = true;
        // available is set by `interface_set_main_dev`, which is what starts
        // the interface -- so go through `set_available` rather than setting
        // the field, or a dynamic interface with a real device never comes up
        let present = i.available;
        i.available = false;
        self.interfaces.push(i);
        self.interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        if let Err(e) = self.register_interface(&name) {
            eprintln!("netifd-rs: cannot register {name}: {e}");
            return status::UNKNOWN_ERROR;
        }
        eprintln!("netifd-rs: Create interface '{name}'");
        if present {
            self.set_available(&name, true);
        }
        // `interface_update`'s create branch does NOT start the interface --
        // it creates it, claims its device and registers the object. It comes
        // up when `interface_set_available(true)` fires, which is why the C
        // leaves a device-less dynamic interface down with no error.
        status::OK
    }

    /// The `remove` timer firing: `vlist_delete`. It takes the interface out
    /// whether it came from the config or from `add_dynamic` -- r55 seemed to
    /// show a config interface surviving, but that dump was taken before the
    /// 100ms timer fired; given two seconds, the C removes it and its
    /// address.
    fn pump_removals(&mut self) {
        if self.remove_pending.is_empty() {
            return;
        }
        for name in std::mem::take(&mut self.remove_pending) {
            if self.iface_index(&name).is_none() {
                continue;
            }
            eprintln!("netifd-rs: Remove interface '{name}'");
            // Exactly one ifdown. `mark_interface_down` flushes the state,
            // releases the claims and emits a single IFEV_DOWN; adding
            // `set_down` first emitted a second one, and skipping both
            // emitted none. The C emits one.
            self.mark_interface_down(&name);
            self.interfaces.retain(|i| i.name != name);
            self.cfg.interfaces.retain(|c| c.name != name);
            if let Err(e) = self.objects.remove_interface(&mut self.conn, &name) {
                eprintln!("netifd-rs: cannot unregister {name}: {e}");
            }
            self.link_state.retain(|(n, _)| *n != name);
            self.protos.retain(|(n, _)| *n != name);
        }
    }

    /// `proto_ext_add_host_dependency`: the protocol says this interface is
    /// only usable while some host, or some other interface, is reachable.
    fn add_host_dependency(&mut self, name: &str, fields: &[blob::Field]) -> i32 {
        let find = |n: &str| fields.iter().find(|f| f.name == n).copied();
        let ifname = find("ifname").and_then(|f| f.as_str()).unwrap_or("").to_string();
        let host = find("host").and_then(|f| f.as_str()).unwrap_or("").to_string();

        // "no host but an interface" is a dependency on that interface alone
        let mut dep = HostDep {
            owner: name.to_string(),
            interface: ifname.clone(),
            host: None,
            any: false,
            satisfied_by: None,
        };
        if host.is_empty() && !ifname.is_empty() {
            dep.any = true;
        } else {
            match host.parse::<std::net::Ipv4Addr>() {
                Ok(a) => dep.host = Some(IpAddr::V4(a)),
                Err(_) => match host.parse::<Ipv6Addr>() {
                    Ok(a) => dep.host = Some(IpAddr::V6(a)),
                    Err(_) => return status::INVALID_ARGUMENT,
                },
            }
        }
        self.resolve_host_dep(&mut dep);
        let satisfied = dep.satisfied_by.is_some();
        self.host_deps.push(dep);
        self.check_dependencies(name);
        if satisfied {
            status::OK
        } else {
            status::NOT_FOUND
        }
    }

    /// `proto_ext_update_host_dep`: a named interface must exist and be up;
    /// a host must be reachable through some interface.
    fn resolve_host_dep(&mut self, dep: &mut HostDep) {
        let mut via: Option<String> = None;
        if !dep.interface.is_empty() {
            let up = self
                .iface_index(&dep.interface)
                .map(|i| self.interfaces[i].state == State::Up)
                .unwrap_or(false);
            if !up {
                dep.satisfied_by = None;
                return;
            }
            via = Some(dep.interface.clone());
        }
        if dep.any {
            dep.satisfied_by = via;
            return;
        }
        let Some(host) = dep.host else {
            dep.satisfied_by = None;
            return;
        };
        let v6 = host.is_ipv6();
        dep.satisfied_by = self.target_route(host, v6, via, None).ok();
    }

    /// `proto_ext_check_dependencies`: the interface is available only while
    /// every dependency it declared is satisfied.
    fn check_dependencies(&mut self, name: &str) {
        let all = self
            .host_deps
            .iter()
            .filter(|d| d.owner == name)
            .all(|d| d.satisfied_by.is_some());
        self.set_available(name, all);
    }

    /// `netifd_add_host_route` -> `interface_ip_add_target_route`: which
    /// interface would carry traffic to this host, adding a host route when
    /// one is needed. A target that is already on one of an interface's own
    /// subnets needs no route at all -- the answer is just that interface's
    /// name, which is what the callers (a tunnel keeping its endpoint
    /// reachable) are asking for.
    fn add_host_route(&mut self, data: &[u8]) -> Result<String, i32> {
        let fields: Vec<blob::Field> = blob::fields(data).collect();
        let find = |n: &str| fields.iter().find(|f| f.name == n).copied();
        let Some(target) = find("target").and_then(|f| f.as_str()) else {
            return Err(status::INVALID_ARGUMENT);
        };
        let v6 = find("v6").and_then(|f| f.as_bool()).unwrap_or(false);
        let exclude = find("exclude").and_then(|f| f.as_bool()).unwrap_or(false);
        let named = find("interface").and_then(|f| f.as_str()).map(|s| s.to_string());

        let addr: IpAddr = match v6 {
            false => target.parse::<std::net::Ipv4Addr>().map(IpAddr::V4),
            true => target.parse::<Ipv6Addr>().map(IpAddr::V6),
        }
        .map_err(|_| status::INVALID_ARGUMENT)?;

        // `exclude` turns the named interface from the one to search into the
        // one to skip
        let (only, skip) = if exclude { (None, named) } else { (named, None) };
        self.target_route(addr, v6, only, skip)
    }

    /// Which interface can reach `addr`, adding a host route if one is
    /// needed. `only` restricts the search to a single interface; `skip`
    /// excludes one.
    fn target_route(
        &mut self,
        addr: IpAddr,
        v6: bool,
        only: Option<String>,
        skip: Option<String>,
    ) -> Result<String, i32> {
        let names: Vec<String> = match &only {
            Some(n) => vec![n.clone()],
            None => self.interfaces.iter().map(|i| i.name.clone()).collect(),
        };
        let mut best: Option<(u8, String, IpAddr)> = None;
        for name in names {
            if Some(&name) == skip.as_ref() {
                continue;
            }
            let Some(idx) = self.iface_index(&name) else { continue };
            let i = &self.interfaces[idx];
            // "look for locally addressable target first": an address whose
            // own subnet covers the target answers immediately
            if i.proto_ip.addresses.iter().any(|a| {
                a.enabled && a.addr.is_ipv6() == v6 && in_prefix(addr, a.addr, a.mask)
            }) {
                return Ok(name);
            }
            // otherwise keep the longest-prefix route across every interface
            for r in &i.proto_ip.routes {
                if !r.enabled || r.target.is_ipv6() != v6 || !in_prefix(addr, r.target, r.mask) {
                    continue;
                }
                if best.as_ref().is_none_or(|(m, _, _)| r.mask > *m) {
                    best = Some((r.mask, name.clone(), r.nexthop));
                }
            }
        }
        let Some((_, name, nexthop)) = best else { return Err(status::NOT_FOUND) };
        // the unspecified address is a request for "who has the default
        // route", and gets no host route of its own
        let unspecified = match addr {
            IpAddr::V4(a) => a.is_unspecified(),
            IpAddr::V6(a) => a.is_unspecified(),
        };
        if unspecified {
            return Ok(name);
        }
        let mask = if v6 { 128 } else { 32 };
        let mut r = interface::Route::new(addr, mask, nexthop);
        r.flags = 0;
        if let Some(idx) = self.iface_index(&name) {
            let dev = self.interfaces[idx].l3_device.clone();
            if let Some(dev) = dev {
                if let Ok(di) = self.sys.if_index(&dev) {
                    if di != 0 {
                        let mut ipset = self.interfaces[idx].proto_ip.clone();
                        self.add_iface_route(&name, di, &r, &mut ipset);
                        if let Some(idx) = self.iface_index(&name) {
                            self.interfaces[idx].proto_ip = ipset;
                            self.interfaces[idx].proto_ip.routes.sort_by(interface::route_order);
                        }
                    }
                }
            }
        }
        Ok(name)
    }

    /// `interface_parse_data`: merge a table of named values into the
    /// interface's data. Note that it clears `updated` FIRST -- so a second
    /// call with the same values leaves the status with no `updated` key at
    /// all, which is how r55 caught this -- and only counts as a change when
    /// a value actually differs.
    fn set_data(&mut self, name: &str, data: &[u8]) -> i32 {
        let Some(idx) = self.iface_index(name) else { return status::NOT_FOUND };
        self.interfaces[idx].updated = 0;
        for f in blob::fields(data) {
            let v = owrt_ubus::convert::field_to_json(&f);
            let key = f.name.to_string();
            match self.interfaces[idx].data.iter_mut().find(|(n, _)| *n == key) {
                Some(slot) => {
                    if slot.1 != v {
                        slot.1 = v;
                        self.interfaces[idx].updated |= interface::updated::DATA;
                    }
                }
                None => {
                    self.interfaces[idx].data.push((key, v));
                    self.interfaces[idx].updated |= interface::updated::DATA;
                }
            }
        }
        // an avl tree keyed by name, so the status prints them sorted
        self.interfaces[idx].data.sort_by(|a, b| a.0.cmp(&b.0));
        if self.interfaces[idx].updated != 0 && self.interfaces[idx].state == State::Up {
            self.emit_event(name, Event::Update);
        }
        status::OK
    }

    /// `interface_handle_config_change`, reached from every `IFPEV_DOWN`. Its
    /// last line is what makes netifd self-healing: an interface that is still
    /// set to autostart comes straight back up. That is how a protocol whose
    /// helper was killed recovers -- link lost, teardown, down, and then up
    /// again with a new helper -- and it is why `ifdown` clearing autostart is
    /// the step that actually keeps an interface down.
    ///
    /// Only a completed teardown gets here. A failed *setup* ends in
    /// IFEV_UP_FAILED, which does not, so a protocol that cannot come up does
    /// not spin.
    fn handle_config_change(&mut self, name: &str) {
        let autostart = self
            .iface_index(name)
            .map(|i| self.interfaces[i].autostart)
            .unwrap_or(false);
        if autostart {
            self.iface_up(name);
        }
    }

    /// `mark_interface_down`: flush everything the protocol applied, release
    /// the L3 device and emit the state's event. Returns early when already
    /// down, so a second call emits nothing.
    fn mark_interface_down(&mut self, name: &str) {
        let Some(idx) = self.iface_index(name) else { return };
        let prev = self.interfaces[idx].state;
        if prev == State::Down {
            return;
        }
        // The C's order: the state and the event first, the kernel afterwards.
        // A subscriber that reads the status on the event therefore sees a
        // DOWN interface whose addresses are still on the device.
        // `IFPEV_DOWN` logs before it marks the interface down
        if prev != State::Setup {
            eprintln!("netifd-rs: Interface '{name}' is now down");
        }
        self.interfaces[idx].state = State::Down;
        match prev {
            State::Up | State::Teardown => self.emit_event(name, Event::Down),
            State::Setup => self.emit_event(name, Event::UpFailed),
            State::Down => {}
        }

        let l3 = self.interfaces[idx].l3_device.clone();
        let addrs: Vec<Address> = self.interfaces[idx].proto_ip.addresses.clone();
        let routes: Vec<interface::Route> = self.interfaces[idx].proto_ip.routes.clone();
        let neighs: Vec<interface::Neighbor> = self.interfaces[idx].proto_ip.neighbors.clone();
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
                        if let Err(e) = self.sys.del_route(di, &sr) {
                            eprintln!(
                                "netifd-rs: {name}: cannot remove the route to {}/{}: {e}",
                                r.target, r.mask
                            );
                        }
                    }
                    for n in &neighs {
                        let sn = sys::Neighbor {
                            addr: n.addr,
                            mac: n.mac,
                            proxy: n.proxy != 0,
                            router: n.router != 0,
                        };
                        let _ = self.sys.neighbor(di, &sn, false);
                    }
                    for a in &addrs {
                        let sa = sys::Address::new(a.addr, a.mask);
                        if let Err(e) = self.sys.del_address(di, &sa) {
                            eprintln!(
                                "netifd-rs: {name}: cannot remove {}/{}: {e}",
                                a.addr, a.mask
                            );
                        }
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
        let released = i.l3_device.take();
        // `device` is main_dev and survives the interface going down
        i.updated = 0;
        i.proto_ip = interface::IpSettings::default();
        i.prefix_assignments.clear();
        // `interface_flush_state` calls `interface_data_flush`, so the data a
        // protocol reported does not survive its interface going down
        i.data.clear();

        self.start_time.retain(|(n, _)| n != name);

        let _ = released;
        // `IFPEV_DOWN`: main_dev is kept only while the interface would come
        // straight back up, so `ifdown` (which clears autostart) releases it
        // and a lost link does not.
        let keep_main = self
            .iface_index(name)
            .map(|i| self.interfaces[i].autostart && self.interfaces[i].available)
            .unwrap_or(false);
        if !keep_main {
            self.iface_unclaim(name, false);
        }
        self.iface_unclaim(name, true);
        self.rescan_devices();
    }

    /// `interface_queue_event`, for the events this build produces.
    ///
    /// Three things happen, and all three matter to a live system: the
    /// `network.interface` broadcast (what scripts listen for), the
    /// `interface.update` / `interface.down` notification on both the shared
    /// and the per-interface object (what subscribers get), and the
    /// hotplug.d call (what reconfigures the firewall, DNS and DHCP).
    /// `interface_queue_event`: the broadcast and the notification go out
    /// every time; whether hotplug.d runs is decided by the queue.
    fn emit_event(&mut self, name: &str, ev: Event) {
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

        self.call_hotplug(name, ev);
    }

    /// `run_cmd`: fork `/sbin/hotplug-call iface` with the event in the
    /// environment.
    ///
    /// This must NOT wait for the child. The hotplug scripts call back into
    /// `network.interface.<name> status` over ubus, so a daemon blocked in
    /// `wait()` deadlocks against its own hotplug handler -- which is exactly
    /// what happened: every ubus call timed out and the scripts reported
    /// "Request timed out". `interface_queue_event` runs one at a time and
    /// returns to the event loop, so the queue below does the same.
    fn call_hotplug(&mut self, name: &str, ev: Event) {
        if !std::path::Path::new(&self.hotplug_path).exists() {
            return;
        }
        // An interface holds at most one queued event and one being handled.
        // Repeating the event already running drops the new one -- which is
        // why a static teardown's two IFEV_DOWNs are one hotplug call, while
        // a shell protocol's two, separated by the teardown script, are two.
        let queued = self.hotplug_queue.iter().position(|(n, _)| n == name);
        let running = self.hotplug_current.as_ref().filter(|(n, _)| n == name).map(|(_, e)| *e);
        match (running, queued) {
            (Some(_), Some(i)) => {
                // an update never displaces a real state change
                if ev != Event::Update {
                    self.hotplug_queue[i].1 = ev;
                }
            }
            (Some(cur), None) => {
                if ev != cur || ev == Event::Update {
                    self.hotplug_queue.push((name.to_string(), ev));
                }
            }
            (None, Some(i)) => {
                // an ifupdate does not displace a queued ifup
                if !(self.hotplug_queue[i].1 == Event::Up && ev == Event::Update) {
                    self.hotplug_queue[i].1 = ev;
                }
            }
            (None, None) => self.hotplug_queue.push((name.to_string(), ev)),
        }
        self.pump_hotplug();
    }

    /// Start the next queued hotplug call if none is running.
    fn pump_hotplug(&mut self) {
        if self.hotplug.is_running() || self.hotplug_queue.is_empty() {
            return;
        }
        let (name, ev) = self.hotplug_queue.remove(0);
        let (argv, env) = self.hotplug_argv(&name, ev);
        match self.hotplug.start(&argv, &env) {
            Ok(()) => self.hotplug_current = Some((name, ev)),
            Err(e) => {
                eprintln!("netifd-rs: cannot run {} for {name}: {e}", self.hotplug_path);
                self.hotplug_current = None;
            }
        }
    }

    fn hotplug_argv(&self, name: &str, ev: Event) -> (Vec<String>, Vec<(String, String)>) {
        let action = match ev {
            Event::Up => "ifup",
            Event::Down => "ifdown",
            Event::UpFailed => "ifup-failed",
            Event::Update => "ifupdate",
        };
        let argv = vec![self.hotplug_path.clone(), "iface".to_string()];
        let mut env = vec![
            ("ACTION".to_string(), action.to_string()),
            ("INTERFACE".to_string(), name.to_string()),
        ];
        if matches!(ev, Event::Up | Event::Update) {
            if let Some(i) = self.interfaces.iter().find(|i| i.name == name) {
                if let Some(d) = &i.l3_device {
                    env.push(("DEVICE".to_string(), d.clone()));
                }
                if matches!(ev, Event::Update) {
                    for (flag, var) in [
                        (interface::updated::ADDRESS, "IFUPDATE_ADDRESSES"),
                        (interface::updated::ROUTE, "IFUPDATE_ROUTES"),
                        (interface::updated::PREFIX, "IFUPDATE_PREFIXES"),
                        (interface::updated::DATA, "IFUPDATE_DATA"),
                    ] {
                        if i.updated & flag != 0 {
                            env.push((var.to_string(), "1".to_string()));
                        }
                    }
                }
            }
        }
        (argv, env)
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
        let mut target = self.objects.route(req.objid);
        let method = req.method.clone();

        // `netifd_add_iface_object` replaces every method of the shared
        // `network.interface` object except `dump` with a resolver that reads
        // the interface name out of the payload and then calls the
        // per-interface handler. `netifd-proto.sh` relies on this: it always
        // calls `ubus call network.interface notify_proto {..., "interface":
        // "<name>"}`, never the per-interface object. Registration is
        // unaffected -- `ubus -v list` shows the object TYPE's signature,
        // which still carries each method's own policy.
        let mut resolved: Option<String> = None;
        if target == ubus::Target::Interface(None) && method != "dump" {
            let name = blob::fields(&req.data)
                .find(|f| f.name == "interface" && f.ty == MsgType::String as u32)
                .and_then(|f| f.as_str().map(|s| s.to_string()));
            let Some(name) = name else {
                let _ = self.conn.reply_status(&req, status::INVALID_ARGUMENT, None);
                return;
            };
            if !self.interfaces.iter().any(|i| i.name == name) {
                let _ = self.conn.reply_status(&req, status::NOT_FOUND, None);
                return;
            }
            resolved = Some(name);
        }
        if let Some(name) = &resolved {
            target = ubus::Target::Interface(Some(name));
        }
        let r = match (target, method.as_str()) {
            // `netifd_reload` is just `config_init_all`: it does not take
            // anything down. Only `netifd_restart` does, and it uses
            // `interface_set_down(NULL)`, which does NOT clear autostart --
            // so everything comes back up afterwards.
            (ubus::Target::Network, "reload") => {
                self.reload();
                self.conn.reply_status(&req, status::OK, None)
            }
            (ubus::Target::Network, "restart") => {
                for name in
                    self.interfaces.iter().map(|i| i.name.clone()).collect::<Vec<_>>()
                {
                    self.set_down(&name);
                }
                self.reload();
                self.conn.reply_status(&req, status::OK, None)
            }
            // `netifd_add_host_route`
            (ubus::Target::Network, "add_host_route") => {
                match self.add_host_route(&req.data) {
                    Ok(iface) => {
                        let mut b = BlobBuf::new();
                        b.msg_string("interface", &iface);
                        let fields = b.payload().to_vec();
                        if let Err(e) = self.conn.reply_data(&req, &fields) {
                            eprintln!("netifd-rs: cannot reply to add_host_route: {e}");
                        }
                        self.conn.reply_status(&req, status::OK, None)
                    }
                    Err(code) => self.conn.reply_status(&req, code, None),
                }
            }
            // `netifd_netns_updown` needs a netns fd passed by the caller
            // (`ubus_request_get_caller_fd`) and answers INVALID_ARGUMENT
            // without one. This build never receives fds and does not do
            // jails, so that is the only answer it can give -- the same one
            // the C gives to the same call.
            (ubus::Target::Network, "netns_updown") => {
                self.conn.reply_status(&req, status::INVALID_ARGUMENT, None)
            }
            // `netifd_add_dynamic`: the whole request is the config.
            (ubus::Target::Network, "add_dynamic") => {
                let code = self.add_dynamic(&req.data);
                self.conn.reply_status(&req, code, None)
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
                    // `netifd_dev_status`: `device_find` misses -> the C
                    // answers INVALID_ARGUMENT, not NOT_FOUND, and it does
                    // not check whether the device is present -- a device
                    // object with no kernel device is still dumped
                    Some(n) => match self.devices.get(&n) {
                        Some(d) => d.dump_status(&mut b, Some(&self.ethtool)),
                        None => {
                            let _ =
                                self.conn.reply_status(&req, status::INVALID_ARGUMENT, None);
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
            // `netifd_handle_set_state`
            (ubus::Target::Device, "set_state") => {
                let code = self.device_set_state(&req.data);
                self.conn.reply_status(&req, code, None)
            }
            // `netifd_handle_alias`. Alias devices themselves are out of
            // scope (R45), so nothing is notified -- but the side effect that
            // r55 saw is real: naming a device here creates a device object
            // for it, which is then reported by `network.device status`.
            (ubus::Target::Device, "set_alias") => {
                let code = self.device_set_alias(&req.data);
                self.conn.reply_status(&req, code, None)
            }
            // `netifd_handle_stp_init` has nothing to initialise without an
            // STP daemon to talk to, and answers OK.
            (ubus::Target::Device, "stp_init") => {
                self.conn.reply_status(&req, status::OK, None)
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
            (ubus::Target::Interface(Some(name)), "renew") => {
                let name = name.to_string();
                self.proto_cmd(&name, proto::Cmd::Renew);
                self.conn.reply_status(&req, status::OK, None)
            }
            // `netifd_handle_set_data` -> `interface_parse_data`
            // `netifd_iface_handle_device` -> `interface_handle_link`.
            // Assigning a device to an interface by hotplug needs the device
            // type's hotplug ops, which nothing in this build has, so `add`
            // is NOT_SUPPORTED -- the same answer the C gives here. `remove`
            // reports that the named device is not linked to this interface.
            (ubus::Target::Interface(Some(name)), m @ ("add_device" | "remove_device")) => {
                let name = name.to_string();
                let has_name = blob::fields(&req.data)
                    .any(|f| f.name == "name" && f.ty == MsgType::String as u32);
                let code = if !has_name {
                    status::INVALID_ARGUMENT
                } else if m == "add_device" {
                    status::NOT_SUPPORTED
                } else {
                    let _ = &name;
                    status::INVALID_ARGUMENT
                };
                self.conn.reply_status(&req, code, None)
            }
            // `netifd_iface_remove`: arms a 100ms timer that deletes the
            // interface from the vlist. A second call while one is pending is
            // INVALID_ARGUMENT.
            (ubus::Target::Interface(Some(name)), "remove") => {
                let name = name.to_string();
                let code = if self.remove_pending.contains(&name) {
                    status::INVALID_ARGUMENT
                } else {
                    self.remove_pending.push(name);
                    status::OK
                };
                self.conn.reply_status(&req, code, None)
            }
            (ubus::Target::Interface(Some(name)), "set_data") => {
                let name = name.to_string();
                let code = self.set_data(&name, &req.data);
                self.conn.reply_status(&req, code, None)
            }
            // `netifd_handle_iface_prepare`: it asks the main device's
            // hotplug ops to prepare, and replies with the bridge they
            // report. No device type in this build has hotplug ops, so the
            // reply is the empty table the C sends in that case.
            (ubus::Target::Interface(Some(name)), "prepare") => {
                let _ = name;
                let b = BlobBuf::new();
                if let Err(e) = self.conn.reply_data(&req, b.payload()) {
                    eprintln!("netifd-rs: cannot reply to prepare: {e}");
                }
                self.conn.reply_status(&req, status::OK, None)
            }
            (ubus::Target::Interface(Some(name)), "notify_proto") => {
                let name = name.to_string();
                let code = self.notify_proto(&name, &req.data);
                self.conn.reply_status(&req, code, None)
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

    /// `get_proto_handlers`: the discovered shell handlers plus the built-in
    /// `static`. A handler is only listed once it can actually be run.
    fn dump_proto_handlers(&self, b: &mut BlobBuf) {
        for h in &self.handlers {
            h.dump_info(b);
        }
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
            Ok(msgs) if !msgs.is_empty() => {
                self.rescan_devices();
                self.update_presence();
                self.update_link_states();
            }
            Ok(_) => {}
            Err(e) => eprintln!("netifd-rs: netlink event read failed: {e}"),
        }
    }

    /// `netifd_ubus_reconnect_timer`: every two seconds until it succeeds.
    /// libubus re-registers every object on the new connection, so this does
    /// the same -- the three fixed objects and one per interface.
    fn retry_bus(&mut self) {
        if now() < self.bus_retry_at {
            return;
        }
        self.bus_retry_at = now() + BUS_RETRY_SECS;
        let conn = match Connection::connect(self.socket.as_deref()) {
            Ok(c) => c,
            Err(_) => return,
        };
        self.conn = conn;
        let objects = match ubus::Objects::register(&mut self.conn) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("netifd-rs: reconnected but cannot register: {e}");
                return;
            }
        };
        self.objects = objects;
        for name in self.interfaces.iter().map(|i| i.name.clone()).collect::<Vec<_>>() {
            if let Err(e) = self.objects.add_interface(&mut self.conn, &name) {
                eprintln!("netifd-rs: reconnected but cannot register {name}: {e}");
            }
        }
        self.bus_down = false;
        eprintln!("netifd-rs: reconnected to ubus");
    }

    fn run(&mut self) -> ! {
        loop {
            if self.bus_down {
                self.retry_bus();
            }
            // While the bus is gone its fd is not polled -- it is closed, and
            // polling it would spin. Everything else keeps running.
            let ubus_fd = if self.bus_down { -1 } else { self.conn.as_raw_fd() };
            let nl_fd = self.events.as_raw_fd();
            let mut fds = [
                PollFd { fd: ubus_fd, events: POLLIN, revents: 0 },
                PollFd { fd: nl_fd, events: POLLIN, revents: 0 },
                PollFd { fd: self.sigchld.as_raw_fd(), events: POLLIN, revents: 0 },
            ];
            // the timeout is only a backstop now that SIGCHLD wakes us
            match owrt_ubus::sys::poll_fds(&mut fds, 1000) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    eprintln!("netifd-rs: poll failed: {e}");
                    std::process::exit(1);
                }
            }
            if fds[2].revents & POLLIN != 0 {
                self.sigchld.drain();
            }
            self.reap_children();
            self.pump_removals();
            self.pump_checkups();
            if fds[1].revents & POLLIN != 0 {
                self.drain_netlink();
            }
            if !self.bus_down && fds[0].revents & (POLLIN | POLLHUP) != 0 {
                match self.conn.read_incoming() {
                    Ok(Incoming::Invoke(req)) => self.handle(req),
                    Ok(_) => {}
                    Err(e) => {
                        // `netifd_ubus_connection_lost`: retry, do not exit.
                        // Exiting only looks survivable because procd restarts
                        // the daemon -- and that loses every interface.
                        eprintln!("netifd-rs: bus connection lost: {e}");
                        self.bus_down = true;
                        self.bus_retry_at = now() + BUS_RETRY_SECS;
                    }
                }
            }
        }
    }
}

fn main() {
    let mut confdir = "/etc/config".to_string();
    let mut hotplug = DEFAULT_HOTPLUG_PATH.to_string();
    let mut protodir = DEFAULT_PROTO_DIR.to_string();
    let mut socket: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" => confdir = args.next().unwrap_or(confdir),
            "-s" => socket = args.next(),
            "-h" => hotplug = args.next().unwrap_or(hotplug),
            "-p" => protodir = args.next().unwrap_or(protodir),
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

    let mut n = match Netifd::new(&confdir, socket.as_deref(), &hotplug, &protodir) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("netifd-rs: startup failed: {e}");
            std::process::exit(1);
        }
    };
    n.reload();
    n.run()
}

#[cfg(test)]
mod reload_tests {
    use super::*;
#[test]
fn loading_the_same_config_twice_reports_no_change() {
    let dir = std::env::temp_dir().join(format!("r54test{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("network"),
        "config interface 'one'\n\toption device 'veth1'\n\toption proto 'static'\n\toption ipaddr '10.1.1.1/24'\n",
    )
    .unwrap();
    let a = config::load(dir.to_str().unwrap()).unwrap();
    let b = config::load(dir.to_str().unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let (x, y) = (&a.interfaces[0], &b.interfaces[0]);
    assert!(!config_changed(x, y), "\nA: {x:#?}\nB: {y:#?}");
}
}
