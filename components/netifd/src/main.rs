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

#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod clock;
mod config;
mod device;
mod ethtool;
mod ethtool_modes;
mod interface;
mod ip;
mod logging;
mod netdev_types;
mod netlink;
mod process;
mod proto;
mod rt;
mod sys;
mod ubus;
mod wireless;

use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

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
/// Where wireless.uc looks for handler scripts.
const DEFAULT_WIRELESS_DIR: &str = "/lib/netifd/wireless";
/// `DEFAULT_RESOLV_CONF`: what dnsmasq reads as its resolvfile.
const DEFAULT_RESOLV_CONF: &str = "/tmp/resolv.conf.d/resolv.conf.auto";

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

/// Keep netifd's existing oversized-reply failure path; ordinary aligned
/// replies can send DATA and final STATUS together without a payload copy.
fn reply_fields(conn: &mut Connection, req: &Request, fields: &[u8]) -> io::Result<()> {
    if fields.len().is_multiple_of(4) && fields.len() <= owrt_ubus::msg::MAX_MSGLEN - 16 {
        conn.reply_data_status(req, fields, status::OK)
    } else {
        conn.reply_data(req, fields).and_then(|()| conn.reply_status(req, status::OK, None))
    }
}

/// A blobmsg array of strings, or a single string as a one-element list.
fn string_list(f: &blob::Field) -> Vec<String> {
    if f.ty == MsgType::Array as u32 {
        return f.children().filter_map(|c| c.as_str().map(|s| s.to_string())).collect();
    }
    f.as_str().map(|s| vec![s.to_string()]).unwrap_or_default()
}

/// Whether a config change needs the interface reloaded. This is
/// `interface_change_config`, as a decision: what a changed interface
/// section needs. The C reloads (teardown + setup) only when the device, the
/// protocol, the protocol's own declared parameters, `zone`, the device
/// options carried in the section, or `auto` (from on to off) changed;
/// metric/table/defaultroute re-apply the IP sets in place, dns/peerdns
/// rewrite resolv.conf, delegate/ip6assign/ip6hint redo the assignments.
/// Comparing the whole section bounced the link for a `list dns` edit
/// (R81 F05).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Change {
    reload: bool,
    reload_ip: bool,
    delegation: bool,
    assignment: bool,
    autostart_changed: bool,
}

/// `proto_static`'s config_params (proto.c).
const STATIC_PARAMS: &[&str] =
    &["ipaddr", "ip6addr", "netmask", "broadcast", "gateway", "ip6gw", "ip6prefix", "ip6deprecated"];

/// `device_attr_list` names an interface section may carry
/// (`interface_device_config_changed`).
const IFACE_DEVICE_OPTS: &[&str] = &[
    "mtu", "mtu6", "macaddr", "txqueuelen", "ipv6", "promisc", "multicast", "rpfilter",
    "acceptlocal", "igmpversion", "mldversion", "neighreachabletime", "neighgcstaletime",
    "neighlocktime", "dadtransmits", "sendredirects", "enabled",
];

fn raw_get<'a>(c: &'a config::InterfaceConfig, name: &str) -> Option<&'a Vec<String>> {
    c.raw.iter().find(|r| r.name == name).map(|r| &r.values)
}

fn raw_differs(a: &config::InterfaceConfig, b: &config::InterfaceConfig, names: &[&str]) -> bool {
    names.iter().any(|n| raw_get(a, n) != raw_get(b, n))
}

fn classify_change(
    o: &config::InterfaceConfig,
    n: &config::InterfaceConfig,
    handler: Option<&proto::Handler>,
) -> Change {
    let mut c = Change::default();
    if o.device != n.device || o.proto != n.proto {
        c.reload = true;
    }
    // `uci_blob_check_equal(old, new, proto_handler->config_params)`
    let params: Vec<&str> = match handler {
        Some(h) => h.config.iter().map(|(name, _)| name.as_str()).collect(),
        None if n.proto == "static" => STATIC_PARAMS.to_vec(),
        None => Vec::new(),
    };
    if raw_differs(o, n, &params) || raw_differs(o, n, IFACE_DEVICE_OPTS) {
        c.reload = true;
    }
    let (oa, na) = (o.auto.unwrap_or(true), n.auto.unwrap_or(true));
    if oa != na {
        c.autostart_changed = true;
        if oa {
            c.reload = true;
        }
    }
    if raw_get(o, "zone") != raw_get(n, "zone") {
        c.reload = true;
    }
    if o.metric != n.metric
        || o.ip4table != n.ip4table
        || o.ip6table != n.ip6table
        || o.defaultroute.unwrap_or(true) != n.defaultroute.unwrap_or(true)
    {
        c.reload_ip = true;
    }
    if o.delegate != n.delegate {
        c.delegation = true;
    }
    if o.ip6assign != n.ip6assign
        || o.ip6hint != n.ip6hint
        || raw_differs(o, n, &["ip6class", "ip6ifaceid", "ip6weight"])
    {
        c.assignment = true;
    }
    c
}

/// `interface_set_route_info`: a route without its own metric or table takes
/// the interface's; a non-main table marks the route SRCTABLE.
fn set_route_info(r: &mut interface::Route, metric: u32, ip4table: u32, ip6table: u32) {
    if r.flags & interface::devroute::METRIC == 0 {
        r.metric = metric;
    }
    if r.flags & interface::devroute::TABLE == 0 {
        r.table = if r.target.is_ipv6() { ip6table } else { ip4table };
        if r.table != 0 {
            r.flags |= interface::devroute::SRCTABLE;
        }
    }
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

/// `ipv6-prefix` walks an interface's prefix vlist (address, then mask),
/// unlike `ipv6-prefix-assignment`, which walks the global head-inserted list.
fn status_prefixes(
    prefixes: &[ip::DevicePrefix],
    interfaces: &[Interface],
    name: &str,
) -> Vec<interface::Prefix> {
    let mut result: Vec<_> = prefixes
        .iter()
        .filter(|p| p.iface.as_deref() == Some(name))
        .map(|p| {
            let mut assigned: Vec<(String, Ipv6Addr, u8)> = interfaces
                .iter()
                .flat_map(|i| {
                    i.prefix_assignments
                        .iter()
                        .filter(|a| {
                            a.owner.as_ref().is_some_and(|(owner, addr, length)| {
                                owner.as_deref() == Some(name)
                                    && *addr == p.addr && *length == p.length
                            })
                        })
                        .map(move |a| (i.name.clone(), a.addr, a.length))
                })
                .collect();
            assigned.sort_by_key(|(_, a, _)| *a);
            interface::Prefix {
                addr: p.addr,
                length: p.length,
                preferred_until: p.preferred_until,
                valid_until: p.valid_until,
                class: p.class.clone(),
                assigned,
            }
        })
        .collect();
    result.sort_unstable_by_key(|p| (p.addr, p.length));
    result
}

/// `system_get_rtime`: seconds on the monotonic clock. See `clock`.
fn now() -> u64 {
    clock::now()
}

fn now_ms() -> u64 {
    clock::now_ms()
}

struct Netifd {
    cfg: Config,
    devices: Devices,
    interfaces: Vec<Interface>,
    prefixes: Vec<ip::DevicePrefix>,
    sys: sys::System,
    events: netlink::Netlink,
    /// Retry a failed recovery dump on the normal maintenance backstop.
    netlink_resync: bool,
    restart_at: Option<u64>,
    ethtool: ethtool::Ethtool,
    conn: Connection,
    /// Storage for read replies, reused across requests so a 32-interface
    /// dump does not regrow a fresh buffer from 1 KiB through several
    /// reallocations every time. Bounded after each send.
    reply: Option<BlobBuf>,
    // Allocation hint only; large dump bytes are still released after sending.
    dump_capacity_hint: usize,
    objects: ubus::Objects,
    confdir: String,
    /// `resolv_conf` (-r): where interface_write_resolv_conf writes.
    resolvconf: String,
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
    /// `bridge_hotplug_prepare`: a wireless handler needs its bridge before
    /// it can create the first port. Cleared when a member is removed.
    prepared_bridges: Vec<String>,
    /// A child's exit wakes the loop through this, rather than waiting for
    /// the poll timeout.
    sigchld: process::ChildSignal,
    /// `network.wireless`. Handlers run one at a time, as `run_handler` does.
    wirelessdir: String,
    whandlers: Vec<wireless::Handler>,
    wconfig: Vec<wireless::Radio>,
    wradios: Vec<WRadio>,
    wslot: process::Slot,
    wcur: Option<(String, &'static str)>,
    wdeadline: Option<u64>,
    wqueue: std::collections::VecDeque<(String, &'static str)>,
    wproc_checked: u64,
    prefix_expiry_checked: u64,
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
    /// Shell protocol state; also holds a static interface's old config
    /// transiently while a reload switches it to another protocol.
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
            // RTNLGRP_LINK only, as system-linux.c's rtnl_event socket: the C
            // acts on RTM_NEWLINK/DELLINK and nothing else. Subscribing to the
            // address groups as well made every RA lifetime refresh, lease and
            // neighbour churn on the box wake the daemon into a full device
            // rescan (~6 ms CPU each on the AX3000T) -- 0.7-1.6% idle CPU
            // against the C's ~0 (R82).
            netlink::grp(netlink::RTNLGRP_LINK),
        )?;
        events.set_nonblocking()?;
        let mut conn = Connection::connect(socket)?;
        conn.set_server_io_timeout(Duration::from_secs(1));
        let objects = ubus::Objects::register(&mut conn)?;
        Ok(Self {
            cfg: Config::default(),
            devices: Devices::new(),
            interfaces: Vec::new(),
            prefixes: Vec::new(),
            sys: sys::System::open()?,
            events,
            netlink_resync: false,
            restart_at: None,
            host_deps: Vec::new(),
            remove_pending: Vec::new(),
            socket: socket.map(|s| s.to_string()),
            bus_down: false,
            bus_retry_at: 0,
            wirelessdir: DEFAULT_WIRELESS_DIR.to_string(),
            whandlers: Vec::new(),
            wconfig: Vec::new(),
            wradios: Vec::new(),
            wslot: process::Slot::default(),
            wcur: None,
            wdeadline: None,
            wqueue: std::collections::VecDeque::new(),
            wproc_checked: 0,
            prefix_expiry_checked: 0,
            link_state: Vec::new(),
            present: Vec::new(),
            prepared_bridges: Vec::new(),
            sigchld: process::ChildSignal::install()?,
            device_objects: Vec::new(),
            claims: Vec::new(),
            parents: Vec::new(),
            claimed_main: Vec::new(),
            claimed_l3: Vec::new(),
            ethtool: ethtool::Ethtool::open()?,
            conn,
            reply: Some(BlobBuf::new()),
            dump_capacity_hint: 0,
            objects,
            confdir: confdir.to_string(),
            resolvconf: DEFAULT_RESOLV_CONF.to_string(),
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
        let _ = self.reload_checked();
    }

    /// Load the config and bring up what it asks for.
    ///
    /// A DELIBERATE DIVERGENCE from the C, and the reason is in the failure
    /// mode. The parser records what it cannot represent in `Config.errors`
    /// and still returns a config -- so a working `static` LAN whose address
    /// was just made invalid parses into an interface with no address, and
    /// applying that tears down a LAN that was carrying traffic in order to
    /// replace it with nothing. The C applies what it understood and logs the
    /// rest; a log line is not what the plan asks for.
    ///
    /// So: at startup the config is applied whatever it says, because
    /// refusing there leaves the box with no network at all and nothing is
    /// running yet to protect. On any later reload a config with errors is
    /// REFUSED whole -- the running state stays exactly as it was and the
    /// caller is told. Fix the config and reload again.
    fn reload_checked(&mut self) -> Result<(), String> {
        let first = self.interfaces.is_empty();
        let old = self.cfg.clone();
        let new = match config::load(&self.confdir) {
            Ok(c) => c,
            Err(e) => {
                logging::log!(Warning, "cannot load network config: {e}");
                return Err(format!("cannot load network config: {e}"));
            }
        };
        for e in new.warnings.iter().chain(new.errors.iter()) {
            logging::log!(Warning, "config: {e}");
        }
        if !first && !new.errors.is_empty() {
            let what: Vec<String> = new.errors.iter().map(|e| e.to_string()).collect();
            logging::log!(Warning,
                "refusing this reload -- {} problem(s); the running \
                 configuration is untouched",
                what.len()
            );
            return Err(format!("configuration refused: {}", what.join("; ")));
        }
        self.cfg = new;

        if self.handlers.is_empty() {
            self.handlers = proto::discover(std::path::Path::new(&self.protodir));
            let names: Vec<&str> = self.handlers.iter().map(|h| h.name.as_str()).collect();
            logging::log!(Debug, "shell protocol handlers: {}", names.join(" "));
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
            if self.device_present_now(&name) {
                self.present.push(name);
            }
        }
        self.create_devices();
        self.build_prefixes();
        if first {
            self.setup_interfaces();
        } else {
            self.apply_config_change(&old);
            // `network.reload` re-reads the wireless config too; it used to be
            // read once at startup and never again
            self.wireless_reload();
        }
        Ok(())
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
            // The removed interface keeps its old config entry until
            // `pump_removals` drops both records: `begin_teardown`,
            // `proto_cmd` and `finish_proto_task` look the protocol up there,
            // and without it a shell protocol's teardown script never ran and
            // the helper was SIGKILLed instead (R88 netifd F1).
            if !self.cfg.interfaces.iter().any(|c| c.name == oc.name) {
                self.cfg.interfaces.push(oc.clone());
            }
            // `set_config_state(if_old, IFC_REMOVE)`: torn down first, removed
            // once it is down -- the proto helper gets its teardown and is
            // then killed with the proto state (R81 F04)
            self.set_config_state(&oc.name, interface::ConfigState::Remove);
        }

        // new, then changed -- both in name order, as the vlist walk is
        let mut names: Vec<String> = new.iter().map(|c| c.name.clone()).collect();
        names.sort();
        for name in names {
            let nc = new.iter().find(|c| c.name == name).cloned().unwrap();
            match old.interfaces.iter().find(|o| o.name == name) {
                None => {
                    logging::log!(Debug, "Create interface '{name}'");
                    let i = self.new_interface(&nc);
                    self.interfaces.push(i);
                    self.interfaces.sort_by(|a, b| a.name.cmp(&b.name));
                    if let Err(e) = self.register_interface(&name) {
                        logging::log!(Warning, "cannot register {name}: {e}");
                    }
                    if nc.auto.unwrap_or(true) {
                        self.iface_up(&name);
                    }
                }
                Some(oc) => {
                    let handler = self.handler_for(&nc.proto).cloned();
                    let ch = classify_change(oc, &nc, handler.as_ref());
                    // everything `interface_change_config` copies over in
                    // place, reload or not
                    let new_routes: Vec<interface::Route> = self.config_routes_for(&nc.name);
                    let mut routes_changed = false;
                    if let Some(i) = self.iface_index(&name) {
                        let iface = &mut self.interfaces[i];
                        iface.metric = nc.metric;
                        iface.dns_metric = nc.dns_metric;
                        iface.ip4table = nc.ip4table.unwrap_or(0);
                        iface.ip6table = nc.ip6table.unwrap_or(0);
                        iface.proto_ip.no_dns = nc.peerdns == Some(false);
                        iface.proto_ip.no_defaultroute = nc.defaultroute == Some(false);
                        iface.proto_ip.no_delegation = nc.delegate == Some(false);
                        // `interface_replace_dns(&if_old->config_ip, ...)`
                        iface.config_ip.dns_servers = nc.dns.clone();
                        iface.config_ip.dns_search = nc.dns_search.clone();
                        if ch.autostart_changed {
                            iface.autostart = nc.auto.unwrap_or(true);
                        }
                        let old_keys: Vec<_> =
                            iface.config_ip.routes.iter().map(route_key).collect();
                        let new_keys: Vec<_> = new_routes.iter().map(route_key).collect();
                        routes_changed = old_keys != new_keys;
                    }
                    if ch.reload {
                        logging::log!(Debug,
                            "Reload interface '{name}' because of config changes"
                        );
                        // proto_shell keeps its own config until the old
                        // protocol is freed. A second reload during teardown
                        // must still use the first running configuration.
                        self.proto_state(&name)
                            .teardown_config
                            .get_or_insert_with(|| Box::new(oc.clone()));
                        self.set_config_state(&name, interface::ConfigState::Reload);
                        continue;
                    }
                    if routes_changed {
                        // the config_ip route vlist: departed routes leave the
                        // kernel, new ones enter it, while the interface is up
                        self.replace_config_routes(&name, new_routes);
                    }
                    if ch.reload_ip {
                        self.reload_ip(&name);
                    }
                    if ch.delegation {
                        self.update_prefix_delegation();
                    } else if ch.assignment {
                        // `interface_merge_assignment_data` ->
                        // `interface_refresh_assignments(true)`
                        self.refresh_prefix_assignments();
                    }
                    self.check_state(&name);
                }
            }
        }
        // `interface_change_config` ends with interface_write_resolv_conf
        self.write_resolv_conf();
    }

    /// The `config route`/`route6` sections attached to `name`, with the
    /// interface's own metric and tables filled in (`interface_set_route_info`).
    fn config_routes_for(&self, name: &str) -> Vec<interface::Route> {
        let (metric, t4, t6) = match self.cfg.interfaces.iter().find(|c| c.name == name) {
            Some(ic) => (ic.metric, ic.ip4table.unwrap_or(0), ic.ip6table.unwrap_or(0)),
            None => (0, 0, 0),
        };
        let mut out: Vec<interface::Route> = self
            .cfg
            .routes
            .iter()
            .filter(|r| r.interface == name)
            .map(|r| {
                let mut x = r.route.clone();
                set_route_info(&mut x, metric, t4, t6);
                x.enabled = false;
                x
            })
            .collect();
        out.sort_by(interface::route_order);
        out
    }

    /// `interface_ip_set_enabled(&iface->config_ip, true)`, routes half: the
    /// static routes of an interface enter the kernel when it comes up. A
    /// route with no interface (DEVROUTE_NODEV) is installed with no device.
    fn apply_config_routes(&mut self, name: &str, devidx: u32) {
        let Some(idx) = self.iface_index(name) else { return };
        let mut routes = std::mem::take(&mut self.interfaces[idx].config_ip.routes);
        for r in &mut routes {
            if r.enabled {
                continue;
            }
            let di = if r.flags & interface::devroute::NODEV != 0 { 0 } else { devidx };
            if let Err(e) = self.sys.add_route(di, &sys_route(r)) {
                logging::log!(Warning, "{name}: cannot add the route to {}/{}: {e}", r.target, r.mask);
            }
            // `route->enabled = _enabled` whatever the kernel said
            r.enabled = true;
        }
        if let Some(idx) = self.iface_index(name) {
            self.interfaces[idx].config_ip.routes = routes;
        }
    }

    fn del_routes(&mut self, devidx: u32, routes: &[interface::Route]) {
        for r in routes {
            if !r.enabled {
                continue;
            }
            let di = if r.flags & interface::devroute::NODEV != 0 { 0 } else { devidx };
            let _ = self.sys.del_route(di, &sys_route(r));
        }
    }

    /// The config_ip route vlist after a reload that did not need a teardown:
    /// what left the config leaves the kernel, what entered it is installed
    /// if the interface is up.
    fn replace_config_routes(&mut self, name: &str, new: Vec<interface::Route>) {
        let Some(idx) = self.iface_index(name) else { return };
        let up = self.interfaces[idx].state == State::Up;
        let devidx = self
            .interfaces[idx]
            .l3_device
            .as_deref()
            .and_then(|d| self.sys.if_index(d).ok())
            .unwrap_or(0);
        let old = std::mem::replace(&mut self.interfaces[idx].config_ip.routes, new);
        if up && devidx != 0 {
            self.del_routes(devidx, &old);
            self.apply_config_routes(name, devidx);
        }
    }

    /// `interface_change_config` with `reload_ip`: metric, ip4table/ip6table
    /// or defaultroute changed. The C disables both IP sets and enables them
    /// again, so every address is re-added and every route re-installed with
    /// the new metric and table, and a default route follows the new
    /// `no_defaultroute` -- without a teardown and without re-running the
    /// protocol (R81 F05).
    fn reload_ip(&mut self, name: &str) {
        let Some(idx) = self.iface_index(name) else { return };
        if self.interfaces[idx].state != State::Up {
            return;
        }
        let Some(dev) = self.interfaces[idx].l3_device.clone() else { return };
        let di = match self.sys.if_index(&dev) {
            Ok(i) if i != 0 => i,
            _ => return,
        };
        let Some(ic) = self.cfg.interfaces.iter().find(|c| c.name == name).cloned() else {
            return;
        };
        let (metric, t4, t6) = (
            self.interfaces[idx].metric,
            self.interfaces[idx].ip4table,
            self.interfaces[idx].ip6table,
        );
        let nodef = self.interfaces[idx].proto_ip.no_defaultroute;
        let mut config_ip = std::mem::take(&mut self.interfaces[idx].config_ip);
        let mut proto_ip = std::mem::take(&mut self.interfaces[idx].proto_ip);
        // disable
        for set in [&config_ip, &proto_ip] {
            for a in &set.addresses {
                let _ = self.sys.del_address(di, &sys::Address::new(a.addr, a.mask));
            }
            self.del_routes(di, &set.routes);
        }
        // enable, with the interface's new metric and tables
        let base = now().min(u32::MAX as u64) as u32;
        for (set, is_proto) in [(&mut config_ip, false), (&mut proto_ip, true)] {
            set.device_index = Some(di);
            for a in &mut set.addresses {
                let mut sa = sys::Address::new(a.addr, a.mask);
                sa.broadcast = a.broadcast.filter(|b| !b.is_unspecified());
                sa.point_to_point = a.point_to_point.and_then(|p| match p {
                    IpAddr::V4(p) if !p.is_unspecified() => Some(p),
                    _ => None,
                });
                if a.addr.is_ipv4() {
                    sa = sa.with_default_broadcast();
                }
                sa.offlink = a.offlink;
                sa.preferred = a.preferred_until.map(|u| u.saturating_sub(base));
                sa.valid = a.valid_until.map(|u| u.saturating_sub(base));
                a.failed = self.sys.add_address(di, &sa).is_err();
                if !a.failed {
                    self.replace_subnet_route(di, &sa, &ic);
                }
            }
            for r in &mut set.routes {
                set_route_info(r, metric, t4, t6);
                r.enabled = !(is_proto && nodef && r.mask == 0);
                if r.enabled {
                    let d = if r.flags & interface::devroute::NODEV != 0 { 0 } else { di };
                    r.failed = self.sys.add_route(d, &sys_route(r)).is_err();
                }
            }
            set.routes.sort_by(interface::route_order);
        }
        if let Some(idx) = self.iface_index(name) {
            self.interfaces[idx].config_ip = config_ip;
            self.interfaces[idx].proto_ip = proto_ip;
        }
    }

    /// `interface_update_prefix_delegation`: `option delegate 0` takes this
    /// interface's delegated prefixes out of the assignment pool. The parent
    /// prefix and its null route remain until the protocol withdraws them.
    fn update_prefix_delegation(&mut self) {
        self.refresh_prefix_assignments();
    }

    /// The prefixes that hand out assignments: every delegated prefix whose
    /// receiving interface does not say `delegate 0` (R81 F08).
    fn delegating_prefixes(&self) -> Vec<ip::DevicePrefix> {
        self.prefixes
            .iter()
            .filter(|p| {
                let Some(owner) = p.iface.as_deref() else { return true };
                !self
                    .interfaces
                    .iter()
                    .any(|i| i.name == owner && i.proto_ip.no_delegation)
            })
            .cloned()
            .collect()
    }

    /// Construct only the daemon-owned part of the status view. The live
    /// interface's addresses, routes, DNS, settings and data stay borrowed.
    fn dump_interface_status(&self, b: &mut BlobBuf, i: &Interface) {
        let prefixes = status_prefixes(&self.prefixes, &self.interfaces, &i.name);
        i.dump_status_with(b, i.current_uptime(), &prefixes);
    }

    /// `set_config_state`: a reload or a removal is performed right away
    /// when the interface is down, and otherwise once its teardown completes
    /// -- `interface_handle_config_change` runs from the IFPEV_DOWN path.
    /// Doing it synchronously here was R81 F11: the setup was refused because
    /// the state machine was still tearing down, and an ifup-failed the C
    /// never sends went out.
    fn set_config_state(&mut self, name: &str, cs: interface::ConfigState) {
        let Some(idx) = self.iface_index(name) else { return };
        self.interfaces[idx].config_state = cs;
        if self.interfaces[idx].state == State::Down {
            self.handle_config_change(name);
        } else {
            // `__interface_set_down(iface, false)`: autostart survives
            self.set_down(name);
        }
    }

    /// `interface_do_reload`, with the interface already down: the state is
    /// rebuilt from the new config and the proto state starts over. The
    /// runtime `autostart` is kept -- `interface_change_config` only resets
    /// it when the `auto` option itself changed -- so an interface that was
    /// `ifdown`ed by hand stays down through a reload, as it does in the C.
    fn do_reload(&mut self, name: &str) {
        let Some(nc) = self.cfg.interfaces.iter().find(|c| c.name == name).cloned() else {
            return;
        };
        let Some(i) = self.iface_index(name) else { return };
        let autostart = self.interfaces[i].autostart;
        let mut fresh = self.new_interface(&nc);
        fresh.autostart = autostart;
        self.interfaces[i] = fresh;
        self.link_state.retain(|(n, _)| n != name);
        // `interface_set_proto_state(iface, NULL)` then `proto_init_interface`
        if let Some(pos) = self.protos.iter().position(|(n, _)| n == name) {
            let (_, mut st) = self.protos.remove(pos);
            st.script.terminate();
            st.task.terminate();
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
            logging::log!(Notice, "Interface '{name}' is not up after the checkup interval");
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
        // `dev->active`: the claim state, external or not (R81 F13)
        if let Some(d) = self.devices.get_mut(name) {
            d.active = true;
        }
        // hostapd owns an external wireless interface's administrative state.
        // Claiming it must neither clear its state nor claim a kernel parent.
        if self.devices.get(name).is_some_and(|d| d.external) {
            self.set_enabled(name, true);
            return;
        }
        // The C claims a device that already has its object (`device_get`
        // created it, clearing its state then). A veth's parent is its peer,
        // and the peer's parent is the device itself: without this the walk
        // below created the object for `name` from the peer's side and
        // cleared it -- taking a freshly enslaved hotplug port back out of
        // its bridge (r83c add_device).
        if !self.device_objects.contains(&name.to_string()) {
            self.device_objects.push(name.to_string());
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
                // `system_if_up`: settings first, then IFF_UP. The order is
                // observable: the kernel resets the IPv6 mtu to the link mtu
                // on NETDEV_UP, so a `mtu6` written after the link came up
                // would stick where the C's does not (r83c).
                self.apply_device_settings(name, i);
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
                    logging::log!(Notice,
                        "Interface '{name}' is {}",
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
        if !self.devices.get(name).is_some_and(|d| d.external) {
            if let Ok(i) = self.sys.if_index(name) {
                if i != 0 {
                    let _ = self.sys.set_link_up(i, false);
                }
            }
        }
        if let Some(d) = self.devices.get_mut(name) {
            d.active = false;
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

    fn proto_config(&self, name: &str) -> Option<&config::InterfaceConfig> {
        self.protos.iter().find(|(n, _)| n == name)
            .and_then(|(_, st)| st.teardown_config.as_deref())
            .or_else(|| self.cfg.interfaces.iter().find(|ic| ic.name == name))
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
    fn rescan_devices(&mut self) -> bool {
        // every device object, not just the config-named ones: a parent
        // claimed through `iflink` has an object too, and the C's
        // `network.device status` lists it
        let known = self.device_objects.clone();
        let msgs = match self.sys.dump_links() {
            Ok(m) => m,
            Err(e) => {
                logging::log!(Warning, "link dump failed: {e}");
                return false;
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
            // `dev->active` is netifd's own claim state (`device_set_state`),
            // not IFF_UP: a device the kernel has up that nothing claimed is
            // `up: false` in the C's status (R81 F13). A first sighting
            // derives it from the claims held so far.
            if self.devices.get(name).is_none() {
                d.active = self.claims.iter().any(|(n, c)| n == name && *c > 0);
            }
            d.link_active = flags & sys::IFF_LOWER_UP != 0;
            d.orig_settings = device::read_settings(name, &self.ethtool, self.ethtool.if_ioctl());
            pending.push(d);
        }
        for mut d in pending {
            if let Some(idx) = self.dsa_conduit(&d.ifname.clone()) {
                d.orig_settings.master_ifindex = idx;
                d.orig_settings.flags |= device::opt::MASTER;
            }
            self.devices.insert(d);
        }
        true
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
                    logging::log!(Warning, "cannot create bridge {}: {e}", dc.name);
                    continue;
                }
            }
            let br = match self.sys.if_index(&dc.name) {
                Ok(i) if i != 0 => i,
                _ => {
                    logging::log!(Warning, "bridge {} did not appear", dc.name);
                    continue;
                }
            };
            self.apply_device_config(&dc, br);

            // Reload must preserve dynamic wireless members and their claims.
            let mut members = self.devices.get(&dc.name)
                .and_then(|d| d.bridge.as_ref()).map(|b| b.members.clone())
                .unwrap_or_default();
            for port in &dc.ports {
                if members.contains(port) {
                    continue;
                }
                match self.sys.if_index(port) {
                    Ok(pi) if pi != 0 => {
                        // a member's own `config device` settings (macaddr)
                        // before enslaving, same as the late-add path
                        self.apply_device_settings(port, pi);
                        if let Err(e) = self.sys.bridge_setmaster(pi, br) {
                            logging::log!(Warning, "cannot add {port} to {}: {e}", dc.name);
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
                                logging::log!(Warning,
                                    "cannot disable IPv6 on {port}: {e}"
                                );
                            }
                        }
                        members.push(port.clone());
                    }
                    _ => logging::log!(Warning, "bridge {} port {port} is absent", dc.name),
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
                logging::log!(Warning, "device {} is absent", dc.name);
                continue;
            }
            self.apply_device_settings(&dc.name, idx);
        }
        self.rescan_devices();
    }

    /// `system_if_apply_settings` for a plain `config device` section: MAC,
    /// MTU and txqueuelen. Called both when the device is present at
    /// create_devices() and when it appears later -- a `config device wan`
    /// with an explicit macaddr that registers after the daemon started must
    /// still get that MAC, or the box comes up with the kernel's MAC instead
    /// of the configured one (the WAN MAC an ISP may pin to).
    fn apply_device_settings(&mut self, name: &str, idx: u32) {
        let Some(dc) = self.cfg.devices.iter().find(|d| d.name == name && d.kind.is_none()).cloned()
        else {
            return;
        };
        self.apply_device_config(&dc, idx);
    }

    /// `system_if_apply_settings`, in the C's order, for the options a
    /// `config device` on this device can carry. `ipv6`, `promisc`,
    /// `multicast` and `mtu6` were parsed and dropped until R81 F12.
    fn apply_device_config(&mut self, dc: &config::DeviceConfig, idx: u32) {
        if let Some(mtu) = dc.mtu {
            let _ = self.sys.set_mtu(idx, mtu);
        }
        // `mtu6`/DEV_OPT_MTU6: parsed, but the C does not lower the IPv6
        // interface MTU for the plain `config device` sections on this box --
        // verified against the reference, which leaves it at the link MTU
        // (R83). Applying it was a divergence, so it is left alone here too.
        if let Some(q) = dc.txqueuelen {
            let _ = self.sys.set_txqueuelen(idx, q);
        }
        if let Some(mac) = dc.macaddr {
            if let Err(e) = self.sys.set_mac(idx, &mac) {
                logging::log!(Warning, "cannot set {} macaddr: {e}", dc.name);
            }
        }
        if let Some(v) = dc.ipv6 {
            let p = sys::sysctl_path("ipv6", &dc.name, "disable_ipv6");
            let _ = sys::sysctl_set(&p, if v { "0" } else { "1" });
        }
        if let Some(v) = dc.promisc {
            let (add, rem) = if v { (sys::IFF_PROMISC, 0) } else { (0, sys::IFF_PROMISC) };
            let _ = self.sys.set_link_flags(idx, add, rem);
        }
        if let Some(v) = dc.multicast {
            let (add, rem) = if v { (sys::IFF_MULTICAST, 0) } else { (0, sys::IFF_MULTICAST) };
            let _ = self.sys.set_link_flags(idx, add, rem);
        }
    }

    /// Reload only the ULA from `globals`. Protocol-owned delegations survive
    /// an unrelated configuration reload, including a change to `delegate`.
    fn build_prefixes(&mut self) {
        let fresh = self.cfg.globals.ula_prefix.filter(|(_, len)| (1..=64).contains(len));
        let old = self.prefixes.iter().find(|p| p.iface.is_none()).map(|p| (p.addr, p.length));
        if old == fresh {
            return;
        }
        if let Some((addr, len)) = old {
            let mut null = sys::Route::v6(addr, len);
            null.metric = i32::MAX as u32;
            null.nodev = true;
            let _ = self.sys.del_route(0, &null);
        }
        let fresh = fresh
            .map(|(addr, len)| ip::DevicePrefix::new(addr, len, "local", None))
            .into_iter()
            .collect();
        ip::replace_prefixes(&mut self.prefixes, None, fresh);
        if !self.interfaces.is_empty() {
            self.refresh_prefix_assignments();
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
        // the interface was started -- and for a bridge, "present" means it
        // has a present member, not that the bridge netdev exists.
        i.available =
            ic.device.as_deref().map(|d| self.device_present_now(d)).unwrap_or(false);
        i.autostart = ic.auto.unwrap_or(true);
        i.metric = ic.metric;
        i.dns_metric = ic.dns_metric;
        i.ip4table = ic.ip4table.unwrap_or(0);
        i.ip6table = ic.ip6table.unwrap_or(0);
        i.proto_ip.no_delegation = ic.delegate == Some(false);
        // `interface_add_dns_server_list(&iface->config_ip, ...)`, and the
        // proto_ip flags from `peerdns`/`defaultroute` (R81 F06)
        i.config_ip.dns_servers = ic.dns.clone();
        i.config_ip.dns_search = ic.dns_search.clone();
        i.config_ip.routes = self.config_routes_for(&ic.name);
        i.proto_ip.no_dns = ic.peerdns == Some(false);
        i.proto_ip.no_defaultroute = ic.defaultroute == Some(false);
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
                logging::log!(Warning, "cannot register {name}: {e}");
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
                .map(|ic| ic.auto.unwrap_or(true))
                .unwrap_or(false);
            if autostart {
                self.iface_up(&name);
            }
        }

        // Like C's interface_start_pending, retain the claims made above.
        // A DHCP interface remains Down while waiting for carrier; releasing
        // its device here would disable the port and prevent a later link-up.
        // Explicit teardown releases ownership through iface_unclaim().
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

        logging::log!(Notice, "Interface '{name}' is setting up now");
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
            logging::log!(Warning,
                "interface {name} uses proto '{}', which this build cannot run; \
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
        // `proto_apply_static_settings` failed: `__interface_set_up` gets -1
        // and calls `mark_interface_down` from IFS_SETUP (an ifup-failed),
        // with the proto error recorded. Skipping the bad option and coming
        // up without it was r61's bad-addr difference (R81 F14 follow-up).
        if let Some((code, value)) = ic.static_error.clone() {
            self.interfaces[idx].state = State::Setup;
            self.interfaces[idx].errors.push(interface::IfaceError {
                subsystem: "proto".into(),
                code,
                data: vec![value],
            });
            self.mark_interface_down(name);
            return;
        }
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
                Err(e) => logging::log!(Warning, "{name}: cannot add {a}/{m}: {e}"),
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
                Err(e) => logging::log!(Warning, "{name}: cannot add {a}/{m}: {e}"),
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
                Err(e) => logging::log!(Warning, "{name}: cannot add default via {gw}: {e}"),
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
                Err(e) => logging::log!(Warning, "{name}: cannot add ip6gw {gw}: {e}"),
            }
        }
        // `list dns` lives in config_ip (set in new_interface) for every
        // protocol, not in the static proto's own settings (R81 F06)
        ipset.no_dns = ic.peerdns == Some(false);
        ipset.no_defaultroute = ic.defaultroute == Some(false);
        ipset.no_delegation = ic.delegate == Some(false);
        self.apply_config_routes(name, devidx);

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
        if !i.proto_ip.routes.is_empty() || !i.config_ip.routes.is_empty() {
            i.updated |= interface::updated::ROUTE;
        }
        i.errors.clear();
        i.started_at = Some(now());

        self.apply_prefix_assignments();
        self.emit_event(name, Event::Up);
        logging::log!(Notice, "Interface '{name}' is now up");
        self.write_resolv_conf();
    }

    /// Run one protocol command for an interface, honouring the state machine.
    fn proto_cmd(&mut self, name: &str, cmd: proto::Cmd) {
        let Some(ic) = self.proto_config(name).cloned() else {
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
                logging::log!(Warning, "{name}: {cmd:?} refused in this state");
            }
            proto::Action::Abort => {
                // SIGTERM both children and wait for them; the abort completes
                // in `reap_children`.
                let st = self.proto_state(name);
                let _ = st.script.signal(process::SIGTERM as u32);
                let _ = st.task.signal(process::SIGTERM as u32);
                // `uloop_timeout_set(&state->teardown_timeout, 1000)`
                st.teardown_deadline = Some(now_ms() + 1000);
            }
            proto::Action::Run { action, env } => {
                if action != "setup" {
                    // `uloop_timeout_cancel(&state->checkup_timeout)` on
                    // teardown and on abort
                    self.proto_state(name).checkup_at = None;
                }
                if action == "teardown" {
                    // `uloop_timeout_set(&state->teardown_timeout, 5000)`
                    self.proto_state(name).teardown_deadline = Some(now_ms() + 5000);
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
                    logging::log!(Warning, "{name}: cannot run {action}: {e}");
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
            .proto_config(name)
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
                st.task_killed = false;
                match st.task.start(&argv, &env) {
                    Ok(()) => status::OK,
                    Err(e) => {
                        logging::log!(Warning, "{name}: cannot run {}: {e}", argv[0]);
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
                self.proto_state(name).available = av;
                self.set_available(name, av);
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
                    self.link_lost(name);
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
    /// Two routes the vlist would treat as one entry. The nexthop is
    /// deliberately NOT part of this: netifd's key is the destination, and a
    /// route whose gateway changed is the same entry replaced in place --
    /// `add_route` carries NLM_F_REPLACE, so the kernel does that in one
    /// step. Treating it as a different route would delete the replacement
    /// immediately after adding it.
    ///
    /// This is also the rule for `updated`: changing only a gateway sets no
    /// IUF_ROUTE bit, which is measurable on the C.
    ///
    /// `vlist_flush` for the three applied lists: anything the previous
    /// update put on the device and this one did not repeat comes off again.
    /// With `keep` the new set starts as a copy of the old, so nothing here
    /// matches and nothing is removed -- which is what `keep` means.
    fn flush_stale_ip(
        &mut self,
        name: &str,
        devidx: u32,
        old: &interface::IpSettings,
        new: &interface::IpSettings,
    ) {
        // The comparisons are the vlist keys, not the whole struct: an address
        // is its prefix, a route its destination and nexthop, a neighbour its
        // address. A renewal that only changes a lifetime is the same entry
        // and must not be removed and re-added.
        for a in &old.addresses {
            // In the pinned C callback, v6 is still false in the old-address
            // branch: IPv6 /64 offlink null routes survive a protocol-only
            // withdrawal. Full interface disable removes them separately.
            if a.addr.is_ipv4() && !new.addresses.iter().any(|n| same_address(n, a) && n.offlink) {
                let mut sa = sys::Address::new(a.addr, a.mask);
                sa.offlink = a.offlink;
                if let Some(route) = sys::offlink_route(&sa) {
                    let _ = self.sys.del_route(0, &route);
                }
            }
            if new.addresses.iter().any(|n| same_address(n, a)) {
                continue;
            }
            let sa = sys::Address::new(a.addr, a.mask);
            if let Err(e) = self.sys.del_address(devidx, &sa) {
                logging::log!(Warning, "{name}: cannot remove {}/{}: {e}", a.addr, a.mask);
            }
        }
        for r in &old.routes {
            if !r.enabled || new.routes.iter().any(|n| same_route(n, r)) {
                continue;
            }
            let _ = self.sys.del_route(devidx, &sys_route(r));
        }
        for n in &old.neighbors {
            if new.neighbors.iter().any(|x| x.addr == n.addr && x.proxy == n.proxy) {
                continue;
            }
            let sn = sys::Neighbor {
                addr: n.addr,
                mac: n.mac,
                proxy: n.proxy != 0,
                router: n.router != 0,
            };
            let _ = self.sys.neighbor(devidx, &sn, false);
        }
    }

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
            logging::log!(Warning, "{name}: proto-created tunnels are out of scope");
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
            logging::log!(Warning, "{name}: proto reported device {l3}, which does not exist");
            return status::INVALID_ARGUMENT;
        }
        // Entries were installed on the old L3 device. An identical lease
        // on a replacement device still needs every kernel operation.
        let same_device = self.iface_index(name).is_some_and(|i| {
            self.interfaces[i].l3_device.as_deref() == Some(l3.as_str())
                && self.interfaces[i].proto_ip.device_index == Some(devidx)
        });
        if !keep {
            let _ = devidx;
            self.iface_claim(name, &l3, true);
        }

        // `interface_update_start(iface, keep)` marks the applied entries
        // stale unless `keep`; whatever this update does not re-add is
        // removed from the kernel by `interface_update_complete` below.
        let previous = self
            .iface_index(name)
            .map(|i| self.interfaces[i].proto_ip.clone())
            .unwrap_or_default();
        let mut ipset = if keep {
            self.iface_index(name)
                .map(|i| self.interfaces[i].proto_ip.clone())
                .unwrap_or_default()
        } else {
            interface::IpSettings::default()
        };
        // `iface->proto_ip.no_dns / no_defaultroute` (peerdns, defaultroute):
        // parsed since R45 but never applied until R81 F06
        ipset.no_dns = ic.peerdns == Some(false);
        ipset.no_defaultroute = ic.defaultroute == Some(false);
        ipset.device_index = Some(devidx);

        // proto_apply_ip_settings: `ipaddr`/`ip6addr` are arrays of tables,
        // each carrying its own mask. A rejected item abandons the remaining
        // IP settings but still lets the interface come up, because
        // proto_ext_update_link ignores this function's return value.
        let mut counts = [0usize, 0usize];
        let mut bad = false;
        for (key, v6) in [("ipaddr", false), ("ip6addr", true)] {
            let Some(list) = find(key) else { continue };
            for (index, item) in list.children().enumerate() {
                let Some(a) = proto::parse_addr_item(&item, v6) else {
                    logging::log!(Warning, "{name}: proto sent an address this build rejects");
                    bad = true;
                    break;
                };
                let mut sa = sys::Address::new(a.ip, a.mask);
                sa.broadcast = a.broadcast.filter(|b| !b.is_unspecified());
                sa.point_to_point = a.point_to_point.and_then(|p| match p {
                    IpAddr::V4(p) if !p.is_unspecified() => Some(p),
                    _ => None,
                });
                sa = sa.with_default_broadcast();
                // v6 carries the lifetimes the protocol reported, and
                // `offlink` becomes IFA_F_NOPREFIXROUTE -- netifd manages the
                // prefix route itself. Without the flag the kernel adds its
                // own host route for a /128, which is visible in `ip -6
                // route` and is how r56 found this.
                sa.preferred = a.preferred;
                sa.valid = a.valid;
                sa.offlink = a.offlink;
                let mut ia = Address::new(a.ip, a.mask);
                ia.index = index;
                ia.point_to_point = sa.point_to_point.map(IpAddr::V4);
                ia.class = a.class.clone();
                // `parse_address_item`: lifetimes become deadlines here
                let base = now().min(u32::MAX as u64) as u32;
                ia.preferred_until = a.preferred.map(|p| base.saturating_add(p));
                ia.valid_until = a.valid.map(|v| base.saturating_add(v));
                ia.broadcast = sa.broadcast;
                ia.offlink = a.offlink;
                let unchanged = same_device
                    && previous.addresses.iter().any(|old| keep_proto_address(old, &ia, base));
                if !unchanged {
                    // IPv4 CREATE|REPLACE does not change an existing peer or
                    // broadcast. The C callback removes the old address when
                    // keep=false, but only refreshes in place for lifetimes.
                    if let Some(old) = previous.addresses.iter().find(|old| {
                        same_device && same_proto_address(old, &ia)
                            && (old.failed || (a.ip.is_ipv4()
                                && (old.broadcast != ia.broadcast
                                    || old.point_to_point != ia.point_to_point)))
                    }) {
                        let mut remove = sys::Address::new(old.addr, old.mask);
                        remove.broadcast = old.broadcast;
                        remove.point_to_point = old.point_to_point.and_then(|p| match p {
                            IpAddr::V4(p) => Some(p),
                            _ => None,
                        });
                        let _ = self.sys.del_address(devidx, &remove);
                    }
                    if let Err(e) = self.sys.add_address(devidx, &sa) {
                        logging::log!(Warning, "{name}: cannot add {}/{}: {e}", a.ip, a.mask);
                        ipset.addresses.retain(|old| !same_proto_address(old, &ia));
                        continue;
                    }
                    if !a.offlink {
                        self.replace_subnet_route(devidx, &sa, &ic);
                    } else if !previous.addresses.iter().any(|old| {
                        old.addr == a.ip && old.mask == a.mask && old.offlink
                    }) {
                        if let Some(route) = sys::offlink_route(&sa) {
                            if let Err(e) = self.sys.add_route(0, &route) {
                                logging::log!(Warning, "{name}: cannot add offlink null route: {e}");
                            }
                        }
                    }
                }
                if let Some(old) = ipset.addresses.iter_mut().find(|old| same_proto_address(old, &ia)) {
                    *old = ia;
                } else {
                    ipset.addresses.push(ia);
                }
                counts[v6 as usize] += 1;
            }
            if bad {
                break;
            }
        }
        // `ip6prefix`: the delegated prefixes, pushed by netifd-proto.sh as
        // plain strings. Until this existed the global prefix list only ever
        // held the ULA, so a LAN whose GUA comes from WAN6 delegation -- which
        // is how this device is actually addressed -- got nothing.
        //
        // They are replaced wholesale for this interface on every update, the
        // same shape as the address and route flush above: whatever the
        // protocol no longer reports has been withdrawn.
        let mut delegated: Vec<ip::DevicePrefix> = Vec::new();
        if let Some(list) = find("ip6prefix") {
            for item in list.children() {
                let Some(text) = item.as_str() else { continue };
                let Some(p) = proto::parse_prefix6(text) else {
                    logging::log!(Warning, "{name}: proto sent a prefix this build rejects: {text}");
                    continue;
                };
                // netifd stores DEADLINES, not lifetimes: `parse_prefix_option`
                // keeps `pref + now` and `system_addr` subtracts `now` again on
                // the way to IFA_CACHEINFO. 0xffffffff is infinite and becomes
                // no deadline at all. Keeping the raw lifetime here happens to
                // produce the right first address and then makes every
                // comparison against it wrong -- expiry, and the cap in the
                // withdrawal path.
                let base = now();
                let deadline = |v: Option<u32>| -> Option<u32> {
                    match v {
                        None | Some(u32::MAX) => None,
                        Some(x) => Some((base + x as u64).min(u32::MAX as u64) as u32),
                    }
                };
                let mut dp = ip::DevicePrefix::new(p.addr, p.length, name, Some(name));
                dp.preferred_until = deadline(p.preferred);
                dp.valid_until = deadline(p.valid);
                dp.excl = p.excl;
                delegated.push(dp);
            }
        }
        let changed_prefixes = self.set_delegated_prefixes(name, delegated);

        // `gateway`/`ip6gw` are applied only when that family got an address
        if !bad {
            for (key, v6) in [("gateway", false), ("ip6gw", true)] {
                if counts[v6 as usize] == 0 {
                    continue;
                }
                let Some(gw) = find(key).and_then(|f| f.as_str()) else { continue };
                let Ok(nexthop) = gw.parse::<IpAddr>() else {
                    logging::log!(Warning, "{name}: proto sent a bad {key} '{gw}'");
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
                let old = same_device.then(|| previous.routes.iter().find(|old| {
                    interface::route_order(old, &r).is_eq()
                })).flatten();
                self.add_iface_route(name, devidx, &r, &mut ipset, old);
            }
        }

        // `routes`/`routes6`: tables parsed by interface_ip_add_route
        for (key, v6) in [("routes", false), ("routes6", true)] {
            let Some(list) = find(key) else { continue };
            for item in list.children() {
                let Some(r) = proto::parse_route_item(&item, v6) else { continue };
                let old = same_device.then(|| previous.routes.iter().find(|old| {
                    interface::route_order(old, &r).is_eq()
                })).flatten();
                self.add_iface_route(name, devidx, &r, &mut ipset, old);
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
                    logging::log!(Warning, "{name}: cannot add the neighbour {}: {e}", n.addr);
                    continue;
                }
                ipset.neighbors.push(n);
            }
        }

        for d in find("dns").map(|f| string_list(&f)).unwrap_or_default() {
            match d.parse::<IpAddr>() {
                Ok(a) => ipset.dns_servers.push(a),
                Err(_) => logging::log!(Warning, "{name}: proto sent a bad dns '{d}'"),
            }
        }
        ipset
            .dns_search
            .extend(find("dns_search").map(|f| string_list(&f)).unwrap_or_default());
        ipset.no_delegation = ic.delegate == Some(false);

        // `interface_update_complete`: vlist_flush drops the entries this
        // update did not renew, and their free callbacks take them out of the
        // kernel. Without this a protocol that reports a new address on every
        // renewal accumulates them all on the device -- r55 caught exactly
        // that, three addresses on veth4 where the C had one.
        self.flush_stale_ip(name, devidx, &previous, &ipset);

        // `interface_update_start` zeroes `updated` unconditionally, and the
        // vlist callbacks set a bit only when an entry is genuinely added or
        // removed -- `if (!node_new || !node_old)`. Re-applying an identical
        // entry sets nothing. So a protocol that renews with the same
        // settings clears the field and leaves it clear, which is why the C's
        // `wan6` shows `updated` for about two seconds after it comes up and
        // then never again, while a static interface keeps its
        // `["addresses"]` forever: nothing a static interface does ever
        // reaches `interface_update_start`.
        let changed_addrs = previous.addresses.len() != ipset.addresses.len()
            || !previous.addresses.iter().all(|a| ipset.addresses.iter().any(|n| same_address(n, a)))
            || !ipset.addresses.iter().all(|a| previous.addresses.iter().any(|n| same_address(n, a)));
        let changed_routes = previous.routes.len() != ipset.routes.len()
            || !previous.routes.iter().all(|r| ipset.routes.iter().any(|n| same_route(n, r)))
            || !ipset.routes.iter().all(|r| previous.routes.iter().any(|n| same_route(n, r)));
        if std::env::var_os("NETIFD_RS_DEBUG_UPDATED").is_some() {
            eprintln!(
                "DBG {name}: keep={keep} prev a={} r={} new a={} r={} ca={} cr={}",
                previous.addresses.len(),
                previous.routes.len(),
                ipset.addresses.len(),
                ipset.routes.len(),
                changed_addrs,
                changed_routes
            );
        }
        let mut new_updated = 0;
        if changed_addrs {
            new_updated |= interface::updated::ADDRESS;
        }
        if changed_routes {
            new_updated |= interface::updated::ROUTE;
        }
        if changed_prefixes {
            new_updated |= interface::updated::PREFIX;
        }

        // interface_add_data runs before IFPEV_UP, in every interface state.
        // Merge directly: an ordinary lease renewal neither needs a temporary
        // Vec nor allocates names for keys already present. Only insertions
        // change the order of the status's name-sorted data table.
        if let (Some(t), Some(idx)) = (find("data"), self.iface_index(name)) {
            let data = &mut self.interfaces[idx].data;
            let mut inserted = false;
            for m in t.children() {
                let value = owrt_ubus::convert::field_to_json(&m);
                match data.iter_mut().find(|(n, _)| n == m.name) {
                    Some((_, old)) => {
                        if *old != value {
                            *old = value;
                            new_updated |= interface::updated::DATA;
                        }
                    }
                    None => {
                        data.push((m.name.to_string(), value));
                        new_updated |= interface::updated::DATA;
                        inserted = true;
                    }
                }
            }
            if inserted {
                data.sort_by(|a, b| a.0.cmp(&b.0));
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
                i.updated = new_updated;
                let update = i.state == State::Up && i.updated != 0;
                if update {
                    self.emit_event(name, Event::Update);
                }
            }
            // `interface_ip_flush` + update: the DNS lists may have changed
            self.write_resolv_conf();
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
            i.updated = new_updated;
            i.errors.clear();
            i.started_at = Some(now());
        }
        self.proto_state(name).sm = proto::Sm::Idle;
        // `interface_ip_set_enabled(&iface->config_ip, true)` at IFPEV_UP
        self.apply_config_routes(name, devidx);
        self.apply_prefix_assignments();
        self.emit_event(name, Event::Up);
        self.write_resolv_conf();
        logging::log!(Notice, "Interface '{name}' is now up");
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
        logging::log!(Notice, "Interface '{name}' has lost the connection");
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
        old: Option<&interface::Route>,
    ) {
        ipset.routes.retain(|entry| !interface::route_order(entry, r).is_eq());
        // `enable_route`: with `no_defaultroute` a default route stays in the
        // list -- dumped under `inactive` -- but out of the kernel
        if ipset.no_defaultroute && r.mask == 0 {
            let mut held = r.clone();
            held.enabled = false;
            ipset.routes.push(held);
            return;
        }
        if old.is_some_and(|old| keep_proto_route(old, r, now())) {
            ipset.routes.push(r.clone());
            return;
        }
        let k = sys_route(r);
        if let Err(e) = self.sys.add_route(devidx, &k) {
            logging::log!(Warning, "{name}: cannot add the route to {}/{}: {e}", r.target, r.mask);
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
        if let Some(pid) = self.hotplug.pid() {
            for line in self.hotplug.poll_lines() {
                logging::log!(Notice, "hotplug ({pid}): {line}");
            }
        }
        // The wireless handler has to be drained while it runs, like the
        // protocol scripts. Reading only at reap deadlocks a handler whose
        // output fills the pipe: the child blocks writing, the parent waits
        // for an exit that cannot come, and because handlers are serialised
        // every other radio is stuck behind it. The r60 stub prints almost
        // nothing, so it never showed this.
        let who = self.wcur.as_ref().map(|(n, _)| n.clone()).unwrap_or_default();
        if let Some(pid) = self.wslot.pid() {
            for line in self.wslot.poll_lines() {
                logging::log!(Notice, "{who} ({pid}): {line}");
            }
        }
        for (name, st) in &mut self.protos {
            for slot in [&mut st.script, &mut st.task] {
                if let Some(pid) = slot.pid() {
                    for line in slot.poll_lines() {
                        logging::log!(Notice, "{name} ({pid}): {line}");
                    }
                }
            }
        }
    }

    fn reap_children(&mut self) {
        self.poll_child_output();
        self.wireless_reap();
        if let (Some(pid), Some((_, _, output))) = (self.hotplug.pid(), self.hotplug.reap()) {
            for line in output.lines().filter(|l| !l.trim().is_empty()) {
                logging::log!(Notice, "hotplug ({pid}): {line}");
            }
            self.hotplug_current = None;
            self.pump_hotplug();
        }
        let names: Vec<String> = self.protos.iter().map(|(n, _)| n.clone()).collect();
        for name in names {
            for which in [proto::Which::Script, proto::Which::Task] {
                let exited = {
                    let st = self.proto_state(&name);
                    let slot = match which {
                        proto::Which::Script => &mut st.script,
                        proto::Which::Task => &mut st.task,
                    };
                    slot.pid().zip(slot.reap())
                };
                let Some((pid, (argv0, status, output))) = exited else { continue };
                for line in output.lines().filter(|l| !l.trim().is_empty()) {
                    logging::log!(Notice, "{name} ({pid}): {line}");
                }
                if status != 0 {
                    logging::log!(Info, "{name}: {argv0} exited {status}");
                }
                if which == proto::Which::Task {
                    let st = self.proto_state(&name);
                    if matches!(st.sm, proto::Sm::Idle | proto::Sm::Setup) {
                        st.last_error = status;
                    }
                }
                self.finish_proto_task(&name, which);
            }
        }
    }

    /// `proto_ext_task_finish`: the state machine's reaction to one child
    /// having exited (or, from the teardown deadline, to both having been
    /// killed). Shared by the reaper and the deadline pump.
    fn finish_proto_task(&mut self, name: &str, which: proto::Which) {
        let Some(ic) = self.proto_config(name).cloned()
        else {
            return;
        };
        let Some(handler) = self.handler_for(&ic.proto).cloned() else { return };
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
            let st = self.proto_state(name);
            proto::task_finish(st, which, &handler, checkup)
        };
        for e in effects {
            match e {
                proto::Finish::LinkLost => {
                    self.link_lost(name);
                }
                // teardown is complete: this is the second IFEV_DOWN,
                // and hotplug.d already ran on the first
                proto::Finish::Down => {
                    self.mark_interface_down(name);
                    self.handle_config_change(name);
                }
                proto::Finish::Teardown => {
                    self.proto_cmd(name, proto::Cmd::Teardown);
                }
                proto::Finish::Renew => {
                    self.proto_cmd(name, proto::Cmd::Renew);
                }
                proto::Finish::SignalTask(sig) => {
                    let st = self.proto_state(name);
                    st.task_killed = true;
                    let _ = st.task.signal(sig);
                }
                proto::Finish::ArmCheckup => {
                    let at = now() + checkup as u64;
                    self.proto_state(name).checkup_at = Some(at);
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
            logging::log!(Warning,
                "{}: cannot take over the {}/{} prefix route: {e}",
                ic.name, addr.ip, addr.mask
            );
        }
    }

    /// Place every interface's `ip6assign` request in every known prefix, then
    /// add the resulting local address to each interface's L3 device.
    /// Recompute the assignments, then withdraw whatever the new set no longer
    /// produces.
    ///
    /// `interface_update_prefix` drives this from the prefix vlist: a prefix
    /// that is still there splices its assignments over and only refreshes the
    /// lifetimes, while one that has gone runs
    /// `interface_update_prefix_assignments(prefix_old, false)`, which walks
    /// every assignment through the withdrawal path and does not rebuild. The
    /// order follows vlist -- entries are added first and stale ones flushed
    /// afterwards -- so a replacement installs the new address before
    /// deprecating the old.
    fn refresh_prefix_assignments(&mut self) {
        type Owner = Option<(Option<String>, Ipv6Addr, u8)>;
        let before: Vec<(String, Ipv6Addr, u8, Option<u32>, Owner)> = self
            .interfaces
            .iter()
            .flat_map(|i| {
                i.prefix_assignments.iter().filter_map(move |a| {
                    a.local
                        .map(|(l, len)| (i.name.clone(), l, len, a.valid_until, a.owner.clone()))
                })
            })
            .collect();

        // Which parent prefixes are still here. A withdrawal follows the
        // PARENT going away, not the local address disappearing: two parents
        // that differ only in length hand out the same local address, and the
        // C withdraws the departing parent's assignment on top of it.
        let live: Vec<(Option<String>, Ipv6Addr, u8)> = self
            .delegating_prefixes()
            .iter()
            .map(|p| (p.iface.clone(), p.addr, p.length))
            .collect();

        self.apply_prefix_assignments();

        for (name, local, len, valid, owner) in before {
            if let Some(o) = &owner {
                if live.contains(o) && self.iface_index(&name).is_some_and(|i| {
                    self.interfaces[i].prefix_assignments.iter().any(|a| {
                        a.owner.as_ref() == Some(o) && a.local == Some((local, len))
                    })
                }) {
                    continue;
                }
            } else {
                // no recorded owner: fall back to address survival
                let still = self
                    .iface_index(&name)
                    .map(|i| {
                        self.interfaces[i]
                            .prefix_assignments
                            .iter()
                            .any(|a| a.local.map(|(l, _)| l) == Some(local))
                    })
                    .unwrap_or(false);
                if still {
                    continue;
                }
            }
            let dev = self.iface_index(&name).and_then(|i| self.interfaces[i].l3_device.clone());
            let Some(dev) = dev else { continue };
            let Ok(di) = self.sys.if_index(&dev) else { continue };
            if di == 0 {
                continue;
            }
            let delegated = owner.as_ref().is_some_and(|(uplink, _, _)| uplink.is_some());
            let valid = owner.as_ref().and_then(|o| self.prefixes.iter().find(|p| {
                (&p.iface, p.addr, p.length) == (&o.0, o.1, o.2)
            })).map(|p| p.valid_until).unwrap_or(valid);
            self.withdraw_assignment(di, local, len, valid, delegated.then_some(dev.as_str()));
        }
    }

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

        let previous: Vec<_> = self.interfaces.iter_mut()
            .map(|i| std::mem::take(&mut i.prefix_assignments)).collect();
        for p in &self.prefixes {
            // `interface_update_prefix` installs an unreachable route for the
            // whole prefix, at the lowest possible priority, so a packet for
            // an unassigned part of it does not loop back out.
            let mut null = sys::Route::v6(p.addr, p.length);
            null.metric = i32::MAX as u32;
            null.nodev = true;
            if let Err(e) = self.sys.add_route(0, &null) {
                logging::log!(Warning, "cannot add the {}/{} null route: {e}", p.addr, p.length);
            }
        }
        let prefixes = self.delegating_prefixes();
        for p in &prefixes {
            for a in ip::assign(p, &reqs) {
                let addr = ip::assignment_address(p, a.assigned);
                let local = ip::local_address(addr, "::1".parse().unwrap());
                let Some(idx) = self.iface_index(&a.name) else { continue };
                let up = self.interfaces[idx].state == State::Up;
                let l3 = self.interfaces[idx].l3_device.clone();
                let was_enabled = previous[idx].iter().any(|old| {
                    old.local == Some((local, a.length))
                        && old.owner.as_ref() == Some(&(p.iface.clone(), p.addr, p.length))
                });
                let valid = !p.valid_until.is_some_and(|v| (v as u64).saturating_sub(1) <= now());
                let mut enabled = was_enabled && valid;
                if up && valid {
                    if let Some(dev) = &l3 {
                        if let Ok(di) = self.sys.if_index(dev) {
                            if di != 0 {
                                let mut sa =
                                    sys::Address::new(IpAddr::V6(local), a.length);
                                // `interface_set_prefix_address`, add path:
                                // DEVADDR_OFFLINK plus netifd's own route. I
                                // briefly removed both after r62 showed the C
                                // with `proto kernel metric 256` -- but that
                                // was the C's WITHDRAWN state, not its live
                                // one. Withdrawal drops the explicit route and
                                // re-adds the address without OFFLINK, so the
                                // kernel makes that route. Matching it while
                                // the assignment is live means matching the
                                // wrong half.
                                sa.offlink = true;
                                // deadlines back to lifetimes, as `system_addr`
                                // does; a deadline already past means zero
                                let base = now();
                                let left = |d: Option<u32>| -> Option<u32> {
                                    d.map(|x| (x as u64).saturating_sub(base).min(u32::MAX as u64) as u32)
                                };
                                sa.preferred = left(p.preferred_until);
                                sa.valid = left(p.valid_until);
                                if let Err(e) = self.sys.add_address(di, &sa) {
                                    logging::log!(Warning,
                                        "{}: cannot add {local}/{}: {e}",
                                        a.name, a.length
                                    );
                                } else {
                                    enabled = true;
                                    if p.iface.is_some() && !was_enabled {
                                        if let Err(e) = self.sys.prefix_reject(dev, local, a.length, true) {
                                            logging::log!(Warning, "{}: cannot add prefix source rule: {e}", a.name);
                                        }
                                    }
                                    // the on-link route for the assignment, never
                                    // narrower than a /64
                                    let rmask = a.length.max(64);
                                    let mut pr =
                                        sys::Route::v6(ip::clear_if_addr(local, rmask), rmask);
                                    let ic =
                                        self.cfg.interfaces.iter().find(|i| i.name == a.name);
                                    pr.metric = ic.map(|i| i.metric).unwrap_or(0);
                                    let t = ic.and_then(|i| i.ip6table).unwrap_or(0);
                                    pr.table = if t != 0 { t } else { sys::RT_TABLE_MAIN };
                                    if let Err(e) = self.sys.add_route(di, &pr) {
                                        logging::log!(Warning,
                                            "{}: cannot add the {}/{rmask} route: {e}",
                                            a.name, pr.target
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                self.interfaces[idx].prefix_assignments.push(
                    interface::PrefixAssignment {
                        addr,
                        length: a.length,
                        preferred_until: p.preferred_until,
                        valid_until: p.valid_until,
                        local: if up && enabled { Some((local, a.length)) } else { None },
                        owner: Some((p.iface.clone(), p.addr, p.length)),
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
        // A DOWN interface can still hold its main device while waiting for
        // carrier. Explicit ifdown must release that claim as the C does.
        if prev == State::Down {
            self.iface_unclaim(name, false);
            return;
        }
        if prev == State::Teardown {
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
        let shell = match self.proto_config(name) {
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

    /// The configured bridge (if any) that lists `port` among its ports.
    fn bridge_of_port(&self, port: &str) -> Option<String> {
        self.cfg
            .devices
            .iter()
            .find(|d| {
                d.kind.as_deref() == Some("bridge") && d.ports.iter().any(|p| p == port)
            })
            .map(|d| d.name.clone())
    }

    /// Whether a device counts as present RIGHT NOW, by the C's rules: a
    /// plain device is present when the kernel has it, but a bridge is
    /// present only while it has a present member (`bridge_member_cb`
    /// increments `n_present` and the first one calls `device_set_present`),
    /// or when `bridge_empty` says an empty bridge is fine. A bridge whose
    /// ports all appear later must NOT count as present just because the
    /// bridge netdev itself exists -- that was exactly the P6 device failure:
    /// `lan` was declared available on an empty br-lan, its one bring-up
    /// unwound, and nothing retried when the DSA ports registered.
    fn device_present_now(&mut self, name: &str) -> bool {
        let kernel = self.sys.if_index(name).unwrap_or(0) != 0;
        let bridge = self
            .cfg
            .devices
            .iter()
            .find(|d| d.name == name && d.kind.as_deref() == Some("bridge"))
            .map(|d| (d.bridge_empty, d.ports.clone()));
        let Some((empty, ports)) = bridge else {
            return kernel;
        };
        if !kernel {
            return false;
        }
        if empty == Some(true) || self.prepared_bridges.iter().any(|b| b == name) {
            return true;
        }
        let mut members = ports;
        if let Some(b) = self.devices.get(name).and_then(|d| d.bridge.as_ref()) {
            members.extend(b.members.iter().cloned());
        }
        members.iter().any(|p| self.sys.if_index(p).unwrap_or(0) != 0)
    }

    /// `bridge_member_cb(DEV_EVENT_ADD)` + `bridge_enable_member` for a port
    /// that appeared after the bridge was built: enslave it, kill its IPv6
    /// unless a device section asked for it, claim it (which claims the DSA
    /// conduit behind it), and reapply the bridge MTU the kernel may have
    /// just recomputed from the new member.
    fn bridge_port_add(&mut self, br: &str, port: &str) {
        let bi = match self.sys.if_index(br) {
            Ok(i) if i != 0 => i,
            _ => return,
        };
        let pi = match self.sys.if_index(port) {
            Ok(i) if i != 0 => i,
            _ => return,
        };
        if let Some(d) = self.devices.get(br) {
            if let Some(b) = &d.bridge {
                if b.members.iter().any(|m| m == port) {
                    return;
                }
            }
        }
        // a member with its own `config device` settings (its macaddr, say)
        // gets them before enslaving, so the bridge inherits the configured
        // MAC rather than the kernel's
        self.apply_device_settings(port, pi);
        if let Err(e) = self.sys.bridge_setmaster(pi, bi) {
            logging::log!(Warning, "cannot add {port} to {br}: {e}");
            return;
        }
        let explicit =
            self.cfg.devices.iter().any(|d| d.name == port && d.ipv6.is_some());
        if !explicit {
            let path = format!("/proc/sys/net/ipv6/conf/{port}/disable_ipv6");
            if let Err(e) = std::fs::write(&path, "1") {
                logging::log!(Warning, "cannot disable IPv6 on {port}: {e}");
            }
        }
        self.device_claim(port);
        if let Some(dc) = self.cfg.devices.iter().find(|d| d.name == br) {
            if let Some(mtu) = dc.mtu {
                let _ = self.sys.set_mtu(bi, mtu);
            }
        }
        if let Some(d) = self.devices.get_mut(br) {
            if let Some(b) = &mut d.bridge {
                b.members.push(port.to_string());
            }
        }
        logging::log!(Info, "bridge {br}: port {port} added");
    }

    /// `bridge_hotplug_del`: a member that is not there is NOT_FOUND; one the
    /// config names stays (`if (!bm->dev.hotplug) return 0`); a hotplug member
    /// leaves the bridge and its claim goes.
    fn bridge_port_detach(&mut self, br: &str, port: &str) -> i32 {
        let member = self
            .devices
            .get(br)
            .and_then(|d| d.bridge.as_ref())
            .is_some_and(|b| b.members.iter().any(|m| m == port));
        if !member {
            return status::NOT_FOUND;
        }
        if self.cfg.devices.iter().any(|d| d.name == br && d.ports.iter().any(|p| p == port)) {
            return 0;
        }
        if let Ok(pi) = self.sys.if_index(port) {
            if pi != 0 {
                if let Err(e) = self.sys.bridge_setmaster(pi, 0) {
                    logging::log!(Warning, "cannot remove {port} from {br}: {e}");
                }
            }
        }
        self.device_release(port);
        self.bridge_port_del(br, port);
        logging::log!(Info, "bridge {br}: port {port} removed");
        0
    }

    /// `bridge_remove_member` bookkeeping for a port whose netdev is gone;
    /// the kernel already dropped the enslavement with the device, and
    /// `device_removed` cleans the claims.
    fn bridge_port_del(&mut self, br: &str, port: &str) {
        if let Some(d) = self.devices.get_mut(br) {
            if let Some(b) = &mut d.bridge {
                b.members.retain(|m| m != port);
            }
        }
    }

    /// `_device_set_present`, for every device this daemon has an object for.
    /// A device that disappears takes its claims with it, so a device that
    /// comes back under the same name is claimed again rather than being
    /// assumed to still be up.
    ///
    /// Two passes: ports first, bridges second. Enslaving a freshly appeared
    /// port is what can make its bridge present, so a bridge's own presence
    /// flip must be evaluated after its members' -- otherwise the interface
    /// on the bridge is told nothing until the NEXT netlink event.
    fn update_presence(&mut self) {
        let mut watch: Vec<String> = self.known_device_names();
        for (n, _) in &self.claims {
            if !watch.contains(n) {
                watch.push(n.clone());
            }
        }
        let bridges: Vec<String> = self
            .cfg
            .devices
            .iter()
            .filter(|d| d.kind.as_deref() == Some("bridge"))
            .map(|d| d.name.clone())
            .collect();
        for name in watch.iter().filter(|n| !bridges.contains(n)).cloned().collect::<Vec<_>>() {
            let now = self.sys.if_index(&name).unwrap_or(0) != 0;
            let was = self.present.contains(&name);
            if now == was {
                continue;
            }
            if now {
                self.present.push(name.clone());
                logging::log!(Debug, "device '{name}' is now present");
                // a plain `config device` (e.g. wan with an explicit macaddr)
                // that appears late gets its settings when its interface
                // claims it (`device_claim` -> `system_if_up`), like the C
                if let Some(br) = self.bridge_of_port(&name) {
                    self.bridge_port_add(&br, &name);
                }
                self.device_added(&name);
            } else {
                self.present.retain(|n| *n != name);
                logging::log!(Debug, "device '{name}' is no longer present");
                if let Some(br) = self.bridge_of_port(&name) {
                    self.bridge_port_del(&br, &name);
                }
                self.device_removed(&name);
            }
        }
        for name in bridges {
            if !watch.contains(&name) {
                continue;
            }
            let now = self.device_present_now(&name);
            let was = self.present.contains(&name);
            if now == was {
                continue;
            }
            if now {
                self.present.push(name.clone());
                logging::log!(Debug, "device '{name}' is now present");
                self.device_added(&name);
            } else {
                self.present.retain(|n| *n != name);
                logging::log!(Debug, "device '{name}' is no longer present");
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
        logging::log!(Notice,
            "Interface '{name}' has link connectivity {}",
            if new_state { "" } else { "loss" }
        );
        self.check_state(name);
    }

    /// `interface_check_state`: losing the link tears the interface down, and
    /// getting it back brings the interface up again if it is still set to
    /// autostart.
    fn check_state(&mut self, name: &str) {
        let Some(idx) = self.iface_index(name) else { return };
        let carrier =
            self.link_state.iter().find(|(n, _)| n == name).map(|(_, s)| *s).unwrap_or(false);
        // proto-static defaults force_link to true. A LAN with no cable
        // still needs its address before wireless can attach to its bridge.
        let force = self.cfg.interfaces.iter().find(|c| c.name == name)
            .is_some_and(|c| c.force_link.unwrap_or(c.proto == "static"));
        let auth = self.interfaces[idx].device.as_deref()
            .and_then(|d| self.devices.get(d)).is_some_and(|d| d.settings.auth);
        let link = carrier || (force && !auth);
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
            logging::log!(Warning, "cannot register {name}: {e}");
            return status::UNKNOWN_ERROR;
        }
        logging::log!(Debug, "Create interface '{name}'");
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
            logging::log!(Debug, "Remove interface '{name}'");
            // Exactly one ifdown. `mark_interface_down` flushes the state
            // and emits a single IFEV_DOWN; adding
            // `set_down` first emitted a second one, and skipping both
            // emitted none. The C emits one.
            self.mark_interface_down(&name);
            // interface_cleanup_state removes main_dev even when autostart
            // kept its claim while the protocol was Down awaiting carrier.
            self.iface_unclaim(&name, false);
            self.interfaces.retain(|i| i.name != name);
            self.cfg.interfaces.retain(|c| c.name != name);
            self.free_unused_devices();
            if let Err(e) = self.objects.remove_interface(&mut self.conn, &name) {
                logging::log!(Warning, "cannot unregister {name}: {e}");
            }
            self.link_state.retain(|(n, _)| *n != name);
            // `proto_ext_free`: `netifd_kill_process` on both tasks. Dropping
            // the slots did not kill anything, so a removed interface's
            // helper lived on (R81 F04).
            if let Some(pos) = self.protos.iter().position(|(n, _)| *n == name) {
                let (_, mut st) = self.protos.remove(pos);
                st.script.terminate();
                st.task.terminate();
            }
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
                        self.add_iface_route(&name, di, &r, &mut ipset, None);
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
        let Some(idx) = self.iface_index(name) else { return };
        match std::mem::take(&mut self.interfaces[idx].config_state) {
            interface::ConfigState::Normal => {}
            interface::ConfigState::Reload => self.do_reload(name),
            interface::ConfigState::Remove => {
                // deferred, as the C's 1 ms remove_timer is: this runs from
                // inside the reaper's walk over the proto states
                if !self.remove_pending.iter().any(|n| n == name) {
                    self.remove_pending.push(name.to_string());
                }
                return;
            }
        }
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
    /// `interface_write_resolv_conf` (this build has no jails): every UP
    /// interface with DNS servers or search domains, ordered by dns_metric,
    /// then metric, then name; config_ip entries first, then proto_ip unless
    /// `no_dns`; a link-local v6 server carries `%<l3 device>`. Written to
    /// `<path>.tmp` and renamed only when the bytes changed -- the C compares
    /// crc32 of old and new, which decides the same thing. dnsmasq reads this
    /// file as its resolvfile: without it every client has a lease and no name
    /// resolution, which is exactly how P6 window #3 failed on the device.
    fn write_resolv_conf(&self) {
        let mut ifs: Vec<&Interface> = self
            .interfaces
            .iter()
            .filter(|i| {
                i.state == State::Up
                    && !(i.config_ip.dns_servers.is_empty()
                        && i.config_ip.dns_search.is_empty()
                        && i.proto_ip.dns_servers.is_empty()
                        && i.proto_ip.dns_search.is_empty())
            })
            .collect();
        ifs.sort_by(|a, b| {
            a.dns_metric
                .cmp(&b.dns_metric)
                .then(a.metric.cmp(&b.metric))
                .then(a.name.cmp(&b.name))
        });
        let mut out = String::new();
        for i in ifs {
            let dev = i.l3_device.clone().or_else(|| i.device.clone()).unwrap_or_default();
            out.push_str(&format!("# Interface {}\n", i.name));
            write_resolv_entries(&mut out, &i.config_ip, &dev);
            if !i.proto_ip.no_dns {
                write_resolv_entries(&mut out, &i.proto_ip, &dev);
            }
        }
        let path = &self.resolvconf;
        if std::fs::read(path).map(|old| old == out.as_bytes()).unwrap_or(false) {
            return;
        }
        let tmp = format!("{path}.tmp");
        let _ = std::fs::remove_file(&tmp);
        if std::fs::write(&tmp, out.as_bytes()).is_err() {
            return;
        }
        if std::fs::rename(&tmp, path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }

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
            logging::log!(Notice, "Interface '{name}' is now down");
        }
        self.interfaces[idx].state = State::Down;
        match prev {
            State::Up | State::Teardown => self.emit_event(name, Event::Down),
            State::Setup => self.emit_event(name, Event::UpFailed),
            State::Down => {}
        }
        // IFPEV_DOWN / IFPEV_LINK_LOST: this interface's servers leave the file
        self.write_resolv_conf();

        let l3 = self.interfaces[idx].l3_device.clone();
        let addrs: Vec<Address> = self.interfaces[idx].proto_ip.addresses.clone();
        let mut routes: Vec<interface::Route> = self.interfaces[idx].proto_ip.routes.clone();
        routes.extend(self.interfaces[idx].config_ip.routes.iter().cloned());
        let neighs: Vec<interface::Neighbor> = self.interfaces[idx].proto_ip.neighbors.clone();
        let assigns = self.interfaces[idx].prefix_assignments.clone();
        if let Some(dev) = l3 {
            if let Ok(di) = self.sys.if_index(&dev) {
                if di != 0 {
                    for r in &routes {
                        // a route `no_defaultroute` held back was never added
                        if !r.enabled {
                            continue;
                        }
                        let d = if r.flags & interface::devroute::NODEV != 0 { 0 } else { di };
                        if let Err(e) = self.sys.del_route(d, &sys_route(r)) {
                            logging::log!(Warning,
                                "{name}: cannot remove the route to {}/{}: {e}",
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
                        let mut sa = sys::Address::new(a.addr, a.mask);
                        sa.offlink = a.offlink;
                        if let Some(route) = sys::offlink_route(&sa) {
                            let _ = self.sys.del_route(0, &route);
                        }
                        if let Err(e) = self.sys.del_address(di, &sa) {
                            logging::log!(Warning,
                                "{name}: cannot remove {}/{}: {e}",
                                a.addr, a.mask
                            );
                        }
                    }
                    for a in &assigns {
                        if let Some((local, len)) = a.local {
                            let delegated = a.owner.as_ref().is_some_and(|(uplink, _, _)| uplink.is_some());
                            self.withdraw_assignment(di, local, len, a.valid_until, delegated.then_some(dev.as_str()));
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

        i.started_at = None;
        // A prefix is only delegated while the uplink that carries it is up.
        // Leaving it behind would keep handing the LAN addresses that no
        // longer route.
        self.set_delegated_prefixes(name, Vec::new());

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
                logging::log!(Warning, "cannot send the {name} interface event: {e}");
            }
        }

        // `netifd_ubus_interface_notify(iface, ev != IFEV_DOWN)`
        let method = if matches!(ev, Event::Down) { "interface.down" } else { "interface.update" };
        let Some(i) = self.interfaces.iter().find(|i| i.name == name) else { return };
        let mut b = BlobBuf::new();
        b.msg_string("interface", name);
        self.dump_interface_status(&mut b, i);
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
                logging::log!(Warning, "cannot notify {method} for {name}: {e}");
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
                logging::log!(Warning, "cannot run {} for {name}: {e}", self.hotplug_path);
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

    fn dump_interface(&self, b: &mut BlobBuf, i: &Interface) {
        b.msg_string("interface", &i.name);
        self.dump_interface_status(b, i);
    }

    /// The device's link counters from one RTM_GETLINK reply. The 23 sysfs
    /// statistics files the C reads are views of the same rtnl_link_stats64,
    /// so this replaces 70 file syscalls per status with a netlink round trip;
    /// None (no reply, no attribute) falls back to the sysfs files.
    fn link_stats(&mut self, ifname: &str) -> Option<[u64; 23]> {
        let hdr = sys::ifinfomsg(sys::AF_UNSPEC, 0, 0, 0);
        let mut a = netlink::Attrs::new();
        a.str0(sys::IFLA_IFNAME, ifname);
        let msg = self.sys.nl.dump_one(sys::RTM_GETLINK, &hdr, a.as_bytes()).ok()??;
        let attrs = msg.attrs(16);
        ethtool::stats64_counters(netlink::attr(&attrs, sys::IFLA_STATS64)?)
    }

    fn take_reply(&mut self) -> BlobBuf {
        self.reply.take().unwrap_or_default()
    }

    /// Send `b` as the DATA + STATUS reply and keep its storage for the next
    /// request, dropping it if an unusually large reply inflated it.
    fn send_reply(&mut self, req: &Request, mut b: BlobBuf) -> io::Result<()> {
        let result = reply_fields(&mut self.conn, req, b.payload());
        b.reset_bounded(64 * 1024);
        self.reply = Some(b);
        result
    }

    fn dump_device(&self, b: &mut BlobBuf, device: &Device, stats: Option<&[u64; 23]>) {
        let mut snapshot = device.clone();
        if let Some(bridge) = &mut snapshot.bridge {
            // bridge_dump_info lists registered members, including configured
            // ports that have not appeared in the kernel yet.
            if let Some(config) = self.cfg.devices.iter().find(|d| d.name == device.ifname) {
                bridge.members.extend(config.ports.iter().cloned());
                bridge.members.sort();
                bridge.members.dedup();
            }
        }
        snapshot.dump_status(b, Some(&self.ethtool), stats);
    }

    fn handle(&mut self, req: Request) {
        self.handle_request(&req);
        self.conn.recycle_request(req);
    }

    fn handle_request(&mut self, req: &Request) {
        let mut target = self.objects.route(req.objid);
        let method = req.method.as_str();

        // `netifd_add_iface_object` replaces every method of the shared
        // `network.interface` object except `dump` with a resolver that reads
        // the interface name out of the payload and then calls the
        // per-interface handler. `netifd-proto.sh` relies on this: it always
        // calls `ubus call network.interface notify_proto {..., "interface":
        // "<name>"}`, never the per-interface object. Registration is
        // unaffected -- `ubus -v list` shows the object TYPE's signature,
        // which still carries each method's own policy.
        let mut resolved: Option<&str> = None;
        if target == ubus::Target::Interface(None) && method != "dump" {
            let name = blob::fields(&req.data)
                .find(|f| f.name == "interface" && f.ty == MsgType::String as u32)
                .and_then(|f| f.as_str());
            let Some(name) = name else {
                let _ = self.conn.reply_status(req, status::INVALID_ARGUMENT, None);
                return;
            };
            if interface::find_by_name(&self.interfaces, name).is_none() {
                let _ = self.conn.reply_status(req, status::NOT_FOUND, None);
                return;
            }
            resolved = Some(name);
        }
        if let Some(name) = &resolved {
            target = ubus::Target::Interface(Some(name));
        }
        let r = match (target, method) {
            // `netifd_reload` is just `config_init_all`: it does not take
            // anything down. Only `netifd_restart` does, and it uses
            // `interface_set_down(NULL)`, which does NOT clear autostart --
            // so everything comes back up afterwards.
            (ubus::Target::Wireless, "status") => {
                let selected = match self.wireless_selector(&req.data) {
                    Ok(selected) => selected,
                    Err(code) => {
                        let _ = self.conn.reply_status(req, code, None);
                        return;
                    }
                };
                let mut b = self.take_reply();
                self.wireless_status_into_blob(&mut b, selected);
                self.send_reply(req, b)
            }
            (ubus::Target::Wireless, "get_validate") => {
                let selected = match self.wireless_selector(&req.data) {
                    Ok(selected) => selected,
                    Err(code) => {
                        let _ = self.conn.reply_status(req, code, None);
                        return;
                    }
                };
                let mut b = self.take_reply();
                let radios = selected.map_or(self.wconfig.as_slice(), |index| {
                    std::slice::from_ref(&self.wconfig[index])
                });
                let text = wireless::get_validate_json(radios, &self.whandlers);
                wireless::json_text_into_blob(&mut b, &text);
                self.send_reply(req, b)
            }
            (ubus::Target::Wireless, "notify") => {
                let st = self.wireless_notify(&blob::fields(&req.data).collect::<Vec<_>>());
                self.conn.reply_status(req, st, None)
            }
            (ubus::Target::Wireless, m @ ("up" | "down" | "retry" | "reconf")) => {
                let st = self.wireless_command(m, &blob::fields(&req.data).collect::<Vec<_>>());
                self.conn.reply_status(req, st, None)
            }
            (ubus::Target::Wireless, _) => {
                self.conn.reply_status(req, status::METHOD_NOT_FOUND, None)
            }
            (ubus::Target::Network, "reload") => {
                // A refused reload has to be visible to the caller, not just
                // in the log -- that is the whole point of refusing.
                let code = match self.reload_checked() {
                    Ok(()) => status::OK,
                    Err(_) => status::INVALID_ARGUMENT,
                };
                self.conn.reply_status(req, code, None)
            }
            (ubus::Target::Network, "restart") => {
                for name in
                    self.interfaces.iter().map(|i| i.name.clone()).collect::<Vec<_>>()
                {
                    self.set_down(&name);
                }
                self.restart_at = Some(now_ms() + 1000);
                self.conn.reply_status(req, status::OK, None)
            }
            // `netifd_add_host_route`
            (ubus::Target::Network, "add_host_route") => {
                match self.add_host_route(&req.data) {
                    Ok(iface) => {
                        let mut b = BlobBuf::new();
                        b.msg_string("interface", &iface);
                        let fields = b.payload().to_vec();
                        if let Err(e) = self.conn.reply_data(req, &fields) {
                            logging::log!(Warning, "cannot reply to add_host_route: {e}");
                        }
                        self.conn.reply_status(req, status::OK, None)
                    }
                    Err(code) => self.conn.reply_status(req, code, None),
                }
            }
            // `netifd_netns_updown` needs a netns fd passed by the caller
            // (`ubus_request_get_caller_fd`) and answers INVALID_ARGUMENT
            // without one. This build never receives fds and does not do
            // jails, so that is the only answer it can give -- the same one
            // the C gives to the same call.
            (ubus::Target::Network, "netns_updown") => {
                self.conn.reply_status(req, status::INVALID_ARGUMENT, None)
            }
            // `netifd_add_dynamic`: the whole request is the config.
            (ubus::Target::Network, "add_dynamic") => {
                let code = self.add_dynamic(&req.data);
                self.conn.reply_status(req, code, None)
            }
            (ubus::Target::Network, "get_proto_handlers") => {
                let mut b = self.take_reply();
                self.dump_proto_handlers(&mut b);
                self.send_reply(req, b)
            }
            (ubus::Target::Network, m) => ubus::not_supported(&mut self.conn, req, m),
            (ubus::Target::Device, "status") => {
                let name = blob::fields(&req.data)
                    .find(|f| f.name == "name" && f.ty == MsgType::String as u32)
                    .and_then(|f| f.as_str().map(|s| s.to_string()));
                let mut b = self.take_reply();
                match name {
                    // `netifd_dev_status`: `device_find` misses -> the C
                    // answers INVALID_ARGUMENT, not NOT_FOUND, and it does
                    // not check whether the device is present -- a device
                    // object with no kernel device is still dumped
                    Some(n) => {
                        if self.devices.get(&n).is_none() {
                            self.reply = Some(b);
                            let _ =
                                self.conn.reply_status(req, status::INVALID_ARGUMENT, None);
                            return;
                        }
                        let stats = self.link_stats(&n);
                        if let Some(d) = self.devices.get(&n) {
                            self.dump_device(&mut b, d, stats.as_ref());
                        }
                    }
                    None => {
                        let names: Vec<String> = self
                            .devices
                            .iter()
                            .filter(|d| d.present)
                            .map(|d| d.ifname.clone())
                            .collect();
                        for name in names {
                            let stats = self.link_stats(&name);
                            let Some(d) = self.devices.get(&name) else { continue };
                            let t = b.msg_open_table(&d.ifname);
                            self.dump_device(&mut b, d, stats.as_ref());
                            b.msg_close(t);
                        }
                    }
                }
                self.send_reply(req, b)
            }
            // `netifd_handle_set_state`
            (ubus::Target::Device, "set_state") => {
                let code = self.device_set_state(&req.data);
                self.conn.reply_status(req, code, None)
            }
            // `netifd_handle_alias`. Alias devices themselves are out of
            // scope (R45), so nothing is notified -- but the side effect that
            // r55 saw is real: naming a device here creates a device object
            // for it, which is then reported by `network.device status`.
            (ubus::Target::Device, "set_alias") => {
                let code = self.device_set_alias(&req.data);
                self.conn.reply_status(req, code, None)
            }
            // `netifd_handle_stp_init` has nothing to initialise without an
            // STP daemon to talk to, and answers OK.
            (ubus::Target::Device, "stp_init") => {
                self.conn.reply_status(req, status::OK, None)
            }
            (ubus::Target::Device, m) => ubus::not_supported(&mut self.conn, req, m),
            (ubus::Target::Interface(_), "dump") => {
                let mut b = self.take_reply();
                if self.dump_capacity_hint > 64 * 1024 {
                    b = BlobBuf::with_capacity(self.dump_capacity_hint);
                }
                let arr = b.msg_open_array("interface");
                for i in &self.interfaces {
                    let t = b.msg_open_table("");
                    self.dump_interface(&mut b, i);
                    b.msg_close(t);
                }
                b.msg_close(arr);
                self.dump_capacity_hint = (b.payload().len() + 4).min(256 * 1024);
                self.send_reply(req, b)
            }
            (ubus::Target::Interface(Some(name)), "status") => {
                // `name` borrows the object table; own it before touching
                // the reply storage, as the other per-interface arms do.
                let name = name.to_string();
                let mut b = self.take_reply();
                let Some(i) = interface::find_by_name(&self.interfaces, &name) else {
                    self.reply = Some(b);
                    let _ = self.conn.reply_status(req, status::NOT_FOUND, None);
                    return;
                };
                self.dump_interface_status(&mut b, i);
                self.send_reply(req, b)
            }
            (ubus::Target::Interface(Some(name)), "up") => {
                let name = name.to_string();
                self.iface_up(&name);
                self.conn.reply_status(req, status::OK, None)
            }
            (ubus::Target::Interface(Some(name)), "down") => {
                let name = name.to_string();
                self.iface_down(&name);
                self.conn.reply_status(req, status::OK, None)
            }
            (ubus::Target::Interface(Some(name)), "renew") => {
                let name = name.to_string();
                self.proto_cmd(&name, proto::Cmd::Renew);
                self.conn.reply_status(req, status::OK, None)
            }
            // `netifd_handle_set_data` -> `interface_parse_data`
            // `netifd_iface_handle_device` -> `interface_handle_link`.
            // `netifd_handle_iface_dev` -> `interface_handle_link`: with a
            // bridge as the main device this is `bridge_hotplug_add/del`, a
            // member joining or leaving at runtime; the interface's own main
            // device is a no-op (0); a non-bridge main device has no hotplug
            // ops in the C either (NOT_SUPPORTED); hotplug-assigning a device
            // to an interface that has none is out of this build's scope and
            // answers NOT_SUPPORTED rather than pretending (R81 F13).
            (ubus::Target::Interface(Some(name)), m @ ("add_device" | "remove_device")) => {
                let name = name.to_string();
                let dev = blob::fields(&req.data)
                    .find(|f| f.name == "name" && f.ty == MsgType::String as u32)
                    .and_then(|f| f.as_str().map(|s| s.to_string()));
                let Some(dev) = dev else {
                    let _ = self.conn.reply_status(req, status::INVALID_ARGUMENT, None);
                    return;
                };
                let link_ext = blob::fields(&req.data)
                    .find(|f| f.name == "link-ext")
                    .and_then(|f| f.as_bool())
                    .unwrap_or(true);
                // `interface_handle_link` looks up the device BEFORE checking
                // whether the main device supports hotplug. Even a rejected
                // add marks an existing device external (device_get(..., 2)).
                if m == "add_device" {
                    if !self.device_objects.contains(&dev) {
                        self.device_objects.push(dev.clone());
                        if !link_ext {
                            self.sys.clear_state(&dev, false);
                        }
                        self.rescan_devices();
                    }
                    if link_ext {
                        if let Some(d) = self.devices.get_mut(&dev) {
                            d.external = true;
                            d.present = !d.deferred;
                        }
                    }
                }
                let main = self
                    .cfg
                    .interfaces
                    .iter()
                    .find(|i| i.name == name)
                    .and_then(|i| i.device.clone());
                let code = match main {
                    Some(md) if md == dev => 0,
                    Some(md)
                        if self
                            .cfg
                            .devices
                            .iter()
                            .any(|x| x.name == md && x.kind.as_deref() == Some("bridge")) =>
                    {
                        if m == "add_device" {
                            if self.sys.if_index(&dev).unwrap_or(0) == 0 {
                                status::NOT_FOUND
                            } else {
                                // The device lookup and external ownership
                                // decision happened before the hotplug call.
                                self.bridge_port_add(&md, &dev);
                                0
                            }
                        } else {
                            self.bridge_port_detach(&md, &dev)
                        }
                    }
                    // `interface_add_link`: a main device without hotplug ops
                    // is NOT_SUPPORTED; `interface_remove_link`: a main device
                    // that was not hotplug-assigned is INVALID_ARGUMENT
                    _ if m == "add_device" => status::NOT_SUPPORTED,
                    _ => status::INVALID_ARGUMENT,
                };
                self.conn.reply_status(req, code, None)
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
                self.conn.reply_status(req, code, None)
            }
            (ubus::Target::Interface(Some(name)), "set_data") => {
                let name = name.to_string();
                let code = self.set_data(&name, &req.data);
                self.conn.reply_status(req, code, None)
            }
            // `netifd_handle_iface_prepare`: the same bridge preparation
            // used by wireless, with only the bridge name in the reply.
            (ubus::Target::Interface(Some(name)), "prepare") => {
                let name = name.to_string();
                let fields = self.prepare_interface_bridge(&name).unwrap_or_default();
                let mut b = BlobBuf::new();
                if let Some((_, owrt_ubus::json::Json::Str(br))) = fields.iter().find(|(k, _)| k == "bridge") {
                    b.msg_string("bridge", br);
                }
                if let Err(e) = self.conn.reply_data(req, b.payload()) {
                    logging::log!(Warning, "cannot reply to prepare: {e}");
                }
                self.conn.reply_status(req, status::OK, None)
            }
            (ubus::Target::Interface(Some(name)), "notify_proto") => {
                let name = name.to_string();
                let code = self.notify_proto(&name, &req.data);
                self.conn.reply_status(req, code, None)
            }
            (ubus::Target::Interface(_), m) => ubus::not_supported(&mut self.conn, req, m),
            (ubus::Target::Unknown, _) => {
                self.conn.reply_status(req, status::NOT_FOUND, None)
            }
        };
        if let Err(e) = r {
            logging::log!(Warning, "reply failed: {e}");
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
            // `cb_rtnl_event`: only link add/remove/change is a device event
            Ok(msgs) if msgs.iter().any(|m| m.ty == sys::RTM_NEWLINK || m.ty == sys::RTM_DELLINK) => {
                self.netlink_resync = true;
            }
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(netlink::ENOBUFS) => {
                logging::log!(Warning, "netlink receive overflow; resynchronizing devices");
                if let Err(error) = self.events.grow_event_buffer() {
                    logging::log!(Warning, "cannot grow netlink receive buffer: {error}");
                }
                self.netlink_resync = true;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => logging::log!(Warning, "netlink event read failed: {e}"),
        }
    }

    fn resync_netlink(&mut self) {
        if self.netlink_resync && self.rescan_devices() {
            self.netlink_resync = false;
            self.update_presence();
            self.update_link_states();
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
        // A failed earlier attempt may still own some object paths. Release
        // it before registering on another transport, even if a child still
        // holds a copied descriptor.
        let _ = self.conn.shutdown();
        let mut conn = match Connection::connect(self.socket.as_deref()) {
            Ok(c) => c,
            Err(_) => return,
        };
        conn.set_server_io_timeout(Duration::from_secs(1));
        let mut objects = match ubus::Objects::register(&mut conn) {
            Ok(o) => o,
            Err(e) => {
                logging::log!(Warning, "reconnected but cannot register: {e}");
                return;
            }
        };
        for name in self.interfaces.iter().map(|i| &i.name) {
            if let Err(e) = objects.add_interface(&mut conn, name) {
                logging::log!(Warning, "reconnected but cannot register {name}: {e}");
                // Keep retrying the complete set. Dropping this local
                // transport removes its partial registrations from ubusd.
                return;
            }
        }
        self.conn = conn;
        self.objects = objects;
        self.bus_down = false;
        logging::log!(Info, "reconnected to ubus");
    }

    /// Messages that arrive while a blocking request is waiting for its own
    /// reply are queued rather than dropped. Nothing new will land on the
    /// socket to wake the loop, so they have to be drained deliberately --
    /// otherwise an invoke that arrived during an `add_object` or
    /// `remove_object` sits until some unrelated event comes in, and its
    /// caller times out. r55 hit exactly that: `network.interface dump`
    /// timing out right after `remove`, intermittently, depending on whether
    /// the dump landed inside that window.
    fn drain_bus(&mut self) {
        while !self.bus_down && self.conn.has_pending() {
            match self.conn.read_incoming() {
                Ok(Incoming::Invoke(req)) => self.handle(req),
                Ok(_) => {}
                Err(e) => {
                    logging::log!(Warning, "bus connection lost: {e}");
                    self.bus_down = true;
                    self.bus_retry_at = now() + BUS_RETRY_SECS;
                    break;
                }
            }
        }
    }

    /// One second as a backstop, or sooner when a proto teardown deadline is
    /// closer than that.
    fn poll_timeout_ms(&self) -> i32 {
        let t = now_ms();
        self.protos
            .iter()
            .filter_map(|(_, st)| st.teardown_deadline)
            .chain(self.wdeadline)
            .chain(self.restart_at)
            .map(|d| d.saturating_sub(t).min(1000) as i32)
            .min()
            .unwrap_or(1000)
    }

    /// `uloop_end` followed by `netifd_kill_processes`: on SIGINT, SIGTERM,
    /// SIGUSR1 or SIGUSR2 the C leaves the interfaces exactly as they are,
    /// SIGKILLs every process it started -- protocol scripts, their helpers,
    /// the hotplug script -- and exits 0. Without this the default disposition
    /// killed netifd alone, so a `service network restart` left udhcpc and
    /// odhcp6c running and the next netifd started a second copy of each
    /// (R81 F03). The exact rootfs also stops its ucode-owned wireless
    /// handler on exit, as the shutdown case in r83_wireless_deadline proves.
    fn shutdown(&mut self) -> ! {
        logging::log!(Info, "terminating on signal");
        for (_, st) in &mut self.protos {
            st.script.terminate();
            st.task.terminate();
        }
        self.hotplug.terminate();
        self.wslot.terminate();
        std::process::exit(0);
    }

    /// `proto_ext_teardown_timeout_cb`: a teardown script that has not exited
    /// 5 s after it started, or an aborted setup still running 1 s after the
    /// SIGTERM, is SIGKILLed together with its helper and the state machine
    /// completes as if both had exited (R81 F09).
    fn pump_proto_deadlines(&mut self) {
        let t = now_ms();
        let names: Vec<String> = self
            .protos
            .iter()
            .filter(|(_, st)| st.teardown_deadline.is_some_and(|d| t >= d))
            .map(|(n, _)| n.clone())
            .collect();
        for name in names {
            logging::log!(Warning, "{name}: teardown timed out, killing the protocol handler");
            let st = self.proto_state(&name);
            st.teardown_deadline = None;
            st.script.terminate();
            st.task.terminate();
            self.finish_proto_task(&name, proto::Which::Script);
        }
    }

    fn run(&mut self) -> ! {
        loop {
            if self.restart_at.is_some_and(|at| now_ms() >= at) {
                self.restart_at = None;
                use std::os::unix::process::CommandExt;
                let mut argv = std::env::args_os();
                if let Some(program) = argv.next() {
                    // main.c netifd_do_restart: execvp(global_argv[0], global_argv).
                    // CLOEXEC descriptors release the old bus registrations.
                    let error = std::process::Command::new(program).args(argv).exec();
                    logging::log!(Warning, "restart exec failed: {error}");
                }
            }
            if self.bus_down {
                self.retry_bus();
            }
            self.drain_bus();
            // While the bus is gone its fd is not polled -- it is closed, and
            // polling it would spin. Everything else keeps running.
            let ubus_fd = if self.bus_down { -1 } else { self.conn.as_raw_fd() };
            let nl_fd = self.events.as_raw_fd();
            let mut fds = [
                PollFd { fd: ubus_fd, events: POLLIN, revents: 0 },
                PollFd { fd: nl_fd, events: POLLIN, revents: 0 },
                PollFd { fd: self.sigchld.as_raw_fd(), events: POLLIN, revents: 0 },
            ];
            // the timeout is a backstop now that SIGCHLD wakes us, or the
            // nearest proto teardown deadline when that is sooner
            let timeout = self.poll_timeout_ms();
            match owrt_ubus::sys::poll_fds(&mut fds, timeout) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    logging::log!(Warning, "poll failed: {e}");
                    std::process::exit(1);
                }
            }
            if fds[2].revents & POLLIN != 0 {
                self.sigchld.drain();
            }
            if self.sigchld.exit_requested() {
                self.shutdown();
            }
            self.reap_children();
            process::reap_retired();
            self.pump_proto_deadlines();
            self.pump_prefix_expiry();
            self.pump_wireless_deadline();
            self.pump_wireless_procs();
            self.pump_removals();
            self.pump_checkups();
            if fds[1].revents & POLLIN != 0 {
                self.drain_netlink();
            }
            self.resync_netlink();
            if !self.bus_down && fds[0].revents & (POLLIN | POLLHUP) != 0 {
                match self.conn.read_incoming() {
                    Ok(Incoming::Invoke(req)) => self.handle(req),
                    Ok(_) => {}
                    Err(e) => {
                        // `netifd_ubus_connection_lost`: retry, do not exit.
                        // Exiting only looks survivable because procd restarts
                        // the daemon -- and that loses every interface.
                        logging::log!(Warning, "bus connection lost: {e}");
                        self.bus_down = true;
                        self.bus_retry_at = now() + BUS_RETRY_SECS;
                    }
                }
                // one read can leave more than one message buffered
                self.drain_bus();
            }
        }
    }
}

/// `write_resolv_conf_entries`: nameserver lines, then search lines.
fn write_resolv_entries(out: &mut String, ip: &interface::IpSettings, dev: &str) {
    for s in &ip.dns_servers {
        match s {
            IpAddr::V6(a) if (a.segments()[0] & 0xffc0) == 0xfe80 => {
                out.push_str(&format!("nameserver {a}%{dev}\n"))
            }
            a => out.push_str(&format!("nameserver {a}\n")),
        }
    }
    for d in &ip.dns_search {
        out.push_str(&format!("search {d}\n"));
    }
}

/// The vlist key of a route: its destination and where it sits, not how it
/// gets there. See the note on `flush_stale_ip`.
/// The config_ip route vlist key plus the fields a re-parse can change.
fn route_key(r: &interface::Route) -> (IpAddr, u8, IpAddr, u32, u32, u32, u32, u32, IpAddr, u8) {
    (r.target, r.mask, r.nexthop, r.flags, r.metric, r.table, r.mtu, r.ty, r.source, r.sourcemask)
}

fn same_route(a: &interface::Route, b: &interface::Route) -> bool {
    a.target == b.target
        && a.mask == b.mask
        && a.table == b.table
        && a.metric == b.metric
        && a.source == b.source
        && a.sourcemask == b.sourcemask
}

/// The vlist key of an address: its prefix. A renewal that only moves a
/// lifetime is the same address, replaced in place.
fn same_address(a: &interface::Address, b: &interface::Address) -> bool {
    a.addr == b.addr && a.mask == b.mask
}

/// C's address callback keeps a successful vlist entry unless flags or IPv4
/// broadcast/peer change; changed deadlines still require a lifetime refresh.
/// The address list only records successful initial installs. `failed` covers
/// subsequent reload_ip failures, which must not become a false cache hit.
fn keep_proto_address(old: &Address, new: &Address, now: u32) -> bool {
    same_proto_address(old, new)
        && old.enabled
        && !old.failed
        && old.preferred_until == new.preferred_until
        && old.valid_until == new.valid_until
        && old.valid_until.is_none_or(|until| until > now)
        && (old.addr.is_ipv6()
            || (old.broadcast == new.broadcast && old.point_to_point == new.point_to_point))
}

fn same_proto_address(old: &Address, new: &Address) -> bool {
    same_address(old, new) && old.index == new.index && old.offlink == new.offlink
}

/// The route vlist key includes flags, metric, table and source. Its callback
/// then compares these four non-key fields. Route lifetimes are daemon expiry
/// deadlines, not kernel attributes: renewing one alone needs no netlink write.
fn keep_proto_route(old: &interface::Route, new: &interface::Route, now: u64) -> bool {
    interface::route_order(old, new).is_eq()
        && old.nexthop == new.nexthop
        && old.mtu == new.mtu
        && old.ty == new.ty
        && old.proto == new.proto
        && old.enabled
        && !old.failed
        && old.valid_until.is_none_or(|until| u64::from(until) > now)
}

// ---------------------------------------------------------------------------
// network.wireless: driving the radios
// ---------------------------------------------------------------------------

/// One radio's live state, mirroring `wdev` in wireless-device.uc.
#[derive(Clone, Debug)]
struct WRadio {
    name: String,
    state: wireless::WState,
    retry: u32,
    retry_setup_failed: bool,
    autostart: bool,
    /// `handler_data[section].ifname`, reported by the handler through notify.
    ifnames: Vec<(String, String)>,
    /// The configuration actually passed to this generation's handler.
    handler_config: owrt_ubus::json::Json,
    /// Dynamic bridge members owned by this radio, for teardown.
    links: Vec<(String, String)>,
    /// `wdev.procs`: processes the handler registered. A registered process
    /// disappearing tears the radio down.
    procs: Vec<(i64, String)>,
    /// `wdev.config_change`: a setup was asked for while the handler was
    /// running; `wdev_setup_cb` runs it again once the handler is done.
    config_change: bool,
    /// `handler_data[wdev.name]`: the device-level record, handed back to the
    /// handler on its next setup and on teardown. Cleared when a teardown
    /// completes, the way `wdev_teardown_cb` empties the whole map.
    device_data: Vec<(String, String)>,
}

impl Netifd {
    fn wradio(&mut self, name: &str) -> Option<&mut WRadio> {
        self.wradios.iter_mut().find(|r| r.name == name)
    }

    /// Discover the handlers, read the config, and start every radio.
    fn wireless_load(&mut self) {
        self.whandlers = wireless::discover(std::path::Path::new(&self.wirelessdir));
        self.wconfig = wireless::load(&self.confdir, &self.whandlers);
        self.wradios = self
            .wconfig
            .iter()
            .map(|r| WRadio {
                name: r.name.clone(),
                state: wireless::WState::Down,
                retry: wireless::DEFAULT_RETRY,
                retry_setup_failed: false,
                autostart: true,
                ifnames: Vec::new(),
                handler_config: owrt_ubus::json::Json::Null,
                links: Vec::new(),
                device_data: Vec::new(),
                procs: Vec::new(),
                config_change: false,
            })
            .collect();
        for name in self.wradios.iter().map(|r| r.name.clone()).collect::<Vec<_>>() {
            self.wireless_setup(&name);
        }
    }

    /// `update_config`: reconcile the radios against a freshly read
    /// `/etc/config/wireless`. A radio that is gone is destroyed, one whose
    /// config is unchanged is left completely alone -- `update()` returns at
    /// `is_equal(this.data, data)` -- and a changed one resets its budget and
    /// sets up again. A reload must not restart radios nothing asked about.
    fn wireless_reload(&mut self) {
        if self.whandlers.is_empty() {
            return;
        }
        let mut fresh = wireless::load_config(&self.confdir, &self.whandlers);

        // gone: destroy
        let gone: Vec<String> = self
            .wconfig
            .iter()
            .filter(|c| !fresh.iter().any(|f| f.name == c.name))
            .map(|c| c.name.clone())
            .collect();
        for name in &gone {
            if let Some(r) = self.wradio(name) {
                r.autostart = false;
            }
            self.wireless_teardown(name);
        }

        // which of the survivors actually changed
        let changed: Vec<String> = fresh
            .iter()
            .filter(|f| {
                self.wconfig
                    .iter()
                    .find(|c| c.name == f.name)
                    .map(|c| !wireless::same_config(c, f))
                    .unwrap_or(false)
            })
            .map(|f| f.name.clone())
            .collect();
        let added: Vec<String> = fresh
            .iter()
            .filter(|f| !self.wconfig.iter().any(|c| c.name == f.name))
            .map(|f| f.name.clone())
            .collect();

        // The schema is unchanged during reload. same_config already proved
        // the exact radio/VIF option and association order for these survivors.
        // Move their immutable bytes instead of re-encoding or shifting that
        // work to the next status request.
        for radio in &mut fresh {
            if let Some(old) = self.wconfig.iter_mut()
                .find(|old| old.name == radio.name && !changed.contains(&radio.name))
            {
                radio.status_config = std::mem::take(&mut old.status_config);
                for (vif, previous) in radio.vifs.iter_mut().zip(&mut old.vifs) {
                    vif.status_config = std::mem::take(&mut previous.status_config);
                }
            } else {
                wireless::cache_status_config(radio, &self.whandlers);
            }
        }
        self.wconfig = fresh;
        // A deleted radio still owns a handler and bridge ports until its
        // teardown completes. Dropping it here skips both kinds of cleanup.
        self.wradios.retain(|r| self.wconfig.iter().any(|c| c.name == r.name)
            || r.state != wireless::WState::Down);
        for name in &added {
            self.wradios.push(WRadio {
                name: name.clone(),
                state: wireless::WState::Down,
                retry: wireless::DEFAULT_RETRY,
                retry_setup_failed: false,
                autostart: true,
                ifnames: Vec::new(),
                handler_config: owrt_ubus::json::Json::Null,
                links: Vec::new(),
                device_data: Vec::new(),
                procs: Vec::new(),
                config_change: false,
            });
        }
        for name in added.iter().chain(changed.iter()) {
            // `update()`: reset, then `check()` sets up again
            if let Some(r) = self.wradio(name) {
                r.retry = wireless::DEFAULT_RETRY;
                r.retry_setup_failed = false;
            }
            self.wireless_setup(name);
        }
    }

    /// `wdev.setup()`: only from up or down, and only while the radio is
    /// allowed to start.
    fn wireless_setup(&mut self, name: &str) {
        if self.wconfig.iter().all(|r| r.name != name) {
            return;
        }
        let Some(r) = self.wradio(name) else { return };
        if !matches!(r.state, wireless::WState::Up | wireless::WState::Down) {
            // `update()` set config_change before calling `check()`, and
            // `wdev_setup_cb` reruns the setup when the handler finishes.
            // Returning without remembering it dropped a reload that landed
            // during a setup (R81 F10).
            r.config_change = true;
            return;
        }
        if !r.autostart || r.retry_setup_failed {
            return;
        }
        r.config_change = false; // `delete this.config_change`
        r.state = wireless::WState::Setup;
        r.procs.clear(); // `wdev_proc_reset`
        self.wqueue.push_back((name.to_string(), "setup"));
        self.wireless_pump();
    }

    /// `interface_set_prefix_address(..., add=false)` on an assignment that was
    /// live. The address is NOT deleted: RFC 7084 L-14 hands it to the kernel
    /// deprecated, so connections still using it survive a renumber and it
    /// ages out on its own. Our own route goes first, and re-adding without
    /// NOPREFIXROUTE is what makes the kernel install one of its own.
    fn withdraw_assignment(&mut self, di: u32, local: Ipv6Addr, len: u8, valid: Option<u32>, reject_dev: Option<&str>) {
        if let Some(dev) = reject_dev {
            let _ = self.sys.prefix_reject(dev, local, len, false);
        }
        let rmask = len.max(64);
        let pr = sys::Route::v6(ip::clear_if_addr(local, rmask), rmask);
        let _ = self.sys.del_route(di, &pr);

        let base = now();
        let mut sa = sys::Address::new(IpAddr::V6(local), len);
        // `valid` is a deadline; the C compares `valid_until - 1 <= now`
        if valid.is_some_and(|v| (v as u64).saturating_sub(1) <= base) {
            let _ = self.sys.del_address(di, &sa);
            return;
        }
        sa.preferred = Some(0); // preferred_until = now
        let cap = 7200u32;
        sa.valid = Some(match valid {
            Some(v) if (v as u64) <= base + cap as u64 => (v as u64).saturating_sub(base) as u32,
            _ => cap,
        });
        if let Err(e) = self.sys.add_address(di, &sa) {
            logging::log!(Warning, "cannot deprecate {local}/{len}: {e}");
        }
    }

    /// Replace the prefixes delegated to one interface. `class` and `iface`
    /// are the uplink's name, which is what the C reports and what the
    /// assignments are keyed by; the ULA keeps `local`.
    fn set_delegated_prefixes(&mut self, iface: &str, fresh: Vec<ip::DevicePrefix>) -> bool {
        // interface_update_prefix sets IUF_PREFIX for added/removed entries,
        // or when a renewal changes either deadline on an existing entry.
        let old: Vec<_> = self.prefixes.iter().filter(|p| p.iface.as_deref() == Some(iface)).collect();
        let changed = old.len() != fresh.len() || fresh.iter().any(|n| {
            !old.iter().any(|p| p.addr == n.addr && p.length == n.length
                && p.preferred_until == n.preferred_until && p.valid_until == n.valid_until)
        });
        // The null route belongs to the parent prefix, and the C removes it in
        // the same `node_old` branch that withdraws the assignments
        // (`system_del_route(NULL, &route)`). This has to be decided against
        // the list as it stands NOW -- after the swap the departing prefix is
        // already gone and there is nothing left to compare against.
        let departing: Vec<(Ipv6Addr, u8)> = self
            .prefixes
            .iter()
            .filter(|p| p.iface.as_deref() == Some(iface))
            .filter(|p| !fresh.iter().any(|n| n.addr == p.addr && n.length == p.length))
            .map(|p| (p.addr, p.length))
            .collect();
        for (addr, length) in departing {
            let mut null = sys::Route::v6(addr, length);
            null.metric = i32::MAX as u32;
            null.nodev = true;
            let _ = self.sys.del_route(0, &null);
        }
        let added = fresh.len();
        let removed = ip::replace_prefixes(&mut self.prefixes, Some(iface), fresh);
        if removed != 0 || added != 0 {
            self.refresh_prefix_assignments();
        }
        changed
    }

    /// The delegated-prefix part of C's interface_ip_valid_until_handler.
    /// A source reject rule has no kernel expiry, so the daemon must withdraw
    /// it even when odhcp6c sends no further notification. Keep C's strict
    /// deadline comparison and only expire protocol state on UP interfaces.
    fn pump_prefix_expiry(&mut self) {
        let t = now();
        if t <= self.prefix_expiry_checked {
            return;
        }
        self.prefix_expiry_checked = t;
        let expired: Vec<(String, Ipv6Addr, u8)> = self.prefixes.iter()
            .filter_map(|p| {
                let owner = p.iface.as_ref()?;
                let deadline = p.valid_until?;
                if (deadline as u64) >= t || !self.iface_index(owner)
                    .is_some_and(|i| self.interfaces[i].state == State::Up) {
                    return None;
                }
                Some((owner.clone(), p.addr, p.length))
            }).collect();
        if expired.is_empty() {
            return;
        }
        for (owner, addr, length) in &expired {
            self.prefixes.retain(|p| !(p.iface.as_ref() == Some(owner)
                && p.addr == *addr && p.length == *length));
            let mut null = sys::Route::v6(*addr, *length);
            null.metric = i32::MAX as u32;
            null.nodev = true;
            let _ = self.sys.del_route(0, &null);
            if let Some(i) = self.iface_index(owner) {
                self.interfaces[i].updated |= interface::updated::PREFIX;
            }
        }
        self.refresh_prefix_assignments();
    }

    /// `wdev_proc_check`, on the one-second interval `wdev_proc_add` starts.
    /// The first registered process that is gone tears its radio down and the
    /// rest of that radio's list is not examined -- the C breaks out of the
    /// loop there too.
    fn pump_wireless_procs(&mut self) {
        if now() <= self.wproc_checked {
            return;
        }
        self.wproc_checked = now();
        let watched: Vec<(String, Vec<(i64, String)>)> = self
            .wradios
            .iter()
            .filter(|r| !r.procs.is_empty())
            .map(|r| (r.name.clone(), r.procs.clone()))
            .collect();
        for (name, procs) in watched {
            for (pid, exe) in procs {
                if process_alive(pid, &exe) {
                    continue;
                }
                logging::log!(Warning, "{name}: process {exe}({pid}) no longer active");
                self.wireless_teardown(&name);
                break;
            }
        }
    }

    /// `start()`: the retry budget resets whatever the state, and a radio
    /// that is not down is left where it is.
    fn wireless_start(&mut self, name: &str) {
        let down = match self.wradio(name) {
            Some(r) => {
                r.autostart = true;
                r.retry = wireless::DEFAULT_RETRY;
                r.retry_setup_failed = false;
                r.state == wireless::WState::Down
            }
            None => return,
        };
        if down {
            self.wireless_setup(name);
        }
    }

    /// `wdev.teardown()`.
    fn wireless_teardown(&mut self, name: &str) {
        let Some(r) = self.wradio(name) else { return };
        if matches!(r.state, wireless::WState::Teardown | wireless::WState::Down) {
            return;
        }
        r.state = wireless::WState::Teardown;
        r.procs.clear(); // `wdev_proc_reset`
        self.wqueue.push_back((name.to_string(), "teardown"));
        self.wireless_pump();
    }

    /// `uc_netifd_interface_get_bridge` and `bridge_hotplug_prepare`.
    /// A valid non-bridge network returns an empty object and stops the search.
    fn prepare_interface_bridge(&mut self, network: &str) -> Option<Vec<(String, owrt_ubus::json::Json)>> {
        use owrt_ubus::json::Json;
        let dev = self.cfg.interfaces.iter().find(|i| i.name == network)?.device.clone()?;
        if !self.cfg.devices.iter().any(|d| d.name == dev && d.kind.as_deref() == Some("bridge")) {
            return Some(Vec::new());
        }
        if !self.prepared_bridges.contains(&dev) {
            self.prepared_bridges.push(dev.clone());
        }
        if self.sys.if_index(&dev).unwrap_or(0) == 0 {
            self.create_devices();
        }
        if self.sys.if_index(&dev).unwrap_or(0) == 0 {
            return None;
        }
        if !self.present.contains(&dev) {
            self.present.push(dev.clone());
        }
        self.device_added(&dev);
        let mut fields = vec![
            ("bridge".into(), Json::Str(dev.clone())),
            ("bridge-ifname".into(), Json::Str(dev.clone())),
        ];
        if let Some(d) = self.devices.get(&dev) {
            if d.settings.has(device::opt::MULTICAST_TO_UNICAST) {
                fields.push(("multicast_to_unicast".into(), Json::Bool(d.settings.multicast_to_unicast)));
            }
        }
        Some(fields)
    }

    fn wireless_prepare_vif(&mut self, vif: &mut owrt_ubus::json::Json) {
        use owrt_ubus::json::Json;
        let networks = vif.get("config").and_then(|c| c.get("network"))
            .and_then(Json::as_array).unwrap_or(&[]).to_vec();
        for net in networks.iter().filter_map(Json::as_str) {
            let Some(fields) = self.prepare_interface_bridge(net) else { continue };
            if let Json::Object(obj) = vif {
                obj.extend(fields);
            }
            break;
        }
        if let Json::Object(obj) = vif {
            if let Some((_, Json::Object(vlans))) = obj.iter_mut().find(|(k, _)| k == "vlans") {
                for (_, vlan) in vlans {
                    self.wireless_prepare_vif(vlan);
                }
            }
        }
    }

    /// Attach interfaces only after NOTIFY_UP, using the same configuration
    /// generation that the handler received. hostapd may already have added
    /// the kernel port; netifd must still own its membership and settings.
    fn wireless_mark_up(&mut self, name: &str) {
        use owrt_ubus::json::Json;
        let Some(r) = self.wradios.iter().find(|r| r.name == name).cloned() else { return };
        let Some(Json::Object(vifs)) = r.handler_config.get("interfaces") else { return };
        let mut records = Vec::new();
        for (_, vif) in vifs {
            records.push((vif, false));
            if let Some(Json::Object(vlans)) = vif.get("vlans") {
                records.extend(vlans.iter().map(|(_, v)| (v, true)));
            }
        }
        for (record, vlan) in records {
            let Some(section) = record.get("name").and_then(Json::as_str) else { continue };
            let Some((_, port)) = r.ifnames.iter().find(|(s, _)| s == section) else { continue };
            let Some(config) = record.get("config") else { continue };
            let Some(networks) = config.get("network").and_then(Json::as_array) else { continue };
            if self.sys.if_index(port).unwrap_or(0) == 0 {
                continue;
            }
            if !self.device_objects.contains(port) {
                self.device_objects.push(port.clone());
            }
            self.rescan_devices();
            if let Some(d) = self.devices.get_mut(port) {
                d.external = true;
            }
            for net in networks.iter().filter_map(Json::as_str) {
                let bridge = self.cfg.interfaces.iter().find(|c| c.name == net)
                    .and_then(|c| c.device.clone()).filter(|dev| self.cfg.devices.iter()
                        .any(|d| d.name == *dev && d.kind.as_deref() == Some("bridge")));
                let Some(br) = bridge else { continue };
                self.bridge_port_add(&br, port);
                if !self.devices.get(&br).and_then(|d| d.bridge.as_ref())
                    .is_some_and(|b| b.members.contains(port)) {
                    continue;
                }
                let ap = vlan || config.get("mode").and_then(Json::as_str) == Some("ap");
                let flag = |key| matches!(config.get(key), Some(Json::Bool(true)));
                let proxy = !vlan && ap && flag("proxy_arp");
                let isolated = !vlan && ap && flag("isolate");
                let mcast = self.devices.get(&br).is_none_or(|d|
                    !d.settings.has(device::opt::MULTICAST_TO_UNICAST) || d.settings.multicast_to_unicast) && ap;
                for (attr, enabled) in [
                    ("multicast_to_unicast", mcast),
                    ("hairpin_mode", (mcast || proxy) && !isolated),
                    ("proxyarp_wifi", proxy),
                    ("isolated", flag("bridge_isolate")),
                    ("bpdu_filter", ap),
                ] {
                    let path = format!("/sys/class/net/{port}/brport/{attr}");
                    if let Err(e) = std::fs::write(&path, if enabled { "1" } else { "0" }) {
                        logging::log!(Warning, "cannot set {port} {attr}: {e}");
                    }
                }
                if let Some(r) = self.wradio(name) {
                    let link = (br, port.clone());
                    if !r.links.contains(&link) {
                        r.links.push(link);
                    }
                }
            }
        }
        self.rescan_devices();
        self.update_presence();
        self.update_link_states();
    }

    fn wireless_remove_links(&mut self, name: &str) {
        let links = self.wradio(name).map(|r| std::mem::take(&mut r.links)).unwrap_or_default();
        for (br, port) in links {
            let other = self.wradios.iter().any(|r| r.links.contains(&(br.clone(), port.clone())));
            if other { continue; }
            if let Ok(pi) = self.sys.if_index(&port) {
                if pi != 0 { let _ = self.sys.bridge_setmaster(pi, 0); }
            }
            self.bridge_port_del(&br, &port);
            self.device_release(&port);
            self.prepared_bridges.retain(|b| *b != br);
            if !self.device_present_now(&br) {
                self.present.retain(|b| *b != br);
                self.device_removed(&br);
                let _ = self.sys.bridge_delbr(&br);
                self.devices.remove(&br);
            }
        }
        self.free_unused_devices();
        self.rescan_devices();
    }

    fn wireless_pump(&mut self) {
        if self.wcur.is_some() {
            return;
        }
        let Some((name, op)) = self.wqueue.pop_front() else { return };
        let cfg = self.wconfig.iter().find(|r| r.name == name).cloned();
        let kind = if op == "setup" {
            cfg.as_ref().and_then(|c| c.kind()).map(str::to_string)
        } else {
            self.wradios.iter().find(|r| r.name == name)
                .and_then(|r| r.handler_config.get("config"))
                .and_then(|c| c.get("type")).and_then(owrt_ubus::json::Json::as_str)
                .map(str::to_string)
        };
        let Some(h) = kind.and_then(|k| self.whandlers.iter().find(|h| h.name == k))
        else {
            return;
        };
        let script = h.script.clone();
        let hname = h.name.clone();
        let file = script
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        let dir = script
            .parent()
            .map(|d| d.to_string_lossy().into_owned())
            .unwrap_or_default();
        let data = self.wradios.iter().find(|r| r.name == name)
            .filter(|r| !r.device_data.is_empty())
            .map(|r| wireless::device_data_record(&r.name, &r.device_data))
            .unwrap_or_else(|| "{}".to_string());
        let mut config = if op == "setup" {
            let Some(cfg) = cfg else { return };
            let mut config = owrt_ubus::json::parse(&wireless::handler_json(&cfg, &self.whandlers, &data))
                .expect("wireless projection is valid JSON");
            if let owrt_ubus::json::Json::Object(obj) = &mut config {
                if let Some((_, owrt_ubus::json::Json::Object(vifs))) = obj.iter_mut().find(|(k, _)| k == "interfaces") {
                    for (_, vif) in vifs { self.wireless_prepare_vif(vif); }
                }
            }
            if let Some(r) = self.wradio(&name) {
                r.handler_config = config.clone();
                r.ifnames.clear();
            }
            config
        } else {
            self.wradio(&name).map(|r| r.handler_config.clone()).unwrap_or(owrt_ubus::json::Json::Null)
        };
        if let owrt_ubus::json::Json::Object(obj) = &mut config {
            if let Some((_, value)) = obj.iter_mut().find(|(k, _)| k == "data") {
                *value = owrt_ubus::json::parse(&data).expect("wireless data is valid JSON");
            }
        }
        let argv = vec![
            format!("./{file}"),
            hname,
            op.to_string(),
            name.clone(),
            config.to_compact(),
        ];
        self.wcur = Some((name.clone(), op));
        if let Err(e) = self.wslot.start_in(&argv, &[], &dir) {
            logging::log!(Warning, "{name}: cannot run the wireless handler: {e}");
            self.wireless_complete();
            return;
        }
        self.wdeadline = Some(now_ms() + 30_000);
    }

    /// wireless-device.uc run_handler_timeout: cancel after 30 s, then run
    /// the normal completion callback so the next radio cannot be starved.
    fn pump_wireless_deadline(&mut self) {
        if self.wdeadline.is_some_and(|deadline| now_ms() >= deadline) {
            self.wslot.terminate();
            self.wireless_complete();
        }
    }

    /// The handler exited. `wdev_setup_cb` / `wdev_teardown_cb`.
    fn wireless_reap(&mut self) {
        let Some((pid, (argv0, status, output))) = self.wslot.pid().zip(self.wslot.reap()) else {
            return;
        };
        let Some((name, _)) = self.wcur.as_ref() else { return };
        for line in output.lines().filter(|l| !l.trim().is_empty()) {
            logging::log!(Notice, "{name} ({pid}): {line}");
        }
        if status != 0 {
            logging::log!(Info, "{name}: {argv0} exited {status}");
        }
        self.wireless_complete();
    }

    fn wireless_complete(&mut self) {
        self.wdeadline = None;
        let Some((name, op)) = self.wcur.take() else { return };
        if op == "setup" {
            // A handler that reported its interfaces up left the state at Up,
            // and there is nothing to retry.
            let still_setting_up = self
                .wradios
                .iter()
                .any(|r| r.name == name && r.state == wireless::WState::Setup);
            if still_setting_up {
                if let Some(r) = self.wradio(&name) {
                    if r.retry > 0 {
                        r.retry -= 1;
                    } else {
                        r.retry_setup_failed = true;
                    }
                }
                self.wireless_teardown(&name);
            } else if self
                .wradios
                .iter()
                .any(|r| r.name == name && r.state == wireless::WState::Up && r.config_change)
            {
                // `wdev_setup_cb`: "state == up && config_change" -> setup again
                self.wireless_setup(&name);
            }
        } else {
            self.wireless_remove_links(&name);
            if let Some(r) = self.wradio(&name) {
                r.state = wireless::WState::Down;
                // `wdev_teardown_cb` empties handler_data wholesale, so a
                // token only survives a reconf, never a completed teardown
                r.ifnames.clear();
                r.device_data.clear();
            }
            if self.wconfig.iter().any(|r| r.name == name) {
                self.wireless_setup(&name);
            } else {
                self.wradios.retain(|r| r.name != name);
            }
        }
        self.wireless_pump();
    }
}

impl Netifd {
    fn wireless_selector(&self, data: &[u8]) -> Result<Option<usize>, i32> {
        let device = ubus::wireless_read_device(data)?;
        let Some(device) = device else { return Ok(None) };
        if device.is_empty() {
            return Ok(None);
        }
        let device = device.split(|byte| *byte == 0).next().unwrap();
        self.wconfig
            .iter()
            .position(|radio| radio.name.as_bytes() == device)
            .ok_or(status::NOT_FOUND)
            .map(Some)
    }

    /// `status` follows the live state machine; only the configuration is
    /// shared with the no-hardware projection. ifnames come from notify.
    fn wireless_status_into_blob(&self, b: &mut BlobBuf, selected: Option<usize>) {
        for (index, cfg) in self.wconfig.iter().enumerate() {
            if selected.is_some_and(|wanted| wanted != index) {
                continue;
            }
            let Some(r) = self.wradios.iter().find(|r| r.name == cfg.name) else { continue };
            let st = wireless::RadioState {
                up: r.state == wireless::WState::Up,
                pending: matches!(
                    r.state,
                    wireless::WState::Setup | wireless::WState::Teardown
                ),
                autostart: r.autostart,
                retry_setup_failed: r.retry_setup_failed,
            };
            wireless::status_into_blob(b, cfg, &self.whandlers, st, &r.ifnames);
        }
    }

    /// `notify`. The handler scripts call this back while their setup runs.
    fn wireless_notify(&mut self, fields: &[blob::Field]) -> i32 {
        let find = |n: &str| fields.iter().find(|f| f.name == n).copied();
        let dev = find("device").and_then(|f| f.as_str()).unwrap_or("").to_string();
        if self.wradios.iter().all(|r| r.name != dev) {
            return status::NOT_FOUND;
        }
        let cmd = find("command").and_then(|f| f.as_u32()).map(|n| n as i64).unwrap_or(-1);
        let vif = find("interface").and_then(|f| f.as_str()).map(|s| s.to_string());
        let vlan = find("vlan").and_then(|f| f.as_str()).map(|s| s.to_string());
        match cmd {
            wireless::NOTIFY_UP => {
                // `wdev_mark_up` refuses unless this is a plain device-level
                // notify and the radio is still setting up.
                if vif.is_some() || vlan.is_some() {
                    return status::INVALID_ARGUMENT;
                }
                let Some(r) = self.wradio(&dev) else { return status::NOT_FOUND };
                if r.state != wireless::WState::Setup {
                    return status::INVALID_ARGUMENT;
                }
                r.state = wireless::WState::Up;
                self.wireless_mark_up(&dev);
                status::OK
            }
            wireless::NOTIFY_SET_DATA => {
                // Only the per-interface `ifname` is kept: that is the one
                // piece of handler data `status` reports.
                let Some(key) = vif else {
                    // no `interface`: this is the device-level record
                    let fields: Vec<(String, String)> = find("data")
                        .map(|f| {
                            f.children()
                                .filter_map(|c| {
                                    let v = c.as_str()?;
                                    Some((c.name.to_string(), owrt_ubus::json::Json::Str(v.to_string()).to_compact()))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    if let Some(r) = self.wradio(&dev) {
                        r.device_data = fields;
                    }
                    return status::OK;
                };
                // Resolve against the exact handler generation, including
                // wifi-vlan records, rather than the current UCI file.
                let record = self.wradios.iter().find(|r| r.name == dev)
                    .and_then(|r| r.handler_config.get("interfaces"))
                    .and_then(|v| v.get(&key));
                let record = if let Some(vlan) = vlan {
                    record.and_then(|v| v.get("vlans")).and_then(|v| v.get(&vlan))
                } else { record };
                let section = record.and_then(|v| v.get("name"))
                    .and_then(owrt_ubus::json::Json::as_str).map(str::to_string);
                let Some(section) = section else { return status::NOT_FOUND };
                let ifname = find("data")
                    .and_then(|f| f.children().into_iter().find(|c| c.name == "ifname"))
                    .and_then(|c| c.as_str().map(|s| s.to_string()));
                let Some(ifname) = ifname else { return status::OK };
                if let Some(r) = self.wradio(&dev) {
                    match r.ifnames.iter_mut().find(|(s, _)| *s == section) {
                        Some(slot) => slot.1 = ifname,
                        None => r.ifnames.push((section, ifname)),
                    }
                }
                status::OK
            }
            wireless::NOTIFY_PROCESS_ADD => {
                // `wdev_proc_add`: only `pid` and `exe` are read. The shipped
                // ucode also accepts `required` and `keep` and never looks at
                // them, so neither does this.
                let st = self.wradio(&dev).map(|r| r.state);
                if !matches!(st, Some(wireless::WState::Setup) | Some(wireless::WState::Up)) {
                    return status::OK;
                }
                let data = find("data");
                let pid = data
                    .and_then(|f| f.children().into_iter().find(|c| c.name == "pid"))
                    .and_then(|c| c.as_u32())
                    .map(|v| v as i64);
                let exe = data
                    .and_then(|f| f.children().into_iter().find(|c| c.name == "exe"))
                    .and_then(|c| c.as_str().map(|s| s.to_string()));
                match (pid, exe) {
                    (Some(pid), Some(exe)) => {
                        logging::log!(Debug, "{dev}: watching {exe}({pid})");
                        if let Some(r) = self.wradio(&dev) {
                            r.procs.push((pid, exe));
                        }
                    }
                    _ => logging::log!(Warning,
                        "{dev}: process_add without a usable pid and exe"
                    ),
                }
                status::OK
            }
            wireless::NOTIFY_SET_RETRY => {
                let retry = find("data")
                    .and_then(|f| f.children().into_iter().find(|c| c.name == "retry"))
                    .and_then(|c| c.as_u32());
                if let Some(r) = self.wradio(&dev) {
                    r.retry = retry.unwrap_or(wireless::DEFAULT_RETRY);
                }
                status::OK
            }
            _ => status::INVALID_ARGUMENT,
        }
    }

    /// `up` / `down` / `retry` / `reconf`. With no `device` the C applies the
    /// command to every radio.
    fn wireless_command(&mut self, cmd: &str, fields: &[blob::Field]) -> i32 {
        let dev = fields
            .iter()
            .find(|f| f.name == "device")
            .and_then(|f| f.as_str())
            .map(|s| s.to_string());
        let names: Vec<String> = match &dev {
            Some(d) => {
                if self.wradios.iter().all(|r| r.name != *d) {
                    return status::NOT_FOUND;
                }
                vec![d.clone()]
            }
            None => self.wradios.iter().map(|r| r.name.clone()).collect(),
        };
        for name in names {
            match cmd {
                "up" => self.wireless_start(&name),
                "down" => {
                    // `stop()`: autostart goes, and only an interface that is
                    // already up is torn down here. One still in setup is left
                    // alone -- its setup completes, finds autostart gone and
                    // settles at down on its own. (The C sets `cancel_setup`
                    // at this point, but nothing in this version ever reads
                    // it.)
                    let state = self.wradio(&name).map(|r| {
                        r.autostart = false;
                        r.state
                    });
                    if state == Some(wireless::WState::Up) {
                        self.wireless_teardown(&name);
                    }
                }
                "retry" => {
                    // `retry_setup()`: only a radio that is down and still
                    // wants to start. That is the recovery path out of
                    // `retry_setup_failed`, because `start` resets the budget.
                    let ok = self
                        .wradio(&name)
                        .map(|r| r.state == wireless::WState::Down && r.autostart)
                        .unwrap_or(false);
                    if ok {
                        self.wireless_start(&name);
                    }
                }
                "reconf" => {
                    // `update(null)`: reset the budget, then `check()`, which
                    // sets up again. Measured rather than assumed -- a reconf
                    // on a radio that had given up produces another full round
                    // of setups (16 against 12 in r60 when this only reset the
                    // flag), and `retry_setup_failed` therefore comes back.
                    if let Some(r) = self.wradio(&name) {
                        r.retry = wireless::DEFAULT_RETRY;
                        r.retry_setup_failed = false;
                    }
                    self.wireless_setup(&name);
                }
                _ => {}
            }
        }
        status::OK
    }
}

/// `check_pid_path`: the process is the one that was registered if
/// `/proc/<pid>/exe` still points at that path. A path the kernel marks
/// `(deleted)` still counts -- the binary was replaced under a running
/// process, which is not the process going away.
///
/// The C reads the link into a buffer exactly as long as `exe`, so a longer
/// real path compares equal on its prefix. That quirk is not reproduced.
fn process_alive(pid: i64, exe: &str) -> bool {
    let Ok(link) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
        return false;
    };
    let path = link.to_string_lossy();
    path == exe || path == format!("{exe} (deleted)")
}

/// One applied route as the kernel wants it. Shared by the add path and the
/// flush below, so a route is removed with exactly the key it was added with.
fn sys_route(r: &interface::Route) -> sys::Route {
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
    k.nodev = r.flags & interface::devroute::NODEV != 0;
    k
}

fn main() {
    use std::io::Write;
    let mut confdir = "/etc/config".to_string();
    let mut hotplug = DEFAULT_HOTPLUG_PATH.to_string();
    let mut protodir = DEFAULT_PROTO_DIR.to_string();
    let mut resolvconf = DEFAULT_RESOLV_CONF.to_string();
    let mut socket: Option<String> = None;
    let mut log_stderr = false;
    let mut log_level = logging::DEFAULT_LEVEL;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" => confdir = args.next().unwrap_or(confdir),
            "-s" => socket = args.next(),
            "-h" => hotplug = args.next().unwrap_or(hotplug),
            "-p" => protodir = args.next().unwrap_or(protodir),
            "-r" => resolvconf = args.next().unwrap_or(resolvconf),
            "-S" => log_stderr = true,
            "-l" => {
                let Some(level) = args.next() else {
                    let _ = writeln!(std::io::stderr(), "netifd-rs: -l requires a level");
                    std::process::exit(1);
                };
                log_level = logging::parse_level(&level);
            }
            level if level.starts_with("-l") && level.len() > 2 => {
                log_level = logging::parse_level(&level[2..]);
            }
            "-V" | "--version" => {
                let _ = writeln!(std::io::stdout(), "{BUILD_ID}");
                return;
            }
            // Diagnostic, not part of the daemon: print what `network.wireless`
            // would answer for this config, so a differential can compare the
            // projection alone (r59) without starting a daemon. Prints and
            // exits before any netlink/ubus/config work, which also makes it
            // the inert identity probe p6_switch.sh uses on the device.
            "--dump-wireless" => {
                let dir = args.next().unwrap_or_else(|| DEFAULT_WIRELESS_DIR.to_string());
                let _ = writeln!(std::io::stdout(), "{}", wireless::dump(&confdir, &dir));
                return;
            }
            other => {
                let _ = writeln!(std::io::stderr(), "netifd-rs: unknown argument {other}");
                std::process::exit(2);
            }
        }
    }

    logging::init(log_stderr, log_level);
    let mut n = match Netifd::new(&confdir, socket.as_deref(), &hotplug, &protodir) {
        Ok(n) => n,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "netifd-rs: startup failed: {e}");
            std::process::exit(1);
        }
    };
    n.resolvconf = resolvconf;
    n.reload();
    n.wireless_load();
    n.run()
}

#[cfg(test)]
mod proto_keep_tests {
    use super::*;

    #[test]
    fn address_keep_requires_success_and_all_kernel_attributes() {
        let mut old = Address::new("192.0.2.2".parse().unwrap(), 24);
        old.broadcast = Some("192.0.2.255".parse().unwrap());
        assert!(keep_proto_address(&old, &old, 10));
        for mutate in [
            |a: &mut Address| a.failed = true,
            |a: &mut Address| a.enabled = false,
            |a: &mut Address| a.index = 1,
            |a: &mut Address| a.offlink = true,
            |a: &mut Address| a.broadcast = Some("192.0.2.127".parse().unwrap()),
            |a: &mut Address| a.point_to_point = Some("192.0.2.1".parse().unwrap()),
        ] {
            let mut changed = old.clone();
            mutate(&mut changed);
            assert!(!keep_proto_address(&changed, &old, 10));
        }
    }

    #[test]
    fn address_lifetime_refresh_and_expiry_are_not_kept() {
        let mut old = Address::new("2001:db8::2".parse().unwrap(), 64);
        old.preferred_until = Some(20);
        old.valid_until = Some(30);
        assert!(keep_proto_address(&old, &old, 10));
        assert!(!keep_proto_address(&old, &old, 30));
        let mut renewed = old.clone();
        renewed.preferred_until = Some(21);
        assert!(!keep_proto_address(&old, &renewed, 10));
        renewed = old.clone();
        renewed.valid_until = Some(31);
        assert!(!keep_proto_address(&old, &renewed, 10));
        renewed = old.clone();
        renewed.class = Some("metadata-only".into());
        assert!(keep_proto_address(&old, &renewed, 10));
    }

    #[test]
    fn route_keep_uses_full_key_and_non_key_attributes_but_not_deadline() {
        let old = interface::Route::new(
            "0.0.0.0".parse().unwrap(), 0, "192.0.2.1".parse().unwrap(),
        );
        assert!(keep_proto_route(&old, &old, 10));
        for mutate in [
            |r: &mut interface::Route| r.failed = true,
            |r: &mut interface::Route| r.enabled = false,
            |r: &mut interface::Route| r.flags = interface::devroute::ONLINK,
            |r: &mut interface::Route| r.metric = 1,
            |r: &mut interface::Route| r.table = 100,
            |r: &mut interface::Route| r.source = "192.0.2.2".parse().unwrap(),
            |r: &mut interface::Route| r.sourcemask = 24,
            |r: &mut interface::Route| r.nexthop = "192.0.2.3".parse().unwrap(),
            |r: &mut interface::Route| r.mtu = 1400,
            |r: &mut interface::Route| r.ty = 6,
            |r: &mut interface::Route| r.proto = 16,
            |r: &mut interface::Route| r.valid_until = Some(10),
        ] {
            let mut changed = old.clone();
            mutate(&mut changed);
            assert!(!keep_proto_route(&changed, &old, 10));
        }
        let mut renewed = old.clone();
        renewed.valid_until = Some(60);
        assert!(keep_proto_route(&old, &renewed, 10));
    }
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
    let ch = classify_change(x, y, None);
    assert!(!ch.reload && !ch.reload_ip && !ch.delegation && !ch.assignment, "{ch:?}\nA: {x:#?}\nB: {y:#?}");
}
}

#[cfg(test)]
mod prefix_status_tests {
    use super::*;
    use owrt_ubus::json::Json;

    #[test]
    fn uplink_prefix_status_keeps_vlist_order_without_reordering_lan_assignments() {
        let expected = [("2001:db8:1::", 56), ("2001:db8:1::", 64), ("2001:db8:2::", 64)];
        let fresh = expected.iter().map(|(addr, len)| {
            ip::DevicePrefix::new(addr.parse().unwrap(), *len, "wan6", Some("wan6"))
        }).collect();
        let mut prefixes = Vec::new();
        ip::replace_prefixes(&mut prefixes, Some("wan6"), fresh);
        let assignment_order = prefixes.clone();
        let view = status_prefixes(&prefixes, &[], "wan6");
        let mut wan = Interface::new("wan6");
        wan.state = State::Up;
        let mut buf = BlobBuf::new();
        wan.dump_status_with(&mut buf, 0, &view);
        let status = owrt_ubus::convert::fields_to_json(buf.payload());
        let Some(Json::Array(rows)) = status.get("ipv6-prefix") else { panic!() };
        assert_eq!(rows.len(), expected.len());
        for (row, (addr, mask)) in rows.iter().zip(expected) {
            assert_eq!(row.get("address").and_then(Json::as_str), Some(addr));
            assert_eq!(row.get("mask"), Some(&Json::Int(mask as i64)));
        }
        assert_eq!(prefixes, assignment_order);
    }
}
