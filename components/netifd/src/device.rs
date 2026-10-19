//! Devices: what the kernel currently reports about an interface, and the
//! `network.device status` projection of it.
//!
//! `device_dump_status` emits its fields in a fixed order and omits any field
//! whose flag is unset, so both the order and the omissions are part of the
//! interface. `device_merge_settings` decides the flag set as
//! `configured | original | valid`, meaning a field appears once the system
//! could read it even if no configuration mentions it.

use std::ffi::{CStr, CString};
use std::io::{self, Read};

use owrt_ubus::blob::BlobBuf;

use crate::ethtool::{self, Ethtool};
use crate::sys;

/// Which settings are present. The bit values are ours, not the kernel's; only
/// the resulting field set is observable.
pub mod opt {
    pub const MTU: u64 = 1 << 0;
    pub const MTU6: u64 = 1 << 1;
    pub const TXQUEUELEN: u64 = 1 << 2;
    pub const MACADDR: u64 = 1 << 3;
    pub const IPV6: u64 = 1 << 4;
    pub const IP6SEGMENTROUTING: u64 = 1 << 5;
    pub const PROMISC: u64 = 1 << 6;
    pub const RPFILTER: u64 = 1 << 7;
    pub const ACCEPTLOCAL: u64 = 1 << 8;
    pub const IGMPVERSION: u64 = 1 << 9;
    pub const MLDVERSION: u64 = 1 << 10;
    pub const NEIGHREACHABLETIME: u64 = 1 << 11;
    pub const NEIGHGCSTALETIME: u64 = 1 << 12;
    pub const NEIGHLOCKTIME: u64 = 1 << 13;
    pub const DADTRANSMITS: u64 = 1 << 14;
    pub const MULTICAST: u64 = 1 << 15;
    pub const SENDREDIRECTS: u64 = 1 << 16;
    pub const DROP_V4_UNICAST_IN_L2_MULTICAST: u64 = 1 << 17;
    pub const DROP_V6_UNICAST_IN_L2_MULTICAST: u64 = 1 << 18;
    pub const DROP_GRATUITOUS_ARP: u64 = 1 << 19;
    pub const DROP_UNSOLICITED_NA: u64 = 1 << 20;
    pub const ARP_ACCEPT: u64 = 1 << 21;
    pub const GRO: u64 = 1 << 22;
    pub const MASTER: u64 = 1 << 23;
    pub const MULTICAST_TO_UNICAST: u64 = 1 << 24;
    pub const MULTICAST_ROUTER: u64 = 1 << 25;
    pub const MULTICAST_FAST_LEAVE: u64 = 1 << 26;
    pub const LEARNING: u64 = 1 << 27;
    pub const UNICAST_FLOOD: u64 = 1 << 28;
    pub const AUTH: u64 = 1 << 29;
    pub const EEE: u64 = 1 << 30;
}

/// One device's settings, read from the kernel or taken from configuration.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub flags: u64,
    pub mtu: u32,
    pub mtu6: u32,
    pub txqueuelen: u32,
    pub macaddr: [u8; 6],
    pub ipv6: bool,
    pub ip6segmentrouting: bool,
    pub promisc: bool,
    pub rpfilter: u32,
    pub acceptlocal: bool,
    pub igmpversion: u32,
    pub mldversion: u32,
    pub neigh4reachabletime: u32,
    pub neigh6reachabletime: u32,
    pub neigh4gcstaletime: u32,
    pub neigh6gcstaletime: u32,
    pub neigh4locktime: u32,
    pub dadtransmits: u32,
    pub multicast: bool,
    pub multicast_to_unicast: bool,
    pub multicast_router: u32,
    pub multicast_fast_leave: bool,
    pub learning: bool,
    pub unicast_flood: bool,
    pub sendredirects: bool,
    pub drop_v4_unicast_in_l2_multicast: bool,
    pub drop_v6_unicast_in_l2_multicast: bool,
    pub drop_gratuitous_arp: bool,
    pub drop_unsolicited_na: bool,
    pub arp_accept: bool,
    pub auth: bool,
    pub gro: bool,
    pub eee: bool,
    /// The DSA conduit's ifindex, when this is a DSA user port.
    pub master_ifindex: u32,
}

impl Settings {
    pub fn has(&self, flag: u64) -> bool {
        self.flags & flag != 0
    }
}

/// `device_merge_settings`: the configured value where one exists, the value
/// read from the system otherwise, with the union of both flag sets.
///
/// The five bridge-port options are taken from the configured settings
/// unconditionally, exactly as the C does — they have no system-read
/// counterpart, so their flags come only from configuration.
pub fn merge_settings(configured: &Settings, orig: &Settings) -> Settings {
    macro_rules! pick {
        ($field:ident, $flag:expr) => {
            if configured.flags & $flag != 0 {
                configured.$field
            } else {
                orig.$field
            }
        };
    }
    Settings {
        flags: configured.flags | orig.flags,
        mtu: pick!(mtu, opt::MTU),
        mtu6: pick!(mtu6, opt::MTU6),
        txqueuelen: pick!(txqueuelen, opt::TXQUEUELEN),
        macaddr: pick!(macaddr, opt::MACADDR),
        ipv6: pick!(ipv6, opt::IPV6),
        ip6segmentrouting: pick!(ip6segmentrouting, opt::IP6SEGMENTROUTING),
        promisc: pick!(promisc, opt::PROMISC),
        rpfilter: pick!(rpfilter, opt::RPFILTER),
        acceptlocal: pick!(acceptlocal, opt::ACCEPTLOCAL),
        igmpversion: pick!(igmpversion, opt::IGMPVERSION),
        mldversion: pick!(mldversion, opt::MLDVERSION),
        neigh4reachabletime: pick!(neigh4reachabletime, opt::NEIGHREACHABLETIME),
        neigh6reachabletime: pick!(neigh6reachabletime, opt::NEIGHREACHABLETIME),
        neigh4gcstaletime: pick!(neigh4gcstaletime, opt::NEIGHGCSTALETIME),
        neigh6gcstaletime: pick!(neigh6gcstaletime, opt::NEIGHGCSTALETIME),
        neigh4locktime: pick!(neigh4locktime, opt::NEIGHLOCKTIME),
        dadtransmits: pick!(dadtransmits, opt::DADTRANSMITS),
        multicast: pick!(multicast, opt::MULTICAST),
        multicast_to_unicast: configured.multicast_to_unicast,
        multicast_router: configured.multicast_router,
        multicast_fast_leave: configured.multicast_fast_leave,
        learning: configured.learning,
        unicast_flood: configured.unicast_flood,
        sendredirects: pick!(sendredirects, opt::SENDREDIRECTS),
        drop_v4_unicast_in_l2_multicast: pick!(
            drop_v4_unicast_in_l2_multicast,
            opt::DROP_V4_UNICAST_IN_L2_MULTICAST
        ),
        drop_v6_unicast_in_l2_multicast: pick!(
            drop_v6_unicast_in_l2_multicast,
            opt::DROP_V6_UNICAST_IN_L2_MULTICAST
        ),
        drop_gratuitous_arp: pick!(drop_gratuitous_arp, opt::DROP_GRATUITOUS_ARP),
        drop_unsolicited_na: pick!(drop_unsolicited_na, opt::DROP_UNSOLICITED_NA),
        arp_accept: pick!(arp_accept, opt::ARP_ACCEPT),
        auth: pick!(auth, opt::AUTH),
        gro: pick!(gro, opt::GRO),
        eee: pick!(eee, opt::EEE),
        master_ifindex: pick!(master_ifindex, opt::MASTER),
    }
}

fn open_sysctl(path: &CStr) -> io::Result<std::fs::File> {
    loop {
        match rustix::fs::openat(rustix::fs::CWD, path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()) {
            Ok(fd) => return Ok(std::fs::File::from(fd)),
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn sysctl(prefix: &str, ifname: &str, file: &str) -> Option<String> {
    let path = CString::new(format!("/proc/sys/net/{prefix}/{ifname}/{file}")).ok()?;
    // musl open adds a redundant F_SETFD on this Linux target; openat
    // preserves atomic CLOEXEC without that compatibility syscall.
    let mut file = open_sysctl(&path).ok()?;
    // These proc files are small. Avoid File::read_to_end's size/flag
    // probes, while preserving complete reads and the same text handling.
    let mut bytes = Vec::with_capacity(32);
    let mut chunk = [0u8; 64];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    String::from_utf8(bytes).ok().map(|s| s.trim().to_string())
}

/// `strtoul(buf, NULL, 0)`: a leading number in any base, 0 when there is none.
fn strtoul(s: &str) -> u32 {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).unwrap_or(0);
    }
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    s[..end].parse().unwrap_or(0)
}

macro_rules! from_sysctl {
    ($s:expr, $prefix:literal, $ifname:expr, $file:literal, $field:ident, $flag:expr) => {
        if let Some(v) = sysctl($prefix, $ifname, $file) {
            $s.$field = strtoul(&v);
            $s.flags |= $flag;
        }
    };
    (bool $s:expr, $prefix:literal, $ifname:expr, $file:literal, $field:ident, $flag:expr) => {
        if let Some(v) = sysctl($prefix, $ifname, $file) {
            $s.$field = strtoul(&v) != 0;
            $s.flags |= $flag;
        }
    };
}

/// `system_if_get_settings`: everything the kernel will tell us about a device
/// that is present, in the same order and with the same flag effects.
pub fn read_settings(ifname: &str, e: &Ethtool, ifc: &sys::IfIoctl) -> Settings {
    let mut s = Settings::default();

    if let Ok(mtu) = ifc.get_mtu(ifname) {
        s.mtu = mtu;
        s.flags |= opt::MTU;
    }
    // mtu6 is the IPv6 sysctl, not an ioctl; 0 means "unset", not "present"
    if let Some(v) = sysctl("ipv6/conf", ifname, "mtu") {
        let mtu6 = strtoul(&v);
        if mtu6 > 0 {
            s.mtu6 = mtu6;
            s.flags |= opt::MTU6;
        }
    }
    if let Ok(q) = ifc.get_txqlen(ifname) {
        s.txqueuelen = q;
        s.flags |= opt::TXQUEUELEN;
    }
    if let Ok(mac) = ifc.get_hwaddr(ifname) {
        s.macaddr = mac;
        s.flags |= opt::MACADDR;
    }
    // disable_ipv6 is inverted into `ipv6`
    if let Some(v) = sysctl("ipv6/conf", ifname, "disable_ipv6") {
        s.ipv6 = strtoul(&v) == 0;
        s.flags |= opt::IPV6;
    }
    from_sysctl!(bool s, "ipv6/conf", ifname, "seg6_enabled", ip6segmentrouting, opt::IP6SEGMENTROUTING);
    if let Ok(flags) = ifc.get_flags(ifname) {
        s.promisc = flags & (sys::IFF_PROMISC as u16) != 0;
        s.flags |= opt::PROMISC;
        s.multicast = flags & (sys::IFF_MULTICAST as u16) != 0;
        s.flags |= opt::MULTICAST;
    }
    from_sysctl!(s, "ipv4/conf", ifname, "rp_filter", rpfilter, opt::RPFILTER);
    from_sysctl!(bool s, "ipv4/conf", ifname, "accept_local", acceptlocal, opt::ACCEPTLOCAL);
    from_sysctl!(s, "ipv4/conf", ifname, "force_igmp_version", igmpversion, opt::IGMPVERSION);
    from_sysctl!(s, "ipv6/conf", ifname, "force_mld_version", mldversion, opt::MLDVERSION);
    from_sysctl!(s, "ipv4/neigh", ifname, "base_reachable_time_ms", neigh4reachabletime, opt::NEIGHREACHABLETIME);
    from_sysctl!(s, "ipv6/neigh", ifname, "base_reachable_time_ms", neigh6reachabletime, opt::NEIGHREACHABLETIME);
    from_sysctl!(s, "ipv4/neigh", ifname, "locktime", neigh4locktime, opt::NEIGHLOCKTIME);
    from_sysctl!(s, "ipv4/neigh", ifname, "gc_stale_time", neigh4gcstaletime, opt::NEIGHGCSTALETIME);
    from_sysctl!(s, "ipv6/neigh", ifname, "gc_stale_time", neigh6gcstaletime, opt::NEIGHGCSTALETIME);
    from_sysctl!(s, "ipv6/conf", ifname, "dad_transmits", dadtransmits, opt::DADTRANSMITS);
    from_sysctl!(bool s, "ipv4/conf", ifname, "send_redirects", sendredirects, opt::SENDREDIRECTS);
    from_sysctl!(bool s, "ipv4/conf", ifname, "drop_unicast_in_l2_multicast", drop_v4_unicast_in_l2_multicast, opt::DROP_V4_UNICAST_IN_L2_MULTICAST);
    from_sysctl!(bool s, "ipv6/conf", ifname, "drop_unicast_in_l2_multicast", drop_v6_unicast_in_l2_multicast, opt::DROP_V6_UNICAST_IN_L2_MULTICAST);
    from_sysctl!(bool s, "ipv4/conf", ifname, "drop_gratuitous_arp", drop_gratuitous_arp, opt::DROP_GRATUITOUS_ARP);
    from_sysctl!(bool s, "ipv6/conf", ifname, "drop_unsolicited_na", drop_unsolicited_na, opt::DROP_UNSOLICITED_NA);
    from_sysctl!(bool s, "ipv4/conf", ifname, "arp_accept", arp_accept, opt::ARP_ACCEPT);

    if let Some(gro) = e.gro(ifname) {
        s.gro = gro;
        s.flags |= opt::GRO;
    }
    s
}

/// A device as netifd tracks it.
#[derive(Clone, Debug)]
pub struct Device {
    pub ifname: String,
    /// `dev->type->name`: "Network device", "bridge", "Bridge VLAN", …
    pub type_name: String,
    pub external: bool,
    pub present: bool,
    /// `dev->sys_present`: the kernel has this device. `present` is this and
    /// not deferred, as `device_refresh_present` computes it.
    pub sys_present: bool,
    /// `dev->deferred`, set by `network.device set_state {"defer":true}`.
    pub deferred: bool,
    /// `dev->active`: brought up by netifd
    pub active: bool,
    /// `dev->link_active`: carrier
    pub link_active: bool,
    pub auth_status: bool,
    pub settings: Settings,
    pub orig_settings: Settings,
    /// Present only for a bridge: its members and the config it was created
    /// with. `bridge_dump_info` emits both right after the ethtool block.
    pub bridge: Option<BridgeState>,
}

impl Device {
    pub fn new(ifname: &str, type_name: &str) -> Self {
        Self {
            ifname: ifname.to_string(),
            type_name: type_name.to_string(),
            external: false,
            sys_present: false,
            deferred: false,
            present: false,
            active: false,
            link_active: false,
            auth_status: false,
            settings: Settings::default(),
            orig_settings: Settings::default(),
            bridge: None,
        }
    }

    /// `device_dump_status` for one device, into an already-open table.
    ///
    /// The order below is the C's, field for field; a reordering would be
    /// visible to every caller that reads the blob rather than JSON.
    ///
    /// `stats` are the link counters from an RTM_GETLINK reply when the caller
    /// has them; otherwise the sysfs statistics files are read as the C does.
    pub fn dump_status(&self, b: &mut BlobBuf, e: Option<&Ethtool>, stats: Option<&[u64; 23]>) {
        b.msg_bool("external", self.external);
        b.msg_bool("present", self.present);
        b.msg_string("type", &self.type_name);
        if !self.present {
            return;
        }
        b.msg_bool("up", self.active);
        b.msg_bool("carrier", self.link_active);
        b.msg_bool("auth_status", self.auth_status);

        if let Some(e) = e {
            self.dump_info(b, e);
        }
        if let Some(br) = &self.bridge {
            br.dump(b);
        }

        if self.active {
            let st = merge_settings(&self.settings, &self.orig_settings);
            if st.has(opt::MASTER) {
                if let Some(name) = if_indextoname(st.master_ifindex) {
                    b.msg_string("conduit", &name);
                }
            }
            if st.has(opt::MTU) {
                b.msg_u32("mtu", st.mtu);
            }
            if st.has(opt::MTU6) {
                b.msg_u32("mtu6", st.mtu6);
            }
            if st.has(opt::MACADDR) {
                b.msg_string("macaddr", &format_macaddr(&st.macaddr));
            }
            if st.has(opt::TXQUEUELEN) {
                b.msg_u32("txqueuelen", st.txqueuelen);
            }
            if st.has(opt::IPV6) {
                b.msg_bool("ipv6", st.ipv6);
            }
            if st.has(opt::IP6SEGMENTROUTING) {
                b.msg_bool("ip6segmentrouting", st.ip6segmentrouting);
            }
            if st.has(opt::PROMISC) {
                b.msg_bool("promisc", st.promisc);
            }
            if st.has(opt::RPFILTER) {
                b.msg_u32("rpfilter", st.rpfilter);
            }
            if st.has(opt::ACCEPTLOCAL) {
                b.msg_bool("acceptlocal", st.acceptlocal);
            }
            if st.has(opt::IGMPVERSION) {
                b.msg_u32("igmpversion", st.igmpversion);
            }
            if st.has(opt::MLDVERSION) {
                b.msg_u32("mldversion", st.mldversion);
            }
            if st.has(opt::NEIGHREACHABLETIME) {
                b.msg_u32("neigh4reachabletime", st.neigh4reachabletime);
                b.msg_u32("neigh6reachabletime", st.neigh6reachabletime);
            }
            if st.has(opt::NEIGHGCSTALETIME) {
                b.msg_u32("neigh4gcstaletime", st.neigh4gcstaletime);
                b.msg_u32("neigh6gcstaletime", st.neigh6gcstaletime);
            }
            if st.has(opt::NEIGHLOCKTIME) {
                b.msg_u32("neigh4locktime", st.neigh4locktime);
            }
            if st.has(opt::DADTRANSMITS) {
                b.msg_u32("dadtransmits", st.dadtransmits);
            }
            if st.has(opt::MULTICAST_TO_UNICAST) {
                b.msg_bool("multicast_to_unicast", st.multicast_to_unicast);
            }
            if st.has(opt::MULTICAST_ROUTER) {
                b.msg_u32("multicast_router", st.multicast_router);
            }
            if st.has(opt::MULTICAST_FAST_LEAVE) {
                b.msg_bool("multicast_fast_leave", st.multicast_fast_leave);
            }
            if st.has(opt::MULTICAST) {
                b.msg_bool("multicast", st.multicast);
            }
            if st.has(opt::LEARNING) {
                b.msg_bool("learning", st.learning);
            }
            if st.has(opt::UNICAST_FLOOD) {
                b.msg_bool("unicast_flood", st.unicast_flood);
            }
            if st.has(opt::SENDREDIRECTS) {
                b.msg_bool("sendredirects", st.sendredirects);
            }
            if st.has(opt::DROP_V4_UNICAST_IN_L2_MULTICAST) {
                b.msg_bool(
                    "drop_v4_unicast_in_l2_multicast",
                    st.drop_v4_unicast_in_l2_multicast,
                );
            }
            if st.has(opt::DROP_V6_UNICAST_IN_L2_MULTICAST) {
                b.msg_bool(
                    "drop_v6_unicast_in_l2_multicast",
                    st.drop_v6_unicast_in_l2_multicast,
                );
            }
            if st.has(opt::DROP_GRATUITOUS_ARP) {
                b.msg_bool("drop_gratuitous_arp", st.drop_gratuitous_arp);
            }
            if st.has(opt::DROP_UNSOLICITED_NA) {
                b.msg_bool("drop_unsolicited_na", st.drop_unsolicited_na);
            }
            if st.has(opt::ARP_ACCEPT) {
                b.msg_bool("arp_accept", st.arp_accept);
            }
            if st.has(opt::AUTH) {
                b.msg_bool("auth", st.auth);
            }
            if st.has(opt::GRO) {
                b.msg_bool("gro", st.gro);
            }
            if st.has(opt::EEE) {
                b.msg_bool("eee", st.eee);
            }
        }

        let s = b.msg_open_table("statistics");
        match stats {
            Some(values) => {
                for (k, v) in ethtool::STAT_COUNTERS.iter().zip(values) {
                    b.msg_u64(k, *v);
                }
            }
            None => {
                for (k, v) in ethtool::statistics(&self.ifname) {
                    b.msg_u64(k, v);
                }
            }
        }
        b.msg_close(s);
    }

    /// `system_if_dump_info`: the ethtool block. A device that does not answer
    /// `ETHTOOL_GLINKSETTINGS` — loopback, a wireless AP interface — gets no
    /// fields at all here, not empty ones.
    fn dump_info(&self, b: &mut BlobBuf, e: &Ethtool) {
        let Ok(i) = e.link_info(&self.ifname) else {
            return;
        };
        let c = b.msg_open_array("link-advertising");
        for m in &i.link_advertising {
            b.msg_string("", m);
        }
        b.msg_close(c);
        let c = b.msg_open_array("link-partner-advertising");
        for m in &i.link_partner_advertising {
            b.msg_string("", m);
        }
        b.msg_close(c);
        let c = b.msg_open_array("link-supported");
        for m in &i.link_supported {
            b.msg_string("", m);
        }
        b.msg_close(c);
        if let Some(sp) = &i.speed {
            b.msg_string("speed", sp);
        }
        b.msg_bool("autoneg", i.autoneg);

        let fc = b.msg_open_table("flow-control");
        b.msg_bool("autoneg", i.pause_autoneg);
        let d = b.msg_open_array("supported");
        for m in &i.pause_supported {
            b.msg_string("", m);
        }
        b.msg_close(d);
        if i.pause_autoneg {
            let d = b.msg_open_array("link-advertising");
            for m in &i.pause_advertising {
                b.msg_string("", m);
            }
            b.msg_close(d);
        }
        let d = b.msg_open_array("link-partner-advertising");
        for m in &i.pause_partner_advertising {
            b.msg_string("", m);
        }
        b.msg_close(d);
        // autonegotiated flow control reports "negotiated"; otherwise the
        // ioctl's own "selected". Exactly one of the two is present.
        if let Some(neg) = &i.pause_negotiated {
            let d = b.msg_open_array("negotiated");
            for m in neg {
                b.msg_string("", m);
            }
            b.msg_close(d);
        }
        if let Some(sel) = &i.pause_selected {
            let d = b.msg_open_array("selected");
            for m in sel {
                b.msg_string("", m);
            }
            b.msg_close(d);
        }
        b.msg_close(fc);

        b.msg_bool("hw-tc-offload", e.feature_value(&self.ifname, "hw-tc-offload"));
        if let Some(dt) = ethtool::devtype(&self.ifname) {
            b.msg_string("devtype", &dt);
        }
    }
}

/// A bridge's members and configuration, as `bridge_dump_info` reports them.
#[derive(Clone, Debug)]
pub struct BridgeState {
    /// In the order netifd's member list holds them, which is config order.
    pub members: Vec<String>,
    pub config: sys::BridgeConfig,
    /// Set only when the config named an STP protocol.
    pub stp_proto: Option<String>,
}

impl BridgeState {
    /// The `bridge-members` array and `bridge-attributes` table, in the C's
    /// field order. `ageing_time` reports 0 when unset, because the C reports
    /// the memset default rather than omitting the field.
    pub fn dump(&self, b: &mut BlobBuf) {
        let c = &self.config;
        let list = b.msg_open_array("bridge-members");
        for m in &self.members {
            b.msg_string("", m);
        }
        b.msg_close(list);

        let t = b.msg_open_table("bridge-attributes");
        b.msg_bool("stp", c.stp);
        b.msg_u32("forward_delay", c.forward_delay);
        b.msg_u32("priority", c.priority as u32);
        b.msg_u32("ageing_time", c.ageing_time.unwrap_or(0));
        b.msg_u32("hello_time", c.hello_time);
        b.msg_u32("max_age", c.max_age);
        b.msg_bool("igmp_snooping", c.igmp_snoop);
        b.msg_bool("bridge_empty", c.bridge_empty);
        b.msg_bool("multicast_querier", c.multicast_querier);
        b.msg_u32("hash_max", c.hash_max);
        b.msg_u32("robustness", c.robustness);
        b.msg_u32("query_interval", c.query_interval);
        b.msg_u32("query_response_interval", c.query_response_interval);
        b.msg_u32("last_member_interval", c.last_member_interval);
        b.msg_bool("vlan_filtering", c.vlan_filtering);
        b.msg_bool("stp_kernel", c.stp_kernel);
        if let Some(p) = &self.stp_proto {
            b.msg_string("stp_proto", p);
        }
        b.msg_close(t);
    }
}

/// `format_macaddr`: lowercase, colon-separated.
pub fn format_macaddr(m: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}

/// `if_indextoname`, via sysfs so no libc call is needed.
pub fn if_indextoname(index: u32) -> Option<String> {
    std::fs::read_dir("/sys/class/net").ok()?.flatten().find_map(|e| {
        let name = e.file_name().to_string_lossy().into_owned();
        let idx = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex")).ok()?;
        (idx.trim().parse::<u32>().ok()? == index).then_some(name)
    })
}

/// The device registry. netifd keeps devices in an AVL tree keyed by name, so
/// `status` with no argument walks them in name order.
#[derive(Default)]
pub struct Devices {
    devices: Vec<Device>,
}

impl Devices {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, ifname: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.ifname == ifname)
    }

    pub fn get_mut(&mut self, ifname: &str) -> Option<&mut Device> {
        self.devices.iter_mut().find(|d| d.ifname == ifname)
    }

    /// Insert or replace, keeping the vector sorted by name.
    pub fn insert(&mut self, dev: Device) {
        match self.devices.binary_search_by(|d| d.ifname.cmp(&dev.ifname)) {
            Ok(i) => self.devices[i] = dev,
            Err(i) => self.devices.insert(i, dev),
        }
    }

    pub fn remove(&mut self, ifname: &str) -> Option<Device> {
        let i = self.devices.iter().position(|d| d.ifname == ifname)?;
        Some(self.devices.remove(i))
    }

    /// In name order, as the AVL walk produces.
    pub fn iter(&self) -> impl Iterator<Item = &Device> {
        self.devices.iter()
    }

    /// `network.device status` with no argument: present devices only.
    #[cfg(test)]
    pub fn dump_all(&self, b: &mut BlobBuf, e: Option<&Ethtool>) {
        for d in self.iter().filter(|d| d.present) {
            let t = b.msg_open_table(&d.ifname);
            d.dump_status(b, e, None);
            b.msg_close(t);
        }
    }
}

/// The ioctl-based getters `system_if_get_settings` uses. Kept separate from
/// the netlink socket because they are `SIOCGIF*` on an AF_INET socket.
impl sys::IfIoctl {
    pub fn get_mtu(&self, ifname: &str) -> io::Result<u32> {
        self.ioctl_u32(ifname, sys::SIOCGIFMTU, 16)
    }

    pub fn get_txqlen(&self, ifname: &str) -> io::Result<u32> {
        self.ioctl_u32(ifname, sys::SIOCGIFTXQLEN, 16)
    }

    pub fn get_flags(&self, ifname: &str) -> io::Result<u16> {
        Ok(self.ioctl_u32(ifname, sys::SIOCGIFFLAGS, 16)? as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn sysctl_open_keeps_close_on_exec_and_open_errors() {
        let file = open_sysctl(c"/proc/sys/kernel/osrelease").unwrap();
        let flags = rustix::io::fcntl_getfd(&file).unwrap();
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC), "FD_CLOEXEC must remain set");
        assert_eq!(open_sysctl(c"/proc/sys/h7b-nonexistent").unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn sysctl_rejects_interior_nul_without_opening_a_prefix_path() {
        assert!(sysctl("ipv4/conf", "lo\0ignored", "rp_filter").is_none());
    }

    #[test]
    fn strtoul_reads_a_leading_number_only() {
        assert_eq!(strtoul("30000\n"), 30000);
        assert_eq!(strtoul("0"), 0);
        assert_eq!(strtoul("0x10"), 16);
        assert_eq!(strtoul("2 3"), 2);
        assert_eq!(strtoul(""), 0);
        assert_eq!(strtoul("abc"), 0);
    }

    #[test]
    fn merge_prefers_configured_and_unions_the_flags() {
        let mut cfg = Settings { mtu: 1400, ..Default::default() };
        cfg.flags |= opt::MTU;
        let mut orig = Settings { mtu: 1500, txqueuelen: 1000, ..Default::default() };
        orig.flags |= opt::MTU | opt::TXQUEUELEN;

        let m = merge_settings(&cfg, &orig);
        assert_eq!(m.mtu, 1400);
        assert_eq!(m.txqueuelen, 1000);
        assert!(m.has(opt::MTU) && m.has(opt::TXQUEUELEN));
    }

    #[test]
    fn a_flag_only_the_system_set_still_shows() {
        let cfg = Settings::default();
        let mut orig = Settings { rpfilter: 2, ..Default::default() };
        orig.flags |= opt::RPFILTER;
        let m = merge_settings(&cfg, &orig);
        assert!(m.has(opt::RPFILTER));
        assert_eq!(m.rpfilter, 2);
    }

    #[test]
    fn a_device_that_is_not_present_stops_after_three_fields() {
        let d = Device::new("wan", "Network device");
        let mut b = BlobBuf::new();
        let t = b.msg_open_table("wan");
        d.dump_status(&mut b, None, None);
        b.msg_close(t);
        let json = owrt_ubus::convert::fields_to_json(b.payload()).unwrap().to_compact();
        assert!(json.contains("\"external\""), "{json}");
        assert!(json.contains("\"present\""), "{json}");
        assert!(json.contains("\"type\""), "{json}");
        assert!(!json.contains("\"up\""), "{json}");
        assert!(!json.contains("\"statistics\""), "{json}");
    }

    #[test]
    fn an_inactive_device_reports_state_but_no_settings() {
        let mut d = Device::new("wan", "Network device");
        d.present = true;
        d.settings.flags |= opt::MTU;
        d.settings.mtu = 1500;
        let mut b = BlobBuf::new();
        d.dump_status(&mut b, None, None);
        let json = owrt_ubus::convert::fields_to_json(b.payload()).unwrap().to_compact();
        assert!(json.contains("\"carrier\""), "{json}");
        assert!(!json.contains("\"mtu\""), "{json}");
        // statistics is always opened, even when empty
        assert!(json.contains("\"statistics\""), "{json}");
    }

    #[test]
    fn the_status_field_order_is_the_c_order() {
        let mut d = Device::new("wan", "Network device");
        d.present = true;
        d.active = true;
        d.link_active = true;
        let mut s = Settings {
            mtu: 1500,
            mtu6: 1500,
            macaddr: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            txqueuelen: 1000,
            ipv6: true,
            rpfilter: 2,
            neigh4reachabletime: 30000,
            neigh6reachabletime: 30000,
            gro: true,
            ..Default::default()
        };
        s.flags = opt::MTU
            | opt::MTU6
            | opt::MACADDR
            | opt::TXQUEUELEN
            | opt::IPV6
            | opt::RPFILTER
            | opt::NEIGHREACHABLETIME
            | opt::GRO;
        d.orig_settings = s;

        let mut b = BlobBuf::new();
        d.dump_status(&mut b, None, None);
        let json = owrt_ubus::convert::fields_to_json(b.payload()).unwrap().to_compact();
        let order: Vec<&str> = [
            "external",
            "present",
            "type",
            "up",
            "carrier",
            "auth_status",
            "mtu",
            "mtu6",
            "macaddr",
            "txqueuelen",
            "ipv6",
            "rpfilter",
            "neigh4reachabletime",
            "neigh6reachabletime",
            "gro",
            "statistics",
        ]
        .into_iter()
        .collect();
        let mut pos = 0;
        for key in order {
            let at = json[pos..]
                .find(&format!("\"{key}\""))
                .unwrap_or_else(|| panic!("{key} missing or out of order in {json}"));
            pos += at;
        }
    }

    #[test]
    fn one_reachable_time_flag_prints_both_families() {
        let mut d = Device::new("lo", "Network device");
        d.present = true;
        d.active = true;
        d.orig_settings.flags = opt::NEIGHGCSTALETIME;
        d.orig_settings.neigh4gcstaletime = 60;
        d.orig_settings.neigh6gcstaletime = 60;
        let mut b = BlobBuf::new();
        d.dump_status(&mut b, None, None);
        let json = owrt_ubus::convert::fields_to_json(b.payload()).unwrap().to_compact();
        assert!(json.contains("neigh4gcstaletime"), "{json}");
        assert!(json.contains("neigh6gcstaletime"), "{json}");
    }

    #[test]
    fn devices_iterate_in_name_order_and_skip_absent_ones() {
        let mut r = Devices::new();
        for n in ["wan", "br-lan", "lo", "lan2"] {
            let mut d = Device::new(n, "Network device");
            d.present = n != "lan2";
            r.insert(d);
        }
        assert_eq!(
            r.iter().map(|d| d.ifname.as_str()).collect::<Vec<_>>(),
            vec!["br-lan", "lan2", "lo", "wan"]
        );
        let mut b = BlobBuf::new();
        r.dump_all(&mut b, None);
        let json = owrt_ubus::convert::fields_to_json(b.payload()).unwrap().to_compact();
        let i_br = json.find("br-lan").unwrap();
        let i_lo = json.find("\"lo\"").unwrap();
        let i_wan = json.find("\"wan\"").unwrap();
        assert!(i_br < i_lo && i_lo < i_wan, "{json}");
        assert!(!json.contains("lan2"), "{json}");
    }

    #[test]
    fn macaddr_is_lowercase_hex() {
        assert_eq!(format_macaddr(&[0x02, 0xab, 0xcd, 0xef, 0x12, 0x34]), "02:ab:cd:ef:12:34");
    }
}
