//! iwinfo_nl80211.c: the nl80211 backend. Helpers keep their C names; the
//! `iwinfo_ops` slots are the `pub fn`s named after the slot (mode, ssid,
//! ...) with the C function in the doc comment. Every `return -1` of the C
//! is an `Err(())`, every `return 0` an `Ok(..)`.

use super::netlink::{self, nla_parse, nla_parse_nested, Attr, Msg, Nlmsg, Policy, Tb, NLM_F_DUMP};
use super::sys::{self, ENOENT, ENOMEM, IFNAMSIZ};
use std::os::fd::OwnedFd;
use super::utils::{self, atoi, cstr, fgets_chunks, readdir, strtok, strtok_all, strtol16, strtoul16};
use super::*;
use std::fs::File;
use std::io::{Read, Write};

// ------------------------------------------------------ nl80211.h constants

const NL80211_CMD_GET_WIPHY: u8 = 1;
const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_NEW_INTERFACE: u8 = 7;
const NL80211_CMD_DEL_INTERFACE: u8 = 8;
const NL80211_CMD_GET_STATION: u8 = 17;
const NL80211_CMD_GET_REG: u8 = 31;
const NL80211_CMD_GET_SCAN: u8 = 32;
const NL80211_CMD_TRIGGER_SCAN: u8 = 33;
const NL80211_CMD_NEW_SCAN_RESULTS: u8 = 34;
const NL80211_CMD_SCAN_ABORTED: u8 = 35;
const NL80211_CMD_GET_SURVEY: u8 = 50;
const NL80211_CMD_GET_PROTOCOL_FEATURES: u8 = 95;

const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_WIPHY_NAME: u16 = 2;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_STA_INFO: u16 = 21;
const NL80211_ATTR_WIPHY_BANDS: u16 = 22;
const NL80211_ATTR_REG_ALPHA2: u16 = 33;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_BSS: u16 = 47;
const NL80211_ATTR_SURVEY_INFO: u16 = 84;
const NL80211_ATTR_WIPHY_TX_POWER_LEVEL: u16 = 98;
const NL80211_ATTR_BSS_HT_OPMODE: u16 = 109;
const NL80211_ATTR_INTERFACE_COMBINATIONS: u16 = 120;
const NL80211_ATTR_CHANNEL_WIDTH: u16 = 159;
const NL80211_ATTR_CENTER_FREQ1: u16 = 160;
const NL80211_ATTR_CENTER_FREQ2: u16 = 161;
const NL80211_ATTR_PROTOCOL_FEATURES: u16 = 173;
const NL80211_ATTR_SPLIT_WIPHY_DUMP: u16 = 174;
const NL80211_ATTR_MAX: usize = 326;

const NL80211_IFTYPE_STATION: u32 = 2;
const NL80211_IFTYPE_AP: u16 = 3;
const NL80211_IFTYPE_MAX: usize = 12;

const NL80211_STA_FLAG_AUTHORIZED: u32 = 1;
const NL80211_STA_FLAG_SHORT_PREAMBLE: u32 = 2;
const NL80211_STA_FLAG_WME: u32 = 3;
const NL80211_STA_FLAG_MFP: u32 = 4;
const NL80211_STA_FLAG_AUTHENTICATED: u32 = 5;
const NL80211_STA_FLAG_TDLS_PEER: u32 = 6;

const NL80211_RATE_INFO_BITRATE: u16 = 1;
const NL80211_RATE_INFO_MCS: u16 = 2;
const NL80211_RATE_INFO_40_MHZ_WIDTH: u16 = 3;
const NL80211_RATE_INFO_SHORT_GI: u16 = 4;
const NL80211_RATE_INFO_BITRATE32: u16 = 5;
const NL80211_RATE_INFO_VHT_MCS: u16 = 6;
const NL80211_RATE_INFO_VHT_NSS: u16 = 7;
const NL80211_RATE_INFO_80_MHZ_WIDTH: u16 = 8;
const NL80211_RATE_INFO_80P80_MHZ_WIDTH: u16 = 9;
const NL80211_RATE_INFO_160_MHZ_WIDTH: u16 = 10;
const NL80211_RATE_INFO_10_MHZ_WIDTH: u16 = 11;
const NL80211_RATE_INFO_5_MHZ_WIDTH: u16 = 12;
const NL80211_RATE_INFO_HE_MCS: u16 = 13;
const NL80211_RATE_INFO_HE_NSS: u16 = 14;
const NL80211_RATE_INFO_HE_GI: u16 = 15;
const NL80211_RATE_INFO_HE_DCM: u16 = 16;
const NL80211_RATE_INFO_320_MHZ_WIDTH: u16 = 18;
const NL80211_RATE_INFO_EHT_MCS: u16 = 19;
const NL80211_RATE_INFO_EHT_NSS: u16 = 20;
const NL80211_RATE_INFO_EHT_GI: u16 = 21;
const NL80211_RATE_INFO_MAX: usize = 29;

const NL80211_STA_INFO_INACTIVE_TIME: u16 = 1;
const NL80211_STA_INFO_RX_BYTES: u16 = 2;
const NL80211_STA_INFO_TX_BYTES: u16 = 3;
const NL80211_STA_INFO_LLID: u16 = 4;
const NL80211_STA_INFO_PLID: u16 = 5;
const NL80211_STA_INFO_PLINK_STATE: u16 = 6;
const NL80211_STA_INFO_SIGNAL: u16 = 7;
const NL80211_STA_INFO_TX_BITRATE: u16 = 8;
const NL80211_STA_INFO_RX_PACKETS: u16 = 9;
const NL80211_STA_INFO_TX_PACKETS: u16 = 10;
const NL80211_STA_INFO_TX_RETRIES: u16 = 11;
const NL80211_STA_INFO_TX_FAILED: u16 = 12;
const NL80211_STA_INFO_SIGNAL_AVG: u16 = 13;
const NL80211_STA_INFO_RX_BITRATE: u16 = 14;
const NL80211_STA_INFO_CONNECTED_TIME: u16 = 16;
const NL80211_STA_INFO_STA_FLAGS: u16 = 17;
const NL80211_STA_INFO_T_OFFSET: u16 = 19;
const NL80211_STA_INFO_LOCAL_PM: u16 = 20;
const NL80211_STA_INFO_PEER_PM: u16 = 21;
const NL80211_STA_INFO_NONPEER_PM: u16 = 22;
const NL80211_STA_INFO_RX_BYTES64: u16 = 23;
const NL80211_STA_INFO_TX_BYTES64: u16 = 24;
const NL80211_STA_INFO_EXPECTED_THROUGHPUT: u16 = 27;
const NL80211_STA_INFO_RX_DROP_MISC: u16 = 28;
const NL80211_STA_INFO_MAX: usize = 43;

const NL80211_BAND_ATTR_FREQS: u16 = 1;
const NL80211_BAND_ATTR_HT_CAPA: u16 = 4;
const NL80211_BAND_ATTR_VHT_CAPA: u16 = 8;
const NL80211_BAND_ATTR_IFTYPE_DATA: u16 = 9;
const NL80211_BAND_ATTR_MAX: usize = 13;

const NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY: u16 = 3;
const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY: u16 = 9;
const NL80211_BAND_IFTYPE_ATTR_MAX: usize = 11;

const NL80211_FREQUENCY_ATTR_FREQ: u16 = 1;
const NL80211_FREQUENCY_ATTR_DISABLED: u16 = 2;
const NL80211_FREQUENCY_ATTR_NO_IR: u16 = 3;
const NL80211_FREQUENCY_ATTR_RADAR: u16 = 5;
const NL80211_FREQUENCY_ATTR_MAX_TX_POWER: u16 = 6;
const NL80211_FREQUENCY_ATTR_NO_HT40_MINUS: u16 = 9;
const NL80211_FREQUENCY_ATTR_NO_HT40_PLUS: u16 = 10;
const NL80211_FREQUENCY_ATTR_NO_80MHZ: u16 = 11;
const NL80211_FREQUENCY_ATTR_NO_160MHZ: u16 = 12;
const NL80211_FREQUENCY_ATTR_INDOOR_ONLY: u16 = 14;
const NL80211_FREQUENCY_ATTR_NO_20MHZ: u16 = 16;
const NL80211_FREQUENCY_ATTR_NO_10MHZ: u16 = 17;
const NL80211_FREQUENCY_ATTR_NO_HE: u16 = 19;
const NL80211_FREQUENCY_ATTR_MAX: usize = 27;

const NL80211_BSS_BSSID: u16 = 1;
const NL80211_BSS_FREQUENCY: u16 = 2;
const NL80211_BSS_TSF: u16 = 3;
const NL80211_BSS_BEACON_INTERVAL: u16 = 4;
const NL80211_BSS_CAPABILITY: u16 = 5;
const NL80211_BSS_INFORMATION_ELEMENTS: u16 = 6;
const NL80211_BSS_SIGNAL_MBM: u16 = 7;
const NL80211_BSS_SIGNAL_UNSPEC: u16 = 8;
const NL80211_BSS_STATUS: u16 = 9;
const NL80211_BSS_SEEN_MS_AGO: u16 = 10;
const NL80211_BSS_MAX: usize = 22;

const NL80211_BSS_STATUS_AUTHENTICATED: u32 = 0;
const NL80211_BSS_STATUS_ASSOCIATED: u32 = 1;
const NL80211_BSS_STATUS_IBSS_JOINED: u32 = 2;

const NL80211_SURVEY_INFO_FREQUENCY: u16 = 1;
const NL80211_SURVEY_INFO_NOISE: u16 = 2;
const NL80211_SURVEY_INFO_IN_USE: u16 = 3;
const NL80211_SURVEY_INFO_TIME: u16 = 4;
const NL80211_SURVEY_INFO_TIME_BUSY: u16 = 5;
const NL80211_SURVEY_INFO_TIME_EXT_BUSY: u16 = 6;
const NL80211_SURVEY_INFO_TIME_RX: u16 = 7;
const NL80211_SURVEY_INFO_TIME_TX: u16 = 8;
const NL80211_SURVEY_INFO_MAX: usize = 12;

const NL80211_BAND_2GHZ: u16 = 0;
const NL80211_BAND_5GHZ: u16 = 1;
const NL80211_BAND_60GHZ: u16 = 2;
const NL80211_BAND_6GHZ: u16 = 3;

const NL80211_CHAN_WIDTH_20_NOHT: i32 = 0;
const NL80211_CHAN_WIDTH_20: i32 = 1;
const NL80211_CHAN_WIDTH_40: i32 = 2;
const NL80211_CHAN_WIDTH_80: i32 = 3;
const NL80211_CHAN_WIDTH_80P80: i32 = 4;
const NL80211_CHAN_WIDTH_160: i32 = 5;
const NL80211_CHAN_WIDTH_5: i32 = 6;
const NL80211_CHAN_WIDTH_10: i32 = 7;
const NL80211_CHAN_WIDTH_320: i32 = 13;

const NL80211_PLINK_LISTEN: u8 = 0;
const NL80211_PLINK_OPN_SNT: u8 = 1;
const NL80211_PLINK_OPN_RCVD: u8 = 2;
const NL80211_PLINK_CNF_RCVD: u8 = 3;
const NL80211_PLINK_ESTAB: u8 = 4;
const NL80211_PLINK_HOLDING: u8 = 5;
const NL80211_PLINK_BLOCKED: u8 = 6;

const NL80211_MESH_POWER_ACTIVE: u32 = 1;
const NL80211_MESH_POWER_LIGHT_SLEEP: u32 = 2;
const NL80211_MESH_POWER_DEEP_SLEEP: u32 = 3;

const NL80211_IFACE_LIMIT_MAX: u16 = 1;
const NL80211_IFACE_LIMIT_TYPES: u16 = 2;
const NUM_NL80211_IFACE_LIMIT: usize = 3;
const NL80211_IFACE_COMB_LIMITS: u16 = 1;
const NL80211_IFACE_COMB_MAXNUM: u16 = 2;
const NUM_NL80211_IFACE_COMB: usize = 8;

const NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP: u32 = 1;

// ------------------------------------------------------------ small helpers

/// `tb[type]`
fn at<'a>(tb: &Tb<'a>, ty: u16) -> Option<Attr<'a>> {
    tb.get(ty as usize).copied().flatten()
}

/// nl80211_readint: atoi() of the first 16 bytes, -1 when unreadable.
fn nl80211_readint(path: &str) -> i32 {
    let Ok(mut f) = File::open(path) else {
        return -1;
    };
    let mut buffer = [0u8; 16];
    match f.read(&mut buffer) {
        Ok(n) if n > 0 => atoi(&buffer[..n]),
        _ => -1,
    }
}

/// nl80211_readstr: one read() of `length - 1` bytes with a trailing
/// newline stripped; None where the C returns <= 0.
fn nl80211_readstr(path: &str, length: usize) -> Option<Vec<u8>> {
    let mut f = File::open(path).ok()?;
    let mut buffer = vec![0u8; length.saturating_sub(1)];
    let mut rv = f.read(&mut buffer).ok()?;
    if rv == 0 {
        return None;
    }
    if buffer[rv - 1] == b'\n' {
        rv -= 1;
    }
    if rv > 0 {
        Some(buffer[..rv].to_vec())
    } else {
        None
    }
}

/// nl80211_get_band
fn nl80211_get_band(nla_type: u16) -> i32 {
    match nla_type {
        NL80211_BAND_2GHZ => IWINFO_BAND_24,
        NL80211_BAND_5GHZ => IWINFO_BAND_5,
        NL80211_BAND_6GHZ => IWINFO_BAND_6,
        NL80211_BAND_60GHZ => IWINFO_BAND_60,
        _ => 0,
    }
}

/// nl80211_phy_path_str: the sysfs device path of a phy relative to
/// /sys/devices/ (leading "platform/" dropped for PCI devices), suffixed
/// with "+N" when N lower-indexed phys share the device.
fn nl80211_phy_path_str(phyname: &str) -> Option<String> {
    let phy_idx = nl80211_readint(&format!("/sys/class/ieee80211/{phyname}/index"));
    if phy_idx < 0 {
        return None;
    }
    let dev = format!("/sys/class/ieee80211/{phyname}/device");
    let link = std::fs::canonicalize(&dev).ok()?;
    let link = link.to_string_lossy().into_owned();
    let prefix = "/sys/devices/";
    let mut link = link.strip_prefix(prefix)?.to_owned();
    if link.starts_with("platform/") && link.contains("/pci") {
        link = link["platform/".len()..].to_owned();
    }
    let Some(entries) = readdir(&format!("{dev}/ieee80211")) else {
        return Some(link);
    };
    let mut seq = 0;
    for e in entries {
        let cur_idx = nl80211_readint(&format!("/sys/class/ieee80211/{e}/index"));
        if cur_idx < 0 {
            continue;
        }
        if cur_idx >= phy_idx {
            continue;
        }
        seq += 1;
    }
    if seq == 0 {
        return Some(link);
    }
    Some(format!("{link}+{seq}"))
}

/// nl80211_phy_idx_from_path
fn nl80211_phy_idx_from_path(path: Option<&str>) -> i32 {
    let Some(path) = path else {
        return -1;
    };
    if path.is_empty() {
        return -1;
    }
    let Some(entries) = readdir("/sys/class/ieee80211") else {
        return -1;
    };
    let mut idx = -1;
    for e in entries {
        let Some(cur_path) = nl80211_phy_path_str(&e) else {
            continue;
        };
        if cur_path.len() < path.len() {
            continue;
        }
        if !cur_path.ends_with(path) {
            continue;
        }
        idx = nl80211_readint(&format!("/sys/class/ieee80211/{e}/index"));
        if idx >= 0 {
            break;
        }
    }
    idx
}

/// nl80211_phy_idx_from_macaddr: fnmatch(opt, <phy>/macaddress, FNM_CASEFOLD)
fn nl80211_phy_idx_from_macaddr(opt: Option<&str>) -> i32 {
    let Some(opt) = opt else {
        return -1;
    };
    let paths = crate::glob::glob("/sys/class/ieee80211/*");
    if paths.is_empty() {
        return -1;
    }
    let pattern = opt.to_ascii_lowercase();
    let mut idx = -1;
    for p in paths {
        let Some(mac) = nl80211_readstr(&format!("{p}/macaddress"), 128) else {
            continue;
        };
        let mac = cstr(&mac).to_ascii_lowercase();
        if !crate::glob::fnmatch(pattern.as_bytes(), &mac) {
            continue;
        }
        idx = nl80211_readint(&format!("{p}/index"));
        if idx > -1 {
            break;
        }
    }
    idx
}

/// nl80211_phy_idx_from_phy
fn nl80211_phy_idx_from_phy(opt: &str) -> i32 {
    nl80211_readint(&format!("/sys/class/ieee80211/{opt}/index"))
}

/// nl80211_phy_idx_from_uci: resolve a `wifi-device` section (type
/// mac80211) via its path, macaddr or phy option.
fn nl80211_phy_idx_from_uci(name: &str) -> i32 {
    let Some(s) = utils::iwinfo_uci_get_radio(name, "mac80211") else {
        return -1;
    };
    let mut idx = nl80211_phy_idx_from_path(utils::uci_lookup_option_string(&s, "path"));
    if idx >= 0 {
        return idx;
    }
    idx = nl80211_phy_idx_from_macaddr(utils::uci_lookup_option_string(&s, "macaddr"));
    if idx >= 0 {
        return idx;
    }
    match utils::uci_lookup_option_string(&s, "phy") {
        Some(opt) => nl80211_phy_idx_from_phy(opt),
        None => -1,
    }
}

/// nl80211_is_ifname: lstat("/sys/class/net/<name>")
fn nl80211_is_ifname(name: &str) -> bool {
    std::fs::symlink_metadata(format!("/sys/class/net/{name}")).is_ok()
}

fn if_nametoindex(name: &str) -> u32 {
    let c = sys::cpath(name.as_bytes());
    owrt_platform::rpcd::interface_index(std::ffi::CStr::from_bytes_until_nul(&c).unwrap())
}

/// nl80211_msg: a request addressed by ifindex (real or "mon." interface)
/// or by wiphy index (phyN / radioN / uci section).
fn nl80211_msg(ifname: &str, cmd: u8, flags: u16) -> Option<Msg> {
    if netlink::nl80211_init() < 0 {
        return None;
    }
    let mut ifidx: u32 = 0;
    let mut phyidx: i32 = -1;
    if let Some(rest) = ifname.strip_prefix("mon.") {
        ifidx = if_nametoindex(rest);
    } else if nl80211_is_ifname(ifname) {
        ifidx = if_nametoindex(ifname);
    } else {
        phyidx = nl80211_phy_idx_from_phy(ifname);
        if phyidx < 0 {
            phyidx = nl80211_phy_idx_from_uci(ifname);
        }
    }
    /* Valid ifidx must be greater than 0 */
    if ifidx == 0 && phyidx < 0 {
        return None;
    }
    let nls = netlink::nls()?;
    let mut cv = Msg::new(nls.nl80211, cmd, flags);
    if ifidx > 0 {
        cv.put_u32(NL80211_ATTR_IFINDEX, ifidx);
    } else if phyidx > -1 {
        cv.put_u32(NL80211_ATTR_WIPHY, phyidx as u32);
    }
    Some(cv)
}

/// nl80211_send
fn nl80211_send(cv: Msg, cb: &mut dyn FnMut(&Nlmsg)) -> i32 {
    netlink::nl80211_send(cv, cb)
}

/// nl80211_request: -ENOMEM when the message cannot be built, else the
/// nl80211_send() result.
fn nl80211_request(ifname: &str, cmd: u8, flags: u16, cb: &mut dyn FnMut(&Nlmsg)) -> i32 {
    let Some(cv) = nl80211_msg(ifname, cmd, flags) else {
        return -ENOMEM;
    };
    nl80211_send(cv, cb)
}

/// nl80211_parse: top-level attribute table of a genl message.
fn nl80211_parse<'a>(msg: &Nlmsg<'a>) -> Tb<'a> {
    nla_parse(msg.genl_attrs(), NL80211_ATTR_MAX, &[]).0
}

/// nl80211_get_protocol_features
fn nl80211_get_protocol_features(ifname: &str) -> u32 {
    let mut features = 0u32;
    if let Some(req) = nl80211_msg(ifname, NL80211_CMD_GET_PROTOCOL_FEATURES, 0) {
        nl80211_send(req, &mut |m: &Nlmsg| {
            if let Some(a) = at(&nl80211_parse(m), NL80211_ATTR_PROTOCOL_FEATURES) {
                features = a.get_u32();
            }
        });
    }
    features
}

/// strncmp(a, b, n) == 0 for C strings
fn strncmp_eq(a: &[u8], b: &[u8], n: usize) -> bool {
    for i in 0..n {
        let ca = a.get(i).copied().unwrap_or(0);
        let cb = b.get(i).copied().unwrap_or(0);
        if ca != cb {
            return false;
        }
        if ca == 0 {
            return true;
        }
    }
    true
}

/// nl80211_subscribe: resolve the multicast group id of `family`/`group`
/// through nlctrl and join it.
fn nl80211_subscribe(family: &str, group: &str) -> i32 {
    // nl80211_ctl(CTRL_CMD_GETFAMILY, 0)
    if netlink::nl80211_init() < 0 {
        return -ENOMEM;
    }
    let Some(nls) = netlink::nls() else {
        return -ENOMEM;
    };
    let mut req = Msg::new(nls.nlctrl, netlink::CTRL_CMD_GETFAMILY, 0);
    req.put_string(netlink::CTRL_ATTR_FAMILY_NAME, family);
    let mut id: i32 = -ENOENT;
    let err = nl80211_send(req, &mut |m: &Nlmsg| {
        // nl80211_subscribe_cb
        let attr = nl80211_parse(m);
        let Some(groups) = at(&attr, netlink::CTRL_ATTR_MCAST_GROUPS) else {
            return;
        };
        for mgrp in groups.nested() {
            let (mgrpinfo, _) = nla_parse(mgrp.data, netlink::CTRL_ATTR_MCAST_GRP_MAX, &[]);
            let (Some(gid), Some(gname)) =
                (at(&mgrpinfo, netlink::CTRL_ATTR_MCAST_GRP_ID), at(&mgrpinfo, netlink::CTRL_ATTR_MCAST_GRP_NAME))
            else {
                continue;
            };
            if strncmp_eq(gname.data, group.as_bytes(), gname.nla_len()) {
                id = gid.get_u32() as i32;
                break;
            }
        }
    });
    if err != 0 {
        return err;
    }
    netlink::nl_socket_add_membership(id)
}

/// __nl80211_wait: subscribe and block until one of `cmds` arrives (or an
/// error message does).
fn nl80211_wait(family: &str, group: &str, cmds: &[u8]) -> i32 {
    if nl80211_subscribe(family, group) != 0 {
        return -ENOENT;
    }
    let Some(nls) = netlink::nls() else {
        return -ENOMEM;
    };
    let mut err = 0;
    let mut recv = 0u8;
    while recv == 0 && err == 0 {
        netlink::recvmsgs(&nls, None, &mut err, &mut |m: &Nlmsg| {
            // nl80211_wait_cb
            let cmd = m.genl_cmd();
            if cmds.contains(&cmd) {
                recv = cmd;
            }
        });
    }
    err
}

/// nl80211_freq2channel (ieee80211_freq_khz_to_channel)
pub fn nl80211_freq2channel(freq: i32) -> i32 {
    if freq == 2484 {
        14
    } else if freq < 2484 {
        (freq - 2407) / 5
    } else if (4910..=4980).contains(&freq) {
        (freq - 4000) / 5
    } else if freq < 5925 {
        (freq - 5000) / 5
    } else if freq == 5935 {
        2
    } else if freq <= 45000 {
        /* DMG band lower limit; see 802.11ax D6.1 27.3.22.2 */
        (freq - 5950) / 5
    } else if (58320..=70200).contains(&freq) {
        (freq - 56160) / 2160
    } else {
        0
    }
}

/// nl80211_channel2freq (ieee80211_channel_to_freq_khz); `band` is the
/// hostapd hw_mode string, `opclass` the op_class.
pub fn nl80211_channel2freq(channel: i32, band: &[u8], opclass: i32) -> i32 {
    if channel < 1 {
        return 0;
    }
    if band.first() != Some(&b'a') {
        if channel == 14 {
            return 2484;
        } else if channel < 14 {
            return (channel * 5) + 2407;
        }
    } else if band == b"ad" {
        if channel < 7 {
            return 56160 + 2160 * channel;
        }
    }
    // 6GHz: opclass between 131 and 137
    else if (131..=137).contains(&opclass) {
        if channel == 2 {
            return 5935;
        }
        if channel < 233 {
            return (channel * 5) + 5950;
        }
    } else if (182..=196).contains(&channel) {
        return (channel * 5) + 4000;
    } else {
        return (channel * 5) + 5000;
    }
    0
}

/// nl80211_freq2band
pub fn nl80211_freq2band(freq: i32) -> u8 {
    if (2412..=2484).contains(&freq) {
        IWINFO_BAND_24 as u8
    } else if (5160..=5885).contains(&freq) {
        IWINFO_BAND_5 as u8
    } else if (5925..=7125).contains(&freq) {
        IWINFO_BAND_6 as u8
    } else if (58320..=69120).contains(&freq) {
        IWINFO_BAND_60 as u8
    } else {
        0
    }
}

/// nl80211_phyname_cb into a `char phy[32]`
fn nl80211_phyname_cb(msg: &Nlmsg, buf: &mut [u8; 32]) {
    match at(&nl80211_parse(msg), NL80211_ATTR_WIPHY_NAME) {
        Some(a) => {
            let n = a.nla_len().min(buf.len());
            buf[..n].copy_from_slice(&a.data[..n]);
        }
        None => buf[0] = 0,
    }
}

fn phy_string(buf: &[u8; 32]) -> Option<String> {
    if buf[0] != 0 {
        Some(String::from_utf8_lossy(cstr(buf)).into_owned())
    } else {
        None
    }
}

/// nl80211_ifname2phy
fn nl80211_ifname2phy(ifname: &str) -> Option<String> {
    let mut phy = [0u8; 32];
    nl80211_request(ifname, NL80211_CMD_GET_WIPHY, 0, &mut |m: &Nlmsg| nl80211_phyname_cb(m, &mut phy));
    phy_string(&phy)
}

/// nl80211_phyidx2name
fn nl80211_phyidx2name(idx: u32) -> Option<String> {
    if netlink::nl80211_init() < 0 {
        return None;
    }
    let nls = netlink::nls()?;
    let mut cv = Msg::new(nls.nl80211, NL80211_CMD_GET_WIPHY, 0);
    cv.put_u32(NL80211_ATTR_WIPHY, idx);
    let mut phy = [0u8; 32];
    nl80211_send(cv, &mut |m: &Nlmsg| nl80211_phyname_cb(m, &mut phy));
    phy_string(&phy)
}

/// nl80211_phy2ifname: the lowest-ifindex netdev on the phy named by
/// phyN / radioN (non-supplicant link_mode preferred); None for anything
/// that is not a phy or radio section.
fn nl80211_phy2ifname(ifname: &str) -> Option<String> {
    let mut phyidx = nl80211_phy_idx_from_phy(ifname);
    if phyidx < 0 {
        phyidx = nl80211_phy_idx_from_uci(ifname);
    }
    if phyidx < 0 {
        return None;
    }
    let mut ifidx = -1;
    let mut lmode = 1;
    let mut nif = String::new();
    if let Some(entries) = readdir("/sys/class/net") {
        for e in entries {
            if nl80211_readint(&format!("/sys/class/net/{e}/phy80211/index")) != phyidx {
                continue;
            }
            let cifidx = nl80211_readint(&format!("/sys/class/net/{e}/ifindex"));
            if cifidx < 0 {
                continue;
            }
            let clmode = nl80211_readint(&format!("/sys/class/net/{e}/link_mode"));
            /* prefer non-supplicant-based devices */
            if ifidx < 0 || cifidx < ifidx || (lmode == 1 && clmode != 1) {
                ifidx = cifidx;
                lmode = clmode;
                nif = e.chars().take(IFNAMSIZ - 1).collect();
            }
        }
    }
    if nif.is_empty() {
        None
    } else {
        Some(nif)
    }
}

/// nl80211_get_mode_cb: NL80211_IFTYPE_* -> IWINFO_OPMODE_*
fn nl80211_get_mode_cb(msg: &Nlmsg, mode: &mut i32) {
    const IFMODES: [i32; NL80211_IFTYPE_MAX + 1] = [
        IWINFO_OPMODE_UNKNOWN,    /* unspecified */
        IWINFO_OPMODE_ADHOC,      /* IBSS */
        IWINFO_OPMODE_CLIENT,     /* managed */
        IWINFO_OPMODE_MASTER,     /* AP */
        IWINFO_OPMODE_AP_VLAN,    /* AP/VLAN */
        IWINFO_OPMODE_WDS,        /* WDS */
        IWINFO_OPMODE_MONITOR,    /* monitor */
        IWINFO_OPMODE_MESHPOINT,  /* mesh point */
        IWINFO_OPMODE_P2P_CLIENT, /* P2P-client */
        IWINFO_OPMODE_P2P_GO,     /* P2P-GO */
        IWINFO_OPMODE_UNKNOWN,
        IWINFO_OPMODE_UNKNOWN,
        IWINFO_OPMODE_UNKNOWN,
    ];
    if let Some(a) = at(&nl80211_parse(msg), NL80211_ATTR_IFTYPE) {
        // DEVIATION: an iftype above NL80211_IFTYPE_MAX indexes past the C
        // array; here it maps to IWINFO_OPMODE_UNKNOWN.
        *mode = IFMODES.get(a.get_u32() as usize).copied().unwrap_or(IWINFO_OPMODE_UNKNOWN);
    }
}

/// nl80211_get_mode
pub fn mode(ifname: &str) -> Result<i32, ()> {
    let mut buf = IWINFO_OPMODE_UNKNOWN;
    let res = nl80211_phy2ifname(ifname);
    nl80211_request(res.as_deref().unwrap_or(ifname), NL80211_CMD_GET_INTERFACE, 0, &mut |m: &Nlmsg| {
        nl80211_get_mode_cb(m, &mut buf)
    });
    if buf == IWINFO_OPMODE_UNKNOWN {
        Err(())
    } else {
        Ok(buf)
    }
}

/// strncpy(dest, val, len - 1) into a zeroed `char dest[len]`
fn strncpy_val(val: &[u8], len: usize) -> Vec<u8> {
    val[..val.len().min(len.saturating_sub(1))].to_vec()
}

/// The fgets()/strtok() line walk of __nl80211_hostapd_query over the
/// hostapd config text: (found, values) with `keys` = (name, dest size).
pub fn hostapd_conf_query(conf: &[u8], ifname: &str, keys: &[(&str, usize)]) -> (i32, Vec<Vec<u8>>) {
    let mut out = vec![Vec::new(); keys.len()];
    let mut found = 0;
    let mut matched = true;
    /* iterate applicable lines and copy found values into dest buffers */
    for line in fgets_chunks(conf, 128) {
        let line = cstr(line);
        let (key, rest) = strtok(line, b" =\t\n");
        let (val, _) = strtok(rest, b"\n");
        let (Some(key), Some(val)) = (key, val) else {
            continue;
        };
        if key.is_empty() || key[0] == b'#' {
            continue;
        }
        if key == b"interface" || key == b"bss" {
            matched = ifname.as_bytes() == val;
        }
        if !matched {
            continue;
        }
        for (i, (search, len)) in keys.iter().enumerate() {
            if search.as_bytes() == key {
                out[i] = strncpy_val(val, *len);
                found += 1;
                break;
            }
        }
    }
    (found, out)
}

/// __nl80211_hostapd_query: read /var/run/hostapd-<phy>.conf of an AP
/// interface; `keys` = (option, dest buffer size). Returns the number of
/// matches and the (strncpy-truncated) values, empty where not found.
fn nl80211_hostapd_query(ifname: &str, keys: &[(&str, usize)]) -> (i32, Vec<Vec<u8>>) {
    let out = vec![Vec::new(); keys.len()];
    let Ok(m) = mode(ifname) else {
        return (0, out);
    };
    if m != IWINFO_OPMODE_MASTER && m != IWINFO_OPMODE_AP_VLAN {
        return (0, out);
    }
    let Some(phy) = nl80211_ifname2phy(ifname) else {
        return (0, out);
    };
    let Ok(conf) = std::fs::read(format!("/var/run/hostapd-{phy}.conf")) else {
        return (0, out);
    };
    hostapd_conf_query(&conf, ifname, keys)
}

/// nl80211_wpactl_recv: select() with a 256 ms timeout, then recv() into a
/// zeroed `buf[blen]` (at most blen - 1 bytes). Returns (result, buffer).
fn nl80211_wpactl_recv(sock: &OwnedFd, blen: usize) -> (isize, Vec<u8>) {
    let mut buf = vec![0u8; blen];
    if !owrt_platform::rpcd::select_readable(sock, 256000).unwrap_or(false) { return (-1, buf); }
    let n = rustix::net::recv(sock, &mut buf[..blen - 1], rustix::net::RecvFlags::empty())
        .map_or(-1, |(_, n)| n as isize);
    (n, buf)
}

/// Preserve the C's connect-before-bind order, address lengths and ownership.
fn nl80211_wpactl_connect(ifname: &str) -> Result<(OwnedFd, Vec<u8>), i32> {
    let sock = rustix::net::socket(rustix::net::AddressFamily::UNIX, rustix::net::SocketType::DGRAM, None).map_err(|_| -1)?;
    let remote = format!("/var/run/wpa_supplicant/{ifname}");
    let _ = rustix::fs::fchmod(&sock, rustix::fs::Mode::from_raw_mode(0o660));
    let flags = rustix::io::fcntl_getfd(&sock).map_err(|_| -1)?;
    rustix::io::fcntl_setfd(&sock, flags | rustix::io::FdFlags::CLOEXEC).map_err(|_| -1)?;
    owrt_platform::rpcd::connect_unix_path(&sock, remote.as_bytes()).map_err(|_| -1)?;
    let path = format!("/var/run/iwinfo-{ifname}-{}", std::process::id());
    owrt_platform::rpcd::bind_unix_path(&sock, path.as_bytes()).map_err(|_| -1)?;
    let gid = rustix::process::Gid::from_raw(101);
    let _ = rustix::fs::chownat(rustix::fs::CWD, path.as_str(), None, Some(gid), rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
    let _ = rustix::fs::chownat(rustix::fs::CWD, path.as_str(), Some(rustix::process::Uid::from_raw(101)), Some(gid), rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
    Ok((sock, path.into_bytes()))
}

fn wpactl_close(sock: OwnedFd, local: &[u8]) {
    drop(sock);
    let _ = std::fs::remove_file(String::from_utf8_lossy(local).as_ref());
}

fn wpactl_send(sock: &OwnedFd, cmd: &[u8]) -> isize {
    rustix::net::send(sock, cmd, rustix::net::SendFlags::empty()).map_or(-1, |n| n as isize)
}

/// The STATUS reply parsing of __nl80211_wpactl_query: `key=value` lines,
/// (found, values) with `keys` = (name, dest size).
pub fn wpactl_status_parse(reply: &[u8], keys: &[(&str, usize)]) -> (i32, Vec<Vec<u8>>) {
    let mut out = vec![Vec::new(); keys.len()];
    let mut found = 0;
    for line in strtok_all(cstr(reply), b"\n") {
        let (key, rest) = strtok(line, b"=");
        let (val, _) = strtok(rest, b"\n");
        let (Some(key), Some(val)) = (key, val) else {
            continue;
        };
        for (i, (search, len)) in keys.iter().enumerate() {
            if search.as_bytes() == key {
                out[i] = strncpy_val(val, *len);
                found += 1;
                break;
            }
        }
    }
    (found, out)
}

/// __nl80211_wpactl_query: "STATUS" over the wpa_supplicant control socket
/// of a client / ad-hoc / mesh interface.
fn nl80211_wpactl_query(ifname: &str, keys: &[(&str, usize)]) -> (i32, Vec<Vec<u8>>) {
    let out = vec![Vec::new(); keys.len()];
    let Ok(m) = mode(ifname) else {
        return (0, out);
    };
    if m != IWINFO_OPMODE_CLIENT && m != IWINFO_OPMODE_ADHOC && m != IWINFO_OPMODE_MESHPOINT {
        return (0, out);
    }
    let Ok((sock, local)) = nl80211_wpactl_connect(ifname) else {
        return (0, out);
    };
    let mut result = (0, out);
    wpactl_send(&sock, b"STATUS");
    loop {
        let (n, buf) = nl80211_wpactl_recv(&sock, 512);
        if n <= 0 {
            break;
        }
        if buf[0] == b'<' {
            continue;
        }
        result = wpactl_status_parse(&buf, keys);
        break;
    }
    wpactl_close(sock, &local);
    result
}

/// nl80211_ifadd: create "tmp.<ifname>" as a station interface on the
/// same phy and enable IPv6 on it (fopen "w" + fwrite "0\n").
fn nl80211_ifadd(ifname: &str) -> Option<String> {
    let mut req = nl80211_msg(ifname, NL80211_CMD_NEW_INTERFACE, 0)?;
    let nif: String = format!("tmp.{ifname}").chars().take(IFNAMSIZ - 1).collect();
    req.put_string(NL80211_ATTR_IFNAME, &nif);
    req.put_u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);
    nl80211_send(req, &mut |_: &Nlmsg| {});
    if let Ok(mut sysfs) = File::create(format!("/proc/sys/net/ipv6/conf/{nif}/disable_ipv6")) {
        let _ = sysfs.write_all(b"0\n");
    }
    Some(nif)
}

/// nl80211_ifdel
fn nl80211_ifdel(ifname: &str) {
    if let Some(mut req) = nl80211_msg(ifname, NL80211_CMD_DEL_INTERFACE, 0) {
        req.put_string(NL80211_ATTR_IFNAME, ifname);
        nl80211_send(req, &mut |_: &Nlmsg| {});
    }
}

/// nl80211_hostapd_hup: SIGHUP the hostapd whose pid is in
/// /var/run/wifi-<phy>.pid
fn nl80211_hostapd_hup(ifname: &str) {
    let Some(phy) = nl80211_ifname2phy(ifname) else {
        return;
    };
    let mut pid = 0;
    if let Ok(mut fd) = File::open(format!("/var/run/wifi-{phy}.pid")) {
        let mut buf = [0u8; 32];
        if let Ok(n) = fd.read(&mut buf) {
            if n > 0 {
                pid = atoi(&buf[..n]);
            }
        }
    }
    if pid > 0 {
        let _ = rustix::process::kill_process(rustix::process::Pid::from_raw(pid).unwrap(), rustix::process::Signal::HUP);
    }
}

/// nl80211_probe
pub fn probe(ifname: &str) -> bool {
    nl80211_ifname2phy(ifname).is_some()
}

/// nl80211_get_macaddr_cb: bssid[0] = 1 marks a copied NL80211_ATTR_MAC.
fn nl80211_get_macaddr_cb(msg: &Nlmsg, bssid: &mut [u8; 7]) {
    if let Some(a) = at(&nl80211_parse(msg), NL80211_ATTR_MAC) {
        bssid[0] = 1;
        let n = a.nla_len().min(6);
        bssid[1..1 + n].copy_from_slice(&a.data[..n]);
    }
}

/// struct nla_policy bss_policy of nl80211_get_ssid_bssid_cb
const SSID_BSS_POLICY: &Policy = &[(NL80211_BSS_STATUS, 4)];

/// nl80211_get_ssid_bssid_cb: from the associated/joined BSS of a scan dump,
/// copy the SSID IE (ssid mode) or the BSSID (bssid mode).
fn nl80211_get_ssid_bssid_cb(msg: &Nlmsg, ssid: Option<&mut [u8; IWINFO_ESSID_MAX_SIZE + 1]>, bssid: &mut [u8; 7]) {
    let tb = nl80211_parse(msg);
    let Some(bss_attr) = at(&tb, NL80211_ATTR_BSS) else {
        return;
    };
    let (bss, rc) = nla_parse_nested(bss_attr, NL80211_BSS_MAX, SSID_BSS_POLICY);
    if rc != 0 {
        return;
    }
    let (Some(bssid_attr), Some(status), Some(ies)) =
        (at(&bss, NL80211_BSS_BSSID), at(&bss, NL80211_BSS_STATUS), at(&bss, NL80211_BSS_INFORMATION_ELEMENTS))
    else {
        return;
    };
    match status.get_u32() {
        NL80211_BSS_STATUS_ASSOCIATED | NL80211_BSS_STATUS_AUTHENTICATED | NL80211_BSS_STATUS_IBSS_JOINED => {
            if let Some(ssid) = ssid {
                let mut ie = ies.data;
                while ie.len() >= 2 && ie.len() >= ie[1] as usize {
                    if ie[0] == 0 {
                        let len = (ie[1] as usize).min(IWINFO_ESSID_MAX_SIZE);
                        let src = ie.get(2..2 + len).unwrap_or(ie.get(2..).unwrap_or(&[]));
                        ssid[..src.len()].copy_from_slice(src);
                        return;
                    }
                    let step = (ie[1] as usize + 2).min(ie.len());
                    ie = &ie[step..];
                }
            } else {
                bssid[0] = 1;
                let n = bssid_attr.nla_len().min(6);
                bssid[1..1 + n].copy_from_slice(&bssid_attr.data[..n]);
            }
        }
        _ => {}
    }
}

/// parse_ssid2: hostapd's wpa_config_parse_string rules (double quoted,
/// hexdump, printf-escaped) into `buf`; -1 on a malformed value or an empty
/// destination (partial writes stay, as in C).
pub fn parse_ssid2(value: &[u8], buf: &mut [u8]) -> i32 {
    if buf.is_empty() {
        return -1;
    }
    let buflen = buf.len();
    let value = cstr(value);
    if value.first() == Some(&b'"') {
        let value = &value[1..];
        let Some(pos) = value.iter().rposition(|&c| c == b'"') else {
            return -1;
        };
        if pos + 1 != value.len() {
            return -1;
        }
        let mut len = pos;
        if len >= buflen {
            len = buflen - 1;
        }
        buf[..len].copy_from_slice(&value[..len]);
        buf[len] = 0;
        0
    } else if value.first() == Some(&b'P') && value.get(1) == Some(&b'"') {
        let value = &value[2..];
        let Some(pos) = value.iter().rposition(|&c| c == b'"') else {
            return -1;
        };
        if pos + 1 != value.len() {
            return -1;
        }
        let mut len = 0;
        let mut i = 0;
        while i < pos && len < buflen - 1 {
            if value[i] == b'\\' && i + 1 < pos {
                i += 1;
                let c = value[i];
                if c == b'x' && i + 2 < pos {
                    buf[len] = strtol16(&value[i + 1..i + 3]).0 as u8;
                    len += 1;
                    i += 3;
                } else if (b'0'..=b'7').contains(&c)
                    && i + 2 < pos
                    && (b'0'..=b'7').contains(&value[i + 1])
                    && (b'0'..=b'7').contains(&value[i + 2])
                {
                    buf[len] = (((c - b'0') as u32) << 6 | ((value[i + 1] - b'0') as u32) << 3 | (value[i + 2] - b'0') as u32)
                        as u8;
                    len += 1;
                    i += 3;
                } else {
                    buf[len] = match c {
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'\\' => b'\\',
                        b'"' => b'"',
                        other => other,
                    };
                    len += 1;
                    i += 1;
                }
            } else {
                buf[len] = value[i];
                len += 1;
                i += 1;
            }
        }
        buf[len] = 0;
        0
    } else {
        let mut len = value.len();
        if len & 1 != 0 {
            return -1;
        }
        len /= 2;
        if len >= buflen {
            len = buflen - 1;
        }
        for i in 0..len {
            let hex = &value[i * 2..i * 2 + 2];
            let (val, end) = strtol16(hex);
            if end != 2 {
                return -1;
            }
            buf[i] = val as u8;
        }
        buf[len] = 0;
        0
    }
}

/// nl80211_get_ssid: scan dump, then hostapd `ssid` / `ssid2`, then the
/// `mesh_id` from network.wireless. Returns the raw SSID bytes.
pub fn ssid(ifname: &str) -> Result<Vec<u8>, ()> {
    let mut sb_ssid = [0u8; IWINFO_ESSID_MAX_SIZE + 1];
    let mut sb_bssid = [0u8; 7];

    /* try to find ssid from scan dump results */
    let res = nl80211_phy2ifname(ifname);
    let target = res.as_deref().unwrap_or(ifname);
    nl80211_request(target, NL80211_CMD_GET_SCAN, NLM_F_DUMP, &mut |m: &Nlmsg| {
        nl80211_get_ssid_bssid_cb(m, Some(&mut sb_ssid), &mut sb_bssid)
    });

    /* failed, try to find from hostapd info */
    if sb_ssid[0] == 0 {
        let (_, v) = nl80211_hostapd_query(ifname, &[("ssid", IWINFO_ESSID_MAX_SIZE + 1)]);
        set_cstr(&mut sb_ssid, &v[0]);
    }

    if sb_ssid[0] == 0 {
        /* ssid2 can be quoted, printf-encoded, or hex; needs parsing. */
        let (found, v) = nl80211_hostapd_query(ifname, &[("ssid2", IWINFO_ESSID_MAX_SIZE * 4 + 3)]);
        if found != 0 {
            parse_ssid2(&v[0], &mut sb_ssid);
        }
    }

    /* failed, try to obtain Mesh ID */
    if sb_ssid[0] == 0 {
        if let Some(mesh_id) = utils::iwinfo_ubus_query(target, "mesh_id") {
            // strncpy(buf, str, IWINFO_ESSID_MAX_SIZE + 1)
            let b = mesh_id.as_bytes();
            let n = b.len().min(sb_ssid.len());
            sb_ssid[..n].copy_from_slice(&b[..n]);
        }
    }

    if sb_ssid[0] == 0 {
        Err(())
    } else {
        Ok(cstr(&sb_ssid).to_vec())
    }
}

fn format_mac(m: &[u8]) -> String {
    format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", m[0], m[1], m[2], m[3], m[4], m[5])
}

/// strtol(&s[off], NULL, 16) for the "xx:xx:xx:xx:xx:xx" walks; 0 past the
/// end of the (zero padded) buffer.
fn mac_octet(s: &[u8], off: usize) -> u8 {
    match s.get(off..) {
        Some(rest) => strtol16(rest).0 as u8,
        None => 0,
    }
}

/// nl80211_get_bssid: interface MAC, else the joined BSS of the scan dump,
/// else hostapd's `bssid`; "XX:XX:XX:XX:XX:XX".
pub fn bssid(ifname: &str) -> Result<String, ()> {
    let mut sb_bssid = [0u8; 7];
    let res = nl80211_phy2ifname(ifname);
    let target = res.as_deref().unwrap_or(ifname);

    /* try to obtain mac address via NL80211_CMD_GET_INTERFACE */
    nl80211_request(target, NL80211_CMD_GET_INTERFACE, 0, &mut |m: &Nlmsg| nl80211_get_macaddr_cb(m, &mut sb_bssid));

    /* failed, try to find bssid from scan dump results */
    if sb_bssid[0] == 0 {
        nl80211_request(target, NL80211_CMD_GET_SCAN, NLM_F_DUMP, &mut |m: &Nlmsg| {
            nl80211_get_ssid_bssid_cb(m, None, &mut sb_bssid)
        });
    }

    /* failed, try to find mac from hostapd info */
    if sb_bssid[0] == 0 {
        let (found, v) = nl80211_hostapd_query(ifname, &[("bssid", "FF:FF:FF:FF:FF:FF\0".len() + 1)]);
        if found != 0 {
            let mut b = [0u8; 19];
            set_cstr(&mut b, &v[0]);
            sb_bssid[0] = 1;
            for (i, off) in [0usize, 3, 6, 9, 12, 15].iter().enumerate() {
                sb_bssid[1 + i] = mac_octet(&b, *off);
            }
        }
    }

    if sb_bssid[0] != 0 {
        Ok(format_mac(&sb_bssid[1..7]))
    } else {
        Err(())
    }
}

/// struct nla_policy bss_policy of nl80211_get_frequency_scan_cb
const FREQ_BSS_POLICY: &Policy = &[(NL80211_BSS_FREQUENCY, 4), (NL80211_BSS_STATUS, 4)];

/// nl80211_get_frequency_scan_cb
fn nl80211_get_frequency_scan_cb(msg: &Nlmsg, freq: &mut i32) {
    let attr = nl80211_parse(msg);
    if let Some(bss) = at(&attr, NL80211_ATTR_BSS) {
        let (binfo, rc) = nla_parse_nested(bss, NL80211_BSS_MAX, FREQ_BSS_POLICY);
        if rc == 0 {
            if let (Some(_), Some(f)) = (at(&binfo, NL80211_BSS_STATUS), at(&binfo, NL80211_BSS_FREQUENCY)) {
                *freq = f.get_u32() as i32;
            }
        }
    }
}

/// nl80211_get_frequency_info_cb / center_freq1_cb / center_freq2_cb
fn nl80211_get_u32_attr_cb(msg: &Nlmsg, ty: u16, out: &mut i32) {
    if let Some(a) = at(&nl80211_parse(msg), ty) {
        *out = a.get_u32() as i32;
    }
}

/// nl80211_get_frequency: interface info, else hostapd hw_mode/channel/
/// op_class, else the scan dump.
pub fn frequency(ifname: &str) -> Result<i32, ()> {
    let mut buf = 0;
    /* try to find frequency from interface info */
    let res = nl80211_phy2ifname(ifname);
    nl80211_request(res.as_deref().unwrap_or(ifname), NL80211_CMD_GET_INTERFACE, 0, &mut |m: &Nlmsg| {
        nl80211_get_u32_attr_cb(m, NL80211_ATTR_WIPHY_FREQ, &mut buf)
    });

    /* failed, try to find frequency from hostapd info */
    if buf == 0 {
        let (found, v) = nl80211_hostapd_query(ifname, &[("hw_mode", 3), ("channel", 4), ("op_class", 4)]);
        if found >= 2 {
            buf = nl80211_channel2freq(atoi(&v[1]), &v[0], atoi(&v[2]));
        }
    }

    /* failed, try to find frequency from scan results */
    if buf == 0 {
        let res = nl80211_phy2ifname(ifname);
        nl80211_request(res.as_deref().unwrap_or(ifname), NL80211_CMD_GET_SCAN, NLM_F_DUMP, &mut |m: &Nlmsg| {
            nl80211_get_frequency_scan_cb(m, &mut buf)
        });
    }

    if buf == 0 {
        Err(())
    } else {
        Ok(buf)
    }
}

/// nl80211_get_center_freq1
fn nl80211_get_center_freq1(ifname: &str) -> Result<i32, ()> {
    let mut buf = 0;
    let res = nl80211_phy2ifname(ifname);
    nl80211_request(res.as_deref().unwrap_or(ifname), NL80211_CMD_GET_INTERFACE, 0, &mut |m: &Nlmsg| {
        nl80211_get_u32_attr_cb(m, NL80211_ATTR_CENTER_FREQ1, &mut buf)
    });
    if buf == 0 {
        Err(())
    } else {
        Ok(buf)
    }
}

/// nl80211_get_center_freq2
fn nl80211_get_center_freq2(ifname: &str) -> Result<i32, ()> {
    let mut buf = 0;
    let res = nl80211_phy2ifname(ifname);
    nl80211_request(res.as_deref().unwrap_or(ifname), NL80211_CMD_GET_INTERFACE, 0, &mut |m: &Nlmsg| {
        nl80211_get_u32_attr_cb(m, NL80211_ATTR_CENTER_FREQ2, &mut buf)
    });
    if buf == 0 {
        Err(())
    } else {
        Ok(buf)
    }
}

/// nl80211_get_channel
pub fn channel(ifname: &str) -> Result<i32, ()> {
    frequency(ifname).map(nl80211_freq2channel)
}

/// nl80211_get_center_chan1
pub fn center_chan1(ifname: &str) -> Result<i32, ()> {
    nl80211_get_center_freq1(ifname).map(nl80211_freq2channel)
}

/// nl80211_get_center_chan2
pub fn center_chan2(ifname: &str) -> Result<i32, ()> {
    nl80211_get_center_freq2(ifname).map(nl80211_freq2channel)
}

/// nl80211_get_txpower: NL80211_ATTR_WIPHY_TX_POWER_LEVEL (mBm) / 100; the
/// value stays 0 when the attribute is absent, Err only on request failure.
pub fn txpower(ifname: &str) -> Result<i32, ()> {
    let mut buf = 0;
    let res = nl80211_phy2ifname(ifname);
    let rc = nl80211_request(res.as_deref().unwrap_or(ifname), NL80211_CMD_GET_INTERFACE, 0, &mut |m: &Nlmsg| {
        if let Some(a) = at(&nl80211_parse(m), NL80211_ATTR_WIPHY_TX_POWER_LEVEL) {
            buf = utils::iwinfo_mbm2dbm(a.get_u32() as i32);
        }
    });
    if rc != 0 {
        return Err(());
    }
    Ok(buf)
}

/// struct nl80211_rssi_rate
#[derive(Default)]
struct RssiRate {
    rate: i16,
    rate_samples: i32,
    rssi: i8,
    rssi_samples: i32,
}

const FILL_SIGNAL_STATS_POLICY: &Policy = &[
    (NL80211_STA_INFO_INACTIVE_TIME, 4),
    (NL80211_STA_INFO_RX_BYTES, 4),
    (NL80211_STA_INFO_TX_BYTES, 4),
    (NL80211_STA_INFO_RX_BYTES64, 8),
    (NL80211_STA_INFO_TX_BYTES64, 8),
    (NL80211_STA_INFO_RX_PACKETS, 4),
    (NL80211_STA_INFO_TX_PACKETS, 4),
    (NL80211_STA_INFO_SIGNAL, 1),
    (NL80211_STA_INFO_LLID, 2),
    (NL80211_STA_INFO_PLID, 2),
    (NL80211_STA_INFO_PLINK_STATE, 1),
];

const RATE_POLICY: &Policy = &[(NL80211_RATE_INFO_BITRATE, 2), (NL80211_RATE_INFO_MCS, 1)];

/// nl80211_fill_signal_cb: running averages of signal (int8) and tx bitrate
/// (int16) over all stations.
fn nl80211_fill_signal_cb(msg: &Nlmsg, rr: &mut RssiRate) {
    let attr = nl80211_parse(msg);
    let Some(sta) = at(&attr, NL80211_ATTR_STA_INFO) else {
        return;
    };
    let (sinfo, rc) = nla_parse_nested(sta, NL80211_STA_INFO_MAX, FILL_SIGNAL_STATS_POLICY);
    if rc != 0 {
        return;
    }
    if let Some(a) = at(&sinfo, NL80211_STA_INFO_SIGNAL) {
        let dbm = a.get_u8() as i8;
        rr.rssi = ((rr.rssi as i32 * rr.rssi_samples + dbm as i32) / (rr.rssi_samples + 1)) as i8;
        rr.rssi_samples += 1;
    }
    if let Some(txb) = at(&sinfo, NL80211_STA_INFO_TX_BITRATE) {
        let (rinfo, rc) = nla_parse_nested(txb, NL80211_RATE_INFO_MAX, RATE_POLICY);
        if rc == 0 {
            if let Some(a) = at(&rinfo, NL80211_RATE_INFO_BITRATE) {
                let mbit = a.get_u16() as i16;
                rr.rate = ((rr.rate as i32 * rr.rate_samples + mbit as i32) / (rr.rate_samples + 1)) as i16;
                rr.rate_samples += 1;
            }
        }
    }
}

/// The `<ifname>` / `<ifname>.sta*` netdev selection shared by
/// nl80211_fill_signal and nl80211_get_assoclist.
fn sta_netdev_matches(name: &str, ifname: &str) -> bool {
    let (n, i) = (name.as_bytes(), ifname.as_bytes());
    n.starts_with(i) && (n.len() == i.len() || n[i.len()..].starts_with(b".sta"))
}

/// nl80211_fill_signal
fn nl80211_fill_signal(ifname: &str) -> RssiRate {
    let mut r = RssiRate::default();
    if let Some(entries) = readdir("/sys/class/net") {
        for de in entries {
            if sta_netdev_matches(&de, ifname) {
                nl80211_request(&de, NL80211_CMD_GET_STATION, NLM_F_DUMP, &mut |m: &Nlmsg| nl80211_fill_signal_cb(m, &mut r));
            }
        }
    }
    r
}

/// nl80211_get_bitrate: averaged tx bitrate in kbit/s
pub fn bitrate(ifname: &str) -> Result<i32, ()> {
    let rr = nl80211_fill_signal(ifname);
    if rr.rate_samples != 0 {
        Ok(rr.rate as i32 * 100)
    } else {
        Err(())
    }
}

/// nl80211_get_signal: averaged station signal in dBm
pub fn signal(ifname: &str) -> Result<i32, ()> {
    let rr = nl80211_fill_signal(ifname);
    if rr.rssi_samples != 0 {
        Ok(rr.rssi as i32)
    } else {
        Err(())
    }
}

const NOISE_SURVEY_POLICY: &Policy = &[(NL80211_SURVEY_INFO_FREQUENCY, 4), (NL80211_SURVEY_INFO_NOISE, 1)];

/// nl80211_get_noise_cb: the noise of the survey entry on our frequency
/// (an in-use entry overrides an earlier one).
fn nl80211_get_noise_cb(msg: &Nlmsg, frequency: u32, noise: &mut u8) {
    let tb = nl80211_parse(msg);
    let Some(survey) = at(&tb, NL80211_ATTR_SURVEY_INFO) else {
        return;
    };
    let (si, rc) = nla_parse_nested(survey, NL80211_SURVEY_INFO_MAX, NOISE_SURVEY_POLICY);
    if rc != 0 {
        return;
    }
    let (Some(n), Some(f)) = (at(&si, NL80211_SURVEY_INFO_NOISE), at(&si, NL80211_SURVEY_INFO_FREQUENCY)) else {
        return;
    };
    if f.get_u32() != frequency {
        return;
    }
    if *noise == 0 || at(&si, NL80211_SURVEY_INFO_IN_USE).is_some() {
        *noise = n.get_u8();
    }
}

/// nl80211_get_noise
pub fn noise(ifname: &str) -> Result<i32, ()> {
    let Ok(freq) = frequency(ifname) else {
        return Err(());
    };
    let fn_frequency = freq as u32;
    let mut fn_noise = 0u8;
    if nl80211_request(ifname, NL80211_CMD_GET_SURVEY, NLM_F_DUMP, &mut |m: &Nlmsg| {
        nl80211_get_noise_cb(m, fn_frequency, &mut fn_noise)
    }) != 0
    {
        return Err(());
    }
    Ok(fn_noise as i8 as i32)
}

/// nl80211_get_quality: signal + 110 clamped to the -110..-40 dBm range
/// (positive values pass through as a quality).
pub fn quality(ifname: &str) -> Result<i32, ()> {
    let mut sig = signal(ifname)?;
    if sig >= 0 {
        Ok(sig)
    } else {
        sig = sig.clamp(-110, -40);
        Ok(sig + 110)
    }
}

/// nl80211_get_quality_max
pub fn quality_max(_ifname: &str) -> Result<i32, ()> {
    /* The cfg80211 wext compat layer assumes a maximum quality of 70 */
    Ok(70)
}

/// nl80211_check_wepkey
fn nl80211_check_wepkey(key: &[u8]) -> i32 {
    match cstr(key).len() {
        0 => 0,
        5 | 10 => IWINFO_CIPHER_WEP40,
        13 | 26 => IWINFO_CIPHER_WEP104,
        _ => 0,
    }
}

const WPA_KEY_MGMT_STRINGS: [(&[u8], i32, i32); 12] = [
    (b"IEEE 802.1X/EAP", 0, IWINFO_KMGMT_8021X),
    (b"EAP-SUITE-B-192", 4, IWINFO_KMGMT_8021X),
    (b"EAP-SUITE-B", 4, IWINFO_KMGMT_8021X),
    (b"EAP-SHA384", 4, IWINFO_KMGMT_8021X),
    (b"EAP-SHA256", 0, IWINFO_KMGMT_8021X),
    (b"PSK-SHA256", 0, IWINFO_KMGMT_PSK),
    (b"NONE", 0, IWINFO_KMGMT_NONE),
    (b"None", 0, IWINFO_KMGMT_NONE),
    (b"PSK", 0, IWINFO_KMGMT_PSK),
    (b"EAP", 0, IWINFO_KMGMT_8021X),
    (b"SAE", 4, IWINFO_KMGMT_SAE),
    (b"OWE", 4, IWINFO_KMGMT_OWE),
];

const WPA_SEP: &[u8] = b" \t\n,-+/";

/// strcspn / strspn over a byte set
fn span(s: &[u8], set: &[u8], in_set: bool) -> usize {
    s.iter().position(|c| set.contains(c) != in_set).unwrap_or(s.len())
}

/// parse_wpa_suites: token-wise key management parsing (separators
/// " \t\n,-+/"), OR-ing versions and suites.
pub fn parse_wpa_suites(s: &[u8], defversion: i32, versions: &mut u8, suites: &mut u8) {
    let s = cstr(s);
    let mut p = 0;
    while p < s.len() {
        let mut q = p;
        for (m, ver, suite) in WPA_KEY_MGMT_STRINGS.iter() {
            let l = m.len();
            if s[q..].starts_with(m) && s.get(q + l).is_none_or(|c| WPA_SEP.contains(c)) {
                let version = if *ver != 0 { *ver } else { defversion };
                *versions |= version as u8;
                *suites |= *suite as u8;
                q += l;
                break;
            }
        }
        if q == p {
            q += span(&s[q..], WPA_SEP, false);
        }
        p = q + span(&s[q..], WPA_SEP, true);
    }
}

const WPA_CIPHER_STRINGS: [(&[u8], i32); 8] = [
    (b"WEP-104", IWINFO_CIPHER_WEP104),
    (b"WEP-40", IWINFO_CIPHER_WEP40),
    (b"NONE", IWINFO_CIPHER_NONE),
    (b"TKIP", IWINFO_CIPHER_TKIP),
    (b"CCMP-256", IWINFO_CIPHER_CCMP256),
    (b"CCMP", IWINFO_CIPHER_CCMP),
    (b"GCMP-256", IWINFO_CIPHER_GCMP256),
    (b"GCMP", IWINFO_CIPHER_GCMP),
];

/// parse_wpa_ciphers
pub fn parse_wpa_ciphers(s: &[u8], ciphers: &mut u16) {
    let s = cstr(s);
    let mut p = 0;
    while p < s.len() {
        let mut q = p;
        for (m, cipher) in WPA_CIPHER_STRINGS.iter() {
            let l = m.len();
            if s[q..].starts_with(m) && s.get(q + l).is_none_or(|c| WPA_SEP.contains(c)) {
                *ciphers |= *cipher as u16;
                q += l;
                break;
            }
        }
        if q == p {
            q += span(&s[q..], WPA_SEP, false);
        }
        p = q + span(&s[q..], WPA_SEP, true);
    }
}

/// The wpa_supplicant STATUS branch of nl80211_get_encryption.
pub fn encryption_from_wpactl(pairwise: &[u8], groupwise: &[u8], key_mgmt: &[u8], mode: &[u8]) -> CryptoEntry {
    let mut c = CryptoEntry::default();
    let key_mgmt = cstr(key_mgmt);
    /* WEP or Open */
    if key_mgmt == b"NONE" {
        parse_wpa_ciphers(pairwise, &mut c.pair_ciphers);
        parse_wpa_ciphers(groupwise, &mut c.group_ciphers);
        if c.pair_ciphers != 0 && c.pair_ciphers != IWINFO_CIPHER_NONE as u16 {
            c.enabled = 1;
            c.auth_suites = IWINFO_KMGMT_NONE as u8;
            c.auth_algs = (IWINFO_AUTH_OPEN | IWINFO_AUTH_SHARED) as u8;
        } else {
            c.pair_ciphers = 0;
            c.group_ciphers = 0;
        }
    }
    /* MESH with SAE */
    else if cstr(mode) == b"mesh" && key_mgmt == b"UNKNOWN" {
        c.enabled = 1;
        c.wpa_version = 4;
        c.auth_suites = IWINFO_KMGMT_SAE as u8;
        c.pair_ciphers = IWINFO_CIPHER_CCMP as u16;
        c.group_ciphers = IWINFO_CIPHER_CCMP as u16;
    }
    /* WPA */
    else {
        parse_wpa_ciphers(pairwise, &mut c.pair_ciphers);
        parse_wpa_ciphers(groupwise, &mut c.group_ciphers);
        let mut p = key_mgmt;
        let mut wpa_version: u8 = 0;
        if p.starts_with(b"WPA2-") || p.starts_with(b"WPA2/") {
            p = &p[5..];
            wpa_version = 2;
        } else if p.starts_with(b"WPA-") {
            p = &p[4..];
            wpa_version = 1;
        }
        parse_wpa_suites(p, wpa_version as i32, &mut c.wpa_version, &mut c.auth_suites);
        c.enabled = (c.wpa_version != 0 && c.auth_suites != 0) as u8;
    }
    c
}

/// The hostapd config branch of nl80211_get_encryption; `v` holds wpa,
/// wpa_key_mgmt, wpa_pairwise, auth_algs, wep_key0..3.
pub fn encryption_from_hostapd(v: &[Vec<u8>]) -> CryptoEntry {
    let mut c = CryptoEntry::default();
    let (wpa, wpa_key_mgmt, wpa_pairwise, auth_algs) = (&v[0], &v[1], &v[2], &v[3]);
    c.wpa_version = 0;
    if !wpa_key_mgmt.is_empty() {
        for p in strtok_all(wpa_key_mgmt, b" \t") {
            let mut p = p;
            if p.starts_with(b"WPA-") {
                p = &p[4..];
            }
            if p.starts_with(b"FT-") {
                p = &p[3..];
            }
            parse_wpa_suites(p, atoi(wpa), &mut c.wpa_version, &mut c.auth_suites);
        }
        c.enabled = (c.wpa_version != 0) as u8;
    }
    if !wpa_pairwise.is_empty() {
        parse_wpa_ciphers(wpa_pairwise, &mut c.pair_ciphers);
    }
    if !auth_algs.is_empty() {
        match atoi(auth_algs) {
            1 => c.auth_algs |= IWINFO_AUTH_OPEN as u8,
            2 => c.auth_algs |= IWINFO_AUTH_SHARED as u8,
            3 => {
                c.auth_algs |= IWINFO_AUTH_OPEN as u8;
                c.auth_algs |= IWINFO_AUTH_SHARED as u8;
            }
            _ => {}
        }
        for key in &v[4..8] {
            c.pair_ciphers |= nl80211_check_wepkey(key) as u16;
        }
        c.enabled = (c.auth_algs != 0 && c.pair_ciphers != 0) as u8;
    }
    c.group_ciphers = c.pair_ciphers;
    c
}

/// nl80211_get_encryption: wpa_supplicant STATUS, else hostapd config, else
/// open for ad-hoc / mesh; Err for anything else.
pub fn encryption(ifname: &str) -> Result<CryptoEntry, ()> {
    /* WPA supplicant */
    let (found, v) =
        nl80211_wpactl_query(ifname, &[("pairwise_cipher", 16), ("group_cipher", 16), ("key_mgmt", 64), ("mode", 16)]);
    if found != 0 {
        return Ok(encryption_from_wpactl(&v[0], &v[1], &v[2], &v[3]));
    }
    /* Hostapd */
    let (found, v) = nl80211_hostapd_query(
        ifname,
        &[
            ("wpa", 2),
            ("wpa_key_mgmt", 64),
            ("wpa_pairwise", 16),
            ("auth_algs", 2),
            ("wep_key0", 27),
            ("wep_key1", 27),
            ("wep_key2", 27),
            ("wep_key3", 27),
        ],
    );
    if found != 0 {
        return Ok(encryption_from_hostapd(&v));
    }
    /* Ad-Hoc or Mesh interfaces without wpa_supplicant are open */
    if let Ok(opmode) = mode(ifname) {
        if opmode == IWINFO_OPMODE_ADHOC || opmode == IWINFO_OPMODE_MESHPOINT {
            return Ok(CryptoEntry::default());
        }
    }
    Err(())
}

/// nl80211_get_phyname: the phy of a netdev, or the given phy/radio name
/// itself when it resolves to a netdev with a phy.
pub fn phyname(ifname: &str) -> Result<String, ()> {
    if let Some(name) = nl80211_ifname2phy(ifname) {
        return Ok(name);
    }
    if let Some(name) = nl80211_phy2ifname(ifname) {
        if nl80211_ifname2phy(&name).is_some() {
            return Ok(ifname.to_owned());
        }
    }
    Err(())
}

/// nl80211_parse_rateinfo
fn nl80211_parse_rateinfo(ri: &Tb, re: &mut RateEntry) {
    if let Some(a) = at(ri, NL80211_RATE_INFO_BITRATE32) {
        re.rate = a.get_u32().wrapping_mul(100);
    } else if let Some(a) = at(ri, NL80211_RATE_INFO_BITRATE) {
        re.rate = (a.get_u16() as u32).wrapping_mul(100);
    }

    if let Some(a) = at(ri, NL80211_RATE_INFO_EHT_MCS) {
        re.is_eht = true;
        re.mcs = a.get_u8() as i8;
        if let Some(n) = at(ri, NL80211_RATE_INFO_EHT_NSS) {
            re.nss = n.get_u8();
        }
        if let Some(g) = at(ri, NL80211_RATE_INFO_EHT_GI) {
            re.eht_gi = g.get_u8();
        }
    } else if let Some(a) = at(ri, NL80211_RATE_INFO_HE_MCS) {
        re.is_he = true;
        re.mcs = a.get_u8() as i8;
        if let Some(n) = at(ri, NL80211_RATE_INFO_HE_NSS) {
            re.nss = n.get_u8();
        }
        if let Some(g) = at(ri, NL80211_RATE_INFO_HE_GI) {
            re.he_gi = g.get_u8();
        }
        if let Some(d) = at(ri, NL80211_RATE_INFO_HE_DCM) {
            re.he_dcm = d.get_u8();
        }
    } else if let Some(a) = at(ri, NL80211_RATE_INFO_VHT_MCS) {
        re.is_vht = true;
        re.mcs = a.get_u8() as i8;
        if let Some(n) = at(ri, NL80211_RATE_INFO_VHT_NSS) {
            re.nss = n.get_u8();
        }
    } else if let Some(a) = at(ri, NL80211_RATE_INFO_MCS) {
        re.is_ht = true;
        re.mcs = a.get_u8() as i8;
    }

    if at(ri, NL80211_RATE_INFO_5_MHZ_WIDTH).is_some() {
        re.mhz = 5;
    } else if at(ri, NL80211_RATE_INFO_10_MHZ_WIDTH).is_some() {
        re.mhz = 10;
    } else if at(ri, NL80211_RATE_INFO_40_MHZ_WIDTH).is_some() {
        re.mhz = 40;
    } else if at(ri, NL80211_RATE_INFO_80_MHZ_WIDTH).is_some() {
        re.mhz = 80;
    } else if at(ri, NL80211_RATE_INFO_80P80_MHZ_WIDTH).is_some() || at(ri, NL80211_RATE_INFO_160_MHZ_WIDTH).is_some() {
        re.mhz = 160;
    } else if at(ri, NL80211_RATE_INFO_320_MHZ_WIDTH).is_some() {
        re.mhz_hi = (320 / 256) as u8;
        re.mhz = (320 % 256) as u8;
    } else {
        re.mhz = 20;
    }

    if at(ri, NL80211_RATE_INFO_SHORT_GI).is_some() {
        re.is_short_gi = true;
    }

    re.is_40mhz = re.mhz == 40;
}

const SURVEY_POLICY: &Policy = &[
    (NL80211_SURVEY_INFO_FREQUENCY, 4),
    (NL80211_SURVEY_INFO_NOISE, 1),
    (NL80211_SURVEY_INFO_TIME, 8),
    (NL80211_SURVEY_INFO_TIME_BUSY, 8),
    (NL80211_SURVEY_INFO_TIME_EXT_BUSY, 8),
    (NL80211_SURVEY_INFO_TIME_RX, 8),
    (NL80211_SURVEY_INFO_TIME_TX, 8),
];

/// nl80211_get_survey_cb
fn nl80211_get_survey_cb(msg: &Nlmsg, arr: &mut Vec<SurveyEntry>) {
    let attr = nl80211_parse(msg);
    // DEVIATION: the C passes attr[NL80211_ATTR_SURVEY_INFO] to
    // nla_parse_nested() unchecked (a NULL would fault); a message without
    // it is skipped here.
    let Some(survey) = at(&attr, NL80211_ATTR_SURVEY_INFO) else {
        return;
    };
    let (sinfo, rc) = nla_parse_nested(survey, NL80211_SURVEY_INFO_MAX, SURVEY_POLICY);
    if rc != 0 {
        return;
    }
    let mut e = SurveyEntry::default();
    if let Some(a) = at(&sinfo, NL80211_SURVEY_INFO_FREQUENCY) {
        e.mhz = a.get_u32();
    }
    if let Some(a) = at(&sinfo, NL80211_SURVEY_INFO_NOISE) {
        e.noise = a.get_u8();
    }
    if let Some(a) = at(&sinfo, NL80211_SURVEY_INFO_TIME) {
        e.active_time = a.get_u64();
    }
    if let Some(a) = at(&sinfo, NL80211_SURVEY_INFO_TIME_BUSY) {
        e.busy_time = a.get_u64();
    }
    if let Some(a) = at(&sinfo, NL80211_SURVEY_INFO_TIME_EXT_BUSY) {
        e.busy_time_ext = a.get_u64();
    }
    if let Some(a) = at(&sinfo, NL80211_SURVEY_INFO_TIME_RX) {
        e.rxtime = a.get_u64();
    }
    if let Some(a) = at(&sinfo, NL80211_SURVEY_INFO_TIME_TX) {
        e.txtime = a.get_u64();
    }
    arr.push(e);
}

/// plink_state_to_str
fn plink_state_to_str(dst: &mut [u8; 16], state: u8) {
    let s: &[u8] = match state {
        NL80211_PLINK_LISTEN => b"LISTEN",
        NL80211_PLINK_OPN_SNT => b"OPN_SNT",
        NL80211_PLINK_OPN_RCVD => b"OPN_RCVD",
        NL80211_PLINK_CNF_RCVD => b"CNF_RCVD",
        NL80211_PLINK_ESTAB => b"ESTAB",
        NL80211_PLINK_HOLDING => b"HOLDING",
        NL80211_PLINK_BLOCKED => b"BLOCKED",
        _ => b"UNKNOWN",
    };
    set_cstr(dst, s);
}

/// power_mode_to_str
fn power_mode_to_str(dst: &mut [u8; 16], a: Attr) {
    let s: &[u8] = match a.get_u32() {
        NL80211_MESH_POWER_ACTIVE => b"ACTIVE",
        NL80211_MESH_POWER_LIGHT_SLEEP => b"LIGHT SLEEP",
        NL80211_MESH_POWER_DEEP_SLEEP => b"DEEP SLEEP",
        _ => b"UNKNOWN",
    };
    set_cstr(dst, s);
}

const ASSOC_STATS_POLICY: &Policy = &[
    (NL80211_STA_INFO_INACTIVE_TIME, 4),
    (NL80211_STA_INFO_RX_PACKETS, 4),
    (NL80211_STA_INFO_TX_PACKETS, 4),
    (NL80211_STA_INFO_SIGNAL, 1),
    (NL80211_STA_INFO_SIGNAL_AVG, 1),
    (NL80211_STA_INFO_RX_BYTES, 4),
    (NL80211_STA_INFO_TX_BYTES, 4),
    (NL80211_STA_INFO_RX_BYTES64, 8),
    (NL80211_STA_INFO_TX_BYTES64, 8),
    (NL80211_STA_INFO_TX_RETRIES, 4),
    (NL80211_STA_INFO_TX_FAILED, 4),
    (NL80211_STA_INFO_CONNECTED_TIME, 4),
    (NL80211_STA_INFO_RX_DROP_MISC, 8),
    (NL80211_STA_INFO_T_OFFSET, 8),
    (NL80211_STA_INFO_STA_FLAGS, 8), /* sizeof(struct nl80211_sta_flag_update) */
    (NL80211_STA_INFO_EXPECTED_THROUGHPUT, 4),
    /* mesh */
    (NL80211_STA_INFO_LLID, 2),
    (NL80211_STA_INFO_PLID, 2),
    (NL80211_STA_INFO_PLINK_STATE, 1),
    (NL80211_STA_INFO_LOCAL_PM, 4),
    (NL80211_STA_INFO_PEER_PM, 4),
    (NL80211_STA_INFO_NONPEER_PM, 4),
];

/// nl80211_get_assoclist_cb
fn nl80211_get_assoclist_cb(msg: &Nlmsg, arr: &mut Vec<AssoclistEntry>) {
    let attr = nl80211_parse(msg);
    let mut e = AssoclistEntry::default();

    if let Some(a) = at(&attr, NL80211_ATTR_MAC) {
        let n = a.nla_len().min(6);
        e.mac[..n].copy_from_slice(&a.data[..n]);
    }

    if let Some(sta) = at(&attr, NL80211_ATTR_STA_INFO) {
        let (sinfo, rc) = nla_parse_nested(sta, NL80211_STA_INFO_MAX, ASSOC_STATS_POLICY);
        if rc == 0 {
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_SIGNAL) {
                e.signal = a.get_u8() as i8;
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_SIGNAL_AVG) {
                e.signal_avg = a.get_u8() as i8;
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_INACTIVE_TIME) {
                e.inactive = a.get_u32();
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_CONNECTED_TIME) {
                e.connected_time = a.get_u32();
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_RX_PACKETS) {
                e.rx_packets = a.get_u32();
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_TX_PACKETS) {
                e.tx_packets = a.get_u32();
            }
            if let Some(r) = at(&sinfo, NL80211_STA_INFO_RX_BITRATE) {
                let (rinfo, rc) = nla_parse_nested(r, NL80211_RATE_INFO_MAX, RATE_POLICY);
                if rc == 0 {
                    nl80211_parse_rateinfo(&rinfo, &mut e.rx_rate);
                }
            }
            if let Some(r) = at(&sinfo, NL80211_STA_INFO_TX_BITRATE) {
                let (rinfo, rc) = nla_parse_nested(r, NL80211_RATE_INFO_MAX, RATE_POLICY);
                if rc == 0 {
                    nl80211_parse_rateinfo(&rinfo, &mut e.tx_rate);
                }
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_RX_BYTES64) {
                e.rx_bytes = a.get_u64();
            } else if let Some(a) = at(&sinfo, NL80211_STA_INFO_RX_BYTES) {
                e.rx_bytes = a.get_u32() as u64;
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_TX_BYTES64) {
                e.tx_bytes = a.get_u64();
            } else if let Some(a) = at(&sinfo, NL80211_STA_INFO_TX_BYTES) {
                e.tx_bytes = a.get_u32() as u64;
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_TX_RETRIES) {
                e.tx_retries = a.get_u32();
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_TX_FAILED) {
                e.tx_failed = a.get_u32();
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_T_OFFSET) {
                e.t_offset = a.get_u64();
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_RX_DROP_MISC) {
                e.rx_drop_misc = a.get_u64();
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_EXPECTED_THROUGHPUT) {
                e.thr = a.get_u32();
            }
            /* mesh */
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_LLID) {
                e.llid = a.get_u16();
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_PLID) {
                e.plid = a.get_u16();
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_PLINK_STATE) {
                plink_state_to_str(&mut e.plink_state, a.get_u8());
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_LOCAL_PM) {
                power_mode_to_str(&mut e.local_ps, a);
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_PEER_PM) {
                power_mode_to_str(&mut e.peer_ps, a);
            }
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_NONPEER_PM) {
                power_mode_to_str(&mut e.nonpeer_ps, a);
            }
            /* Station flags: struct nl80211_sta_flag_update { u32 mask; u32 set; } */
            if let Some(a) = at(&sinfo, NL80211_STA_INFO_STA_FLAGS) {
                let mask = a.get_u32();
                let set = match a.data.get(4..8) {
                    Some(b) => u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
                    None => 0,
                };
                let flag = |bit: u32| mask & (1 << bit) != 0 && set & (1 << bit) != 0;
                if flag(NL80211_STA_FLAG_AUTHORIZED) {
                    e.is_authorized = true;
                }
                if flag(NL80211_STA_FLAG_AUTHENTICATED) {
                    e.is_authenticated = true;
                }
                if flag(NL80211_STA_FLAG_SHORT_PREAMBLE) {
                    e.is_preamble_short = true;
                }
                if flag(NL80211_STA_FLAG_WME) {
                    e.is_wme = true;
                }
                if flag(NL80211_STA_FLAG_MFP) {
                    e.is_mfp = true;
                }
                if flag(NL80211_STA_FLAG_TDLS_PEER) {
                    e.is_tdls = true;
                }
            }
        }
    }

    e.noise = 0; /* filled in by caller */
    arr.push(e);
}

/// nl80211_get_survey: always Ok; empty when the dump request failed.
pub fn survey(ifname: &str) -> Result<Vec<SurveyEntry>, ()> {
    let mut arr = Vec::new();
    let rc = nl80211_request(ifname, NL80211_CMD_GET_SURVEY, NLM_F_DUMP, &mut |m: &Nlmsg| nl80211_get_survey_cb(m, &mut arr));
    if rc != 0 {
        arr.clear();
    }
    Ok(arr)
}

/// nl80211_get_assoclist: stations of `<ifname>` and `<ifname>.sta*`, noise
/// filled from the survey. Err only when /sys/class/net cannot be read.
pub fn assoclist(ifname: &str) -> Result<Vec<AssoclistEntry>, ()> {
    let Some(entries) = readdir("/sys/class/net") else {
        return Err(());
    };
    let mut arr = Vec::new();
    for de in entries {
        if sta_netdev_matches(&de, ifname) {
            nl80211_request(&de, NL80211_CMD_GET_STATION, NLM_F_DUMP, &mut |m: &Nlmsg| nl80211_get_assoclist_cb(m, &mut arr));
        }
    }
    if let Ok(n) = noise(ifname) {
        for e in arr.iter_mut() {
            e.noise = n as i8;
        }
    }
    Ok(arr)
}

const TXPWR_FREQ_POLICY: &Policy = &[(NL80211_FREQUENCY_ATTR_FREQ, 4), (NL80211_FREQUENCY_ATTR_MAX_TX_POWER, 4)];

/// nl80211_get_txpwrlist_cb: `dbm_max` holds the current channel on entry
/// (0 = any) and the max tx power (dBm) of the matching frequency on exit.
fn nl80211_get_txpwrlist_cb(msg: &Nlmsg, dbm_max: &mut i32) {
    let attr = nl80211_parse(msg);
    let ch_cur = *dbm_max;
    *dbm_max = -1;
    // DEVIATION: nla_for_each_nested() over a missing NL80211_ATTR_WIPHY_BANDS
    // / NL80211_BAND_ATTR_FREQS dereferences NULL in C; absent attributes
    // iterate as empty here.
    let Some(bands_attr) = at(&attr, NL80211_ATTR_WIPHY_BANDS) else {
        return;
    };
    for band in bands_attr.nested() {
        let (bands, _) = nla_parse(band.data, NL80211_BAND_ATTR_MAX, &[]);
        let Some(freqs_attr) = at(&bands, NL80211_BAND_ATTR_FREQS) else {
            continue;
        };
        for freq in freqs_attr.nested() {
            let (freqs, _) = nla_parse(freq.data, NL80211_FREQUENCY_ATTR_MAX, TXPWR_FREQ_POLICY);
            let ch_cmp = nl80211_freq2channel(at(&freqs, NL80211_FREQUENCY_ATTR_FREQ).map_or(0, |a| a.get_u32()) as i32);
            if ch_cur == 0 || ch_cmp == ch_cur {
                if let Some(p) = at(&freqs, NL80211_FREQUENCY_ATTR_MAX_TX_POWER) {
                    *dbm_max = (0.01 * p.get_u32() as f64) as i32;
                    break;
                }
            }
        }
    }
}

/// nl80211_get_txpwrlist: 0 .. max dBm of the current channel
pub fn txpwrlist(ifname: &str) -> Result<Vec<TxpwrlistEntry>, ()> {
    let ch_cur = channel(ifname).unwrap_or(0);
    /* initialize the value pointer with channel for callback */
    let mut dbm_max = ch_cur;
    let err = nl80211_request(ifname, NL80211_CMD_GET_WIPHY, 0, &mut |m: &Nlmsg| nl80211_get_txpwrlist_cb(m, &mut dbm_max));
    if err != 0 {
        return Err(());
    }
    let mut list = Vec::new();
    let mut dbm_cur = 0;
    while dbm_cur < dbm_max {
        list.push(TxpwrlistEntry { dbm: dbm_cur as u8, mw: utils::iwinfo_dbm2mw(dbm_cur) as u16 });
        dbm_cur += 1;
    }
    list.push(TxpwrlistEntry { dbm: dbm_max as u8, mw: utils::iwinfo_dbm2mw(dbm_max) as u16 });
    Ok(list)
}

/// nl80211_get_scancrypto: wpa_supplicant scan flags like
/// "[WPA2-PSK-CCMP][ESS]" into a crypto entry.
pub fn nl80211_get_scancrypto(spec: &[u8], c: &mut CryptoEntry) {
    c.enabled = 0;
    for p in strtok_all(cstr(spec), b"[]") {
        if p == b"WEP" {
            c.enabled = 1;
            c.auth_suites = IWINFO_KMGMT_NONE as u8;
            c.auth_algs = (IWINFO_AUTH_OPEN | IWINFO_AUTH_SHARED) as u8;
            c.pair_ciphers = (IWINFO_CIPHER_WEP40 | IWINFO_CIPHER_WEP104) as u16;
            break;
        }
        let (proto, rest) = strtok(p, b"-");
        let (suites, _) = strtok(rest, b"]");
        let (Some(proto), Some(suites)) = (proto, suites) else {
            continue;
        };
        let wpa_version = if proto == b"WPA2" || proto == b"RSN" {
            2
        } else if proto == b"WPA" {
            1
        } else {
            continue;
        };
        c.enabled = 1;
        parse_wpa_suites(suites, wpa_version, &mut c.wpa_version, &mut c.auth_suites);
        parse_wpa_ciphers(suites, &mut c.pair_ciphers);
    }
}

fn ie_at(ie: &[u8], i: usize) -> u8 {
    ie.get(i).copied().unwrap_or(0)
}

/// nl80211_get_scanlist_he_operation
fn nl80211_get_scanlist_he_operation(len: u8, ie: &[u8], e: &mut ScanlistEntry) {
    let mut offset: u8 = 6;
    /* 6 GHz Operation Info not present */
    if ie_at(ie, 2) & 0x02 == 0 {
        return;
    }
    /* VHT Operation Info present */
    if ie_at(ie, 1) & 0x40 != 0 {
        offset += 3;
    }
    /* Co Hosted BSS present */
    if ie_at(ie, 1) & 0x80 != 0 {
        offset += 1;
    }
    if (len as i32) - (offset as i32) < 5 {
        return;
    }
    let o = offset as usize;
    e.he_chan_info.chan_width = ie_at(ie, o + 1) & 0x03;
    e.he_chan_info.center_chan_1 = ie_at(ie, o + 2);
    e.he_chan_info.center_chan_2 = ie_at(ie, o + 3);
}

/// nl80211_get_scanlist_eht_operation
fn nl80211_get_scanlist_eht_operation(len: u8, ie: &[u8], e: &mut ScanlistEntry) {
    /* EHT Operation Info not present */
    if ie_at(ie, 0) & 0x01 == 0 {
        return;
    }
    if len < 8 {
        return;
    }
    e.eht_chan_info.chan_width = ie_at(ie, 5) & 0x07;
    e.eht_chan_info.center_chan_1 = ie_at(ie, 6);
    e.eht_chan_info.center_chan_2 = ie_at(ie, 7);
}

/// nl80211_get_scanlist_extension
fn nl80211_get_scanlist_extension(len: u8, ie: &[u8], e: &mut ScanlistEntry) {
    if len < 1 {
        return;
    }
    let rest = ie.get(1..).unwrap_or(&[]);
    match ie_at(ie, 0) {
        36 => nl80211_get_scanlist_he_operation(len - 1, rest, e), /* HE Operation */
        106 => nl80211_get_scanlist_eht_operation(len - 1, rest, e), /* EHT Operation */
        _ => {}
    }
}

/// nl80211_get_scanlist_ie: SSID / Mesh ID, RSN, WPA vendor IE, HT / VHT
/// operation and the HE / EHT extension elements.
// DEVIATION: the C IE walk (`ielen >= ie[1]`, not `ie[1] + 2`) may read up
// to two bytes past a truncated last element; element bodies are clamped to
// the buffer here, so only malformed frames can differ.
pub fn nl80211_get_scanlist_ie(ies: &[u8], e: &mut ScanlistEntry) {
    let mut ie = ies;
    while ie.len() >= 2 && ie.len() >= ie[1] as usize {
        let ielen = ie[1] as usize;
        let body = ie.get(2..2 + ielen).unwrap_or(ie.get(2..).unwrap_or(&[]));
        match ie[0] {
            0 | 114 => {
                /* SSID / Mesh ID */
                if e.ssid[0] == 0 {
                    let len = ielen.min(IWINFO_ESSID_MAX_SIZE).min(body.len());
                    e.ssid[..len].copy_from_slice(&body[..len]);
                    e.ssid[len] = 0;
                }
            }
            48 => {
                /* RSN */
                utils::iwinfo_parse_rsn(&mut e.crypto, body, IWINFO_CIPHER_CCMP as u16, IWINFO_KMGMT_8021X as u8);
            }
            221 => {
                /* Vendor */
                if ielen >= 4 && body.get(0..3) == Some(&[0x00, 0x50, 0xf2]) && ie_at(body, 3) == 1 {
                    utils::iwinfo_parse_rsn(
                        &mut e.crypto,
                        body.get(4..).unwrap_or(&[]),
                        IWINFO_CIPHER_TKIP as u16,
                        IWINFO_KMGMT_PSK as u8,
                    );
                }
            }
            61 => {
                /* HT operation */
                if ielen >= 3 {
                    e.ht_chan_info.primary_chan = ie_at(body, 0);
                    e.ht_chan_info.secondary_chan_off = ie_at(body, 1) & 0x3;
                    e.ht_chan_info.chan_width = (ie_at(body, 2) & 0x4) >> 2;
                }
            }
            192 => {
                /* VHT operation */
                if ielen >= 3 {
                    e.vht_chan_info.chan_width = ie_at(body, 0);
                    e.vht_chan_info.center_chan_1 = ie_at(body, 1);
                    e.vht_chan_info.center_chan_2 = ie_at(body, 2);
                }
            }
            255 => {
                /* Extension Tag */
                nl80211_get_scanlist_extension(ie[1], body, e);
            }
            _ => {}
        }
        let step = (ielen + 2).min(ie.len());
        ie = &ie[step..];
    }
}

const SCAN_BSS_POLICY: &Policy = &[
    (NL80211_BSS_TSF, 8),
    (NL80211_BSS_FREQUENCY, 4),
    (NL80211_BSS_BEACON_INTERVAL, 2),
    (NL80211_BSS_CAPABILITY, 2),
    (NL80211_BSS_SIGNAL_MBM, 4),
    (NL80211_BSS_SIGNAL_UNSPEC, 1),
    (NL80211_BSS_STATUS, 4),
    (NL80211_BSS_SEEN_MS_AGO, 4),
];

/// nl80211_get_scanlist_cb
fn nl80211_get_scanlist_cb(msg: &Nlmsg, sl: &mut Vec<ScanlistEntry>) {
    let tb = nl80211_parse(msg);
    let Some(bss_attr) = at(&tb, NL80211_ATTR_BSS) else {
        return;
    };
    let (bss, rc) = nla_parse_nested(bss_attr, NL80211_BSS_MAX, SCAN_BSS_POLICY);
    if rc != 0 {
        return;
    }
    let Some(bssid) = at(&bss, NL80211_BSS_BSSID) else {
        return;
    };

    let caps = at(&bss, NL80211_BSS_CAPABILITY).map_or(0, |a| a.get_u16());

    let mut e = ScanlistEntry::default();
    let n = bssid.nla_len().min(6);
    e.mac[..n].copy_from_slice(&bssid.data[..n]);

    if caps & (1 << 1) != 0 {
        e.mode = IWINFO_OPMODE_ADHOC;
    } else if caps & (1 << 0) != 0 {
        e.mode = IWINFO_OPMODE_MASTER;
    } else {
        e.mode = IWINFO_OPMODE_MESHPOINT;
    }

    if caps & (1 << 4) != 0 {
        e.crypto.enabled = 1;
    }

    if let Some(f) = at(&bss, NL80211_BSS_FREQUENCY) {
        e.mhz = f.get_u32();
        e.band = nl80211_freq2band(e.mhz as i32);
        e.channel = nl80211_freq2channel(e.mhz as i32) as u8;
    }

    if let Some(ies) = at(&bss, NL80211_BSS_INFORMATION_ELEMENTS) {
        nl80211_get_scanlist_ie(ies.data, &mut e);
    }

    if let Some(s) = at(&bss, NL80211_BSS_SIGNAL_MBM) {
        e.signal = ((s.get_u32() as i32) / 100) as u8;
        let mut rssi = (e.signal as i32 - 0x100) as i8;
        rssi = rssi.clamp(-110, -40);
        e.quality = (rssi as i32 + 110) as u8;
        e.quality_max = 70;
    }

    if e.crypto.enabled != 0 && e.crypto.wpa_version == 0 {
        e.crypto.auth_algs = (IWINFO_AUTH_OPEN | IWINFO_AUTH_SHARED) as u8;
        e.crypto.pair_ciphers = (IWINFO_CIPHER_WEP40 | IWINFO_CIPHER_WEP104) as u16;
    }

    sl.push(e);
}

/// nl80211_get_scanlist_nl: trigger a scan, wait for the result event and
/// dump the scan table.
fn nl80211_get_scanlist_nl(ifname: &str) -> Result<Vec<ScanlistEntry>, ()> {
    if nl80211_request(ifname, NL80211_CMD_TRIGGER_SCAN, 0, &mut |_: &Nlmsg| {}) != 0 {
        return Err(());
    }
    if nl80211_wait("nl80211", "scan", &[NL80211_CMD_NEW_SCAN_RESULTS, NL80211_CMD_SCAN_ABORTED]) != 0 {
        return Err(());
    }
    let mut sl = Vec::new();
    if nl80211_request(ifname, NL80211_CMD_GET_SCAN, NLM_F_DUMP, &mut |m: &Nlmsg| nl80211_get_scanlist_cb(m, &mut sl)) != 0 {
        return Err(());
    }
    Ok(sl)
}

/// wpasupp_ssid_decode: undo wpa_supplicant's printf-escaping into `out`
/// (NUL-terminated when it fits). Returns the decoded length.
// DEVIATION: a trailing lone backslash makes the C step past the string's
// terminator; decoding stops at the end of the input here.
pub fn wpasupp_ssid_decode(input: &[u8], out: &mut [u8]) -> usize {
    fn hex(x: u8) -> u8 {
        if x >= b'a' {
            x - b'a' + 10
        } else if x >= b'A' {
            x - b'A' + 10
        } else {
            x.wrapping_sub(b'0')
        }
    }
    let input = cstr(input);
    let outlen = out.len();
    let mut len = 0;
    let mut i = 0;
    while i < input.len() {
        if len + 1 >= outlen {
            break;
        }
        if input[i] == b'\\' {
            i += 1;
            match input.get(i) {
                Some(b'n') => {
                    out[len] = b'\n';
                    len += 1;
                    i += 1;
                }
                Some(b'r') => {
                    out[len] = b'\r';
                    len += 1;
                    i += 1;
                }
                Some(b't') => {
                    out[len] = b'\t';
                    len += 1;
                    i += 1;
                }
                Some(b'e') => {
                    out[len] = 0x1b;
                    len += 1;
                    i += 1;
                }
                Some(b'x') => {
                    let (h, l) = (input.get(i + 1).copied(), input.get(i + 2).copied());
                    if let (Some(h), Some(l)) = (h, l) {
                        if h.is_ascii_hexdigit() && l.is_ascii_hexdigit() {
                            out[len] = hex(h).wrapping_mul(16).wrapping_add(hex(l));
                            len += 1;
                        }
                    }
                    i += 3;
                }
                Some(&c) => {
                    out[len] = c;
                    len += 1;
                    i += 1;
                }
                None => break,
            }
        } else {
            out[len] = input[i];
            len += 1;
            i += 1;
        }
    }
    if outlen > len {
        out[len] = 0;
    }
    len
}

/// One SCAN_RESULTS line of nl80211_get_scanlist_wpactl:
/// "bssid\tfreq\tsignal\tflags\tssid".
pub fn wpactl_scan_line(line: &[u8], qmax: i32) -> Option<ScanlistEntry> {
    let (bssid, rest) = strtok(line, b"\t");
    let (freq, rest) = strtok(rest, b"\t");
    let (sig, rest) = strtok(rest, b"\t");
    let (flags, rest) = strtok(rest, b"\t");
    let (ssid, _) = strtok(rest, b"\n");
    let (Some(bssid), Some(freq), Some(sig), Some(flags)) = (bssid, freq, sig, flags) else {
        return None;
    };
    let mut e = ScanlistEntry::default();

    /* BSSID */
    for (i, off) in [0usize, 3, 6, 9, 12, 15].iter().enumerate() {
        e.mac[i] = mac_octet(bssid, *off);
    }

    /* SSID */
    match ssid {
        Some(s) => {
            wpasupp_ssid_decode(s, &mut e.ssid);
        }
        None => e.ssid[0] = 0,
    }

    /* Mode */
    if flags.windows(6).any(|w| w == b"[MESH]") {
        e.mode = IWINFO_OPMODE_MESHPOINT;
    } else if flags.windows(6).any(|w| w == b"[IBSS]") {
        e.mode = IWINFO_OPMODE_ADHOC;
    } else {
        e.mode = IWINFO_OPMODE_MASTER;
    }

    /* Channel */
    e.mhz = atoi(freq) as u32;
    e.band = nl80211_freq2band(e.mhz as i32);
    e.channel = nl80211_freq2channel(e.mhz as i32) as u8;

    /* Signal */
    let mut rssi = atoi(sig);
    e.signal = rssi as u8;

    /* Quality */
    if rssi < 0 {
        rssi = rssi.clamp(-110, -40);
        e.quality = (rssi + 110) as u8;
    } else {
        e.quality = rssi as u8;
    }

    /* Max. Quality */
    e.quality_max = qmax as u8;

    /* Crypto */
    nl80211_get_scancrypto(flags, &mut e.crypto);

    Some(e)
}

/// nl80211_get_scanlist_wpactl: ATTACH + SCAN on the wpa_supplicant control
/// socket, wait (up to 75 x 256 ms) for CTRL-EVENT-SCAN-RESULTS, then parse
/// one SCAN_RESULTS reply (4095 bytes at most, as the C buffer). Err carries
/// the C return value (< 0).
fn nl80211_get_scanlist_wpactl(ifname: &str) -> Result<Vec<ScanlistEntry>, i32> {
    let (sock, local) = nl80211_wpactl_connect(ifname)?;
    let mut count: i32 = -1;
    let mut ready = false;
    let mut list = Vec::new();

    wpactl_send(&sock, b"ATTACH");
    wpactl_send(&sock, b"SCAN");

    /* wait for scan results (see the C comment on the 75 tries) */
    let mut tries: i32 = 0;
    while tries < 75 {
        let (n, reply) = nl80211_wpactl_recv(&sock, 4096);
        if n > 0 {
            let reply = cstr(&reply);
            /* got an event notification */
            if reply.first() == Some(&b'<') {
                /* scan results are ready */
                if reply.windows(23).any(|w| w == b"CTRL-EVENT-SCAN-RESULTS") {
                    /* send "SCAN_RESULTS" command */
                    ready = wpactl_send(&sock, b"SCAN_RESULTS") == 12;
                    break;
                }
                /* is another unrelated event, retry */
                tries -= 1;
            }
            /* scanning already in progress, keep awaiting results */
            else if reply == b"FAIL-BUSY\n" {
                tries -= 1;
            }
            /* another failure, abort */
            else if reply.starts_with(b"FAIL-") {
                break;
            }
        }
        tries += 1;
    }

    /* receive and parse scan results if the wait above didn't time out
     * (C: `while (ready)`; the body always breaks except on event lines) */
    if ready {
        loop {
            let (n, reply) = nl80211_wpactl_recv(&sock, 4096);
            if n <= 0 {
                break;
            }
            let reply = cstr(&reply);
            /* received an event notification, receive again */
            if reply.first() == Some(&b'<') {
                continue;
            }
            let qmax = quality_max(ifname).unwrap_or(70);
            for line in strtok_all(reply, b"\n") {
                /* skip header line */
                if count < 0 {
                    count += 1;
                    continue;
                }
                if let Some(e) = wpactl_scan_line(line, qmax) {
                    list.push(e);
                    count += 1;
                }
            }
            break;
        }
    }

    wpactl_close(sock, &local);

    if count >= 0 {
        Ok(list)
    } else {
        Err(-1)
    }
}

/// nl80211_get_scanlist: radioN -> an existing or temporary netdev; then
/// wpa_supplicant, a direct nl80211 scan on station/ad-hoc/monitor/master
/// interfaces that can be brought up, or an AP scan through a temporary
/// station interface (tearing the AP down if the driver cannot add one).
pub fn scanlist(ifname: &str) -> Result<Vec<ScanlistEntry>, ()> {
    /* Got a radioX pseudo interface, find some interface on it or create one */
    if ifname.starts_with("radio") {
        /* Reuse existing interface */
        if let Some(res) = nl80211_phy2ifname(ifname) {
            return scanlist(&res);
        }
        /* Need to spawn a temporary iface for scanning */
        else if let Some(res) = nl80211_ifadd(ifname) {
            let rv = scanlist(&res);
            nl80211_ifdel(&res);
            return rv;
        }
    }

    /* WPA supplicant */
    if let Ok(list) = nl80211_get_scanlist_wpactl(ifname) {
        return Ok(list);
    }

    /* station / ad-hoc / monitor scan */
    let m = mode(ifname);
    if let Ok(m) = m {
        if (m == IWINFO_OPMODE_ADHOC || m == IWINFO_OPMODE_MASTER || m == IWINFO_OPMODE_CLIENT || m == IWINFO_OPMODE_MONITOR)
            && utils::iwinfo_ifup(ifname)
        {
            return nl80211_get_scanlist_nl(ifname);
        }
    }

    /* AP scan */
    /* Got a temp interface, don't create yet another one */
    if ifname.starts_with("tmp.") {
        if !utils::iwinfo_ifup(ifname) {
            return Err(());
        }
        let rv = nl80211_get_scanlist_nl(ifname);
        utils::iwinfo_ifdown(ifname);
        return rv;
    }

    /* Spawn a new scan interface */
    let Some(res) = nl80211_ifadd(ifname) else {
        return Err(());
    };
    utils::iwinfo_ifmac(&res);

    /* if we can take the new interface up, the driver supports an
     * additional interface and there's no need to tear down the ap */
    let rv = if utils::iwinfo_ifup(&res) {
        let rv = nl80211_get_scanlist_nl(&res);
        utils::iwinfo_ifdown(&res);
        rv
    }
    /* driver cannot create secondary interface, take down ap during scan */
    else if utils::iwinfo_ifdown(ifname) && utils::iwinfo_ifup(&res) {
        let rv = nl80211_get_scanlist_nl(&res);
        utils::iwinfo_ifdown(&res);
        utils::iwinfo_ifup(ifname);
        nl80211_hostapd_hup(ifname);
        rv
    } else {
        Err(())
    };

    nl80211_ifdel(&res);
    rv
}

/// nl80211_get_freqlist_cb
fn nl80211_get_freqlist_cb(msg: &Nlmsg, arr: &mut Vec<FreqlistEntry>) {
    let attr = nl80211_parse(msg);
    let Some(bands_attr) = at(&attr, NL80211_ATTR_WIPHY_BANDS) else {
        return;
    };
    for band in bands_attr.nested() {
        let (bands, _) = nla_parse(band.data, NL80211_BAND_ATTR_MAX, &[]);
        let Some(freqs_attr) = at(&bands, NL80211_BAND_ATTR_FREQS) else {
            continue;
        };
        for freq in freqs_attr.nested() {
            let (freqs, _) = nla_parse(freq.data, NL80211_FREQUENCY_ATTR_MAX, &[]);
            let Some(f) = at(&freqs, NL80211_FREQUENCY_ATTR_FREQ) else {
                continue;
            };
            if at(&freqs, NL80211_FREQUENCY_ATTR_DISABLED).is_some() {
                continue;
            }
            // The C backend ORs `flags` into the caller's buffer. rpcd hands
            // it uninitialized stack memory, producing spurious restrictions.
            // Keep only kernel flags; R92 checks against a zeroed C control.
            let mut e = FreqlistEntry::default();
            e.band = nl80211_get_band(band.raw_type) as u8;
            e.mhz = f.get_u32();
            e.channel = nl80211_freq2channel(e.mhz as i32) as u8;

            if at(&freqs, NL80211_FREQUENCY_ATTR_NO_HT40_MINUS).is_some() {
                e.flags |= IWINFO_FREQ_NO_HT40MINUS;
            }
            if at(&freqs, NL80211_FREQUENCY_ATTR_NO_HT40_PLUS).is_some() {
                e.flags |= IWINFO_FREQ_NO_HT40PLUS;
            }
            if at(&freqs, NL80211_FREQUENCY_ATTR_NO_80MHZ).is_some() {
                e.flags |= IWINFO_FREQ_NO_80MHZ;
            }
            if at(&freqs, NL80211_FREQUENCY_ATTR_NO_160MHZ).is_some() {
                e.flags |= IWINFO_FREQ_NO_160MHZ;
            }
            if at(&freqs, NL80211_FREQUENCY_ATTR_NO_20MHZ).is_some() {
                e.flags |= IWINFO_FREQ_NO_20MHZ;
            }
            if at(&freqs, NL80211_FREQUENCY_ATTR_NO_10MHZ).is_some() {
                e.flags |= IWINFO_FREQ_NO_10MHZ;
            }
            if at(&freqs, NL80211_FREQUENCY_ATTR_NO_HE).is_some() {
                e.flags |= IWINFO_FREQ_NO_HE;
            }
            if at(&freqs, NL80211_FREQUENCY_ATTR_NO_IR).is_some() && at(&freqs, NL80211_FREQUENCY_ATTR_RADAR).is_none() {
                e.flags |= IWINFO_FREQ_NO_IR;
            }
            if at(&freqs, NL80211_FREQUENCY_ATTR_INDOOR_ONLY).is_some() {
                e.flags |= IWINFO_FREQ_INDOOR_ONLY;
            }

            /* keep backwards compatibility */
            e.restricted = (e.flags & IWINFO_FREQ_NO_IR != 0) as u8;

            arr.push(e);
        }
    }
}

/// GET_WIPHY with NL80211_ATTR_SPLIT_WIPHY_DUMP (dump when the kernel
/// advertises split dumps), shared by freqlist / hwmodelist / htmodelist.
fn nl80211_split_wiphy(ifname: &str, cb: &mut dyn FnMut(&Nlmsg)) -> Result<(), ()> {
    let features = nl80211_get_protocol_features(ifname);
    let flags = if features & NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP != 0 { NLM_F_DUMP } else { 0 };
    let Some(mut cv) = nl80211_msg(ifname, NL80211_CMD_GET_WIPHY, flags) else {
        return Err(());
    };
    cv.put_flag(NL80211_ATTR_SPLIT_WIPHY_DUMP);
    if nl80211_send(cv, cb) != 0 {
        return Err(());
    }
    Ok(())
}

/// nl80211_get_freqlist
pub fn freqlist(ifname: &str) -> Result<Vec<FreqlistEntry>, ()> {
    let mut arr = Vec::new();
    nl80211_split_wiphy(ifname, &mut |m: &Nlmsg| nl80211_get_freqlist_cb(m, &mut arr))?;
    Ok(arr)
}

/// nl80211_get_country: the regulatory alpha2 (two characters, possibly
/// empty when the reply carries none); Err only on request failure.
pub fn country(ifname: &str) -> Result<String, ()> {
    let mut buf = [0u8; 3];
    let rc = nl80211_request(ifname, NL80211_CMD_GET_REG, 0, &mut |m: &Nlmsg| {
        match at(&nl80211_parse(m), NL80211_ATTR_REG_ALPHA2) {
            Some(a) => {
                let n = a.nla_len().min(2);
                buf[..n].copy_from_slice(&a.data[..n]);
            }
            None => buf[0] = 0,
        }
    });
    if rc != 0 {
        return Err(());
    }
    Ok(String::from_utf8_lossy(cstr(&buf)).into_owned())
}

/// nl80211_get_countrylist: every ISO 3166 label as a country entry.
pub fn countrylist(_ifname: &str) -> Result<Vec<CountryEntry>, ()> {
    Ok(IWINFO_ISO3166_NAMES
        .iter()
        .map(|l| CountryEntry {
            iso3166: l.iso3166,
            ccode: [(l.iso3166 / 256) as u8, (l.iso3166 % 256) as u8, 0, 0],
        })
        .collect())
}

/// struct nl80211_modes; the HE/EHT PHY capability arrays keep the C byte
/// layout (`uint16_t he_phy_cap[6]` filled from byte offset 1).
#[derive(Default)]
struct Modes {
    ok: bool,
    hw: u32,
    ht: u32,
    bands: u8,
    nl_ht: u16,
    nl_vht: u32,
    he_phy_cap: [u8; 12],
    eht_phy_cap: [u8; 18],
}

impl Modes {
    fn he_phy_cap0(&self) -> u16 {
        u16::from_ne_bytes([self.he_phy_cap[0], self.he_phy_cap[1]])
    }

    fn eht_phy_cap0(&self) -> u16 {
        u16::from_ne_bytes([self.eht_phy_cap[0], self.eht_phy_cap[1]])
    }
}

const fn bit(x: u32) -> u32 {
    1 << x
}

/// nl80211_eval_modelist
fn nl80211_eval_modelist(m: &mut Modes) {
    /* Treat any nonzero capability as 11n */
    if m.nl_ht > 0 {
        m.hw |= IWINFO_80211_N as u32;
        m.ht |= IWINFO_HTMODE_HT20 as u32;
        if m.nl_ht & (1 << 1) != 0 {
            m.ht |= IWINFO_HTMODE_HT40 as u32;
        }
    }

    let he0 = m.he_phy_cap0() as u32;
    if he0 != 0 {
        m.hw |= IWINFO_80211_AX as u32;
        m.ht |= IWINFO_HTMODE_HE20 as u32;
        if he0 & bit(9) != 0 {
            m.ht |= IWINFO_HTMODE_HE40 as u32;
        }
        if he0 & bit(10) != 0 {
            m.ht |= (IWINFO_HTMODE_HE40 | IWINFO_HTMODE_HE80) as u32;
        }
        if he0 & bit(11) != 0 {
            m.ht |= IWINFO_HTMODE_HE160 as u32;
        }
        if he0 & bit(12) != 0 {
            m.ht |= (IWINFO_HTMODE_HE160 | IWINFO_HTMODE_HE80_80) as u32;
        }
    }

    let eht0 = m.eht_phy_cap0() as u32;
    if eht0 != 0 {
        m.hw |= IWINFO_80211_BE as u32;
        m.ht |= IWINFO_HTMODE_EHT20 as u32;
        if he0 & bit(9) != 0 {
            m.ht |= IWINFO_HTMODE_EHT40 as u32;
        }
        if he0 & bit(10) != 0 {
            m.ht |= (IWINFO_HTMODE_EHT40 | IWINFO_HTMODE_EHT80) as u32;
        }
        if he0 & bit(11) != 0 {
            m.ht |= IWINFO_HTMODE_EHT160 as u32;
        }
        if he0 & bit(12) != 0 {
            m.ht |= (IWINFO_HTMODE_EHT160 | IWINFO_HTMODE_EHT80_80) as u32;
        }
        if eht0 & bit(9) != 0 && m.bands & IWINFO_BAND_6 as u8 != 0 {
            m.ht |= IWINFO_HTMODE_EHT320 as u32;
        }
    }

    if m.bands & IWINFO_BAND_24 as u8 != 0 {
        m.hw |= IWINFO_80211_B as u32;
        m.hw |= IWINFO_80211_G as u32;
    }

    if m.bands & IWINFO_BAND_5 as u8 != 0 {
        /* Treat any nonzero capability as 11ac */
        if m.nl_vht > 0 {
            m.hw |= IWINFO_80211_AC as u32;
            m.ht |= (IWINFO_HTMODE_VHT20 | IWINFO_HTMODE_VHT40 | IWINFO_HTMODE_VHT80) as u32;
            match (m.nl_vht >> 2) & 3 {
                2 => {
                    m.ht |= IWINFO_HTMODE_VHT80_80 as u32;
                    m.ht |= IWINFO_HTMODE_VHT160 as u32;
                }
                1 => m.ht |= IWINFO_HTMODE_VHT160 as u32,
                _ => {}
            }
        } else {
            m.hw |= IWINFO_80211_A as u32;
        }
    }

    if m.bands & IWINFO_BAND_60 as u8 != 0 {
        m.hw |= IWINFO_80211_AD as u32;
    }
}

/// nl80211_get_modelist_cb
fn nl80211_get_modelist_cb(msg: &Nlmsg, m: &mut Modes) {
    let attr = nl80211_parse(msg);
    let Some(bands_attr) = at(&attr, NL80211_ATTR_WIPHY_BANDS) else {
        return;
    };
    for band in bands_attr.nested() {
        m.bands |= nl80211_get_band(band.raw_type) as u8;
        let (bands, _) = nla_parse(band.data, NL80211_BAND_ATTR_MAX, &[]);

        if let Some(a) = at(&bands, NL80211_BAND_ATTR_HT_CAPA) {
            m.nl_ht = a.get_u16();
        }
        if let Some(a) = at(&bands, NL80211_BAND_ATTR_VHT_CAPA) {
            m.nl_vht = a.get_u32();
        }
        if let Some(iftype_data) = at(&bands, NL80211_BAND_ATTR_IFTYPE_DATA) {
            for nl_iftype in iftype_data.nested() {
                let (tb, _) = nla_parse(nl_iftype.data, NL80211_BAND_IFTYPE_ATTR_MAX, &[]);
                // HE
                if let Some(a) = at(&tb, NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY) {
                    let len = a.nla_len().min(m.he_phy_cap.len() - 1);
                    m.he_phy_cap[1..1 + len].copy_from_slice(&a.data[..len]);
                }
                // EHT
                if let Some(a) = at(&tb, NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY) {
                    let len = a.nla_len().min(m.eht_phy_cap.len() - 1);
                    m.eht_phy_cap[1..1 + len].copy_from_slice(&a.data[..len]);
                }
            }
        }
    }
    m.ok = true;
}

/// nl80211_get_hwmodelist
pub fn hwmodelist(ifname: &str) -> Result<i32, ()> {
    let mut m = Modes::default();
    nl80211_split_wiphy(ifname, &mut |msg: &Nlmsg| nl80211_get_modelist_cb(msg, &mut m))?;
    nl80211_eval_modelist(&mut m);
    Ok(m.hw as i32)
}

/// nl80211_get_htmodelist
pub fn htmodelist(ifname: &str) -> Result<i32, ()> {
    let mut m = Modes::default();
    nl80211_split_wiphy(ifname, &mut |msg: &Nlmsg| nl80211_get_modelist_cb(msg, &mut m))?;
    nl80211_eval_modelist(&mut m);
    Ok(m.ht as i32)
}

/// nl80211_get_htmode: channel width from the interface, generation from
/// hostapd (ieee80211ax/be) or wpa_supplicant (wifi_generation), VHT vs HT
/// from NL80211_ATTR_BSS_HT_OPMODE == -1.
pub fn htmode(ifname: &str) -> Result<i32, ()> {
    let mut width = 0i32;
    let mut opmode = 0i32;
    let res = nl80211_phy2ifname(ifname);
    let target = res.as_deref().unwrap_or(ifname);
    let err = nl80211_request(target, NL80211_CMD_GET_INTERFACE, 0, &mut |m: &Nlmsg| {
        let tb = nl80211_parse(m);
        if let Some(cur) = at(&tb, NL80211_ATTR_CHANNEL_WIDTH) {
            width = cur.get_u32() as i32;
        }
        if let Some(cur) = at(&tb, NL80211_ATTR_BSS_HT_OPMODE) {
            opmode = cur.get_u32() as i32;
        }
    });
    if err != 0 {
        return Err(());
    }

    let mut he = false;
    let mut eht = false;
    let (found, v) = nl80211_hostapd_query(target, &[("ieee80211be", 2)]);
    if found != 0 {
        eht = v[0].first() == Some(&b'1');
    }
    let (found, v) = nl80211_hostapd_query(target, &[("ieee80211ax", 2)]);
    if found != 0 {
        he = v[0].first() == Some(&b'1');
    } else {
        let (found, v) = nl80211_wpactl_query(target, &[("wifi_generation", 2)]);
        if found != 0 {
            he = v[0].first() == Some(&b'6');
            eht = v[0].first() == Some(&b'7');
        }
    }

    let buf = match width {
        NL80211_CHAN_WIDTH_20 => {
            if eht {
                IWINFO_HTMODE_EHT20
            } else if he {
                IWINFO_HTMODE_HE20
            } else if opmode == -1 {
                IWINFO_HTMODE_VHT20
            } else {
                IWINFO_HTMODE_HT20
            }
        }
        NL80211_CHAN_WIDTH_40 => {
            if eht {
                IWINFO_HTMODE_EHT40
            } else if he {
                IWINFO_HTMODE_HE40
            } else if opmode == -1 {
                IWINFO_HTMODE_VHT40
            } else {
                IWINFO_HTMODE_HT40
            }
        }
        NL80211_CHAN_WIDTH_80 => {
            if eht {
                IWINFO_HTMODE_EHT80
            } else if he {
                IWINFO_HTMODE_HE80
            } else {
                IWINFO_HTMODE_VHT80
            }
        }
        NL80211_CHAN_WIDTH_80P80 => {
            if eht {
                IWINFO_HTMODE_EHT80_80
            } else if he {
                IWINFO_HTMODE_HE80_80
            } else {
                IWINFO_HTMODE_VHT80_80
            }
        }
        NL80211_CHAN_WIDTH_160 => {
            if eht {
                IWINFO_HTMODE_EHT160
            } else if he {
                IWINFO_HTMODE_HE160
            } else {
                IWINFO_HTMODE_VHT160
            }
        }
        NL80211_CHAN_WIDTH_320 => IWINFO_HTMODE_EHT320,
        NL80211_CHAN_WIDTH_5 | NL80211_CHAN_WIDTH_10 | NL80211_CHAN_WIDTH_20_NOHT => IWINFO_HTMODE_NOHT,
        _ => return Err(()),
    };
    Ok(buf)
}

const IFACE_COMB_POLICY: &Policy = &[(NL80211_IFACE_COMB_MAXNUM, 4)];
const IFACE_LIMIT_POLICY: &Policy = &[(NL80211_IFACE_LIMIT_MAX, 4)];

/// nl80211_get_ifcomb_cb: 1 when some interface combination allows two or
/// more AP interfaces.
fn nl80211_get_ifcomb_cb(msg: &Nlmsg, ret: &mut i32) {
    let attr = nl80211_parse(msg);
    *ret = 0;
    let Some(combs) = at(&attr, NL80211_ATTR_INTERFACE_COMBINATIONS) else {
        return;
    };
    for comb in combs.nested() {
        let (tb_comb, _) = nla_parse_nested(comb, NUM_NL80211_IFACE_COMB, IFACE_COMB_POLICY);
        let Some(limits) = at(&tb_comb, NL80211_IFACE_COMB_LIMITS) else {
            continue;
        };
        for limit in limits.nested() {
            let (tb_limit, _) = nla_parse_nested(limit, NUM_NL80211_IFACE_LIMIT, IFACE_LIMIT_POLICY);
            let (Some(types), Some(max)) = (at(&tb_limit, NL80211_IFACE_LIMIT_TYPES), at(&tb_limit, NL80211_IFACE_LIMIT_MAX))
            else {
                continue;
            };
            if max.get_u32() < 2 {
                continue;
            }
            for mode in types.nested() {
                if mode.nla_type() == NL80211_IFTYPE_AP {
                    *ret = 1;
                }
            }
        }
    }
}

/// nl80211_get_mbssid_support
pub fn mbssid_support(ifname: &str) -> Result<i32, ()> {
    let mut buf = 0;
    if nl80211_request(ifname, NL80211_CMD_GET_WIPHY, 0, &mut |m: &Nlmsg| nl80211_get_ifcomb_cb(m, &mut buf)) != 0 {
        return Err(());
    }
    Ok(buf)
}

/// nl80211_hardware_id_from_fdt: the of_node compatible string of the phy
/// (or netdev) device.
fn nl80211_hardware_id_from_fdt(id: &mut HardwareId, ifname: &str) -> i32 {
    /* Try to determine the phy name from the given interface */
    let phy = nl80211_ifname2phy(ifname);
    let path = match &phy {
        Some(phy) => format!("/sys/class/ieee80211/{phy}/device/of_node/compatible"),
        None => format!("/sys/class/net/{ifname}/device/of_node/compatible"),
    };
    let Some(s) = nl80211_readstr(&path, id.compatible.len()) else {
        return -1;
    };
    // readstr() wrote `rv` bytes followed by a NUL into the zeroed array
    let n = s.len().min(id.compatible.len() - 1);
    id.compatible[..n].copy_from_slice(&s[..n]);
    id.compatible[n] = 0;
    0
}

/// nl80211_get_hardware_id: PCI/USB ids from sysfs, else the FDT
/// compatible string, else the board config partition.
pub fn hardware_id(ifname: &str) -> Result<HardwareId, ()> {
    let mut id = HardwareId::default();

    /* Try to determine the phy name from the given interface */
    let phy = nl80211_ifname2phy(ifname);
    let base = match &phy {
        Some(phy) => format!("/sys/class/ieee80211/{phy}/device"),
        None => format!("/sys/class/net/{ifname}/device"),
    };

    #[allow(clippy::type_complexity)]
    let lookup: [(&str, fn(&mut HardwareId) -> &mut u16); 6] = [
        ("vendor", |id| &mut id.vendor_id),
        ("device", |id| &mut id.device_id),
        ("subsystem_vendor", |id| &mut id.subsystem_vendor_id),
        ("subsystem_device", |id| &mut id.subsystem_device_id),
        ("../idVendor", |id| &mut id.subsystem_vendor_id),
        ("../idProduct", |id| &mut id.subsystem_device_id),
    ];

    for (path, dest) in lookup.iter() {
        if let Some(num) = nl80211_readstr(&format!("{base}/{path}"), 8) {
            *dest(&mut id) = strtoul16(&num) as u16;
        }
    }

    /* Failed to obtain hardware PCI/USB IDs... */
    if id.vendor_id == 0 && id.device_id == 0 && id.subsystem_vendor_id == 0 && id.subsystem_device_id == 0 {
        /* ... first fallback to FDT ... */
        if nl80211_hardware_id_from_fdt(&mut id, ifname) == -1 {
            /* ... then board config */
            if utils::iwinfo_hardware_id_from_mtd(&mut id) != 0 {
                return Err(());
            }
            return Ok(id);
        }
    }

    Ok(id)
}

/// nl80211_get_hardware_entry
fn nl80211_get_hardware_entry(ifname: &str) -> Option<HardwareEntry> {
    let id = hardware_id(ifname).ok()?;
    utils::iwinfo_hardware(&id)
}

/// nl80211_get_hardware_name: "<vendor> <device>" or "Generic MAC80211".
pub fn hardware_name(ifname: &str) -> Result<String, ()> {
    match nl80211_get_hardware_entry(ifname) {
        None => Ok("Generic MAC80211".to_owned()),
        Some(hw) => Ok(format!(
            "{} {}",
            String::from_utf8_lossy(cstr(&hw.vendor_name)),
            String::from_utf8_lossy(cstr(&hw.device_name))
        )),
    }
}

/// nl80211_get_txpower_offset
pub fn txpower_offset(ifname: &str) -> Result<i32, ()> {
    match nl80211_get_hardware_entry(ifname) {
        Some(hw) => Ok(hw.txpower_offset as i32),
        None => Err(()),
    }
}

/// nl80211_get_frequency_offset
pub fn frequency_offset(ifname: &str) -> Result<i32, ()> {
    match nl80211_get_hardware_entry(ifname) {
        Some(hw) => Ok(hw.frequency_offset as i32),
        None => Err(()),
    }
}

/// nl80211_lookup_phyname: "path=...", "macaddr=..." or a wireless config
/// section name -> phy name.
pub fn lookup_phy(section: &str) -> Result<String, ()> {
    let idx = if let Some(p) = section.strip_prefix("path=") {
        nl80211_phy_idx_from_path(Some(p))
    } else if let Some(m) = section.strip_prefix("macaddr=") {
        nl80211_phy_idx_from_macaddr(Some(m))
    } else {
        nl80211_phy_idx_from_uci(section)
    };
    if idx < 0 {
        return Err(());
    }
    nl80211_phyidx2name(idx as u32).ok_or(())
}

/// nl80211_phy_path
pub fn phy_path(phyname: &str) -> Result<String, ()> {
    if phyname.contains('/') {
        return Err(());
    }
    nl80211_phy_path_str(phyname).ok_or(())
}

/// nl80211_close
pub fn close() {
    netlink::nl80211_close();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssid2_requires_space_for_its_terminator() {
        for input in [b"\"wifi\"".as_slice(), b"P\"wifi\"", b"77696669", b""] {
            assert_eq!(parse_ssid2(input, &mut []), -1);
            let mut terminator = [0xff];
            assert_eq!(parse_ssid2(input, &mut terminator), 0);
            assert_eq!(terminator, [0]);
        }
    }

    #[test]
    fn freq_channel() {
        assert_eq!(nl80211_freq2channel(2412), 1);
        assert_eq!(nl80211_freq2channel(2484), 14);
        assert_eq!(nl80211_freq2channel(2472), 13);
        assert_eq!(nl80211_freq2channel(4920), 184);
        assert_eq!(nl80211_freq2channel(5180), 36);
        assert_eq!(nl80211_freq2channel(5825), 165);
        assert_eq!(nl80211_freq2channel(5935), 2);
        assert_eq!(nl80211_freq2channel(5955), 1);
        assert_eq!(nl80211_freq2channel(6115), 33);
        assert_eq!(nl80211_freq2channel(58320), 1);
        assert_eq!(nl80211_freq2channel(70200), 6);
        assert_eq!(nl80211_freq2channel(80000), 0);
        assert_eq!(nl80211_freq2channel(0), -481);

        assert_eq!(nl80211_channel2freq(0, b"g", 0), 0);
        assert_eq!(nl80211_channel2freq(1, b"g", 0), 2412);
        assert_eq!(nl80211_channel2freq(14, b"", 0), 2484);
        assert_eq!(nl80211_channel2freq(36, b"g", 0), 0);
        assert_eq!(nl80211_channel2freq(36, b"a", 0), 5180);
        assert_eq!(nl80211_channel2freq(184, b"a", 0), 4920);
        assert_eq!(nl80211_channel2freq(2, b"a", 131), 5935);
        assert_eq!(nl80211_channel2freq(1, b"a", 133), 5955);
        assert_eq!(nl80211_channel2freq(233, b"a", 133), 0);
        assert_eq!(nl80211_channel2freq(3, b"ad", 0), 62640);
        assert_eq!(nl80211_channel2freq(7, b"ad", 0), 0);

        assert_eq!(nl80211_freq2band(2437), IWINFO_BAND_24 as u8);
        assert_eq!(nl80211_freq2band(5500), IWINFO_BAND_5 as u8);
        assert_eq!(nl80211_freq2band(6135), IWINFO_BAND_6 as u8);
        assert_eq!(nl80211_freq2band(60480), IWINFO_BAND_60 as u8);
        assert_eq!(nl80211_freq2band(5900), 0);
    }

    const HOSTAPD_CONF: &[u8] = b"driver=nl80211\n\
logger_syslog=127\n\
# comment=ignored\n\
hw_mode=g\n\
channel=6\n\
ieee80211ax=1\n\
interface=phy0-ap0\n\
ssid=Home Net\n\
bssid=aa:bb:cc:dd:ee:ff\n\
wpa=2\n\
wpa_key_mgmt=WPA-PSK WPA-PSK-SHA256 SAE\n\
wpa_pairwise=CCMP\n\
auth_algs=1\n\
bss=phy0-ap1\n\
ssid=Guest\n\
wpa=0\n";

    #[test]
    fn hostapd_conf() {
        let (found, v) = hostapd_conf_query(HOSTAPD_CONF, "phy0-ap0", &[("ssid", 33), ("hw_mode", 3), ("channel", 4), ("op_class", 4)]);
        assert_eq!(found, 3);
        assert_eq!(v[0], b"Home Net");
        assert_eq!(v[1], b"g");
        assert_eq!(v[2], b"6");
        assert!(v[3].is_empty());
        // values are strncpy()-truncated to the destination size - 1
        let (_, v) = hostapd_conf_query(HOSTAPD_CONF, "phy0-ap0", &[("ssid", 5), ("wpa", 2)]);
        assert_eq!(v[0], b"Home");
        assert_eq!(v[1], b"2");
        // a bss= line switches the match; global keys before interface= match everyone
        let (found, v) = hostapd_conf_query(HOSTAPD_CONF, "phy0-ap1", &[("ssid", 33), ("wpa", 2), ("channel", 4), ("bssid", 19)]);
        assert_eq!(found, 3);
        assert_eq!(v[0], b"Guest");
        assert_eq!(v[1], b"0");
        assert_eq!(v[2], b"6");
        assert!(v[3].is_empty());
        let (found, _) = hostapd_conf_query(HOSTAPD_CONF, "phy1-ap0", &[("ssid", 33)]);
        assert_eq!(found, 0);
        // encryption from the hostapd branch
        let (_, v) = hostapd_conf_query(
            HOSTAPD_CONF,
            "phy0-ap0",
            &[("wpa", 2), ("wpa_key_mgmt", 64), ("wpa_pairwise", 16), ("auth_algs", 2), ("wep_key0", 27), ("wep_key1", 27), ("wep_key2", 27), ("wep_key3", 27)],
        );
        let c = encryption_from_hostapd(&v);
        assert_eq!(c.enabled, 1);
        assert_eq!(c.wpa_version, 2 | 4);
        assert_eq!(c.auth_suites, (IWINFO_KMGMT_PSK | IWINFO_KMGMT_SAE) as u8);
        assert_eq!(c.pair_ciphers, IWINFO_CIPHER_CCMP as u16);
        assert_eq!(c.group_ciphers, IWINFO_CIPHER_CCMP as u16);
        assert_eq!(c.auth_algs, IWINFO_AUTH_OPEN as u8);
        // frequency fallback from hw_mode/channel
        assert_eq!(nl80211_channel2freq(atoi(b"6"), b"g", atoi(b"")), 2437);
    }

    #[test]
    fn wpactl_status() {
        let reply = b"bssid=00:11:22:33:44:55\nfreq=5180\nssid=Up\nkey_mgmt=WPA2-PSK\npairwise_cipher=CCMP\ngroup_cipher=CCMP\nmode=station\nwifi_generation=6\nempty=\n";
        let (found, v) = wpactl_status_parse(reply, &[("pairwise_cipher", 16), ("group_cipher", 16), ("key_mgmt", 64), ("mode", 16), ("empty", 8)]);
        assert_eq!(found, 4);
        assert_eq!(v[2], b"WPA2-PSK");
        assert_eq!(v[3], b"station");
        assert!(v[4].is_empty());
        let c = encryption_from_wpactl(&v[0], &v[1], &v[2], &v[3]);
        assert_eq!(c.enabled, 1);
        assert_eq!(c.wpa_version, 2);
        assert_eq!(c.auth_suites, IWINFO_KMGMT_PSK as u8);
        assert_eq!(c.pair_ciphers, IWINFO_CIPHER_CCMP as u16);
        let c = encryption_from_wpactl(b"NONE", b"NONE", b"NONE", b"station");
        assert_eq!(c.enabled, 0);
        assert_eq!(c.pair_ciphers, 0);
        let c = encryption_from_wpactl(b"WEP-104", b"WEP-104", b"NONE", b"station");
        assert_eq!(c.enabled, 1);
        assert_eq!(c.pair_ciphers, IWINFO_CIPHER_WEP104 as u16);
        assert_eq!(c.auth_algs, (IWINFO_AUTH_OPEN | IWINFO_AUTH_SHARED) as u8);
        let c = encryption_from_wpactl(b"CCMP", b"CCMP", b"UNKNOWN", b"mesh");
        assert_eq!(c.wpa_version, 4);
        assert_eq!(c.auth_suites, IWINFO_KMGMT_SAE as u8);
        let (_, v) = wpactl_status_parse(reply, &[("wifi_generation", 2)]);
        assert_eq!(v[0], b"6");
    }

    #[test]
    fn wpa_suites_and_ciphers() {
        let (mut ver, mut suites) = (0u8, 0u8);
        parse_wpa_suites(b"PSK+SAE", 2, &mut ver, &mut suites);
        assert_eq!(ver, 2 | 4);
        assert_eq!(suites, (IWINFO_KMGMT_PSK | IWINFO_KMGMT_SAE) as u8);
        let (mut ver, mut suites) = (0u8, 0u8);
        parse_wpa_suites(b"PSK-SHA256", 2, &mut ver, &mut suites);
        assert_eq!(suites, IWINFO_KMGMT_PSK as u8);
        let (mut ver, mut suites) = (0u8, 0u8);
        parse_wpa_suites(b"EAP-SUITE-B-192", 0, &mut ver, &mut suites);
        assert_eq!(ver, 4);
        assert_eq!(suites, IWINFO_KMGMT_8021X as u8);
        let (mut ver, mut suites) = (0u8, 0u8);
        parse_wpa_suites(b"PSKX", 1, &mut ver, &mut suites);
        assert_eq!((ver, suites), (0, 0));
        let mut ciphers = 0u16;
        parse_wpa_ciphers(b"CCMP-256+GCMP TKIP", &mut ciphers);
        assert_eq!(ciphers, (IWINFO_CIPHER_CCMP256 | IWINFO_CIPHER_GCMP | IWINFO_CIPHER_TKIP) as u16);
    }

    #[test]
    fn scancrypto_and_scan_line() {
        let mut c = CryptoEntry::default();
        nl80211_get_scancrypto(b"[WPA2-PSK-CCMP][ESS]", &mut c);
        assert_eq!(c.enabled, 1);
        assert_eq!(c.wpa_version, 2);
        assert_eq!(c.auth_suites, IWINFO_KMGMT_PSK as u8);
        assert_eq!(c.pair_ciphers, IWINFO_CIPHER_CCMP as u16);
        let mut c = CryptoEntry::default();
        nl80211_get_scancrypto(b"[WPA-PSK-TKIP+CCMP][WPA2-PSK-CCMP][WPS][ESS]", &mut c);
        assert_eq!(c.wpa_version, 3);
        assert_eq!(c.pair_ciphers, (IWINFO_CIPHER_TKIP | IWINFO_CIPHER_CCMP) as u16);
        let mut c = CryptoEntry::default();
        nl80211_get_scancrypto(b"[WEP][ESS]", &mut c);
        assert_eq!(c.enabled, 1);
        assert_eq!(c.pair_ciphers, (IWINFO_CIPHER_WEP40 | IWINFO_CIPHER_WEP104) as u16);
        let mut c = CryptoEntry::default();
        nl80211_get_scancrypto(b"[ESS]", &mut c);
        assert_eq!(c.enabled, 0);

        let e = wpactl_scan_line(b"00:11:22:33:44:55\t2437\t-67\t[WPA2-PSK-CCMP][ESS]\tCaf\\xc3\\xa9 \\\"x\\\"", 70).unwrap();
        assert_eq!(e.mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(e.mhz, 2437);
        assert_eq!(e.channel, 6);
        assert_eq!(e.band, IWINFO_BAND_24 as u8);
        assert_eq!(e.signal, (-67i32) as u8);
        assert_eq!(e.signal as i32 - 0x100, -67);
        assert_eq!(e.quality, 43);
        assert_eq!(e.quality_max, 70);
        assert_eq!(e.mode, IWINFO_OPMODE_MASTER);
        assert_eq!(cstr(&e.ssid), "Caf\u{e9} \"x\"".as_bytes());
        let e = wpactl_scan_line(b"00:11:22:33:44:55\t5180\t-30\t[MESH]\t", 70).unwrap();
        assert_eq!(e.mode, IWINFO_OPMODE_MESHPOINT);
        assert_eq!(e.quality, 70);
        assert_eq!(e.ssid[0], 0);
        assert!(wpactl_scan_line(b"00:11:22:33:44:55\t5180", 70).is_none());
    }

    #[test]
    fn ssid_decoding() {
        let mut buf = [0u8; 33];
        assert_eq!(parse_ssid2(b"\"test\"", &mut buf), 0);
        assert_eq!(cstr(&buf), b"test");
        let mut buf = [0u8; 33];
        assert_eq!(parse_ssid2(b"74657374", &mut buf), 0);
        assert_eq!(cstr(&buf), b"test");
        let mut buf = [0u8; 33];
        assert_eq!(parse_ssid2(b"P\"hello\\nthere\\x41\\101\\\\\"", &mut buf), 0);
        assert_eq!(cstr(&buf), b"hello\nthereAA\\");
        let mut buf = [0u8; 33];
        assert_eq!(parse_ssid2(b"\"unterminated", &mut buf), -1);
        assert_eq!(parse_ssid2(b"abc", &mut buf), -1);
        assert_eq!(parse_ssid2(b"zz", &mut buf), -1);
        let mut buf = [0u8; 33];
        let long = [b'a'; 40];
        let quoted = [&b"\""[..], &long, &b"\""[..]].concat();
        assert_eq!(parse_ssid2(&quoted, &mut buf), 0);
        assert_eq!(cstr(&buf).len(), 32);

        let mut out = [0u8; 33];
        assert_eq!(wpasupp_ssid_decode(b"a\\tb\\x41\\e\\q", &mut out), 6);
        assert_eq!(cstr(&out), b"a\tbA\x1bq");
        let mut out = [0u8; 4];
        assert_eq!(wpasupp_ssid_decode(b"abcdef", &mut out), 3);
        assert_eq!(cstr(&out), b"abc");
    }

    #[test]
    fn scan_ies() {
        let mut e = ScanlistEntry::default();
        let ies = [
            0x00, 0x04, b'O', b'p', b'e', b'n', // SSID
            0x3d, 0x03, 0x06, 0x05, 0x04, // HT operation: primary 6, offset below(1), width 1
            0xc0, 0x03, 0x01, 0x2a, 0x00, // VHT operation
            0x30, 0x12, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, // RSN
        ];
        nl80211_get_scanlist_ie(&ies, &mut e);
        assert_eq!(cstr(&e.ssid), b"Open");
        assert_eq!(e.ht_chan_info.primary_chan, 6);
        assert_eq!(e.ht_chan_info.secondary_chan_off, 1);
        assert_eq!(e.ht_chan_info.chan_width, 1);
        assert_eq!(e.vht_chan_info.chan_width, 1);
        assert_eq!(e.vht_chan_info.center_chan_1, 42);
        assert_eq!(e.crypto.wpa_version, 2);
        assert_eq!(e.crypto.auth_suites, IWINFO_KMGMT_PSK as u8);
        assert_eq!(e.crypto.pair_ciphers, IWINFO_CIPHER_CCMP as u16);
        // HE operation with 6 GHz info: ext id 36, params (3 bytes, byte 2 bit 1 =
        // 6 GHz info present), bss color, mcs set (2), [6ghz: prim, ctrl, ccfs0, ccfs1, min rate]
        let mut e = ScanlistEntry::default();
        let he = [0xff, 0x0c, 36, 0x00, 0x00, 0x02, 0xff, 0xff, 0xff, 0x01, 0x02, 0x07, 0x00, 0x00];
        nl80211_get_scanlist_ie(&he, &mut e);
        assert_eq!(e.he_chan_info.chan_width, 2);
        assert_eq!(e.he_chan_info.center_chan_1, 7);
        // an element whose length exceeds the remaining buffer ends the C walk
        // (`ielen >= ie[1]` fails) before it is looked at
        let mut e = ScanlistEntry::default();
        nl80211_get_scanlist_ie(&[0x00, 0x08, b'a', b'b'], &mut e);
        assert_eq!(e.ssid[0], 0);
        // short by one byte: the C reads past the buffer, the port clamps
        let mut e = ScanlistEntry::default();
        nl80211_get_scanlist_ie(&[0x00, 0x03, b'a', b'b'], &mut e);
        assert_eq!(cstr(&e.ssid), b"ab");
    }

    #[test]
    fn eval_modelist() {
        let mut m = Modes { bands: (IWINFO_BAND_24 | IWINFO_BAND_5) as u8, nl_ht: 0x1ff, nl_vht: 0x338001b2, ..Modes::default() };
        m.he_phy_cap[1] = 0x1c; // he_phy_cap[0] = 0x1c00 -> bits 10, 11, 12
        nl80211_eval_modelist(&mut m);
        assert_eq!(m.hw as i32, IWINFO_80211_B | IWINFO_80211_G | IWINFO_80211_N | IWINFO_80211_AC | IWINFO_80211_AX);
        let ht = m.ht as i32;
        assert!(ht & IWINFO_HTMODE_HT40 != 0);
        assert!(ht & IWINFO_HTMODE_HE160 != 0 && ht & IWINFO_HTMODE_HE80_80 != 0);
        assert!(ht & IWINFO_HTMODE_VHT80 != 0);
        assert!(ht & IWINFO_HTMODE_VHT160 == 0); // (nl_vht >> 2) & 3 == 0
        assert_eq!(utils::iwinfo_format_hwmodes(m.hw as i32), "ac/ax/b/g/n");
    }
}
