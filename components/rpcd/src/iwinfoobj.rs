//! rpcd iwinfo.c port: the `iwinfo` ubus object on the Rust nl80211 backend
//! (`crate::iwinfo`). Every method opens the backend for the requested device
//! (INVALID_ARGUMENT without `device`, NOT_FOUND when the probe fails), fills
//! the reply in the C field order and ends with `rpc_iwinfo_close()`.

use crate::iwinfo::{self as iw, nl80211, utils, CryptoEntry, RateEntry};
use crate::session::{arg_str, Reply};
use owrt_ubus::blob::MsgType;
use owrt_ubus::{status, BlobBuf};

pub fn signature() -> Vec<(&'static str, Vec<(&'static str, MsgType)>)> {
    use MsgType::*;
    vec![
        ("devices", vec![]),
        ("info", vec![("device", String)]),
        ("scan", vec![("device", String)]),
        ("assoclist", vec![("device", String), ("mac", String)]),
        ("freqlist", vec![("device", String)]),
        ("txpowerlist", vec![("device", String)]),
        ("countrylist", vec![("device", String)]),
        ("survey", vec![("device", String)]),
        ("phyname", vec![("section", String)]),
    ]
}

fn code(c: i32) -> Reply {
    Reply::empty(c)
}

/// rpc_iwinfo_open: device argument + iwinfo_backend() probe.
fn open(raw: &[u8]) -> Result<String, i32> {
    let Some(dev) = arg_str(raw, "device") else {
        return Err(status::INVALID_ARGUMENT);
    };
    if iw::iwinfo_type(dev).is_none() {
        return Err(status::NOT_FOUND);
    }
    Ok(dev.to_owned())
}

/// rpc_iwinfo_close
fn close() {
    iw::iwinfo_finish();
}

/// blobmsg_add_string with the C `char[]` payload (may be non-UTF-8).
fn add_bytes(b: &mut BlobBuf, name: &str, s: &[u8]) {
    let mut v = s.to_vec();
    v.push(0);
    b.msg_field(MsgType::String as u32, name, &v);
}

fn mac_str(m: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// rpc_iwinfo_call_int: u32 of the int, or map[rv] when a name table is given.
fn call_int(b: &mut BlobBuf, name: &str, r: Result<i32, ()>, map: Option<&[&str]>) {
    if let Ok(rv) = r {
        match map {
            None => {
                b.msg_u32(name, rv as u32);
            }
            Some(m) => {
                // DEVIATION: map[rv] with rv outside the table is out-of-bounds in C
                b.msg_string(name, m.get(rv as usize).copied().unwrap_or(""));
            }
        }
    }
}

fn call_str(b: &mut BlobBuf, name: &str, r: Result<String, ()>) {
    if let Ok(s) = r {
        b.msg_string(name, &s);
    }
}

/// rpc_iwinfo_add_bit_array
fn add_bit_array(
    b: &mut BlobBuf,
    name: &str,
    mut bits: u32,
    values: &[&str],
    lower: bool,
    zero: u32,
) {
    if bits == 0 {
        bits = zero;
    }
    let c = b.msg_open_array(name);
    for (i, v) in values.iter().enumerate() {
        if bits & (1u32 << i) != 0 {
            if lower {
                b.msg_string("", &v.to_ascii_lowercase());
            } else {
                b.msg_string("", v);
            }
        }
    }
    b.msg_close(c);
}

/// rpc_iwinfo_add_encryption
pub fn add_encryption(b: &mut BlobBuf, name: &str, e: &CryptoEntry) {
    let c = b.msg_open_table(name);
    b.msg_bool("enabled", e.enabled != 0);
    if e.enabled != 0 {
        if e.wpa_version == 0 {
            add_bit_array(
                b,
                "wep",
                e.auth_algs as u32,
                &iw::IWINFO_AUTH_NAMES,
                true,
                0,
            );
        } else {
            let d = b.msg_open_array("wpa");
            for v in 1..=3u32 {
                if e.wpa_version as u32 & (1 << (v - 1)) != 0 {
                    b.msg_u32("", v);
                }
            }
            b.msg_close(d);
            add_bit_array(
                b,
                "authentication",
                e.auth_suites as u32,
                &iw::IWINFO_KMGMT_NAMES,
                true,
                iw::IWINFO_KMGMT_NONE as u32,
            );
        }
        add_bit_array(
            b,
            "ciphers",
            (e.pair_ciphers | e.group_ciphers) as u32,
            &iw::IWINFO_CIPHER_NAMES,
            true,
            iw::IWINFO_CIPHER_NONE as u32,
        );
    }
    b.msg_close(c);
}

/// rpc_iwinfo_call_hw_ht_mode
fn hw_ht_mode(b: &mut BlobBuf, dev: &str, hwmodelist: i32) {
    let text = utils::iwinfo_format_hwmodes(hwmodelist);
    if !text.is_empty() {
        b.msg_string("hwmodes_text", &text);
    }
    if hwmodelist == iw::IWINFO_80211_AD {
        b.msg_string("hwmode", "ad");
        return;
    }
    let Ok(htmode) = nl80211::htmode(dev) else {
        return;
    };
    let (hwmode_str, htmode_str) = match utils::iwinfo_htmode_name(htmode) {
        Some(hs) => {
            let hw = if utils::iwinfo_htmode_is_ht(htmode) {
                "n"
            } else if utils::iwinfo_htmode_is_vht(htmode) {
                "ac"
            } else if utils::iwinfo_htmode_is_he(htmode) {
                "ax"
            } else if utils::iwinfo_htmode_is_eht(htmode) {
                "be"
            } else if hwmodelist & iw::IWINFO_80211_N != 0 {
                "n"
            } else if hwmodelist & iw::IWINFO_80211_G != 0 {
                "g"
            } else if hwmodelist & iw::IWINFO_80211_B != 0 {
                "b"
            } else if hwmodelist & iw::IWINFO_80211_A != 0 {
                "a"
            } else {
                "unknown"
            };
            (hw, hs)
        }
        None => ("unknown", "unknown"),
    };
    b.msg_string("hwmode", hwmode_str);
    b.msg_string("htmode", htmode_str);
}

fn info(raw: &[u8]) -> Reply {
    let dev = match open(raw) {
        Ok(d) => d,
        Err(c) => return code(c),
    };
    let mut b = BlobBuf::new();
    call_str(&mut b, "phy", nl80211::phyname(&dev));
    if let Ok(ssid) = nl80211::ssid(&dev) {
        add_bytes(&mut b, "ssid", &ssid);
    }
    call_str(&mut b, "bssid", nl80211::bssid(&dev));
    call_str(&mut b, "country", nl80211::country(&dev));
    call_int(
        &mut b,
        "mode",
        nl80211::mode(&dev),
        Some(&iw::IWINFO_OPMODE_NAMES),
    );
    call_int(&mut b, "channel", nl80211::channel(&dev), None);
    call_int(&mut b, "center_chan1", nl80211::center_chan1(&dev), None);
    call_int(&mut b, "center_chan2", nl80211::center_chan2(&dev), None);
    call_int(&mut b, "frequency", nl80211::frequency(&dev), None);
    call_int(
        &mut b,
        "frequency_offset",
        nl80211::frequency_offset(&dev),
        None,
    );
    call_int(&mut b, "txpower", nl80211::txpower(&dev), None);
    call_int(
        &mut b,
        "txpower_offset",
        nl80211::txpower_offset(&dev),
        None,
    );
    call_int(&mut b, "quality", nl80211::quality(&dev), None);
    call_int(&mut b, "quality_max", nl80211::quality_max(&dev), None);
    call_int(&mut b, "signal", nl80211::signal(&dev), None);
    call_int(&mut b, "noise", nl80211::noise(&dev), None);
    call_int(&mut b, "bitrate", nl80211::bitrate(&dev), None);
    if let Ok(crypto) = nl80211::encryption(&dev) {
        add_encryption(&mut b, "encryption", &crypto);
    }
    if let Ok(modes) = nl80211::htmodelist(&dev) {
        add_bit_array(
            &mut b,
            "htmodes",
            (modes & !iw::IWINFO_HTMODE_NOHT) as u32,
            &iw::IWINFO_HTMODE_NAMES,
            false,
            0,
        );
    }
    let hwmodes = match nl80211::hwmodelist(&dev) {
        Ok(modes) => {
            add_bit_array(
                &mut b,
                "hwmodes",
                modes as u32,
                &iw::IWINFO_80211_NAMES,
                false,
                0,
            );
            modes
        }
        Err(()) => -1,
    };
    if hwmodes > 0 {
        hw_ht_mode(&mut b, &dev, hwmodes);
    }
    let c = b.msg_open_table("hardware");
    if let Ok(ids) = nl80211::hardware_id(&dev) {
        let a = b.msg_open_array("id");
        b.msg_u32("", ids.vendor_id as u32);
        b.msg_u32("", ids.device_id as u32);
        b.msg_u32("", ids.subsystem_vendor_id as u32);
        b.msg_u32("", ids.subsystem_device_id as u32);
        b.msg_close(a);
    }
    call_str(&mut b, "name", nl80211::hardware_name(&dev));
    b.msg_close(c);
    close();
    Reply::one(status::OK, b.into_payload())
}

// DEVIATION: the C indexes these tables with IE-derived values unchecked; an
// out-of-range index reads adjacent memory there and yields 0 / "" here.
fn tbl_u16(t: &[u16], i: u8) -> u32 {
    t.get(i as usize).copied().unwrap_or(0) as u32
}

fn scan(raw: &[u8]) -> Reply {
    let dev = match open(raw) {
        Ok(d) => d,
        Err(c) => return code(c),
    };
    let mut b = BlobBuf::new();
    let c = b.msg_open_array("results");
    if let Ok(list) = nl80211::scanlist(&dev) {
        for e in &list {
            let d = b.msg_open_table("");
            let ssid = iw::cstr(&e.ssid);
            if !ssid.is_empty() {
                add_bytes(&mut b, "ssid", ssid);
            }
            b.msg_string("bssid", &mac_str(&e.mac));
            b.msg_string(
                "mode",
                iw::IWINFO_OPMODE_NAMES
                    .get(e.mode as usize)
                    .copied()
                    .unwrap_or(""),
            );
            let band = utils::iwinfo_band2ghz(e.band);
            if band > 0 {
                b.msg_u32("band", band);
            }
            b.msg_u32("channel", e.channel as u32);
            b.msg_u32("mhz", e.mhz);
            b.msg_u32("signal", (e.signal as i32 - 0x100) as u32);
            b.msg_u32("quality", e.quality as u32);
            b.msg_u32("quality_max", e.quality_max as u32);
            if e.ht_chan_info.primary_chan != 0 {
                let t = b.msg_open_table("ht_operation");
                b.msg_u32("primary_channel", e.ht_chan_info.primary_chan as u32);
                b.msg_string(
                    "secondary_channel_offset",
                    iw::HT_SECONDARY_OFFSET
                        .get(e.ht_chan_info.secondary_chan_off as usize)
                        .copied()
                        .unwrap_or(""),
                );
                b.msg_u32(
                    "channel_width",
                    tbl_u16(&iw::HT_CHAN_WIDTH, e.ht_chan_info.chan_width),
                );
                b.msg_close(t);
            }
            if e.vht_chan_info.center_chan_1 != 0 {
                let t = b.msg_open_table("vht_operation");
                b.msg_u32(
                    "channel_width",
                    tbl_u16(&iw::VHT_CHAN_WIDTH, e.vht_chan_info.chan_width),
                );
                b.msg_u32("center_freq_1", e.vht_chan_info.center_chan_1 as u32);
                b.msg_u32("center_freq_2", e.vht_chan_info.center_chan_2 as u32);
                b.msg_close(t);
            }
            if e.he_chan_info.center_chan_1 != 0 {
                let t = b.msg_open_table("he_operation");
                b.msg_u32(
                    "channel_width",
                    tbl_u16(&iw::EHT_CHAN_WIDTH, e.he_chan_info.chan_width),
                );
                b.msg_u32("center_freq_1", e.he_chan_info.center_chan_1 as u32);
                b.msg_u32("center_freq_2", e.he_chan_info.center_chan_2 as u32);
                b.msg_close(t);
            }
            if e.eht_chan_info.center_chan_1 != 0 {
                let t = b.msg_open_table("eht_operation");
                b.msg_u32(
                    "channel_width",
                    tbl_u16(&iw::EHT_CHAN_WIDTH, e.eht_chan_info.chan_width),
                );
                b.msg_u32("center_freq_1", e.eht_chan_info.center_chan_1 as u32);
                b.msg_u32("center_freq_2", e.eht_chan_info.center_chan_2 as u32);
                b.msg_close(t);
            }
            add_encryption(&mut b, "encryption", &e.crypto);
            b.msg_close(d);
        }
    }
    b.msg_close(c);
    close();
    Reply::one(status::OK, b.into_payload())
}

/// rpc_iwinfo_add_rateinfo
fn add_rateinfo(b: &mut BlobBuf, r: &RateEntry) {
    b.msg_bool("ht", r.is_ht);
    b.msg_bool("vht", r.is_vht);
    b.msg_bool("he", r.is_he);
    b.msg_bool("eht", r.is_eht);
    b.msg_u32("mhz", r.mhz_hi as u32 * 256 + r.mhz as u32);
    b.msg_u32("rate", r.rate);
    if r.is_ht {
        b.msg_u32("mcs", r.mcs as i32 as u32);
        b.msg_bool("40mhz", r.is_40mhz);
        b.msg_bool("short_gi", r.is_short_gi);
    } else if r.is_vht {
        b.msg_u32("mcs", r.mcs as i32 as u32);
        b.msg_u32("nss", r.nss as u32);
        b.msg_bool("short_gi", r.is_short_gi);
    } else if r.is_he {
        b.msg_u32("mcs", r.mcs as i32 as u32);
        b.msg_u32("nss", r.nss as u32);
        b.msg_u32("he_gi", r.he_gi as u32);
        b.msg_u32("he_dcm", r.he_dcm as u32);
    } else if r.is_eht {
        b.msg_u32("mcs", r.mcs as i32 as u32);
        b.msg_u32("nss", r.nss as u32);
        b.msg_u32("eht_gi", r.eht_gi as u32);
    }
}

fn assoclist(raw: &[u8]) -> Reply {
    let dev = match open(raw) {
        Ok(d) => d,
        Err(c) => return code(c),
    };
    let macaddr = arg_str(raw, "mac").and_then(crate::lucirpc::ether_aton);
    let mut b = BlobBuf::new();
    let c = if macaddr.is_none() {
        Some(b.msg_open_array("results"))
    } else {
        None
    };
    let mut found = false;
    if let Ok(list) = nl80211::assoclist(&dev) {
        for a in &list {
            let d = match macaddr {
                None => Some(b.msg_open_table("")),
                Some(m) => {
                    if m != a.mac {
                        continue;
                    }
                    None
                }
            };
            b.msg_string("mac", &mac_str(&a.mac));
            b.msg_u32("signal", a.signal as i32 as u32);
            b.msg_u32("signal_avg", a.signal_avg as i32 as u32);
            b.msg_u32("noise", a.noise as i32 as u32);
            b.msg_u32("inactive", a.inactive);
            b.msg_u32("connected_time", a.connected_time);
            b.msg_u32("thr", a.thr);
            b.msg_bool("authorized", a.is_authorized);
            b.msg_bool("authenticated", a.is_authenticated);
            b.msg_string(
                "preamble",
                if a.is_preamble_short { "short" } else { "long" },
            );
            b.msg_bool("wme", a.is_wme);
            b.msg_bool("mfp", a.is_mfp);
            b.msg_bool("tdls", a.is_tdls);
            b.msg_u16("mesh llid", a.llid);
            b.msg_u16("mesh plid", a.plid);
            add_bytes(&mut b, "mesh plink", iw::cstr(&a.plink_state));
            add_bytes(&mut b, "mesh local PS", iw::cstr(&a.local_ps));
            add_bytes(&mut b, "mesh peer PS", iw::cstr(&a.peer_ps));
            add_bytes(&mut b, "mesh non-peer PS", iw::cstr(&a.nonpeer_ps));
            let e = b.msg_open_table("rx");
            b.msg_u64("drop_misc", a.rx_drop_misc);
            b.msg_u32("packets", a.rx_packets);
            b.msg_u64("bytes", a.rx_bytes);
            add_rateinfo(&mut b, &a.rx_rate);
            b.msg_close(e);
            let e = b.msg_open_table("tx");
            b.msg_u32("failed", a.tx_failed);
            b.msg_u32("retries", a.tx_retries);
            b.msg_u32("packets", a.tx_packets);
            b.msg_u64("bytes", a.tx_bytes);
            add_rateinfo(&mut b, &a.tx_rate);
            b.msg_close(e);
            found = true;
            match d {
                Some(cookie) => b.msg_close(cookie),
                None => break,
            }
        }
    }
    match c {
        Some(cookie) => b.msg_close(cookie),
        None => {
            if !found {
                // C returns before rpc_iwinfo_close(): the handle stays open
                return code(status::NOT_FOUND);
            }
        }
    }
    close();
    Reply::one(status::OK, b.into_payload())
}

fn survey(raw: &[u8]) -> Reply {
    let dev = match open(raw) {
        Ok(d) => d,
        Err(c) => return code(c),
    };
    let mut b = BlobBuf::new();
    let c = b.msg_open_array("results");
    if let Ok(list) = nl80211::survey(&dev) {
        for e in &list {
            let d = b.msg_open_table("");
            b.msg_u32("mhz", e.mhz);
            b.msg_u32("noise", e.noise as u32);
            b.msg_u64("active_time", e.active_time);
            b.msg_u64("busy_time", e.busy_time);
            b.msg_u64("busy_time_ext", e.busy_time_ext);
            b.msg_u64("rx_time", e.rxtime);
            b.msg_u64("tx_time", e.txtime);
            b.msg_close(d);
        }
    }
    b.msg_close(c);
    close();
    Reply::one(status::OK, b.into_payload())
}

fn freqlist(raw: &[u8]) -> Reply {
    let dev = match open(raw) {
        Ok(d) => d,
        Err(c) => return code(c),
    };
    let mut b = BlobBuf::new();
    let c = b.msg_open_array("results");
    if let Ok(list) = nl80211::freqlist(&dev) {
        let ch = nl80211::channel(&dev).unwrap_or(-1);
        for f in &list {
            let d = b.msg_open_table("");
            let band = utils::iwinfo_band2ghz(f.band);
            if band > 0 {
                b.msg_u32("band", band);
            }
            b.msg_u32("channel", f.channel as u32);
            b.msg_u32("mhz", f.mhz);
            b.msg_bool("restricted", f.restricted != 0);
            add_bit_array(
                &mut b,
                "flags",
                f.flags,
                &iw::IWINFO_FREQ_FLAG_NAMES,
                true,
                0,
            );
            if ch > -1 {
                b.msg_bool("active", f.channel as i32 == ch);
            }
            b.msg_close(d);
        }
    }
    b.msg_close(c);
    close();
    Reply::one(status::OK, b.into_payload())
}

fn txpowerlist(raw: &[u8]) -> Reply {
    let dev = match open(raw) {
        Ok(d) => d,
        Err(c) => return code(c),
    };
    let mut b = BlobBuf::new();
    let c = b.msg_open_array("results");
    if let Ok(list) = nl80211::txpwrlist(&dev) {
        let pwr = nl80211::txpower(&dev).unwrap_or(-1);
        let off = nl80211::txpower_offset(&dev).unwrap_or(0);
        for t in &list {
            let d = b.msg_open_table("");
            b.msg_u32("dbm", (t.dbm as i32 + off) as u32);
            b.msg_u32("mw", utils::iwinfo_dbm2mw(t.dbm as i32 + off) as u32);
            if pwr > -1 {
                b.msg_bool("active", t.dbm as i32 == pwr);
            }
            b.msg_close(d);
        }
    }
    b.msg_close(c);
    close();
    Reply::one(status::OK, b.into_payload())
}

fn countrylist(raw: &[u8]) -> Reply {
    let dev = match open(raw) {
        Ok(d) => d,
        Err(c) => return code(c),
    };
    let mut b = BlobBuf::new();
    let c = b.msg_open_array("results");
    if let Ok(list) = nl80211::countrylist(&dev) {
        let cur = nl80211::country(&dev).unwrap_or_default();
        for l in iw::IWINFO_ISO3166_NAMES.iter() {
            let Some(entry) = list.iter().find(|e| e.iso3166 == l.iso3166) else {
                continue;
            };
            let ccode = iw::cstr(&entry.ccode);
            let d = b.msg_open_table("");
            add_bytes(&mut b, "code", ccode);
            b.msg_string("country", l.name);
            let iso = [(l.iso3166 / 256) as u8, (l.iso3166 % 256) as u8];
            add_bytes(&mut b, "iso3166", &iso);
            if !cur.is_empty() {
                // strncmp(ccode, cur, 2)
                let a: Vec<u8> = ccode.iter().take(2).copied().collect();
                let bb: Vec<u8> = cur.as_bytes().iter().take(2).copied().collect();
                b.msg_bool("active", a == bb);
            }
            b.msg_close(d);
        }
    }
    b.msg_close(c);
    close();
    Reply::one(status::OK, b.into_payload())
}

fn phyname(raw: &[u8]) -> Reply {
    let Some(section) = arg_str(raw, "section") else {
        return code(status::INVALID_ARGUMENT);
    };
    // backends nl80211 / madwifi / wl: only nl80211 is compiled in
    let r = nl80211::lookup_phy(section);
    close();
    match r {
        Ok(name) => {
            let mut b = BlobBuf::new();
            b.msg_string("phyname", &name);
            Reply::one(status::OK, b.into_payload())
        }
        Err(()) => code(status::NOT_FOUND),
    }
}

fn devices() -> Reply {
    let Ok(rd) = std::fs::read_dir("/sys/class/net") else {
        return code(status::UNKNOWN_ERROR);
    };
    let mut b = BlobBuf::new();
    let c = b.msg_open_array("devices");
    for e in rd.flatten() {
        if !e.file_type().map(|t| t.is_symlink()).unwrap_or(false) {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if iw::iwinfo_type(&name).is_some() {
            b.msg_string("", &name);
        }
    }
    b.msg_close(c);
    close();
    Reply::one(status::OK, b.into_payload())
}

pub fn call(method: &str, raw: &[u8]) -> Reply {
    match method {
        "devices" => devices(),
        "info" => info(raw),
        "scan" => scan(raw),
        "assoclist" => assoclist(raw),
        "freqlist" => freqlist(raw),
        "txpowerlist" => txpowerlist(raw),
        "countrylist" => countrylist(raw),
        "survey" => survey(raw),
        "phyname" => phyname(raw),
        _ => code(status::METHOD_NOT_FOUND),
    }
}

/// rpc_luci_get_iwinfo (luci-rpc.c): the `iwinfo` sub-table of
/// getWirelessDevices. False when the backend probe fails (nothing added).
pub fn luci_iwinfo(b: &mut BlobBuf, dev: &str, phy_only: bool) -> bool {
    if iw::iwinfo_type(dev).is_none() {
        return false;
    }
    let o = b.msg_open_table("iwinfo");
    call_int(b, "signal", nl80211::signal(dev), None);
    call_int(b, "noise", nl80211::noise(dev), None);
    call_int(b, "channel", nl80211::channel(dev), None);
    call_str(b, "country", nl80211::country(dev));
    call_str(b, "phy", nl80211::phyname(dev));
    call_int(b, "txpower", nl80211::txpower(dev), None);
    call_int(b, "txpower_offset", nl80211::txpower_offset(dev), None);
    call_int(b, "frequency", nl80211::frequency(dev), None);
    call_int(b, "frequency_offset", nl80211::frequency_offset(dev), None);
    if let Ok(modes) = nl80211::hwmodelist(dev) {
        add_bit_array(b, "hwmodes", modes as u32, &iw::IWINFO_80211_NAMES, true, 0);
        let text = utils::iwinfo_format_hwmodes(modes);
        if !text.is_empty() {
            b.msg_string("hwmodes_text", &text);
        }
    }
    if let Ok(modes) = nl80211::htmodelist(dev) {
        add_bit_array(
            b,
            "htmodes",
            (modes & !iw::IWINFO_HTMODE_NOHT) as u32,
            &iw::IWINFO_HTMODE_NAMES,
            false,
            0,
        );
    }
    if let Ok(ids) = nl80211::hardware_id(dev) {
        let o2 = b.msg_open_table("hardware");
        let a = b.msg_open_array("id");
        b.msg_u32("", ids.vendor_id as u32);
        b.msg_u32("", ids.device_id as u32);
        b.msg_u32("", ids.subsystem_vendor_id as u32);
        b.msg_u32("", ids.subsystem_device_id as u32);
        b.msg_close(a);
        call_str(b, "name", nl80211::hardware_name(dev));
        b.msg_close(o2);
    }
    if !phy_only {
        call_int(b, "quality", nl80211::quality(dev), None);
        call_int(b, "quality_max", nl80211::quality_max(dev), None);
        call_int(b, "bitrate", nl80211::bitrate(dev), None);
        if let Ok(m) = nl80211::mode(dev) {
            b.msg_string(
                "mode",
                iw::IWINFO_OPMODE_NAMES
                    .get(m as usize)
                    .copied()
                    .unwrap_or(""),
            );
        }
        if let Ok(ssid) = nl80211::ssid(dev) {
            add_bytes(b, "ssid", &ssid);
        }
        call_str(b, "bssid", nl80211::bssid(dev));
        if let Ok(crypto) = nl80211::encryption(dev) {
            add_encryption(b, "encryption", &crypto);
        }
    }
    b.msg_close(o);
    // iw_close() = iwinfo_close(): only the utility socket, not nl80211
    utils::iwinfo_close();
    true
}

/// `rpcd-rs --iwinfo-bench <ifname>`: run the `info` op sequence once per op,
/// print wall time and the number of nl80211 requests each op issued.
pub fn bench(dev: &str) {
    use crate::iwinfo::netlink::SENDS;
    use std::io::Write;
    use std::sync::atomic::Ordering;
    use std::time::Instant;
    if iw::iwinfo_type(dev).is_none() {
        let _ = writeln!(std::io::stderr(), "{dev}: nl80211 probe failed");
        return;
    }
    macro_rules! op {
        ($name:expr, $e:expr) => {{
            let s0 = SENDS.load(Ordering::Relaxed);
            let t = Instant::now();
            let ok = $e.is_ok();
            let _ = writeln!(
                std::io::stdout(),
                "{:<18} {:>8.2} ms  nl_sends={:<3} {}",
                $name,
                t.elapsed().as_secs_f64() * 1000.0,
                SENDS.load(Ordering::Relaxed) - s0,
                if ok { "ok" } else { "err" }
            );
        }};
    }
    let t_all = Instant::now();
    let s_all = SENDS.load(Ordering::Relaxed);
    op!("phyname", nl80211::phyname(dev));
    op!("ssid", nl80211::ssid(dev));
    op!("bssid", nl80211::bssid(dev));
    op!("country", nl80211::country(dev));
    op!("mode", nl80211::mode(dev));
    op!("channel", nl80211::channel(dev));
    op!("center_chan1", nl80211::center_chan1(dev));
    op!("center_chan2", nl80211::center_chan2(dev));
    op!("frequency", nl80211::frequency(dev));
    op!("frequency_offset", nl80211::frequency_offset(dev));
    op!("txpower", nl80211::txpower(dev));
    op!("txpower_offset", nl80211::txpower_offset(dev));
    op!("quality", nl80211::quality(dev));
    op!("quality_max", nl80211::quality_max(dev));
    op!("signal", nl80211::signal(dev));
    op!("noise", nl80211::noise(dev));
    op!("bitrate", nl80211::bitrate(dev));
    op!("encryption", nl80211::encryption(dev));
    op!("htmodelist", nl80211::htmodelist(dev));
    op!("hwmodelist", nl80211::hwmodelist(dev));
    op!("htmode", nl80211::htmode(dev));
    op!("hardware_id", nl80211::hardware_id(dev));
    op!("hardware_name", nl80211::hardware_name(dev));
    op!("assoclist", nl80211::assoclist(dev));
    let _ = writeln!(
        std::io::stdout(),
        "total              {:>8.2} ms  nl_sends={}",
        t_all.elapsed().as_secs_f64() * 1000.0,
        SENDS.load(Ordering::Relaxed) - s_all
    );
    iw::iwinfo_finish();
}
