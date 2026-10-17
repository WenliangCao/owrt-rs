//! The ethtool and sysfs half of `network.device status`.
//!
//! `system_if_dump_info` drives SIOCETHTOOL directly; the struct layouts here
//! are the kernel's, asserted by `tools/check_abi.sh` against the real headers
//! so a layout drift fails the build rather than the device.

use std::ffi::{CStr, CString};
use std::io::{self, Read};
use std::os::fd::{AsFd, OwnedFd};

use crate::ethtool_modes::{
    ETHTOOL_LINK_MODE_ASYM_PAUSE_BIT, ETHTOOL_LINK_MODE_PAUSE_BIT, ETHTOOL_MODES,
};


const ETHTOOL_GPAUSEPARAM: u32 = 0x12;
const ETHTOOL_GSTRINGS: u32 = 0x1b;
const ETHTOOL_GSSET_INFO: u32 = 0x37;
const ETHTOOL_GFEATURES: u32 = 0x3a;
const ETHTOOL_GGRO: u32 = 0x2b;
const ETHTOOL_GLINKSETTINGS: u32 = 0x4c;

const ETH_SS_FEATURES: u32 = 4;
const ETH_GSTRING_LEN: usize = 32;

const DUPLEX_HALF: u8 = 0;
const SPEED_UNKNOWN: u32 = u32::MAX;

/// The ioctl socket netifd keeps open for the lifetime of the process
/// (`sock_ioctl` in system-linux.c).
pub struct Ethtool {
    ioctl: crate::sys::IfIoctl,
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// One device's link settings, in the shape `network.device status` reports.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct LinkInfo {
    pub link_advertising: Vec<String>,
    pub link_partner_advertising: Vec<String>,
    pub link_supported: Vec<String>,
    /// `"1000F"` / `"100H"`; absent when the speed is unknown or zero.
    pub speed: Option<String>,
    pub autoneg: bool,
    pub pause_autoneg: bool,
    pub pause_supported: Vec<String>,
    pub pause_advertising: Vec<String>,
    pub pause_partner_advertising: Vec<String>,
    /// `pause_autoneg` false: the `selected` array from the pause ioctl.
    pub pause_selected: Option<Vec<String>>,
    /// `pause_autoneg` true: the `negotiated` array, derived from both sides'
    /// advertisements.
    pub pause_negotiated: Option<Vec<String>>,
}

impl Ethtool {
    pub fn open() -> io::Result<Self> {
        Ok(Self { ioctl: crate::sys::IfIoctl::open()? })
    }

    /// SIOCGIF* and SIOCETHTOOL use the same unbound datagram socket.
    pub fn if_ioctl(&self) -> &crate::sys::IfIoctl {
        &self.ioctl
    }

    fn call(&self, name: &str, buf: &mut [u8]) -> io::Result<()> {
        owrt_platform::netifd::ethtool_query(&self.ioctl, name, buf)
    }

    /// `ETHTOOL_GPAUSEPARAM`; on failure netifd reports autoneg with no
    /// rx/tx, which is reproduced here.
    fn pause(&self, name: &str) -> (bool, bool, bool) {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&ETHTOOL_GPAUSEPARAM.to_le_bytes());
        match self.call(name, &mut b) {
            Ok(()) => (u32_at(&b, 8) != 0, u32_at(&b, 12) != 0, u32_at(&b, 4) != 0),
            Err(_) => (false, false, true),
        }
    }

    /// `ETHTOOL_GLINKSETTINGS`, the two-call handshake: the first call returns
    /// the negated word count, the second fills the masks.
    pub fn link_info(&self, name: &str) -> io::Result<LinkInfo> {
        let (rx_pause, tx_pause, pause_autoneg) = self.pause(name);

        // header 48 bytes + 3 * 127 words of mask space, as in system-linux.c
        let mut b = vec![0u8; 48 + 4 * 3 * 127];
        b[0..4].copy_from_slice(&ETHTOOL_GLINKSETTINGS.to_le_bytes());
        self.call(name, &mut b)?;
        let nwords = b[15] as i8;
        if nwords >= 0 || u32_at(&b, 0) != ETHTOOL_GLINKSETTINGS {
            return Err(io::Error::from_raw_os_error(95)); // EOPNOTSUPP
        }
        b[15] = (-nwords) as u8;
        self.call(name, &mut b)?;
        let nwords = b[15] as i8;
        if nwords <= 0 || u32_at(&b, 0) != ETHTOOL_GLINKSETTINGS {
            return Err(io::Error::from_raw_os_error(5)); // EIO
        }
        let nw = nwords as usize;

        let words = |base: usize| -> Vec<u32> {
            (0..nw).map(|i| u32_at(&b, 48 + 4 * (base * nw + i))).collect()
        };
        let supported = words(0);
        let advertising = words(1);
        let lp_advertising = words(2);

        let speed = u32_at(&b, 4);
        let duplex = b[8];
        let autoneg = b[11] != 0;

        let mut info = LinkInfo {
            link_advertising: link_modes(&advertising),
            link_partner_advertising: link_modes(&lp_advertising),
            link_supported: link_modes(&supported),
            speed: None,
            autoneg,
            pause_autoneg,
            pause_supported: pause_modes(&supported),
            pause_advertising: Vec::new(),
            pause_partner_advertising: pause_modes(&lp_advertising),
            pause_selected: None,
            pause_negotiated: None,
        };
        if speed != SPEED_UNKNOWN && speed != 0 {
            info.speed =
                Some(format!("{}{}", speed, if duplex == DUPLEX_HALF { 'H' } else { 'F' }));
        }
        if pause_autoneg {
            info.pause_advertising = pause_modes(&advertising);
            info.pause_negotiated = Some(autoneg_pause(&advertising, &lp_advertising));
        } else {
            let mut sel = Vec::new();
            if rx_pause {
                sel.push("rx".to_string());
            }
            if tx_pause {
                sel.push("tx".to_string());
            }
            info.pause_selected = Some(sel);
        }
        Ok(info)
    }

    /// Index of a named feature in `ETH_SS_FEATURES`, or `None`.
    fn feature_index(&self, name: &str, key: &str) -> Option<usize> {
        let mut info = [0u8; 24]; // 16-byte header + one u32 of data, padded
        info[0..4].copy_from_slice(&ETHTOOL_GSSET_INFO.to_le_bytes());
        info[8..16].copy_from_slice(&(1u64 << ETH_SS_FEATURES).to_le_bytes());
        self.call(name, &mut info).ok()?;
        if u64::from_le_bytes(info[8..16].try_into().ok()?) == 0 {
            return None;
        }
        let count = u32_at(&info, 16) as usize;
        if count == 0 {
            return None;
        }

        let mut gs = vec![0u8; 12 + count * ETH_GSTRING_LEN];
        gs[0..4].copy_from_slice(&ETHTOOL_GSTRINGS.to_le_bytes());
        gs[4..8].copy_from_slice(&ETH_SS_FEATURES.to_le_bytes());
        gs[8..12].copy_from_slice(&(count as u32).to_le_bytes());
        self.call(name, &mut gs).ok()?;
        (0..count).find(|i| {
            let s = &gs[12 + i * ETH_GSTRING_LEN..12 + (i + 1) * ETH_GSTRING_LEN];
            let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
            s[..end] == *key.as_bytes()
        })
    }

    /// Whether a named feature is active, e.g. `hw-tc-offload`.
    ///
    /// netifd sizes this request `DIV_ROUND_UP(idx, 32)` blocks and then reads
    /// block `idx / 32`, which is one block short whenever `idx` is a positive
    /// multiple of 32. We size it `idx / 32 + 1`, so the block we read is
    /// always one we asked the kernel to fill. Deliberate difference, recorded
    /// in docs/contracts/netifd.md; the reported value is unaffected except in
    /// the case where the C read past its own allocation.
    pub fn feature_value(&self, name: &str, key: &str) -> bool {
        let Some(idx) = self.feature_index(name, key) else {
            return false;
        };
        let blocks = idx / 32 + 1;
        let mut f = vec![0u8; 8 + blocks * 16];
        f[0..4].copy_from_slice(&ETHTOOL_GFEATURES.to_le_bytes());
        f[4..8].copy_from_slice(&(blocks as u32).to_le_bytes());
        if self.call(name, &mut f).is_err() {
            return false;
        }
        // each block is available/requested/active/never_changed
        let active = u32_at(&f, 8 + (idx / 32) * 16 + 8);
        active & (1u32 << (idx % 32)) != 0
    }
}

impl Ethtool {
    /// `ETHTOOL_GGRO` via `struct ethtool_value { cmd, data }`; `None` when
    /// the device does not support the query, which leaves the flag unset.
    pub fn gro(&self, name: &str) -> Option<bool> {
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&ETHTOOL_GGRO.to_le_bytes());
        self.call(name, &mut b).ok()?;
        Some(u32_at(&b, 4) != 0)
    }
}

/// Test one bit of a link-mode mask, mirroring
/// `ethtool_link_mode_test_bit`: out-of-range bits read as clear.
fn test_bit(mask: &[u32], bit: i32) -> bool {
    if bit < 0 {
        return false;
    }
    let (w, b) = (bit as usize / 32, bit as usize % 32);
    mask.get(w).is_some_and(|v| v & (1 << b) != 0)
}

/// The mode names for a mask, in the generated table's order, with the `-H` /
/// `-F` suffix netifd appends. Half comes before full for the same mode.
pub fn link_modes(mask: &[u32]) -> Vec<String> {
    let mut out = Vec::new();
    for (_, half, full, name) in ETHTOOL_MODES {
        if test_bit(mask, *half) {
            out.push(format!("{name}-H"));
        }
        if test_bit(mask, *full) {
            out.push(format!("{name}-F"));
        }
    }
    out
}

pub fn pause_modes(mask: &[u32]) -> Vec<String> {
    let mut out = Vec::new();
    if test_bit(mask, ETHTOOL_LINK_MODE_PAUSE_BIT) {
        out.push("pause".to_string());
    }
    if test_bit(mask, ETHTOOL_LINK_MODE_ASYM_PAUSE_BIT) {
        out.push("asym_pause".to_string());
    }
    out
}

/// `system_add_ethtool_pause_an`: the `negotiated` array, per IEEE 802.3-2005
/// table 28B-3.
///
/// The C names its two locals `an_rx`/`an_tx` and then emits `"rx"` for
/// `an_tx` and `"tx"` for `an_rx` — the labels are swapped with respect to the
/// variables. That is what every caller sees today, so it is reproduced here
/// rather than corrected; see docs/contracts/netifd.md.
fn autoneg_pause(advertising: &[u32], lp: &[u32]) -> Vec<String> {
    let a_pause = test_bit(advertising, ETHTOOL_LINK_MODE_PAUSE_BIT);
    let a_asym = test_bit(advertising, ETHTOOL_LINK_MODE_ASYM_PAUSE_BIT);
    let l_pause = test_bit(lp, ETHTOOL_LINK_MODE_PAUSE_BIT);
    let l_asym = test_bit(lp, ETHTOOL_LINK_MODE_ASYM_PAUSE_BIT);

    let (mut an_rx, mut an_tx) = (false, false);
    if a_pause && l_pause {
        an_rx = true;
        an_tx = true;
    } else if a_asym && l_asym {
        if a_pause {
            an_rx = true;
        } else if l_pause {
            an_tx = true;
        }
    }

    let mut out = Vec::new();
    if an_tx {
        out.push("rx".to_string());
    }
    if an_rx {
        out.push("tx".to_string());
    }
    out
}

/// `/sys/class/net/<ifname>/<attr>`, read the way `system_get_dev_sysfs` does:
/// into a fixed buffer, truncated at the first newline. The buffer size is the
/// caller's, and the truncation is load-bearing — `system_add_devtype` passes a
/// 100-byte buffer, so it only ever sees the FIRST LINE of `uevent`, which for
/// most devices is `INTERFACE=` and not `DEVTYPE=`.
pub fn dev_sysfs_n(ifname: &str, attr: &str, buf_sz: usize) -> Option<String> {
    let raw = std::fs::read(format!("/sys/class/net/{ifname}/{attr}")).ok()?;
    let raw = &raw[..raw.len().min(buf_sz.saturating_sub(1))];
    let end = raw.iter().position(|&b| b == b'\n').unwrap_or(raw.len());
    Some(String::from_utf8_lossy(&raw[..end]).into_owned())
}

/// `system_add_devtype`: `DEVTYPE=` from the first line of the device's uevent
/// if it is there, otherwise the ARPHRD number from `type` mapped through the
/// netdev table, whose last entry is the default for an unknown number.
pub fn devtype(ifname: &str) -> Option<String> {
    if let Some(line) = dev_sysfs_n(ifname, "uevent", 100) {
        if let Some(v) = line.split("DEVTYPE=").nth(1) {
            return Some(v.to_string());
        }
    }
    let n: u16 = dev_sysfs_n(ifname, "type", 100)?.trim().parse().ok()?;
    let t = crate::netdev_types::NETDEV_TYPES;
    Some(t.iter().find(|(id, _)| *id == n).map_or(t[t.len() - 1].1, |(_, name)| name).to_string())
}

/// The 23 counters `system_if_dump_stats` reports, in its own order — which is
/// column-major over the source's 3-column table, not alphabetical.
pub const STAT_COUNTERS: &[&str] = &[
    "collisions",
    "rx_frame_errors",
    "tx_compressed",
    "multicast",
    "rx_length_errors",
    "tx_dropped",
    "rx_bytes",
    "rx_missed_errors",
    "tx_errors",
    "rx_compressed",
    "rx_over_errors",
    "tx_fifo_errors",
    "rx_crc_errors",
    "rx_packets",
    "tx_heartbeat_errors",
    "rx_dropped",
    "tx_aborted_errors",
    "tx_packets",
    "rx_errors",
    "tx_bytes",
    "tx_window_errors",
    "rx_fifo_errors",
    "tx_carrier_errors",
];

/// Position of each `STAT_COUNTERS` entry inside `struct rtnl_link_stats64`
/// (rx_packets, tx_packets, rx_bytes, tx_bytes, rx_errors, tx_errors,
/// rx_dropped, tx_dropped, multicast, collisions, rx_length_errors,
/// rx_over_errors, rx_crc_errors, rx_frame_errors, rx_fifo_errors,
/// rx_missed_errors, tx_aborted_errors, tx_carrier_errors, tx_fifo_errors,
/// tx_heartbeat_errors, tx_window_errors, rx_compressed, tx_compressed).
/// The sysfs `statistics/*` files print exactly these fields, so the IFLA_STATS64
/// attribute of one RTM_GETLINK reply carries the same 23 values as 23
/// open/read/close triples.
const STATS64_INDEX: [usize; 23] = [9, 13, 22, 8, 10, 7, 2, 15, 5, 21, 11, 18, 12, 0, 19, 6, 16, 1, 4, 3, 20, 14, 17];

/// The 23 counters from an IFLA_STATS64 payload, in `STAT_COUNTERS` order.
/// None when the payload is too short for the fields used here.
pub fn stats64_counters(payload: &[u8]) -> Option<[u64; 23]> {
    if payload.len() < 23 * 8 {
        return None;
    }
    let mut out = [0u64; 23];
    for (slot, &field) in out.iter_mut().zip(STATS64_INDEX.iter()) {
        let at = field * 8;
        *slot = u64::from_ne_bytes(payload[at..at + 8].try_into().unwrap());
    }
    Some(out)
}

/// Counters that exist for this device, in `STAT_COUNTERS` order. A counter
/// whose file is missing or unparsable is omitted, as in the C.
pub fn statistics(ifname: &str) -> Vec<(&'static str, u64)> {
    let Ok(path) = CString::new(format!("/sys/class/net/{ifname}/statistics")) else {
        return Vec::new();
    };
    statistics_at(&path)
}

fn open_readonly_at(dir: impl AsFd, path: &CStr) -> Option<OwnedFd> {
    rustix::fs::openat(dir, path, rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty()).ok()
}

fn statistics_at(path: &CStr) -> Vec<(&'static str, u64)> {
    let Some(dir) = open_readonly_at(rustix::fs::CWD, path) else { return Vec::new() };
    let mut values = Vec::with_capacity(STAT_COUNTERS.len());
    for &name in STAT_COUNTERS {
        // Kernel counter names are fixed and fit here. Reuse stack storage
        // rather than allocating a full path and decimal String per field.
        let mut name_buf = [0u8; 32];
        name_buf[..name.len()].copy_from_slice(name.as_bytes());
        let path = CStr::from_bytes_with_nul(&name_buf[..name.len() + 1]).unwrap();
        let Some(fd) = open_readonly_at(&dir, path) else { continue };
        let mut file = std::fs::File::from(fd);
        // sysfs emits at most 20 decimal digits plus a newline for u64.
        // Reading that bounded value needs neither fstat nor an EOF probe.
        let mut buf = [0u8; 64];
        let len = loop {
            match file.read(&mut buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Ok(n) if n < buf.len() => break n,
                _ => break 0,
            }
        };
        if let Some(value) = std::str::from_utf8(&buf[..len])
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
        {
            values.push((name, value));
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_modes_use_the_generated_order_and_suffixes() {
        // 10baseT half (bit 0) and 1000baseT full (bit 5)
        let mask = [1u32 << 0 | 1 << 5];
        assert_eq!(link_modes(&mask), vec!["10baseT-H", "1000baseT-F"]);
    }

    #[test]
    fn half_precedes_full_for_the_same_mode() {
        let mask = [0b11u32]; // 10baseT half and full
        assert_eq!(link_modes(&mask), vec!["10baseT-H", "10baseT-F"]);
    }

    #[test]
    fn bits_outside_the_mask_read_as_clear() {
        assert!(!test_bit(&[], 0));
        assert!(!test_bit(&[0xffff_ffff], 32));
        assert!(!test_bit(&[0, 0xffff_ffff], -1));
        assert!(test_bit(&[0, 1], 32));
    }

    #[test]
    fn pause_modes_read_the_two_named_bits() {
        assert_eq!(pause_modes(&[1 << ETHTOOL_LINK_MODE_PAUSE_BIT]), vec!["pause"]);
        assert_eq!(
            pause_modes(&[(1 << ETHTOOL_LINK_MODE_PAUSE_BIT)
                | (1 << ETHTOOL_LINK_MODE_ASYM_PAUSE_BIT)]),
            vec!["pause", "asym_pause"]
        );
        assert!(pause_modes(&[0]).is_empty());
    }

    #[test]
    fn autoneg_pause_follows_the_802_3_table_with_the_c_label_swap() {
        let p = 1u32 << ETHTOOL_LINK_MODE_PAUSE_BIT;
        let a = 1u32 << ETHTOOL_LINK_MODE_ASYM_PAUSE_BIT;
        // both advertise Pause: symmetric, so both labels appear
        assert_eq!(autoneg_pause(&[p], &[p]), vec!["rx", "tx"]);
        // asym on both, local advertises Pause: the C sets an_rx and prints "tx"
        assert_eq!(autoneg_pause(&[p | a], &[a]), vec!["tx"]);
        // asym on both, only the partner advertises Pause: an_tx, prints "rx"
        assert_eq!(autoneg_pause(&[a], &[p | a]), vec!["rx"]);
        assert_eq!(autoneg_pause(&[p | a], &[p | a]), vec!["rx", "tx"]);
        // asym on one side only: nothing negotiated
        assert!(autoneg_pause(&[0], &[p]).is_empty());
        assert!(autoneg_pause(&[a], &[p]).is_empty());
    }

    #[test]
    fn the_counter_list_is_the_c_order_not_sorted() {
        assert_eq!(STAT_COUNTERS.len(), 23);
        assert_eq!(STAT_COUNTERS[0], "collisions");
        assert_eq!(STAT_COUNTERS[1], "rx_frame_errors");
        assert_eq!(STAT_COUNTERS[2], "tx_compressed");
        assert_eq!(STAT_COUNTERS[22], "tx_carrier_errors");
        let mut sorted = STAT_COUNTERS.to_vec();
        sorted.sort_unstable();
        assert_ne!(sorted, STAT_COUNTERS.to_vec());
    }

    #[test]
    fn counters_keep_order_and_observe_changes_missing_files_and_full_u64() {
        let dir = std::env::temp_dir().join(format!(
            "netifd-statistics-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
        assert!(statistics_at(&path).is_empty());
        std::fs::write(dir.join("rx_bytes"), b"18446744073709551615\n").unwrap();
        std::fs::write(dir.join("collisions"), b"0\n").unwrap();
        std::fs::write(dir.join("tx_bytes"), b"18446744073709551616\n").unwrap();
        std::fs::write(dir.join("rx_packets"), b"invalid\n").unwrap();
        assert_eq!(statistics_at(&path), [("collisions", 0), ("rx_bytes", u64::MAX)]);
        std::fs::write(dir.join("rx_bytes"), b"12345\n").unwrap();
        std::fs::remove_file(dir.join("collisions")).unwrap();
        assert_eq!(statistics_at(&path), [("rx_bytes", 12345)]);
        // The directory and each counter are reopened for every snapshot;
        // no descriptor or value survives a device disappearing.
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(statistics_at(&path).is_empty());
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("rx_bytes"), b"7\n").unwrap();
        assert_eq!(statistics_at(&path), [("rx_bytes", 7)]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
