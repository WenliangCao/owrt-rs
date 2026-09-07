//! The ethtool and sysfs half of `network.device status`.
//!
//! `system_if_dump_info` drives SIOCETHTOOL directly; the struct layouts here
//! are the kernel's, asserted by `tools/check_abi.sh` against the real headers
//! so a layout drift fails the build rather than the device.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::ethtool_modes::{
    ETHTOOL_LINK_MODE_ASYM_PAUSE_BIT, ETHTOOL_LINK_MODE_PAUSE_BIT, ETHTOOL_MODES,
};

const AF_INET: i32 = 2;
const SOCK_DGRAM: i32 = 2;
const SOCK_CLOEXEC: i32 = 0o2000000;
const SIOCETHTOOL: u64 = 0x8946;

const ETHTOOL_GPAUSEPARAM: u32 = 0x12;
const ETHTOOL_GSTRINGS: u32 = 0x1b;
const ETHTOOL_GSSET_INFO: u32 = 0x37;
const ETHTOOL_GFEATURES: u32 = 0x3a;
const ETHTOOL_GLINKSETTINGS: u32 = 0x4c;

const ETH_SS_FEATURES: u32 = 4;
const ETH_GSTRING_LEN: usize = 32;
const IFNAMSIZ: usize = 16;

const DUPLEX_HALF: u8 = 0;
const SPEED_UNKNOWN: u32 = u32::MAX;

extern "C" {
    fn socket(domain: i32, ty: i32, proto: i32) -> i32;
    fn ioctl(fd: i32, req: u64, arg: *mut u8) -> i32;
}

/// The ioctl socket netifd keeps open for the lifetime of the process
/// (`sock_ioctl` in system-linux.c).
pub struct Ethtool {
    fd: OwnedFd,
}

/// `struct ifreq`: a 16-byte name followed by a union whose largest member is
/// 24 bytes; on 64-bit `ifr_data` is a pointer at offset 16.
fn ifreq(name: &str, data: *mut u8) -> [u8; 40] {
    let mut r = [0u8; 40];
    let n = name.as_bytes();
    let len = n.len().min(IFNAMSIZ - 1);
    r[..len].copy_from_slice(&n[..len]);
    r[16..24].copy_from_slice(&(data as usize as u64).to_le_bytes());
    r
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
    /// Present only when `pause_autoneg` is false: the negotiated result.
    pub pause_selected: Option<Vec<String>>,
    /// Present only when `pause_autoneg` is true: rx/tx as autonegotiated.
    pub pause_rx: bool,
    pub pause_tx: bool,
}

impl Ethtool {
    pub fn open() -> io::Result<Self> {
        // SAFETY: socket(2) with constant arguments; the result is checked
        // before being adopted as a descriptor.
        let raw = unsafe { socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket(2) just returned this descriptor and nothing else
        // holds it.
        Ok(Self { fd: unsafe { OwnedFd::from_raw_fd(raw) } })
    }

    fn call(&self, name: &str, buf: &mut [u8]) -> io::Result<()> {
        let mut req = ifreq(name, buf.as_mut_ptr());
        // SAFETY: ioctl(2) on our own socket. `req` describes a live buffer
        // whose lifetime spans the call; the kernel writes only inside `buf`,
        // whose length each caller sized from the command's own header.
        if unsafe { ioctl(self.fd.as_raw_fd(), SIOCETHTOOL, req.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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
            pause_rx: false,
            pause_tx: false,
        };
        if speed != SPEED_UNKNOWN && speed != 0 {
            info.speed =
                Some(format!("{}{}", speed, if duplex == DUPLEX_HALF { 'H' } else { 'F' }));
        }
        if pause_autoneg {
            info.pause_advertising = pause_modes(&advertising);
            let (rx, tx) = autoneg_pause(&advertising, &lp_advertising);
            info.pause_rx = rx;
            info.pause_tx = tx;
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

/// `system_add_ethtool_pause_an`: the negotiated rx/tx from both sides'
/// Pause and Asym_Pause advertisements.
fn autoneg_pause(advertising: &[u32], lp: &[u32]) -> (bool, bool) {
    let a_pause = test_bit(advertising, ETHTOOL_LINK_MODE_PAUSE_BIT);
    let a_asym = test_bit(advertising, ETHTOOL_LINK_MODE_ASYM_PAUSE_BIT);
    let l_pause = test_bit(lp, ETHTOOL_LINK_MODE_PAUSE_BIT);
    let l_asym = test_bit(lp, ETHTOOL_LINK_MODE_ASYM_PAUSE_BIT);
    if a_pause && l_pause {
        (true, true)
    } else if a_pause && a_asym && l_asym {
        (true, false)
    } else if a_asym && l_pause && l_asym {
        (false, true)
    } else {
        (false, false)
    }
}

/// `/sys/class/net/<ifname>/<attr>`.
pub fn dev_sysfs(ifname: &str, attr: &str) -> io::Result<String> {
    Ok(std::fs::read_to_string(format!("/sys/class/net/{ifname}/{attr}"))?.trim().to_string())
}

/// `DEVTYPE=` from the device's uevent, if it declares one.
pub fn devtype(ifname: &str) -> Option<String> {
    let uevent = dev_sysfs(ifname, "uevent").ok()?;
    uevent
        .lines()
        .find_map(|l| l.strip_prefix("DEVTYPE=").map(|v| v.to_string()))
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

/// Counters that exist for this device, in `STAT_COUNTERS` order. A counter
/// whose file is missing or unparsable is omitted, as in the C.
pub fn statistics(ifname: &str) -> Vec<(&'static str, u64)> {
    STAT_COUNTERS
        .iter()
        .filter_map(|c| {
            dev_sysfs(ifname, &format!("statistics/{c}"))
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|v| (*c, v))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_puts_the_pointer_at_offset_sixteen() {
        let mut buf = [0u8; 8];
        let r = ifreq("br-lan", buf.as_mut_ptr());
        assert_eq!(&r[..6], b"br-lan");
        assert_eq!(r[6], 0);
        assert_eq!(u64::from_le_bytes(r[16..24].try_into().unwrap()), buf.as_ptr() as u64);
    }

    #[test]
    fn a_too_long_name_is_truncated_and_still_terminated() {
        let mut buf = [0u8; 8];
        let r = ifreq("0123456789abcdefghij", buf.as_mut_ptr());
        assert_eq!(&r[..15], b"0123456789abcde");
        assert_eq!(r[15], 0);
    }

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
    fn autoneg_pause_follows_the_802_3_table() {
        let p = 1u32 << ETHTOOL_LINK_MODE_PAUSE_BIT;
        let a = 1u32 << ETHTOOL_LINK_MODE_ASYM_PAUSE_BIT;
        assert_eq!(autoneg_pause(&[p], &[p]), (true, true));
        assert_eq!(autoneg_pause(&[p | a], &[a]), (true, false));
        assert_eq!(autoneg_pause(&[a], &[p | a]), (false, true));
        assert_eq!(autoneg_pause(&[0], &[p]), (false, false));
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
}
