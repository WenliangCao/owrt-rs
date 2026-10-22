//! libiwinfo (commit f5dd57a8) nl80211 backend in Rust: `iwinfo.h` structs
//! and constants live here, `tables` = iwinfo_lib.c, `utils` =
//! iwinfo_utils.c, `netlink` = the libnl-tiny transport, `nl80211` =
//! iwinfo_nl80211.c. Ops return `Err(())` exactly where the C returns -1.
#![allow(dead_code)]

pub mod netlink;
pub mod nl80211;
pub mod sys;
pub mod tables;
pub mod utils;

pub use tables::*;

pub const IWINFO_BUFSIZE: usize = 24 * 1024;
pub const IWINFO_ESSID_MAX_SIZE: usize = 32;

// enum iwinfo_80211 as the bit masks the C code uses after macro expansion.
pub const IWINFO_80211_A: i32 = 1 << 0;
pub const IWINFO_80211_B: i32 = 1 << 1;
pub const IWINFO_80211_G: i32 = 1 << 2;
pub const IWINFO_80211_N: i32 = 1 << 3;
pub const IWINFO_80211_AC: i32 = 1 << 4;
pub const IWINFO_80211_AD: i32 = 1 << 5;
pub const IWINFO_80211_AX: i32 = 1 << 6;
pub const IWINFO_80211_BE: i32 = 1 << 7;
pub const IWINFO_80211_COUNT: i32 = 8;

pub const IWINFO_BAND_24: i32 = 1 << 0;
pub const IWINFO_BAND_5: i32 = 1 << 1;
pub const IWINFO_BAND_6: i32 = 1 << 2;
pub const IWINFO_BAND_60: i32 = 1 << 3;
pub const IWINFO_BAND_COUNT: i32 = 4;

pub const IWINFO_CIPHER_NONE: i32 = 1 << 0;
pub const IWINFO_CIPHER_WEP40: i32 = 1 << 1;
pub const IWINFO_CIPHER_TKIP: i32 = 1 << 2;
pub const IWINFO_CIPHER_WRAP: i32 = 1 << 3;
pub const IWINFO_CIPHER_CCMP: i32 = 1 << 4;
pub const IWINFO_CIPHER_WEP104: i32 = 1 << 5;
pub const IWINFO_CIPHER_AESOCB: i32 = 1 << 6;
pub const IWINFO_CIPHER_CKIP: i32 = 1 << 7;
pub const IWINFO_CIPHER_GCMP: i32 = 1 << 8;
pub const IWINFO_CIPHER_CCMP256: i32 = 1 << 9;
pub const IWINFO_CIPHER_GCMP256: i32 = 1 << 10;
pub const IWINFO_CIPHER_COUNT: i32 = 11;

pub const IWINFO_KMGMT_NONE: i32 = 1 << 0;
pub const IWINFO_KMGMT_8021X: i32 = 1 << 1;
pub const IWINFO_KMGMT_PSK: i32 = 1 << 2;
pub const IWINFO_KMGMT_SAE: i32 = 1 << 3;
pub const IWINFO_KMGMT_OWE: i32 = 1 << 4;
pub const IWINFO_KMGMT_COUNT: i32 = 5;

pub const IWINFO_AUTH_OPEN: i32 = 1 << 0;
pub const IWINFO_AUTH_SHARED: i32 = 1 << 1;
pub const IWINFO_AUTH_COUNT: i32 = 2;

pub const IWINFO_FREQ_NO_10MHZ: u32 = 1 << 0;
pub const IWINFO_FREQ_NO_20MHZ: u32 = 1 << 1;
pub const IWINFO_FREQ_NO_HT40PLUS: u32 = 1 << 2;
pub const IWINFO_FREQ_NO_HT40MINUS: u32 = 1 << 3;
pub const IWINFO_FREQ_NO_80MHZ: u32 = 1 << 4;
pub const IWINFO_FREQ_NO_160MHZ: u32 = 1 << 5;
pub const IWINFO_FREQ_NO_HE: u32 = 1 << 6;
pub const IWINFO_FREQ_NO_IR: u32 = 1 << 7;
pub const IWINFO_FREQ_INDOOR_ONLY: u32 = 1 << 8;
pub const IWINFO_FREQ_FLAG_COUNT: i32 = 9;

// enum iwinfo_opmode (plain values, no bit macros in C)
pub const IWINFO_OPMODE_UNKNOWN: i32 = 0;
pub const IWINFO_OPMODE_MASTER: i32 = 1;
pub const IWINFO_OPMODE_ADHOC: i32 = 2;
pub const IWINFO_OPMODE_CLIENT: i32 = 3;
pub const IWINFO_OPMODE_MONITOR: i32 = 4;
pub const IWINFO_OPMODE_AP_VLAN: i32 = 5;
pub const IWINFO_OPMODE_WDS: i32 = 6;
pub const IWINFO_OPMODE_MESHPOINT: i32 = 7;
pub const IWINFO_OPMODE_P2P_CLIENT: i32 = 8;
pub const IWINFO_OPMODE_P2P_GO: i32 = 9;
pub const IWINFO_OPMODE_COUNT: i32 = 10;

pub const IWINFO_HTMODE_HT20: i32 = 1 << 0;
pub const IWINFO_HTMODE_HT40: i32 = 1 << 1;
pub const IWINFO_HTMODE_VHT20: i32 = 1 << 2;
pub const IWINFO_HTMODE_VHT40: i32 = 1 << 3;
pub const IWINFO_HTMODE_VHT80: i32 = 1 << 4;
pub const IWINFO_HTMODE_VHT80_80: i32 = 1 << 5;
pub const IWINFO_HTMODE_VHT160: i32 = 1 << 6;
pub const IWINFO_HTMODE_NOHT: i32 = 1 << 7;
pub const IWINFO_HTMODE_HE20: i32 = 1 << 8;
pub const IWINFO_HTMODE_HE40: i32 = 1 << 9;
pub const IWINFO_HTMODE_HE80: i32 = 1 << 10;
pub const IWINFO_HTMODE_HE80_80: i32 = 1 << 11;
pub const IWINFO_HTMODE_HE160: i32 = 1 << 12;
pub const IWINFO_HTMODE_EHT20: i32 = 1 << 13;
pub const IWINFO_HTMODE_EHT40: i32 = 1 << 14;
pub const IWINFO_HTMODE_EHT80: i32 = 1 << 15;
pub const IWINFO_HTMODE_EHT80_80: i32 = 1 << 16;
pub const IWINFO_HTMODE_EHT160: i32 = 1 << 17;
pub const IWINFO_HTMODE_EHT320: i32 = 1 << 18;
pub const IWINFO_HTMODE_COUNT: i32 = 19;

pub const IWINFO_HARDWARE_FILE: &str = "/usr/share/libiwinfo/devices.txt";

/// struct iwinfo_rate_entry (the `:1` bit fields are bools).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateEntry {
    pub rate: u32,
    pub mcs: i8,
    pub is_40mhz: bool,
    pub is_short_gi: bool,
    pub is_ht: bool,
    pub is_vht: bool,
    pub is_he: bool,
    pub is_eht: bool,
    pub he_gi: u8,
    pub he_dcm: u8,
    pub mhz: u8,
    pub nss: u8,
    pub mhz_hi: u8,
    pub eht_gi: u8,
}

/// struct iwinfo_assoclist_entry; the `char[16]` fields keep their C layout
/// (NUL-terminated, see `cstr`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AssoclistEntry {
    pub mac: [u8; 6],
    pub signal: i8,
    pub signal_avg: i8,
    pub noise: i8,
    pub inactive: u32,
    pub connected_time: u32,
    pub rx_packets: u32,
    pub tx_packets: u32,
    pub rx_drop_misc: u64,
    pub rx_rate: RateEntry,
    pub tx_rate: RateEntry,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub tx_retries: u32,
    pub tx_failed: u32,
    pub t_offset: u64,
    pub is_authorized: bool,
    pub is_authenticated: bool,
    pub is_preamble_short: bool,
    pub is_wme: bool,
    pub is_mfp: bool,
    pub is_tdls: bool,
    pub thr: u32,
    pub llid: u16,
    pub plid: u16,
    pub plink_state: [u8; 16],
    pub local_ps: [u8; 16],
    pub peer_ps: [u8; 16],
    pub nonpeer_ps: [u8; 16],
}

/// struct iwinfo_survey_entry
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SurveyEntry {
    pub active_time: u64,
    pub busy_time: u64,
    pub busy_time_ext: u64,
    pub rxtime: u64,
    pub txtime: u64,
    pub mhz: u32,
    pub noise: u8,
}

/// struct iwinfo_txpwrlist_entry
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxpwrlistEntry {
    pub dbm: u8,
    pub mw: u16,
}

/// struct iwinfo_freqlist_entry
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FreqlistEntry {
    pub band: u8,
    pub channel: u8,
    pub mhz: u32,
    pub restricted: u8,
    pub flags: u32,
}

/// struct iwinfo_crypto_entry
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CryptoEntry {
    pub enabled: u8,
    pub wpa_version: u8,
    pub group_ciphers: u16,
    pub pair_ciphers: u16,
    pub auth_suites: u8,
    pub auth_algs: u8,
}

/// struct iwinfo_scanlist_ht_chan_entry
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanlistHtChanEntry {
    pub primary_chan: u8,
    pub secondary_chan_off: u8,
    pub chan_width: u8,
}

/// struct iwinfo_scanlist_vht_chan_entry (also used for he/eht)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanlistVhtChanEntry {
    pub chan_width: u8,
    pub center_chan_1: u8,
    pub center_chan_2: u8,
}

/// struct iwinfo_scanlist_entry; `ssid` is the C `char[33]` (see `cstr`),
/// `mode` an enum iwinfo_opmode value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanlistEntry {
    pub mac: [u8; 6],
    pub ssid: [u8; IWINFO_ESSID_MAX_SIZE + 1],
    pub mode: i32,
    pub band: u8,
    pub channel: u8,
    pub mhz: u32,
    pub signal: u8,
    pub quality: u8,
    pub quality_max: u8,
    pub crypto: CryptoEntry,
    pub ht_chan_info: ScanlistHtChanEntry,
    pub vht_chan_info: ScanlistVhtChanEntry,
    pub he_chan_info: ScanlistVhtChanEntry,
    pub eht_chan_info: ScanlistVhtChanEntry,
}

impl Default for ScanlistEntry {
    fn default() -> Self {
        ScanlistEntry {
            mac: [0; 6],
            ssid: [0; IWINFO_ESSID_MAX_SIZE + 1],
            mode: IWINFO_OPMODE_UNKNOWN,
            band: 0,
            channel: 0,
            mhz: 0,
            signal: 0,
            quality: 0,
            quality_max: 0,
            crypto: CryptoEntry::default(),
            ht_chan_info: ScanlistHtChanEntry::default(),
            vht_chan_info: ScanlistVhtChanEntry::default(),
            he_chan_info: ScanlistVhtChanEntry::default(),
            eht_chan_info: ScanlistVhtChanEntry::default(),
        }
    }
}

/// struct iwinfo_country_entry
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CountryEntry {
    pub iso3166: u16,
    pub ccode: [u8; 4],
}

/// struct iwinfo_iso3166_label
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Iso3166Label {
    pub iso3166: u16,
    pub name: &'static str,
}

/// struct iwinfo_hardware_id
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardwareId {
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsystem_vendor_id: u16,
    pub subsystem_device_id: u16,
    pub compatible: [u8; 128],
}

impl Default for HardwareId {
    fn default() -> Self {
        HardwareId {
            vendor_id: 0,
            device_id: 0,
            subsystem_vendor_id: 0,
            subsystem_device_id: 0,
            compatible: [0; 128],
        }
    }
}

/// struct iwinfo_hardware_entry
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardwareEntry {
    pub vendor_name: [u8; 64],
    pub device_name: [u8; 64],
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsystem_vendor_id: u16,
    pub subsystem_device_id: u16,
    pub txpower_offset: i16,
    pub frequency_offset: i16,
    pub compatible: [u8; 128],
}

impl Default for HardwareEntry {
    fn default() -> Self {
        HardwareEntry {
            vendor_name: [0; 64],
            device_name: [0; 64],
            vendor_id: 0,
            device_id: 0,
            subsystem_vendor_id: 0,
            subsystem_device_id: 0,
            txpower_offset: 0,
            frequency_offset: 0,
            compatible: [0; 128],
        }
    }
}

/// The C-string view of a fixed `char[]` field: bytes up to the first NUL.
pub fn cstr(buf: &[u8]) -> &[u8] {
    match buf.iter().position(|&b| b == 0) {
        Some(n) => &buf[..n],
        None => buf,
    }
}

/// strcpy()/strncpy()-into-zeroed-buffer: copy at most `dst.len() - 1` bytes
/// and NUL-terminate (the C `char[]` fields are always written that way).
pub fn set_cstr(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len().saturating_sub(1));
    dst[..n].copy_from_slice(&src[..n]);
    for b in &mut dst[n..] {
        *b = 0;
    }
}

/// iwinfo_type(): the backend name when the nl80211 probe succeeds. The
/// library on the device is built with USE_NL80211 only, so this is the
/// whole `backends[]` walk.
pub fn iwinfo_type(ifname: &str) -> Option<&'static str> {
    if nl80211::probe(ifname) {
        Some("nl80211")
    } else {
        None
    }
}

/// iwinfo_finish(): nl80211_ops.close() + iwinfo_close().
pub fn iwinfo_finish() {
    netlink::nl80211_close();
    utils::iwinfo_close();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cstr_helpers() {
        let mut b = [0u8; 4];
        set_cstr(&mut b, b"abcdef");
        assert_eq!(&b, b"abc\0");
        assert_eq!(cstr(&b), b"abc");
        set_cstr(&mut b, b"x");
        assert_eq!(cstr(&b), b"x");
        assert_eq!(cstr(b"no-nul"), b"no-nul");
    }
}
