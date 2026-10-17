//! iwinfo_utils.c: the shared helpers (ioctl socket, dBm/mW, name lookups,
//! ifup/ifdown/ifmac, devices.txt hardware db, /proc/mtd board id, RSN IE
//! parsing, the uci radio lookup and the network.wireless ubus query), plus
//! the small libc string emulations (atoi/strtol/strtok/fgets) the backend
//! needs to keep the C parsing rules byte for byte.

use super::sys::{Ifreq, IFF_RUNNING, IFF_UP, SIOCGIFFLAGS, SIOCGIFHWADDR, SIOCSIFFLAGS, SIOCSIFHWADDR};
use super::tables::{IWINFO_80211_NAMES, IWINFO_BAND_NAMES, IWINFO_HTMODE_NAMES};
use super::*;
use owrt_ubus::convert::fields_to_json;
use owrt_ubus::json::Json;
use owrt_ubus::Connection;
use owrt_uci::model::{OptionValue, Ptr, Section, LOOKUP_EXTENDED};
use std::cell::RefCell;
use std::os::fd::OwnedFd;
use std::io::Read;

pub const LOG10_MAGIC: f64 = 1.25892541179;

// ------------------------------------------------------------ libc emulation

/// The C-string view of a buffer (bytes up to the first NUL).
pub fn cstr(buf: &[u8]) -> &[u8] {
    super::cstr(buf)
}

fn isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// atoi(): leading whitespace, optional sign, decimal digits, rest ignored.
pub fn atoi(s: &[u8]) -> i32 {
    let s = cstr(s);
    let mut i = 0;
    while i < s.len() && isspace(s[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut v: i64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        v = v.wrapping_mul(10).wrapping_add((s[i] - b'0') as i64);
        i += 1;
    }
    (if neg { -v } else { v }) as i32
}

/// strtol(s, &end, 16): returns the value and the index `end` points at
/// (== 0 when nothing was consumed).
pub fn strtol16(s: &[u8]) -> (i64, usize) {
    let s = cstr(s);
    let mut i = 0;
    while i < s.len() && isspace(s[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    if i + 1 < s.len() && s[i] == b'0' && (s[i + 1] == b'x' || s[i + 1] == b'X') && s.get(i + 2).is_some_and(|c| c.is_ascii_hexdigit()) {
        i += 2;
    }
    let start = i;
    let mut v: i64 = 0;
    while i < s.len() && s[i].is_ascii_hexdigit() {
        v = v.wrapping_mul(16).wrapping_add((s[i] as char).to_digit(16).unwrap_or(0) as i64);
        i += 1;
    }
    if i == start {
        return (0, 0);
    }
    (if neg { -v } else { v }, i)
}

/// strtoul(s, NULL, 16)
pub fn strtoul16(s: &[u8]) -> u64 {
    strtol16(s).0 as u64
}

/// strtok(s, delim) on a fresh string: skips leading delimiters, returns the
/// token and the remainder following the delimiter that ended it (an empty
/// remainder when the token ran to the end).
pub fn strtok<'a>(s: &'a [u8], delim: &[u8]) -> (Option<&'a [u8]>, &'a [u8]) {
    let Some(start) = s.iter().position(|c| !delim.contains(c)) else {
        return (None, &s[s.len()..]);
    };
    let rest = &s[start..];
    match rest.iter().position(|c| delim.contains(c)) {
        Some(end) => (Some(&rest[..end]), &rest[end + 1..]),
        None => (Some(rest), &rest[rest.len()..]),
    }
}

/// All strtok() tokens of `s` for `delim` (maximal runs of non-delimiters).
pub fn strtok_all<'a>(s: &'a [u8], delim: &[u8]) -> Vec<&'a [u8]> {
    s.split(|c| delim.contains(c)).filter(|t| !t.is_empty()).collect()
}

/// fgets(buf, size, fp) loop: successive chunks of at most `size - 1` bytes,
/// each ending after the first newline. Long lines split like the C code
/// sees them.
pub fn fgets_chunks(data: &[u8], size: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut pos = 0;
    let max = size.saturating_sub(1).max(1);
    while pos < data.len() {
        let rest = &data[pos..];
        let n = match rest.iter().take(max).position(|&c| c == b'\n') {
            Some(i) => i + 1,
            None => rest.len().min(max),
        };
        out.push(&rest[..n]);
        pos += n;
    }
    out
}

/// opendir()/readdir(): entry names in directory order, `.` and `..`
/// included as readdir() yields them; None when opendir() fails.
pub fn readdir(path: &str) -> Option<Vec<String>> {
    let rd = std::fs::read_dir(path).ok()?;
    let mut names = vec![".".to_owned(), "..".to_owned()];
    for e in rd.flatten() {
        names.push(e.file_name().to_string_lossy().into_owned());
    }
    Some(names)
}

// ------------------------------------------------------------- ioctl socket

thread_local! {
    static IOCTL_SOCKET: RefCell<Option<OwnedFd>> = const { RefCell::new(None) };
}

/// iwinfo_ioctl: the cached descriptor remains owned throughout the call.
pub fn iwinfo_ioctl(cmd: u64, ifr: &mut Ifreq) -> i32 {
    IOCTL_SOCKET.with(|cell| {
        let mut socket = cell.borrow_mut();
        if socket.is_none() {
            let Ok(fd) = rustix::net::socket(rustix::net::AddressFamily::INET, rustix::net::SocketType::DGRAM, None) else { return -1; };
            if let Ok(flags) = rustix::io::fcntl_getfd(&fd) {
                let _ = rustix::io::fcntl_setfd(&fd, flags | rustix::io::FdFlags::CLOEXEC);
            }
            *socket = Some(fd);
        }
        match owrt_platform::rpcd::interface_ioctl(socket.as_ref().unwrap(), cmd, &ifr.name, &mut ifr.data) {
            Ok(()) => 0,
            Err(_) => -1,
        }
    })
}

pub fn iwinfo_close() { IOCTL_SOCKET.with(|cell| cell.borrow_mut().take()); }

// --------------------------------------------------------------- conversions

/// iwinfo_dbm2mw
pub fn iwinfo_dbm2mw(input: i32) -> i32 {
    let mut res = 1.0f64;
    let ip = input / 10;
    let fp = input % 10;
    for _ in 0..ip {
        res *= 10.0;
    }
    for _ in 0..fp {
        res *= LOG10_MAGIC;
    }
    res as i32
}

/// iwinfo_mw2dbm
pub fn iwinfo_mw2dbm(input: i32) -> i32 {
    let mut fin = input as f64;
    let mut res = 0;
    while fin > 10.0 {
        res += 10;
        fin /= 10.0;
    }
    while fin > 1.000001 {
        res += 1;
        fin /= LOG10_MAGIC;
    }
    res
}

/// iwinfo_mbm2dbm (static inline in utils.h)
pub fn iwinfo_mbm2dbm(gain: i32) -> i32 {
    gain / 100
}

/// iwinfo_bit: index of the lowest set bit within `max` bits, -1 if none.
fn iwinfo_bit(value: i32, max: i32) -> i32 {
    if max > 31 || (value & ((1 << max) - 1)) == 0 {
        return -1;
    }
    let mut value = value;
    let mut i = 0;
    while i < max {
        if value & 1 != 0 {
            break;
        }
        value >>= 1;
        i += 1;
    }
    i
}

/// iwinfo_name
fn iwinfo_name(mask: i32, max: i32, names: &'static [&'static str]) -> Option<&'static str> {
    let index = iwinfo_bit(mask, max);
    if index < 0 {
        return None;
    }
    names.get(index as usize).copied()
}

/// iwinfo_band_name
pub fn iwinfo_band_name(mask: i32) -> Option<&'static str> {
    iwinfo_name(mask, IWINFO_BAND_COUNT, &IWINFO_BAND_NAMES)
}

/// iwinfo_htmode_name
pub fn iwinfo_htmode_name(mask: i32) -> Option<&'static str> {
    iwinfo_name(mask, IWINFO_HTMODE_COUNT, &IWINFO_HTMODE_NAMES)
}

/// iwinfo_band2ghz
pub fn iwinfo_band2ghz(band: u8) -> u32 {
    match band as i32 {
        IWINFO_BAND_24 => 2,
        IWINFO_BAND_5 => 5,
        IWINFO_BAND_6 => 6,
        IWINFO_BAND_60 => 60,
        _ => 0,
    }
}

/// iwinfo_ghz2band
pub fn iwinfo_ghz2band(ghz: u32) -> u8 {
    match ghz {
        2 => IWINFO_BAND_24 as u8,
        5 => IWINFO_BAND_5 as u8,
        6 => IWINFO_BAND_6 as u8,
        60 => IWINFO_BAND_60 as u8,
        _ => 0,
    }
}

/// iwinfo_format_hwmodes: "ad/ac/ax/a/b/be/g/n" order; empty when no
/// 802.11 bit is set. Both C callers pass 32-byte buffers, which always fit
/// the longest result (19 bytes), so no snprintf truncation is modelled.
pub fn iwinfo_format_hwmodes(modes: i32) -> String {
    // bit numbers as per IWINFO_80211_*:  ad ac ax  a  b  be g  n
    const ORDER: [usize; 8] = [5, 4, 6, 0, 1, 7, 2, 3];
    let mut buf = String::new();
    if modes & ((1 << IWINFO_80211_COUNT) - 1) == 0 {
        return buf;
    }
    for &o in ORDER.iter() {
        if modes & (1 << o) != 0 {
            buf.push_str(IWINFO_80211_NAMES[o]);
            buf.push('/');
        }
    }
    buf.pop();
    buf
}

/// iwinfo_htmode_is_ht
pub fn iwinfo_htmode_is_ht(htmode: i32) -> bool {
    matches!(htmode, IWINFO_HTMODE_HT20 | IWINFO_HTMODE_HT40)
}

/// iwinfo_htmode_is_vht
pub fn iwinfo_htmode_is_vht(htmode: i32) -> bool {
    matches!(
        htmode,
        IWINFO_HTMODE_VHT20 | IWINFO_HTMODE_VHT40 | IWINFO_HTMODE_VHT80 | IWINFO_HTMODE_VHT80_80 | IWINFO_HTMODE_VHT160
    )
}

/// iwinfo_htmode_is_he
pub fn iwinfo_htmode_is_he(htmode: i32) -> bool {
    matches!(
        htmode,
        IWINFO_HTMODE_HE20 | IWINFO_HTMODE_HE40 | IWINFO_HTMODE_HE80 | IWINFO_HTMODE_HE80_80 | IWINFO_HTMODE_HE160
    )
}

/// iwinfo_htmode_is_eht
pub fn iwinfo_htmode_is_eht(htmode: i32) -> bool {
    matches!(
        htmode,
        IWINFO_HTMODE_EHT20
            | IWINFO_HTMODE_EHT40
            | IWINFO_HTMODE_EHT80
            | IWINFO_HTMODE_EHT80_80
            | IWINFO_HTMODE_EHT160
            | IWINFO_HTMODE_EHT320
    )
}

// ------------------------------------------------------------- if up/down

/// iwinfo_ifup: true (C `1`) when the interface was brought up.
pub fn iwinfo_ifup(ifname: &str) -> bool {
    let mut ifr = Ifreq::new(ifname);
    if iwinfo_ioctl(SIOCGIFFLAGS, &mut ifr) != 0 {
        return false;
    }
    ifr.set_flags(ifr.flags() | (IFF_UP | IFF_RUNNING));
    iwinfo_ioctl(SIOCSIFFLAGS, &mut ifr) == 0
}

/// iwinfo_ifdown
pub fn iwinfo_ifdown(ifname: &str) -> bool {
    let mut ifr = Ifreq::new(ifname);
    if iwinfo_ioctl(SIOCGIFFLAGS, &mut ifr) != 0 {
        return false;
    }
    ifr.set_flags(ifr.flags() & !(IFF_UP | IFF_RUNNING));
    iwinfo_ioctl(SIOCSIFFLAGS, &mut ifr) == 0
}

/// iwinfo_ifmac: set the locally administered bit and bump octets 1 and 2.
pub fn iwinfo_ifmac(ifname: &str) -> bool {
    let mut ifr = Ifreq::new(ifname);
    if iwinfo_ioctl(SIOCGIFHWADDR, &mut ifr) != 0 {
        return false;
    }
    // ifr_hwaddr.sa_data starts at union offset 2 (after sa_family)
    ifr.data[2] |= 0x02;
    ifr.data[3] = ifr.data[3].wrapping_add(1);
    ifr.data[4] = ifr.data[4].wrapping_add(1);
    iwinfo_ioctl(SIOCSIFHWADDR, &mut ifr) == 0
}

// ---------------------------------------------------------- devices.txt

/// sscanf() cursor for the two devices.txt line formats.
struct Scan<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Scan<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && isspace(self.s[self.i]) {
            self.i += 1;
        }
    }

    /// `%hx`
    fn hx(&mut self) -> Option<u16> {
        self.ws();
        let (v, end) = strtol16(&self.s[self.i..]);
        if end == 0 {
            return None;
        }
        self.i += end;
        Some(v as u16)
    }

    /// `%d` (as i64; callers narrow like the C conversion does)
    fn d(&mut self) -> Option<i64> {
        self.ws();
        let s = &self.s[self.i..];
        let mut j = 0;
        let mut neg = false;
        if j < s.len() && (s[j] == b'+' || s[j] == b'-') {
            neg = s[j] == b'-';
            j += 1;
        }
        let start = j;
        let mut v: i64 = 0;
        while j < s.len() && s[j].is_ascii_digit() {
            v = v.wrapping_mul(10).wrapping_add((s[j] - b'0') as i64);
            j += 1;
        }
        if j == start {
            return None;
        }
        self.i += j;
        Some(if neg { -v } else { v })
    }

    /// `%hd`
    fn hd(&mut self) -> Option<i16> {
        self.d().map(|v| v as i16)
    }

    /// `%x` into an unsigned int
    fn hx_wide(&mut self) -> Option<u32> {
        self.ws();
        let (v, end) = strtol16(&self.s[self.i..]);
        if end == 0 {
            return None;
        }
        self.i += end;
        Some(v as u32)
    }

    /// A literal non-space format character (no whitespace skipping).
    fn lit(&mut self, c: u8) -> bool {
        if self.s.get(self.i) == Some(&c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    /// `%N[^"]`: one to N characters other than `excl`.
    fn set(&mut self, max: usize, excl: u8) -> Option<&'a [u8]> {
        let s = &self.s[self.i..];
        let n = s.iter().take(max).position(|&c| c == excl).unwrap_or(s.len().min(max));
        if n == 0 {
            return None;
        }
        self.i += n;
        Some(&s[..n])
    }
}

/// `sscanf(buf, "%hx %hx %hx %hx %hd %hd \"%63[^\"]\" \"%63[^\"]\"", ...)`:
/// fills `e` field by field and returns the conversion count.
fn sscanf_ids(buf: &[u8], e: &mut HardwareEntry) -> i32 {
    let mut sc = Scan { s: buf, i: 0 };
    let mut n = 0;
    macro_rules! step {
        ($v:expr) => {
            match $v {
                Some(x) => {
                    n += 1;
                    x
                }
                None => return n,
            }
        };
    }
    e.vendor_id = step!(sc.hx());
    e.device_id = step!(sc.hx());
    e.subsystem_vendor_id = step!(sc.hx());
    e.subsystem_device_id = step!(sc.hx());
    e.txpower_offset = step!(sc.hd());
    e.frequency_offset = step!(sc.hd());
    sc.ws();
    if !sc.lit(b'"') {
        return n;
    }
    let v = step!(sc.set(63, b'"'));
    set_cstr(&mut e.vendor_name, v);
    if !sc.lit(b'"') {
        return n;
    }
    sc.ws();
    if !sc.lit(b'"') {
        return n;
    }
    let d = step!(sc.set(63, b'"'));
    set_cstr(&mut e.device_name, d);
    if !sc.lit(b'"') {
        return n;
    }
    n
}

/// `sscanf(buf, "\"%127[^\"]\" %hd %hd \"%63[^\"]\" \"%63[^\"]\"", ...)`
fn sscanf_compatible(buf: &[u8], e: &mut HardwareEntry) -> i32 {
    let mut sc = Scan { s: buf, i: 0 };
    let mut n = 0;
    macro_rules! step {
        ($v:expr) => {
            match $v {
                Some(x) => {
                    n += 1;
                    x
                }
                None => return n,
            }
        };
    }
    if !sc.lit(b'"') {
        return n;
    }
    let c = step!(sc.set(127, b'"'));
    set_cstr(&mut e.compatible, c);
    if !sc.lit(b'"') {
        return n;
    }
    e.txpower_offset = step!(sc.hd());
    e.frequency_offset = step!(sc.hd());
    sc.ws();
    if !sc.lit(b'"') {
        return n;
    }
    let v = step!(sc.set(63, b'"'));
    set_cstr(&mut e.vendor_name, v);
    if !sc.lit(b'"') {
        return n;
    }
    sc.ws();
    if !sc.lit(b'"') {
        return n;
    }
    let d = step!(sc.set(63, b'"'));
    set_cstr(&mut e.device_name, d);
    if !sc.lit(b'"') {
        return n;
    }
    n
}

/// The per-line body of iwinfo_hardware(): parse one fgets() chunk and
/// match it against `id`; Some(entry) when it is the entry to return.
fn iwinfo_hardware_line(buf: &[u8], id: &HardwareId) -> Option<HardwareEntry> {
    let buf = cstr(buf);
    if buf.first() == Some(&b'#') {
        return None;
    }
    let mut e = HardwareEntry::default();
    if sscanf_ids(buf, &mut e) != 8 && sscanf_compatible(buf, &mut e) != 5 {
        return None;
    }
    if e.vendor_id != 0xffff && e.vendor_id != id.vendor_id {
        return None;
    }
    if e.device_id != 0xffff && e.device_id != id.device_id {
        return None;
    }
    if e.subsystem_vendor_id != 0xffff && e.subsystem_vendor_id != id.subsystem_vendor_id {
        return None;
    }
    if e.subsystem_device_id != 0xffff && e.subsystem_device_id != id.subsystem_device_id {
        return None;
    }
    if cstr(&e.compatible) != cstr(&id.compatible) {
        return None;
    }
    Some(e)
}

/// iwinfo_hardware() over an in-memory copy of the database file.
pub fn iwinfo_hardware_from(db: &[u8], id: &HardwareId) -> Option<HardwareEntry> {
    fgets_chunks(db, 256 - 1).into_iter().find_map(|line| iwinfo_hardware_line(line, id))
}

/// iwinfo_hardware: first devices.txt entry matching `id` (0xffff wildcards,
/// exact compatible string).
pub fn iwinfo_hardware(id: &HardwareId) -> Option<HardwareEntry> {
    let db = std::fs::read(IWINFO_HARDWARE_FILE).ok()?;
    iwinfo_hardware_from(&db, id)
}

// ------------------------------------------------------------ /proc/mtd

/// `fscanf(mtd, "mtd%d: %x %*x %127s", &off, &len, buf)` at `pos`:
/// (conversions assigned, new position, off, len, name). Literal characters
/// must match exactly; `%d`/`%x`/`%s` skip leading whitespace; `%*x` is
/// consumed but not counted.
fn fscanf_mtd_line(data: &[u8], pos: usize) -> (i32, usize, i32, u32, Vec<u8>) {
    let mut sc = Scan { s: data, i: pos };
    for &c in b"mtd" {
        if !sc.lit(c) {
            return (0, sc.i, 0, 0, Vec::new());
        }
    }
    let Some(off) = sc.d() else {
        return (0, sc.i, 0, 0, Vec::new());
    };
    let off = off as i32;
    if !sc.lit(b':') {
        return (1, sc.i, off, 0, Vec::new());
    }
    let Some(len) = sc.hx_wide() else {
        return (1, sc.i, off, 0, Vec::new());
    };
    if sc.hx_wide().is_none() {
        return (2, sc.i, off, len, Vec::new());
    }
    sc.ws();
    let s = &data[sc.i..];
    let n = s.iter().take(127).position(|&c| isspace(c)).unwrap_or(s.len().min(127));
    if n == 0 {
        return (2, sc.i, off, len, Vec::new());
    }
    sc.i += n;
    (3, sc.i, off, len, s[..n].to_vec())
}

/// The fgets()/fscanf() alternation of iwinfo_hardware_id_from_mtd over the
/// /proc/mtd contents: the matching partition index or -1.
pub fn mtd_find_partition(data: &[u8]) -> (i32, u32) {
    let mut pos = 0;
    let mut off = -1;
    let mut len = 0;
    loop {
        // fgets(buf, 128, mtd)
        if pos >= data.len() {
            break;
        }
        let rest = &data[pos..];
        pos += match rest.iter().take(127).position(|&c| c == b'\n') {
            Some(i) => i + 1,
            None => rest.len().min(127),
        };
        // fscanf(mtd, "mtd%d: %x %*x %127s", &off, &len, buf)
        let (n, npos, o, l, name) = fscanf_mtd_line(data, pos);
        pos = npos;
        if n < 3 || (name != b"\"boardconfig\"" && name != b"\"EEPROM\"" && name != b"\"factory\"") {
            off = -1;
            continue;
        }
        off = o;
        len = l;
        break;
    }
    (off, len)
}

/// iwinfo_hardware_id_from_mtd: scan the board-config partition for the
/// AR531X / AR5416 / Rt3xxx / MediaTek EEPROM magics.
pub fn iwinfo_hardware_id_from_mtd(id: &mut HardwareId) -> i32 {
    let Ok(mtd) = std::fs::read("/proc/mtd") else {
        return -1;
    };
    let (off, len) = mtd_find_partition(&mtd);
    if off < 0 {
        return -1;
    }
    let Ok(mut f) = std::fs::File::open(format!("/dev/mtdblock{off}")) else {
        return -1;
    };
    // DEVIATION: the C code mmap()s the partition with MAP_LOCKED and reads
    // 16-bit words through the mapping; reading the same bytes with read()
    // yields identical data without the mlock requirement.
    let mut bc = Vec::new();
    if f.read_to_end(&mut bc).is_ok() {
        let word = |i: i64| -> u16 {
            if i < 0 {
                return 0;
            }
            let b = i as usize * 2;
            match bc.get(b..b + 2) {
                Some(w) => u16::from_ne_bytes([w[0], w[1]]),
                None => 0,
            }
        };
        id.vendor_id = 0;
        id.device_id = 0;
        let mut o: i64 = (len as i64) / 2 - 0x800;
        while o >= 0 {
            let w = word(o);
            /* AR531X board data magic */
            if w == 0x3533 && word(o + 1) == 0x3131 {
                id.vendor_id = word(o + 0x7d);
                id.device_id = word(o + 0x7c);
                id.subsystem_vendor_id = word(o + 0x84);
                id.subsystem_device_id = word(o + 0x83);
                break;
            }
            /* AR5416 EEPROM magic */
            else if w == 0xA55A || w == 0x5AA5 {
                id.vendor_id = word(o + 0x0D);
                id.device_id = word(o + 0x0E);
                id.subsystem_vendor_id = word(o + 0x13);
                id.subsystem_device_id = word(o + 0x14);
                break;
            }
            /* Rt3xxx SoC */
            else if matches!(
                w,
                0x3050 | 0x5030 | 0x3051 | 0x5130 | 0x3052 | 0x5230 | 0x3350 | 0x5033 | 0x3352 | 0x5233 | 0x3662
                    | 0x6236 | 0x3883 | 0x8338 | 0x5350 | 0x5053
            ) {
                /* vendor: RaLink */
                id.vendor_id = 0x1814;
                id.subsystem_vendor_id = 0x1814;
                /* device */
                if (w & 0xf0) == 0x30 || (w & 0xff) == 0x53 {
                    id.device_id = (w >> 8) | ((w & 0x00ff) << 8);
                } else {
                    id.device_id = w;
                }
                /* subsystem from EEPROM_NIC_CONF0_RF_TYPE */
                id.subsystem_device_id = (word(o + 0x1a) & 0x0f00) >> 8;
            } else if matches!(w, 0x7620 | 0x2076 | 0x7628 | 0x2876 | 0x7688 | 0x8876) {
                /* vendor: MediaTek */
                id.vendor_id = 0x14c3;
                id.subsystem_vendor_id = 0x14c3;
                /* device */
                if (w & 0xff) == 0x76 {
                    id.device_id = (w >> 8) | ((w & 0x00ff) << 8);
                } else {
                    id.device_id = w;
                }
                /* subsystem from EEPROM_NIC_CONF0_RF_TYPE */
                id.subsystem_device_id = (word(o + 0x1a) & 0x0f00) >> 8;
            }
            o -= 0x800;
        }
    }
    if id.vendor_id != 0 && id.device_id != 0 {
        0
    } else {
        -1
    }
}

// ------------------------------------------------------------------- RSN

/// iwinfo_parse_rsn_cipher
fn iwinfo_parse_rsn_cipher(idx: u8, ciphers: &mut u16) {
    match idx {
        0 => *ciphers |= IWINFO_CIPHER_NONE as u16,
        1 => *ciphers |= IWINFO_CIPHER_WEP40 as u16,
        2 => *ciphers |= IWINFO_CIPHER_TKIP as u16,
        3 => {} /* WRAP */
        4 => *ciphers |= IWINFO_CIPHER_CCMP as u16,
        5 => *ciphers |= IWINFO_CIPHER_WEP104 as u16,
        8 => *ciphers |= IWINFO_CIPHER_GCMP as u16,
        9 => *ciphers |= IWINFO_CIPHER_GCMP256 as u16,
        10 => *ciphers |= IWINFO_CIPHER_CCMP256 as u16,
        /* 6 AES-128-CMAC, 7 no group addressed, 11..13 BIP */
        _ => {}
    }
}

const MS_OUI: [u8; 3] = [0x00, 0x50, 0xf2];
const IEEE80211_OUI: [u8; 3] = [0x00, 0x0f, 0xac];

fn oui_at(data: &[u8], off: usize) -> Option<[u8; 3]> {
    data.get(off..off + 3).map(|b| [b[0], b[1], b[2]])
}

fn is_known_oui(data: &[u8], off: usize) -> bool {
    matches!(oui_at(data, off), Some(o) if o == MS_OUI || o == IEEE80211_OUI)
}

/// iwinfo_parse_rsn: `data` is the IE payload (version field included).
// DEVIATION: the C walks `data` with unchecked pointer arithmetic (and a
// uint8_t `len` that wraps below 2); a truncated or malformed IE reads past
// its end there. Here every access is bounds checked and reads as absent.
pub fn iwinfo_parse_rsn(c: &mut CryptoEntry, data: &[u8], defcipher: u16, defauth: u8) {
    let mut wpa_version: u8 = 0;
    let mut p = 2usize;
    let mut len = (data.len() as i32) - 2;

    if oui_at(data, p) == Some(MS_OUI) {
        wpa_version |= 1;
    } else if oui_at(data, p) == Some(IEEE80211_OUI) {
        wpa_version |= 2;
    }

    if len < 4 {
        c.group_ciphers |= defcipher;
        c.pair_ciphers |= defcipher;
        c.auth_suites |= defauth;
        return;
    }

    if is_known_oui(data, p) {
        iwinfo_parse_rsn_cipher(data.get(p + 3).copied().unwrap_or(0), &mut c.group_ciphers);
    }

    p += 4;
    len -= 4;

    if len < 2 {
        c.pair_ciphers |= defcipher;
        c.auth_suites |= defauth;
        return;
    }

    let at = |i: usize| -> u8 { data.get(i).copied().unwrap_or(0) };
    let mut count = (at(p) as i32) | ((at(p + 1) as i32) << 8);
    if 2 + count * 4 > len {
        return;
    }

    for i in 0..count as usize {
        if is_known_oui(data, p + 2 + i * 4) {
            iwinfo_parse_rsn_cipher(at(p + 2 + i * 4 + 3), &mut c.pair_ciphers);
        }
    }

    p += 2 + count as usize * 4;
    len -= 2 + count * 4;

    if len < 2 {
        c.auth_suites |= defauth;
        return;
    }

    count = (at(p) as i32) | ((at(p + 1) as i32) << 8);
    if 2 + count * 4 > len {
        return;
    }

    for i in 0..count as usize {
        if is_known_oui(data, p + 2 + i * 4) {
            match at(p + 2 + i * 4 + 3) {
                1 => {
                    /* IEEE 802.1x */
                    c.wpa_version |= wpa_version;
                    c.auth_suites |= IWINFO_KMGMT_8021X as u8;
                }
                2 => {
                    /* PSK */
                    c.wpa_version |= wpa_version;
                    c.auth_suites |= IWINFO_KMGMT_PSK as u8;
                }
                8 => {
                    /* SAE */
                    c.wpa_version |= 4;
                    c.auth_suites |= IWINFO_KMGMT_SAE as u8;
                }
                11..=13 => {
                    /* 802.1x Suite-B / Suite-B-192 / FT SHA-384 */
                    c.wpa_version |= 4;
                    c.auth_suites |= IWINFO_KMGMT_8021X as u8;
                }
                18 => {
                    /* OWE */
                    c.wpa_version |= 4;
                    c.auth_suites |= IWINFO_KMGMT_OWE as u8;
                }
                _ => {}
            }
        }
    }
}

// ------------------------------------------------------------------- uci

/// uci_lookup_option_string(): the option's value when it is a plain string.
pub fn uci_lookup_option_string<'a>(s: &'a Section, name: &str) -> Option<&'a str> {
    let o = &s.options[s.find_option(name)?];
    match &o.value {
        OptionValue::Str(v) => std::str::from_utf8(v).ok(),
        OptionValue::List(_) => None,
    }
}

/// iwinfo_uci_get_radio: the `wifi-device` section `name` of the wireless
/// config (extended `@type[n]` lookups allowed) when its `type` is `ty`.
pub fn iwinfo_uci_get_radio(name: &str, ty: &str) -> Option<Section> {
    let mut ctx = owrt_uci::Context::new();
    let mut ptr = Ptr {
        package: Some("wireless".to_owned()),
        section: Some(name.to_owned()),
        flags: if name.starts_with('@') { LOOKUP_EXTENDED } else { 0 },
        ..Ptr::default()
    };
    if owrt_uci::ops::lookup_ptr(&mut ctx, &mut ptr, None, true).is_err() {
        return None;
    }
    let (Some(p), Some(s)) = (ptr.p, ptr.s) else {
        return None;
    };
    let sec = ctx.root.get(p)?.sections.get(s)?;
    if sec.ty != "wifi-device" {
        return None;
    }
    let opt = uci_lookup_option_string(sec, "type")?;
    if opt != ty {
        return None;
    }
    Some(sec.clone())
}

// ------------------------------------------------------------------ ubus

/// iwinfo_ubus_query_cb: walk `network.wireless status` for the interface
/// entry whose `ifname` matches and return its `config.<field>` string.
fn iwinfo_ubus_query_cb(msg: &Json, ifname: &str, field: &str) -> Option<String> {
    let Json::Object(radios) = msg else {
        return None;
    };
    for (_, radio) in radios {
        let Json::Object(items) = radio else {
            continue;
        };
        for (name, cur2) in items {
            let Json::Array(ifaces) = cur2 else {
                continue;
            };
            if name != "interfaces" {
                continue;
            }
            for cur3 in ifaces {
                let Some(Json::Str(name)) = cur3.get("ifname") else {
                    continue;
                };
                let Some(cfg @ Json::Object(_)) = cur3.get("config") else {
                    continue;
                };
                if name != ifname {
                    continue;
                }
                let Some(Json::Str(res)) = cfg.get(field) else {
                    continue;
                };
                return Some(res.clone());
            }
        }
    }
    None
}

/// iwinfo_ubus_query: `ubus call network.wireless status` (250 ms) and pick
/// `config.<field>` of the interface `ifname`. None when nothing was copied.
pub fn iwinfo_ubus_query(ifname: &str, field: &str) -> Option<String> {
    let mut ctx = Connection::connect(None).ok()?;
    // ubus_lookup_id() has no timeout in libubus; 0 waits like it does.
    let id = ctx.lookup_id("network.wireless", 0).ok()?;
    let reply = ctx.invoke_status(id, "status", &[], 250).ok()?;
    let msg = fields_to_json(&reply.fields());
    iwinfo_ubus_query_cb(&msg, ifname, field)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dbm_mw() {
        assert_eq!(iwinfo_dbm2mw(0), 1);
        assert_eq!(iwinfo_dbm2mw(10), 10);
        assert_eq!(iwinfo_dbm2mw(20), 100);
        assert_eq!(iwinfo_dbm2mw(23), 199);
        assert_eq!(iwinfo_dbm2mw(-1), 1);
        assert_eq!(iwinfo_mw2dbm(1), 0);
        assert_eq!(iwinfo_mw2dbm(100), 20);
        // the C loop divides by LOG10_MAGIC while fin > 1.000001: 200 mW -> 24
        assert_eq!(iwinfo_mw2dbm(200), 24);
        assert_eq!(iwinfo_mw2dbm(10), 10);
        assert_eq!(iwinfo_mw2dbm(11), 11);
        assert_eq!(iwinfo_mbm2dbm(2300), 23);
        assert_eq!(iwinfo_mbm2dbm(-150), -1);
    }

    #[test]
    fn format_hwmodes() {
        assert_eq!(iwinfo_format_hwmodes(IWINFO_80211_B | IWINFO_80211_G | IWINFO_80211_N), "b/g/n");
        assert_eq!(iwinfo_format_hwmodes(IWINFO_80211_A | IWINFO_80211_N | IWINFO_80211_AC | IWINFO_80211_AX), "ac/ax/a/n");
        assert_eq!(iwinfo_format_hwmodes(0xff), "ad/ac/ax/a/b/be/g/n");
        assert_eq!(iwinfo_format_hwmodes(0), "");
        assert_eq!(iwinfo_format_hwmodes(1 << 20), "");
        assert_eq!(iwinfo_htmode_name(IWINFO_HTMODE_HE80), Some("HE80"));
        assert_eq!(iwinfo_htmode_name(0), None);
        assert_eq!(iwinfo_band_name(IWINFO_BAND_6), Some("6 GHz"));
        assert!(iwinfo_htmode_is_vht(IWINFO_HTMODE_VHT80_80));
        assert!(!iwinfo_htmode_is_ht(IWINFO_HTMODE_NOHT));
        assert!(iwinfo_htmode_is_eht(IWINFO_HTMODE_EHT320));
        assert_eq!(iwinfo_band2ghz(IWINFO_BAND_5 as u8), 5);
        assert_eq!(iwinfo_ghz2band(6), IWINFO_BAND_6 as u8);
    }

    const DB: &[u8] = b"# libiwinfo hardware database\n\
# vendor id | device id | subsystem vendor id | subsystem device id |\n\
0x0777 0x11ac 0x0777 0xe7f9    0      0  \"Ubiquiti\" \"LiteBeam 5AC\"\n\
0xffff 0xffff 0xffff 0xc3a2   10      0  \"Ubiquiti\" \"PicoStation2 HP\"\n\
0x168c 0xffff 0x0777 0xe005    5      0  \"Ubiquiti\" \"NanoStation M5\" /* airOS XM */\n\
0x14c3 0x7915 0x14c3 0x7915    0      0  \"MediaTek\" \"MT7915E\"\n\
0x0000 0x0000 0x148f 0x7601    0      0  \"MediaTek\" \"MT7601U\"\n\
\"mediatek,mt7981-wmac\"  0      0  \"MediaTek\" \"MT7981\"\n\
\"ralink,rt7620-wmac\"    0      -1  \"Ralink\" \"MT7620\"\n";

    fn id(v: u16, d: u16, sv: u16, sd: u16, compat: &[u8]) -> HardwareId {
        let mut id = HardwareId { vendor_id: v, device_id: d, subsystem_vendor_id: sv, subsystem_device_id: sd, ..HardwareId::default() };
        set_cstr(&mut id.compatible, compat);
        id
    }

    #[test]
    fn hardware_db() {
        let e = iwinfo_hardware_from(DB, &id(0x14c3, 0x7915, 0x14c3, 0x7915, b"")).expect("mt7915");
        assert_eq!(cstr(&e.vendor_name), b"MediaTek");
        assert_eq!(cstr(&e.device_name), b"MT7915E");
        assert_eq!(cstr(&e.compatible), b"");
        // wildcard vendor/device/subvendor, exact subdevice, offsets
        let e = iwinfo_hardware_from(DB, &id(0x168c, 0x002a, 0x0777, 0xc3a2, b"")).expect("pico");
        assert_eq!(cstr(&e.device_name), b"PicoStation2 HP");
        assert_eq!(e.txpower_offset, 10);
        // trailing comment after the last field is ignored
        let e = iwinfo_hardware_from(DB, &id(0x168c, 0x0029, 0x0777, 0xe005, b"")).expect("nano");
        assert_eq!(cstr(&e.device_name), b"NanoStation M5");
        assert_eq!(e.txpower_offset, 5);
        // compatible-string lines require zero ids and an exact compatible
        let e = iwinfo_hardware_from(DB, &id(0, 0, 0, 0, b"mediatek,mt7981-wmac")).expect("mt7981");
        assert_eq!(cstr(&e.vendor_name), b"MediaTek");
        assert_eq!(cstr(&e.device_name), b"MT7981");
        assert_eq!(cstr(&e.compatible), b"mediatek,mt7981-wmac");
        assert_eq!(e.vendor_id, 0);
        let e = iwinfo_hardware_from(DB, &id(0, 0, 0, 0, b"ralink,rt7620-wmac")).expect("rt7620");
        assert_eq!(e.frequency_offset, -1);
        assert!(iwinfo_hardware_from(DB, &id(0x14c3, 0x7981, 0, 0, b"mediatek,mt7981-wmac")).is_none());
        assert!(iwinfo_hardware_from(DB, &id(0, 0, 0, 0, b"")).is_none());
        assert!(iwinfo_hardware_from(DB, &id(0x1234, 0x5678, 0, 0, b"")).is_none());
        // a 64+ char name fails the %63[^"] conversion and skips the line
        let long = b"0x1111 0x2222 0x3333 0x4444 0 0 \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" \"x\"\n";
        assert!(iwinfo_hardware_from(long, &id(0x1111, 0x2222, 0x3333, 0x4444, b"")).is_none());
    }

    #[test]
    fn proc_mtd() {
        let mtd = b"dev:    size   erasesize  name\n\
mtd0: 00040000 00010000 \"u-boot\"\n\
mtd1: 00010000 00010000 \"u-boot-env\"\n\
mtd2: 00010000 00010000 \"factory\"\n\
mtd3: 00f80000 00010000 \"firmware\"\n";
        assert_eq!(mtd_find_partition(mtd), (2, 0x10000));
        let none = b"dev:    size   erasesize  name\nmtd0: 00040000 00010000 \"u-boot\"\n";
        assert_eq!(mtd_find_partition(none).0, -1);
        assert_eq!(mtd_find_partition(b"").0, -1);
    }

    #[test]
    fn libc_emulation() {
        assert_eq!(atoi(b"  42abc"), 42);
        assert_eq!(atoi(b"-7\n"), -7);
        assert_eq!(atoi(b"x"), 0);
        assert_eq!(strtol16(b"aa:bb"), (0xaa, 2));
        assert_eq!(strtol16(b"0x14c3\n"), (0x14c3, 6));
        assert_eq!(strtol16(b":aa"), (0, 0));
        assert_eq!(strtoul16(b"0e8d"), 0x0e8d);
        assert_eq!(strtok(b"ssid=My Net\n", b" =\t\n"), (Some(&b"ssid"[..]), &b"My Net\n"[..]));
        assert_eq!(strtok(b"\n\n", b"\n").0, None);
        assert_eq!(strtok(b"key", b"=").1, &b""[..]);
        assert_eq!(fgets_chunks(b"abc\ndef", 128), vec![&b"abc\n"[..], &b"def"[..]]);
        assert_eq!(fgets_chunks(b"abcdef\n", 4), vec![&b"abc"[..], &b"def"[..], &b"\n"[..]]);
    }

    #[test]
    fn rsn_ie() {
        // RSN IE payload: version 1, group CCMP, 1 pairwise CCMP, 1 AKM PSK
        let ie = [
            0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,
        ];
        let mut c = CryptoEntry::default();
        iwinfo_parse_rsn(&mut c, &ie, IWINFO_CIPHER_CCMP as u16, IWINFO_KMGMT_8021X as u8);
        assert_eq!(c.wpa_version, 2);
        assert_eq!(c.group_ciphers, IWINFO_CIPHER_CCMP as u16);
        assert_eq!(c.pair_ciphers, IWINFO_CIPHER_CCMP as u16);
        assert_eq!(c.auth_suites, IWINFO_KMGMT_PSK as u8);
        // short IE: defaults
        let mut c = CryptoEntry::default();
        iwinfo_parse_rsn(&mut c, &ie[..4], IWINFO_CIPHER_TKIP as u16, IWINFO_KMGMT_PSK as u8);
        assert_eq!(c.pair_ciphers, IWINFO_CIPHER_TKIP as u16);
        assert_eq!(c.auth_suites, IWINFO_KMGMT_PSK as u8);
        assert_eq!(c.wpa_version, 0);
    }

    #[test]
    fn ubus_query_cb() {
        let msg = owrt_ubus::json::parse(
            r#"{"radio0":{"up":true,"interfaces":[{"section":"default_radio0","ifname":"phy0-ap0","config":{"mode":"ap","ssid":"x"}},{"ifname":"phy0-mesh0","config":{"mode":"mesh","mesh_id":"MyMesh"}}]},"radio1":{"interfaces":[]}}"#,
        )
        .unwrap();
        assert_eq!(iwinfo_ubus_query_cb(&msg, "phy0-mesh0", "mesh_id"), Some("MyMesh".to_owned()));
        assert_eq!(iwinfo_ubus_query_cb(&msg, "phy0-ap0", "mesh_id"), None);
        assert_eq!(iwinfo_ubus_query_cb(&msg, "phy1-ap0", "mesh_id"), None);
    }
}
