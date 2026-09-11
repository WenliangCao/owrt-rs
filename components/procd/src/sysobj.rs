//! `system.c`'s read-only halves: the `board` and `info` replies.
//!
//! Everything here is what the shipping procd answers OUTSIDE PID 1 too, so
//! it is directly comparable in r65. Quirks preserved on purpose:
//!
//! - the aarch64 `system` string is built from cpuinfo's "CPU revision" as
//!   `ARMv8 Processor rev <hex-parsed>`;
//! - the os-release value parser copies ONLY what sits inside quotes (or
//!   after a backslash) -- an unquoted value comes out empty;
//! - `rootfs_type` follows an overlay mount to /rom rather than parsing
//!   lowerdir;
//! - `localtime` is `time() + tm_gmtoff`, i.e. a UTC-shifted epoch, not a
//!   string.

use owrt_ubus::blob::BlobBuf;
use std::io::Read;

#[repr(C)]
struct Utsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

#[repr(C)]
struct Sysinfo {
    uptime: i64,
    loads: [u64; 3],
    totalram: u64,
    freeram: u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap: u64,
    procs: u16,
    _pad: u16,
    totalhigh: u64,
    freehigh: u64,
    mem_unit: u32,
    _reserved: [u8; 256],
}

#[repr(C)]
struct StatVfs {
    f_bsize: u64,
    f_frsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_favail: u64,
    _tail: [u8; 64],
}

#[repr(C)]
struct Tm {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    tm_wday: i32,
    tm_yday: i32,
    tm_isdst: i32,
    tm_gmtoff: i64,
    tm_zone: *const u8,
}

extern "C" {
    fn uname(buf: *mut Utsname) -> i32;
    fn sysinfo(info: *mut Sysinfo) -> i32;
    fn statvfs(path: *const u8, buf: *mut StatVfs) -> i32;
    fn time(t: *mut i64) -> i64;
    fn localtime_r(t: *const i64, tm: *mut Tm) -> *mut Tm;
}

fn cstr(field: &[u8]) -> &str {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    std::str::from_utf8(&field[..end]).unwrap_or("")
}

/// First line of a file, cut at tab/newline like `strtok(line, "\t\n")`.
fn first_line(path: &str) -> Option<String> {
    let raw = std::fs::read(path).ok()?;
    let line: Vec<u8> = raw
        .iter()
        .copied()
        .take_while(|b| *b != b'\n' && *b != b'\t' && *b != 0)
        .collect();
    if line.is_empty() {
        return None;
    }
    String::from_utf8(line).ok()
}

/// `system_rootfs_type()`.
fn rootfs_type() -> Option<String> {
    let mounts = std::fs::read_to_string("/proc/self/mounts").ok()?;
    let mut mp = "/";
    // The overlay redirect re-walks the list once, exactly like the fseek.
    for _pass in 0..2 {
        for line in mounts.lines() {
            let mut it = line.split(' ');
            let (_dev, point, ty) = (it.next()?, it.next()?, it.next()?);
            if point != mp {
                continue;
            }
            if ty == "overlay" {
                if mp == "/rom" {
                    return Some("overlay".to_string());
                }
                mp = "/rom";
                break;
            }
            return Some(ty.to_string());
        }
        if mp != "/rom" {
            return None;
        }
    }
    None
}

/// The os-release value parser: only quoted runs and backslash escapes make
/// it into the output.
fn release_value(val: &str) -> String {
    let mut out = String::new();
    let mut chars = val.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' | '"' => {
                for c in chars.by_ref() {
                    if c == ch {
                        break;
                    }
                    out.push(c);
                }
            }
            '\\' => {
                if let Some(c) = chars.next() {
                    out.push(c);
                }
            }
            _ => {}
        }
    }
    out
}

/// `system_board()`.
pub fn build_board(b: &mut BlobBuf) {
    // SAFETY: uname writes into a zeroed struct of the kernel's layout.
    let mut uts: Utsname = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { uname(&mut uts) } >= 0 {
        b.msg_string("kernel", cstr(&uts.release));
        b.msg_string("hostname", cstr(&uts.nodename));
    }

    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in cpuinfo.lines() {
            // strtok(line, "\t:") / strtok(NULL, "\t\n"): the value keeps
            // its leading ": " minus the first two bytes (val + 2).
            let Some((key, val)) = line.split_once(':') else { continue };
            let key = key.trim_end_matches(['\t', ' ']);
            if key.eq_ignore_ascii_case("CPU revision") {
                let rev = i64::from_str_radix(val.trim(), 16).unwrap_or(0);
                b.msg_string("system", &format!("ARMv8 Processor rev {rev}"));
                break;
            }
        }
    }

    if let Some(model) =
        first_line("/tmp/sysinfo/model").or_else(|| first_line("/proc/device-tree/model"))
    {
        b.msg_string("model", &model);
    } else if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in cpuinfo.lines() {
            let Some((key, val)) = line.split_once(':') else { continue };
            let key = key.trim_end_matches(['\t', ' ']);
            if key.eq_ignore_ascii_case("machine") || key.eq_ignore_ascii_case("hardware") {
                b.msg_string("model", val.strip_prefix(' ').unwrap_or(val));
                break;
            }
        }
    }

    if let Some(name) = first_line("/tmp/sysinfo/board_name") {
        b.msg_string("board_name", &name);
    } else if let Some(compat) = first_line("/proc/device-tree/compatible") {
        b.msg_string("board_name", &compat.replace(',', "-"));
    }

    if let Some(t) = rootfs_type() {
        b.msg_string("rootfs_type", &t);
    }

    if let Ok(osrel) = std::fs::read_to_string("/usr/lib/os-release") {
        let t = b.msg_open_table("release");
        for line in osrel.lines() {
            let Some((key, val)) = line.split_once('=') else { continue };
            let key = match key {
                k if k.eq_ignore_ascii_case("NAME") => "distribution",
                k if k.eq_ignore_ascii_case("VERSION") => "version",
                k if k.eq_ignore_ascii_case("BUILD_ID") => "revision",
                k if k.eq_ignore_ascii_case("VERSION_CODENAME") => "codename",
                k if k.eq_ignore_ascii_case("OPENWRT_BOARD") => "target",
                k if k.eq_ignore_ascii_case("OPENWRT_RELEASE") => "description",
                k if k.eq_ignore_ascii_case("OPENWRT_BUILD_DATE") => "builddate",
                k if k.eq_ignore_ascii_case("FIRMWARE_URL") => "firmware_url",
                _ => continue,
            };
            b.msg_string(key, &release_value(val));
        }
        b.msg_close(t);
    }
}

/// `kscale()`.
fn kscale(blocks: u64, bs: u64) -> u64 {
    (blocks * bs + 512) / 1024
}

/// `system_info()`. Returns false on the two UNKNOWN_ERROR paths.
pub fn build_info(b: &mut BlobBuf) -> bool {
    // SAFETY: sysinfo fills the kernel-layout struct.
    let mut info: Sysinfo = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { sysinfo(&mut info) } != 0 {
        return false;
    }
    let Ok(mut file) = std::fs::File::open("/proc/meminfo") else {
        return false;
    };
    // procfs reports size zero. Start with room for the normal report rather
    // than growing from 32 bytes through several small read() calls. Read to
    // EOF on every request, including reports larger than this initial room.
    let mut meminfo = String::with_capacity(4096);
    if file.read_to_string(&mut meminfo).is_err() {
        return false;
    }
    drop(file);
    let mut available: u64 = 0;
    let mut cached: u64 = 0;
    for line in meminfo.lines() {
        let Some((key, val)) = line.split_once(':') else { continue };
        if key.eq_ignore_ascii_case("MemAvailable") {
            available = 1024 * crate::sys::atoi_u32(val) as u64;
        } else if key.eq_ignore_ascii_case("Cached") {
            cached = 1024 * crate::sys::atoi_u32(val) as u64;
        }
    }

    // SAFETY: time with a null-free out param; localtime_r fills `tm`.
    let now = unsafe { time(std::ptr::null_mut()) };
    let mut tm: Tm = unsafe { std::mem::zeroed() };
    // SAFETY: `now` and `tm` are live locals.
    if unsafe { localtime_r(&now, &mut tm) }.is_null() {
        return false;
    }

    b.msg_u32("localtime", (now + tm.tm_gmtoff) as u32);
    b.msg_u32("uptime", info.uptime as u32);
    let a = b.msg_open_array("load");
    for l in info.loads {
        b.msg_u32("", l as u32);
    }
    b.msg_close(a);
    let unit = info.mem_unit as u64;
    let m = b.msg_open_table("memory");
    b.msg_u64("total", unit * info.totalram);
    b.msg_u64("free", unit * info.freeram);
    b.msg_u64("shared", unit * info.sharedram);
    b.msg_u64("buffered", unit * info.bufferram);
    b.msg_u64("available", available);
    b.msg_u64("cached", cached);
    b.msg_close(m);

    for (path, name) in [(c"/", "root"), (c"/tmp", "tmp")] {
        // SAFETY: statvfs fills the struct for a NUL-terminated path.
        let mut s: StatVfs = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { statvfs(path.as_ptr().cast(), &mut s) } != 0 {
            continue;
        }
        let frsize = if s.f_frsize == 0 { s.f_bsize } else { s.f_frsize };
        let t = b.msg_open_table(name);
        b.msg_u64("total", kscale(s.f_blocks, frsize));
        b.msg_u64("free", kscale(s.f_bfree, frsize));
        b.msg_u64("used", kscale(s.f_blocks - s.f_bfree, frsize));
        b.msg_u64("avail", kscale(s.f_bavail, frsize));
        b.msg_close(t);
    }

    let sw = b.msg_open_table("swap");
    b.msg_u64("total", unit * info.totalswap);
    b.msg_u64("free", unit * info.freeswap);
    b.msg_close(sw);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_release_parser_keeps_only_quoted_text() {
        assert_eq!(release_value("\"OpenWrt\""), "OpenWrt");
        assert_eq!(release_value("'a' plus \"b\""), "ab");
        assert_eq!(release_value("bare-word"), "", "unquoted values vanish");
        assert_eq!(release_value("pre\\xpost"), "x", "backslash keeps one char");
    }

    #[test]
    fn board_and_info_build_on_this_host() {
        let mut b = BlobBuf::new();
        build_board(&mut b);
        let names: Vec<String> = owrt_ubus::blob::fields(b.payload()).map(|f| f.name.to_string()).collect();
        assert!(names.contains(&"kernel".to_string()), "{names:?}");
        let mut b = BlobBuf::new();
        assert!(build_info(&mut b));
        let names: Vec<String> = owrt_ubus::blob::fields(b.payload()).map(|f| f.name.to_string()).collect();
        for want in ["localtime", "uptime", "load", "memory", "swap"] {
            assert!(names.contains(&want.to_string()), "{names:?}");
        }
    }
}
