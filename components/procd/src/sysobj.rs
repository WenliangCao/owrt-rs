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
    let uts = rustix::system::uname();
    b.msg_string("kernel", uts.release().to_str().unwrap_or(""));
    b.msg_string("hostname", uts.nodename().to_str().unwrap_or(""));

    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in cpuinfo.lines() {
            // strtok(line, "\t:") / strtok(NULL, "\t\n"): the value keeps
            // its leading ": " minus the first two bytes (val + 2).
            let Some((key, val)) = line.split_once(':') else {
                continue;
            };
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
            let Some((key, val)) = line.split_once(':') else {
                continue;
            };
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
            let Some((key, val)) = line.split_once('=') else {
                continue;
            };
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

/// `/proc/meminfo` for `system info`. The descriptor is opened once at
/// startup and every request reads the report with one pread from offset
/// zero, which makes procfs regenerate it: one syscall instead of open, a
/// read, a second read for EOF and close. The descriptor count therefore
/// stays constant after startup. Without the descriptor (no /proc yet), each
/// request falls back to the open-and-read path.
pub struct Meminfo {
    file: Option<std::fs::File>,
    buf: Vec<u8>,
}

impl Meminfo {
    const ROOM: usize = 8192;

    pub fn open() -> Meminfo {
        Meminfo {
            file: std::fs::File::open("/proc/meminfo").ok(),
            buf: Vec::new(),
        }
    }

    /// The current report, or None when it cannot be read.
    fn read(&mut self) -> Option<&[u8]> {
        use std::os::unix::fs::FileExt;
        if let Some(file) = &self.file {
            self.buf.resize(Self::ROOM, 0);
            if let Ok(mut got) = file.read_at(&mut self.buf, 0) {
                // A procfs read returns the whole report when it fits; only
                // a full buffer needs more reads to reach EOF.
                while got == self.buf.len() {
                    self.buf.resize(got + Self::ROOM, 0);
                    match file.read_at(&mut self.buf[got..], got as u64) {
                        Ok(0) => break,
                        Ok(more) => got += more,
                        Err(_) => return None,
                    }
                }
                self.buf.truncate(got);
                return Some(&self.buf);
            }
        }
        self.buf.clear();
        let mut file = std::fs::File::open("/proc/meminfo").ok()?;
        file.read_to_end(&mut self.buf).ok()?;
        Some(&self.buf)
    }
}

/// The MemAvailable and Cached values (bytes) as the C parses them:
/// `strtok(line, " :")` for the key, `strtok(NULL, " ")` for the value,
/// `strcasecmp` on the key, and a line without both parts is skipped.
pub(crate) fn scan_meminfo(text: &[u8]) -> (u64, u64) {
    let mut available: u64 = 0;
    let mut cached: u64 = 0;
    for line in text.split(|&b| b == b'\n') {
        let start = match line.iter().position(|&b| b != b' ' && b != b':') {
            Some(start) => start,
            None => continue,
        };
        let line = &line[start..];
        // Compare only the two complete keys we consume. The boundary check
        // preserves strtok's space/colon delimiter and last occurrence wins.
        let (target, key_end) = if line.len() > 12
            && matches!(line[12], b' ' | b':')
            && line[..12].eq_ignore_ascii_case(b"MemAvailable")
        {
            (&mut available, 12)
        } else if line.len() > 6
            && matches!(line[6], b' ' | b':')
            && line[..6].eq_ignore_ascii_case(b"Cached")
        {
            (&mut cached, 6)
        } else {
            continue;
        };
        let rest = &line[key_end + 1..];
        let Some(val_start) = rest.iter().position(|&b| b != b' ') else {
            continue;
        };
        let Ok(val) = std::str::from_utf8(&rest[val_start..]) else {
            continue;
        };
        *target = 1024 * crate::sys::atoi_u32(val) as u64;
    }
    (available, cached)
}

/// `system_info()`. Returns false on the two UNKNOWN_ERROR paths.
pub fn build_info(b: &mut BlobBuf, meminfo: &mut Meminfo) -> bool {
    let info = rustix::system::sysinfo();
    let Some(text) = meminfo.read() else {
        return false;
    };
    let (available, cached) = scan_meminfo(text);
    let Some(localtime) = owrt_platform::procd::compatibility::local_epoch() else {
        return false;
    };
    b.msg_u32("localtime", localtime as u32);
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
        let Ok(s) = rustix::fs::statvfs(path) else {
            continue;
        };
        let frsize = if s.f_frsize == 0 {
            s.f_bsize
        } else {
            s.f_frsize
        };
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
    fn meminfo_scan_matches_the_c_tokenizer() {
        let text = b"MemTotal:        1000 kB\nMEMAVAILABLE:   123 kB\n  Cached:  7 kB\nCached\n:  :bad\nSwapCached:  9 kB\n";
        assert_eq!(scan_meminfo(text), (123 * 1024, 7 * 1024));
        // A key without a value is skipped (strtok returns NULL for val).
        assert_eq!(scan_meminfo(b"Cached:\nMemAvailable\n"), (0, 0));
        assert_eq!(
            scan_meminfo(b"Cached:5\nMemAvailable:6 kB"),
            (6 * 1024, 5 * 1024)
        );
    }

    #[test]
    fn meminfo_keys_require_a_complete_token_and_keep_last_value() {
        for (text, expected) in [
            (&b"CachedExtra: 9\nMemAvailableExtra: 8"[..], (0, 0)),
            (&b"Cached\t9\nMemAvailable\t8"[..], (0, 0)),
            (
                &b"::  cAcHeD 7\n :mEmAvAiLaBlE: 8"[..],
                (8 * 1024, 7 * 1024),
            ),
            (
                &b"Cached: 7\nCached:\nCached\nMemAvailable: 8\nMemAvailable "[..],
                (8 * 1024, 7 * 1024),
            ),
            (
                &b"Cached: 7\nCached 9\nMemAvailable: 8\nMemAvailable 10"[..],
                (10 * 1024, 9 * 1024),
            ),
            // strtok uses only space after the first delimiter: the second
            // colon reaches atoi and changes the previous value to zero.
            (
                &b"Cached: 7\nCached::9\nMemAvailable: 8\nMemAvailable::10"[..],
                (0, 0),
            ),
        ] {
            assert_eq!(scan_meminfo(text), expected, "{text:?}");
        }
    }

    #[test]
    fn meminfo_pread_and_fallback_agree() {
        let mut kept = Meminfo::open();
        let mut fresh = Meminfo {
            file: None,
            buf: Vec::new(),
        };
        let a = kept.read().map(|t| scan_meminfo(t));
        let b = fresh.read().map(|t| scan_meminfo(t));
        assert!(a.is_some() && b.is_some());
        // Values move between the two reads; both must at least be present.
        assert!(a.unwrap().0 > 0 && b.unwrap().0 > 0);
    }

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
        let names: Vec<String> = owrt_ubus::blob::fields(b.payload())
            .map(|f| f.name.to_string())
            .collect();
        assert!(names.contains(&"kernel".to_string()), "{names:?}");
        let mut b = BlobBuf::new();
        assert!(build_info(&mut b, &mut Meminfo::open()));
        let names: Vec<String> = owrt_ubus::blob::fields(b.payload())
            .map(|f| f.name.to_string())
            .collect();
        for want in ["localtime", "uptime", "load", "memory", "swap"] {
            assert!(names.contains(&want.to_string()), "{names:?}");
        }
    }
}
