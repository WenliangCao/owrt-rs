//! libc-compatible text/regex operations, with no pointer escaping.
use std::ffi::CString;

extern "C" {
    fn regcomp(preg: *mut u8, pattern: *const u8, cflags: i32) -> i32;
    fn regexec(
        preg: *const u8,
        string: *const u8,
        nmatch: usize,
        pmatch: *mut u8,
        eflags: i32,
    ) -> i32;
    fn regfree(preg: *mut u8);
}

const REG_EXTENDED: i32 = 1;
const REG_NOSUB: i32 = 1 << 3;
/// `regex_t` is opaque and its size differs per libc: glibc 64 bytes,
/// musl 64 bytes (aarch64). 256 over-allocates safely because only the
/// library writes into it. The wrapper forces the ALIGNMENT the real
/// struct has (pointers inside -> 8): a bare [u8; N] is align-1, and
/// handing that to code that loads 8-byte fields is UB on paper even
/// where aarch64 tolerates the load. (R73 hygiene.)
const REGEX_T_SIZE: usize = 256;

#[repr(C, align(8))]
struct RegexStorage([u8; REGEX_T_SIZE]);

/// `eq_regex_cmp()`. Plain equality, or POSIX extended regex through the
/// platform's own regcomp/regexec -- the same implementation the C calls, so
/// there is no second regex dialect to keep in step. A pattern that fails to
/// compile is false, exactly as in the C.
pub fn regex_matches(s: &str, pattern: &str) -> bool {
    let (Ok(cpat), Ok(cs)) = (CString::new(pattern), CString::new(s)) else {
        return false;
    };
    let mut reg = RegexStorage([0u8; REGEX_T_SIZE]);
    // SAFETY: `reg` is a zeroed, 8-aligned buffer at least as large as
    // regex_t on this platform, and `cpat` is a NUL-terminated string that
    // outlives the call.
    if unsafe {
        regcomp(
            reg.0.as_mut_ptr(),
            cpat.as_ptr().cast(),
            REG_EXTENDED | REG_NOSUB,
        )
    } != 0
    {
        return false;
    }
    // SAFETY: `reg` was successfully compiled above; nmatch 0 with a null
    // pmatch is what REG_NOSUB expects.
    let hit = unsafe {
        regexec(
            reg.0.as_ptr(),
            cs.as_ptr().cast(),
            0,
            std::ptr::null_mut(),
            0,
        ) == 0
    };
    // SAFETY: frees the compiled regex exactly once.
    unsafe { regfree(reg.0.as_mut_ptr()) };
    hit
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

unsafe extern "C" {
    fn time(value: *mut i64) -> i64;
    fn localtime_r(value: *const i64, out: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

pub fn local_epoch() -> Option<i64> {
    // SAFETY: scalar time query; localtime_r initializes one correctly aligned
    // Linux64 tm. No libc-owned string pointer is returned to the caller.
    unsafe {
        let now = time(std::ptr::null_mut());
        let mut tm = std::mem::MaybeUninit::<Tm>::uninit();
        if localtime_r(&now, tm.as_mut_ptr().cast()).is_null() {
            None
        } else {
            Some(now + tm.assume_init().tm_gmtoff)
        }
    }
}

unsafe extern "C" {
    fn openlog(ident: *const std::ffi::c_char, option: i32, facility: i32);
    fn syslog(priority: i32, format: *const std::ffi::c_char, ...);
    fn closelog();
    fn if_nametoindex(name: *const std::ffi::c_char) -> u32;
}
pub fn open_procd_log() {
    // SAFETY: libc retains only this static program identifier.
    unsafe {
        openlog(c"procd".as_ptr(), 0, 24);
    }
}
pub fn syslog_line(priority: i32, line: &std::ffi::CStr) {
    // SAFETY: format and message are terminated and live for the call.
    unsafe {
        syslog(priority, c"%s".as_ptr(), line.as_ptr());
    }
}
pub fn syslog_instance(
    ident: &std::ffi::CStr,
    facility: i32,
    priority: i32,
    line: &std::ffi::CStr,
) {
    // SAFETY: ident remains live until closelog and the static restore, so
    // openlog never retains a dangling caller pointer after this function.
    unsafe {
        openlog(ident.as_ptr(), 0, facility);
        syslog(priority, c"%s".as_ptr(), line.as_ptr());
        closelog();
        openlog(c"procd".as_ptr(), 0, 24);
    }
}
pub fn interface_index(name: &str) -> u32 {
    let Ok(name) = CString::new(name) else {
        return 0;
    };
    // SAFETY: terminated caller-owned name; scalar result does not borrow it.
    unsafe { if_nametoindex(name.as_ptr()) }
}
