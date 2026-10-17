//! Owned NSS results and libc's process-wide credential transitions.
use std::ffi::{c_char, CStr, CString};
use std::io;
#[repr(C)]
struct Passwd {
    name: *mut c_char,
    password: *mut c_char,
    uid: u32,
    gid: u32,
    gecos: *mut c_char,
    directory: *mut c_char,
    shell: *mut c_char,
}
#[repr(C)]
struct Group {
    name: *mut c_char,
    password: *mut c_char,
    gid: u32,
    members: *mut *mut c_char,
}
unsafe extern "C" {
    fn getpwnam_r(
        name: *const c_char,
        entry: *mut Passwd,
        buffer: *mut c_char,
        length: usize,
        result: *mut *mut Passwd,
    ) -> i32;
    fn getgrnam_r(
        name: *const c_char,
        entry: *mut Group,
        buffer: *mut c_char,
        length: usize,
        result: *mut *mut Group,
    ) -> i32;
    fn initgroups(name: *const c_char, gid: u32) -> i32;
    fn setgid(gid: u32) -> i32;
    fn setuid(uid: u32) -> i32;
}
fn lookup_user_fields(name: &str, include_home: bool) -> Option<(u32, u32, String)> {
    let name = CString::new(name).ok()?;
    let mut length: usize = 1024;
    loop {
        let mut buffer = vec![0; length];
        let mut entry = std::mem::MaybeUninit::<Passwd>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: caller-owned aligned record/buffer and a terminated name;
        // reentrant libc storage is copied before any local allocation drops.
        let code = unsafe {
            getpwnam_r(
                name.as_ptr(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if code == 34 {
            length = length.checked_mul(2)?;
            continue;
        }
        if code != 0 || result.is_null() {
            return None;
        }
        // SAFETY: success with non-null result initialized this record.
        let entry = unsafe { entry.assume_init() };
        let home = if !include_home || entry.directory.is_null() {
            String::new()
        } else {
            // SAFETY: reentrant lookup supplied a terminated name in buffer.
            unsafe { CStr::from_ptr(entry.directory) }
                .to_string_lossy()
                .into_owned()
        };
        return Some((entry.uid, entry.gid, home));
    }
}
pub fn lookup_user_home(name: &str) -> Option<(u32, u32, String)> {
    lookup_user_fields(name, true)
}
pub fn lookup_user(name: &str) -> Option<(u32, u32)> {
    lookup_user_fields(name, false).map(|(uid, gid, _)| (uid, gid))
}
pub fn lookup_group(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    let mut length: usize = 1024;
    loop {
        let mut buffer = vec![0; length];
        let mut entry = std::mem::MaybeUninit::<Group>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: initialized writable buffer and one aligned output record.
        let code = unsafe {
            getgrnam_r(
                name.as_ptr(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if code == 34 {
            length = length.checked_mul(2)?;
            continue;
        }
        if code != 0 || result.is_null() {
            return None;
        }
        // SAFETY: the successful lookup initialized the record.
        return Some(unsafe { entry.assume_init() }.gid);
    }
}
pub fn init_groups(user: &str, gid: u32) -> bool {
    let Ok(user) = CString::new(user) else {
        return false;
    };
    // SAFETY: terminated name remains live; libc preserves NSS/group semantics.
    unsafe { initgroups(user.as_ptr(), gid) == 0 }
}
pub fn set_gid(gid: u32) -> io::Result<()> {
    // SAFETY: libc changes all process threads, unlike per-thread raw setgid.
    if unsafe { setgid(gid) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub fn set_uid(uid: u32) -> io::Result<()> {
    // SAFETY: scalar ID; preserve libc's process-wide credential semantics.
    if unsafe { setuid(uid) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

unsafe extern "C" {
    fn getpwuid_r(
        uid: u32,
        entry: *mut Passwd,
        buffer: *mut c_char,
        length: usize,
        result: *mut *mut Passwd,
    ) -> i32;
    fn getgrgid_r(
        gid: u32,
        entry: *mut Group,
        buffer: *mut c_char,
        length: usize,
        result: *mut *mut Group,
    ) -> i32;
}
/// ubusd's peer identity accepts only the libc name's strict UTF-8 spelling.
pub fn user_name(uid: u32) -> Option<String> {
    let mut length: usize = 1024;
    loop {
        let mut buffer = vec![0; length];
        let mut entry = std::mem::MaybeUninit::<Passwd>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: reentrant lookup writes one record and its caller-owned
        // string storage; all pointers remain private until copied below.
        let code = unsafe {
            getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if code == 34 {
            length = length.checked_mul(2)?;
            continue;
        }
        if code != 0 || result.is_null() {
            return None;
        }
        // SAFETY: successful lookup initialized the record and terminated name.
        let entry = unsafe { entry.assume_init() };
        if entry.name.is_null() {
            return None;
        }
        // SAFETY: the NSS name belongs to the live private buffer.
        return unsafe { CStr::from_ptr(entry.name) }
            .to_str()
            .ok()
            .map(str::to_owned);
    }
}
pub fn group_name(gid: u32) -> Option<String> {
    let mut length: usize = 1024;
    loop {
        let mut buffer = vec![0; length];
        let mut entry = std::mem::MaybeUninit::<Group>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: output record and backing string buffer are exclusively owned.
        let code = unsafe {
            getgrgid_r(
                gid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if code == 34 {
            length = length.checked_mul(2)?;
            continue;
        }
        if code != 0 || result.is_null() {
            return None;
        }
        // SAFETY: successful lookup initialized this record.
        let entry = unsafe { entry.assume_init() };
        if entry.name.is_null() {
            return None;
        }
        // SAFETY: the name is terminated within live reentrant lookup storage.
        return unsafe { CStr::from_ptr(entry.name) }
            .to_str()
            .ok()
            .map(str::to_owned);
    }
}
