//! Borrowed libc readdir entries, retaining the existing d_type and allocation
//! behavior. The directory handle and each short-lived entry never escape.
use std::ffi::{c_char, c_void, CStr, CString};
use std::io;
use std::ptr::NonNull;

#[repr(C)]
struct Dirent {
    ino: u64,
    off: i64,
    reclen: u16,
    ty: u8,
    name: [c_char; 256],
}
unsafe extern "C" {
    fn opendir(path: *const c_char) -> *mut c_void;
    fn readdir(dir: *mut c_void) -> *mut Dirent;
    fn closedir(dir: *mut c_void) -> i32;
    fn __errno_location() -> *mut i32;
}
struct Directory(NonNull<c_void>);
impl Drop for Directory {
    fn drop(&mut self) {
        // SAFETY: this handle came from opendir and has one owner.
        unsafe {
            closedir(self.0.as_ptr());
        }
    }
}

pub fn entries(path: &str, mut visit: impl FnMut(&[u8], u8)) -> io::Result<()> {
    let path = CString::new(path).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: the terminated path lives across opendir; only success is owned.
    let dir = Directory(
        NonNull::new(unsafe { opendir(path.as_ptr()) }).ok_or_else(io::Error::last_os_error)?,
    );
    loop {
        // SAFETY: Linux exposes this calling thread's errno; clearing it before
        // readdir distinguishes an error return from end-of-directory.
        unsafe {
            *__errno_location() = 0;
        }
        // SAFETY: exclusively owned open handle; previous entry borrow ended.
        let entry = unsafe { readdir(dir.0.as_ptr()) };
        if entry.is_null() {
            let err = io::Error::last_os_error();
            return if err.raw_os_error() == Some(0) {
                Ok(())
            } else {
                Err(err)
            };
        }
        // SAFETY: verified Linux64 dirent prefix, followed by a terminated name.
        // Do not form a reference to the potentially shorter trailing array.
        let (name, ty) = unsafe {
            (
                CStr::from_ptr(std::ptr::addr_of!((*entry).name).cast()).to_bytes(),
                (*entry).ty,
            )
        };
        visit(name, ty);
    }
}

#[test]
fn dirent_layout_matches_linux_sdk() {
    assert_eq!(std::mem::size_of::<Dirent>(), 280);
    assert_eq!(std::mem::offset_of!(Dirent, ty), 18);
    assert_eq!(std::mem::offset_of!(Dirent, name), 19);
}

#[test]
fn entries_clears_errno_before_readdir_and_propagates_open_errors() {
    let missing = entries("/nonexistent-owrt-platform-dir-check", |_, _| {});
    assert_eq!(
        missing.unwrap_err().kind(),
        io::ErrorKind::NotFound,
        "missing directory error must propagate"
    );

    let nul = entries("bad\0dir", |_, _| {});
    assert_eq!(nul.unwrap_err().kind(), io::ErrorKind::InvalidInput);

    let temp_dir =
        std::env::temp_dir().join(format!("owrt-platform-dir-test-{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("alpha"), b"").unwrap();
    let path_str = temp_dir.to_str().unwrap();

    let mut seen = Vec::new();
    let (res, _) = crate::unix::with_errno(5, || {
        entries(path_str, |name, _| {
            seen.push(String::from_utf8_lossy(name).into_owned());
        })
    });
    let _ = std::fs::remove_dir_all(&temp_dir);
    res.expect("stale errno before readdir must not be reported as an error");
    assert!(seen.iter().any(|n| n == "alpha"));
}
