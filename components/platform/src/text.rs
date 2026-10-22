//! Serialized access to libc's shared crypt output; no pointer escapes.
use std::ffi::{c_char, CStr};
use std::sync::Mutex;
#[cfg_attr(target_env = "gnu", link(name = "crypt"))]
unsafe extern "C" {
    fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
}
static CRYPT: Mutex<()> = Mutex::new(());
pub fn with_crypt(key: &CStr, salt: &CStr, compare: impl FnOnce(&[u8]) -> bool) -> bool {
    let _guard = CRYPT
        .lock()
        .expect("crypt comparison panicked while holding libc output");
    // SAFETY: terminated inputs live across crypt; its global buffer stays
    // locked until the borrowed comparison finishes. No result pointer escapes.
    let result = unsafe { crypt(key.as_ptr(), salt.as_ptr()) };
    if result.is_null() {
        return false;
    }
    // SAFETY: successful crypt output is terminated and held under CRYPT.
    compare(unsafe { CStr::from_ptr(result) }.to_bytes())
}
