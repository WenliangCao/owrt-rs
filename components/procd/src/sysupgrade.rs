//! `system.c`'s firmware half plus `sysupgrade.c`: the
//! `validate_firmware_image` call (a fork/exec of
//! /usr/libexec/validate_firmware_image whose stdout must be one JSON
//! object) and `sysupgrade_exec_upgraded` (chroot to the prefix, hand over
//! the watchdog fd, export UPGRADE_* variables, execvp /sbin/upgraded --
//! which replaces THIS process on success).
//!
//! Faithful quirks:
//! - any spawn/exec failure of the validate script surfaces as
//!   "no JSON input" (the C forks first; a failed execl leaves an empty
//!   pipe);
//! - the first complete JSON value wins and trailing output is ignored
//!   (json_tokener semantics); a complete non-object is
//!   "result is not an JSON object" (sic);
//! - the child is NOT waited for -- the main loop's reaper collects it;
//! - option names are prefixed UPGRADE_OPT_, uppercased, and dropped whole
//!   if any character is not alphanumeric or '_'; only integer-typed values
//!   are exported, formatted as unsigned;
//! - a failed execvp cleans up (WDTFD unset, cloexec restored, chroot("."))
//!   and returns; the caller answers UBUS_STATUS_UNKNOWN_ERROR with no
//!   error table, exactly like the C.

use std::ffi::CString;
use std::io::Read;

use owrt_ubus::blob::{BlobBuf, MsgType};

pub const VALIDATE_SCRIPT: &str = "/usr/libexec/validate_firmware_image";

use owrt_ubus::convert::json_to_fields as json_to_blob;

/// `validate_firmware_image_call()`: run the validate script on `file` and
/// return the validation JSON as a blobmsg payload, or the error message the
/// C would put in a sysupgrade error reply.
pub fn validate_call(file: &str) -> Result<Vec<u8>, String> {
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(VALIDATE_SCRIPT);
    cmd.arg(file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    crate::proc::inherit_ignored_sigpipe(&mut cmd);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        // The C forks unconditionally; a failed execl exits the child with
        // an empty pipe, which reads as zero bytes below.
        Err(_) => return Err("no JSON input".to_string()),
    };
    let Some(mut out) = child.stdout.take() else {
        return Err("no JSON input".to_string());
    };
    // The reaper in the main loop collects the child; the C never waits
    // either. Dropping the handle does not kill or wait.
    drop(child);

    let mut acc: Vec<u8> = Vec::new();
    let mut buf = [0u8; 64];
    let mut err = "incomplete JSON input".to_string();
    loop {
        let n = match out.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(format!(
                    "read() failed: {} ({})",
                    e,
                    e.raw_os_error().unwrap_or(0)
                ))
            }
        };
        acc.extend_from_slice(&buf[..n]);
        // Try after every chunk: the first complete value wins and trailing
        // bytes are ignored, like json_tokener_parse_ex. An error at this
        // point may still be an incomplete document, so keep reading.
        let text = String::from_utf8_lossy(&acc);
        match owrt_ubus::json::parse_prefix(&text) {
            Ok(owrt_ubus::json::Json::Object(fields)) => {
                let mut b = BlobBuf::new();
                for (k, v) in &fields {
                    json_to_blob(&mut b, k, v);
                }
                return Ok(b.payload().to_vec());
            }
            Ok(_) => return Err("result is not an JSON object".to_string()),
            Err(e) => {
                err = format!("failed to parse JSON: {e}");
            }
        }
    }
    if acc.is_empty() {
        return Err("no JSON input".to_string());
    }
    Err(err)
}

/// One UPGRADE_OPT_ export: `Some((name, value))` when the option survives
/// the C's filters, else `None`. `ty`/`data` are the blobmsg field type and
/// payload.
pub fn option_env(name: &str, ty: u32, data: &[u8]) -> Option<(String, String)> {
    let mut out = String::with_capacity(12 + name.len());
    out.push_str("UPGRADE_OPT_");
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c.to_ascii_uppercase());
        } else {
            crate::sys::stderr_line(&format!("Option \"{name}\" contains invalid characters"));
            return None;
        }
    }
    // Only the three integer types are exported; the C prints the value
    // through an int then "%u".
    let v: u32 = match ty {
        t if t == MsgType::Int32 as u32 && data.len() >= 4 => {
            u32::from_be_bytes(data[..4].try_into().ok()?)
        }
        t if t == MsgType::Int16 as u32 && data.len() >= 2 => {
            u16::from_be_bytes(data[..2].try_into().ok()?) as u32
        }
        t if t == MsgType::Int8 as u32 && !data.is_empty() => data[0] as u32,
        t => {
            crate::sys::stderr_line(&format!("Option \"{name}\" has unsupported type: {t}"));
            return None;
        }
    };
    Some((out, format!("{v}")))
}

/// `sysupgrade_exec_upgraded()`. Returns only when something failed; on
/// success execvp replaces this process with /sbin/upgraded.
///
/// # Safety
/// Call only from the sole process thread, with no concurrent readers or
/// writers of libc environment storage. The handover mutates the environment
/// before exec and restores watchdog inheritance if exec fails.
#[expect(
    unsafe_code,
    reason = "the process owner must establish environment mutation prerequisites"
)]
pub unsafe fn exec_upgraded(
    prefix: &str,
    path: &str,
    backup: Option<&str>,
    command: Option<&str>,
    options: &[(String, String)],
    wdt: &mut crate::watchdog::Wdt,
) {
    let Ok(cprefix) = CString::new(prefix) else {
        return;
    };
    if rustix::process::chroot(&cprefix).is_err() {
        crate::sys::stderr_line("Failed to chroot for upgraded exec.");
        return;
    }

    if let Some(fd) = wdt.handover_fd() {
        wdt.set_cloexec(false);
        std::env::set_var("WDTFD", fd.to_string());
    }
    if let Some(b) = backup {
        std::env::set_var("UPGRADE_BACKUP", b);
    }
    for (k, v) in options {
        std::env::set_var(k, v);
    }

    let argv0 = CString::new("/sbin/upgraded").unwrap();
    let mut argv: Vec<CString> = vec![argv0.clone(), CString::new(path).unwrap_or_default()];
    if let Some(c) = command {
        if let Ok(c) = CString::new(c) {
            argv.push(c);
        }
    }
    let _ = owrt_platform::procd::process::execvp(&argv0, &argv);

    // Cleanup on failure, exactly the C's order.
    crate::sys::stderr_line("Failed to exec upgraded.");
    std::env::remove_var("WDTFD");
    wdt.set_cloexec(true);
    let Ok(dot) = CString::new(".") else { return };
    if rustix::process::chroot(&dot).is_err() {
        crate::sys::stderr_line("Failed to reset chroot, exiting.");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_names_follow_the_c_filter() {
        // Int32 payload 7, big-endian, like blobmsg.
        let (k, v) = option_env("save_config", MsgType::Int32 as u32, &7u32.to_be_bytes()).unwrap();
        assert_eq!(k, "UPGRADE_OPT_SAVE_CONFIG");
        assert_eq!(v, "7");
        assert!(option_env("bad-name", MsgType::Int32 as u32, &7u32.to_be_bytes()).is_none());
        assert!(
            option_env("s", MsgType::String as u32, b"x\0").is_none(),
            "strings are not exported"
        );
        let (_, v) = option_env("x", MsgType::Int8 as u32, &[1]).unwrap();
        assert_eq!(v, "1");
    }

    #[test]
    fn validate_maps_a_missing_script_to_no_json_input() {
        // The script path is fixed; on a dev host it does not exist, which
        // must read exactly like the C's failed execl: an empty pipe.
        if std::path::Path::new(VALIDATE_SCRIPT).exists() {
            return; // a real OpenWrt host; the other cases cover it
        }
        assert_eq!(
            validate_call("/nonexistent"),
            Err("no JSON input".to_string())
        );
    }
}
