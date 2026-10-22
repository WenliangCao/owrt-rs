//! rpcd sys.c port (`rpc-sys` object): packagelist over the apk database,
//! password_set via /bin/passwd, sysupgrade/factory/reboot triggers.

use crate::session::{arg, arg_str, Reply};
use crate::{file, Ctx, Deferrer};
use owrt_ubus::blob::MsgType;
use owrt_ubus::convert::object_to_payload;
use owrt_ubus::{status, BlobBuf, Request};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::Duration;

pub fn signature() -> Vec<(&'static str, Vec<(&'static str, MsgType)>)> {
    use MsgType::*;
    vec![
        ("packagelist", vec![("all", Int8)]),
        ("password_set", vec![("user", String), ("password", String)]),
        ("upgrade_test", vec![]),
        ("upgrade_start", vec![("keep", Int8)]),
        ("upgrade_clean", vec![]),
        ("factory", vec![]),
        ("reboot", vec![]),
    ]
}

/// rpc_errno_status
fn errno_status(e: &std::io::Error) -> i32 {
    match e.raw_os_error() {
        Some(13) => status::PERMISSION_DENIED, // EACCES
        Some(20) => status::INVALID_ARGUMENT,  // ENOTDIR
        Some(2) => status::NOT_FOUND,          // ENOENT
        Some(22) => status::INVALID_ARGUMENT,  // EINVAL
        _ => status::UNKNOWN_ERROR,
    }
}

fn code(c: i32) -> Reply {
    Reply::empty(c)
}

/// is_all_or_world: `pkg` (NUL-terminated) against world lines terminated by
/// one of "\n@~<>=" (man 5 apk-world). `world` None means `all`.
fn is_all_or_world(pkg: &[u8], world: Option<&[&[u8]]>) -> bool {
    let Some(world) = world else { return true };
    for item in world {
        if item.first() == Some(&0) {
            break; // C stops at the sentinel entry (*world[i] == 0)
        }
        let mut c = 0;
        while c < pkg.len() && c < item.len() && pkg[c] == item[c] {
            c += 1;
        }
        if c == pkg.len() && c < item.len() && b"\n@~<>=".contains(&item[c]) {
            return true;
        }
    }
    false
}

fn is_blank(line: &[u8]) -> bool {
    line.iter().all(|c| c.is_ascii_whitespace())
}

/// sscanf(line, "X: %127s"): skip "X:" then whitespace, take one token of at
/// most 127 bytes. None when no token.
fn scan_token(line: &[u8]) -> Option<Vec<u8>> {
    let rest = line.get(2..)?;
    let start = rest.iter().position(|c| !c.is_ascii_whitespace())?;
    let tok: Vec<u8> = rest[start..]
        .iter()
        .take_while(|c| !c.is_ascii_whitespace())
        .take(127)
        .copied()
        .collect();
    if tok.is_empty() {
        None
    } else {
        Some(tok)
    }
}

/// fgets(line, 516): lines longer than 515 bytes arrive in chunks.
fn fgets_chunks(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    for line in data.split_inclusive(|&c| c == b'\n') {
        let mut rest = line;
        while rest.len() > 515 {
            out.push(&rest[..515]);
            rest = &rest[515..];
        }
        if !rest.is_empty() {
            out.push(rest);
        }
    }
    out
}

fn parse_abi(line: &[u8], abi: &mut Vec<u8>) {
    let Some(payload) = line.get(2..) else { return };
    let mut toks = payload
        .split(|c| matches!(c, b' ' | b'=' | b'\n'))
        .filter(|t| !t.is_empty());
    while let Some(tok) = toks.next() {
        if tok == b"openwrt:abiversion" {
            if let Some(v) = toks.next() {
                *abi = v.iter().take(127).copied().collect();
            }
            break;
        }
    }
}

fn packagelist(raw: &[u8]) -> Reply {
    let all = arg(raw, "all", MsgType::Int8)
        .and_then(|f| f.as_bool())
        .unwrap_or(false);
    let Ok(db) = fs::read("/lib/apk/db/installed") else {
        return code(status::NOT_FOUND);
    };
    let mut world_buf: Vec<u8> = Vec::new();
    let mut world: Option<Vec<&[u8]>> = None;
    if !all {
        let mut f = match fs::File::open("/etc/apk/world") {
            Ok(f) => f,
            Err(e) => return code(errno_status(&e)),
        };
        let size = match f.metadata() {
            Ok(m) => m.len() as usize,
            Err(e) => return code(errno_status(&e)),
        };
        if size == 0 {
            return code(status::UNKNOWN_ERROR);
        }
        world_buf.resize(size, 0);
        if f.read_exact(&mut world_buf).is_err() {
            return code(status::UNKNOWN_ERROR);
        }
        if world_buf[size - 1] != b'\n' {
            return code(status::UNKNOWN_ERROR);
        }
        world_buf.push(0);
    }
    if !all {
        // world[i] points at each line start; the last entry is the NUL sentinel
        let mut items: Vec<&[u8]> = Vec::new();
        let mut start = 0;
        for (i, &c) in world_buf.iter().enumerate() {
            if c == b'\n' {
                items.push(&world_buf[start..]);
                start = i + 1;
            }
        }
        items.push(&world_buf[start..]);
        world = Some(items);
    }
    let mut b = BlobBuf::new();
    let t = b.msg_open_table("packages");
    let (mut abi, mut pkg, mut ver): (Vec<u8>, Vec<u8>, Vec<u8>) = (vec![], vec![], vec![]);
    for line in fgets_chunks(&db) {
        match line.first() {
            Some(b'P') => pkg = scan_token(line).unwrap_or_default(),
            Some(b'V') => ver = scan_token(line).unwrap_or_default(),
            Some(b'g') => parse_abi(line, &mut abi),
            _ => {
                if is_blank(line) {
                    if !pkg.is_empty() && !ver.is_empty() {
                        let w = world.as_deref();
                        let mut keep = is_all_or_world(&pkg, w);
                        let mut name = pkg.clone();
                        if !abi.is_empty() && abi.len() <= pkg.len() {
                            name.truncate(pkg.len() - abi.len());
                            if !keep {
                                keep = is_all_or_world(&name, w);
                            }
                        }
                        if keep {
                            b.msg_string(
                                &String::from_utf8_lossy(&name),
                                &String::from_utf8_lossy(&ver),
                            );
                        }
                    }
                    abi.clear();
                    pkg.clear();
                    ver.clear();
                }
            }
        }
    }
    b.msg_close(t);
    Reply::one(0, b.into_payload())
}

/// rpc_cgi_password_set: `/bin/passwd <user>` fed the password twice.
fn password_set(raw: &[u8]) -> Reply {
    let (Some(user), Some(password)) = (arg_str(raw, "user"), arg_str(raw, "password")) else {
        return code(status::INVALID_ARGUMENT);
    };
    let passwd = "/bin/passwd";
    let Ok(m) = fs::metadata(passwd) else {
        return code(status::NOT_FOUND);
    };
    if m.permissions().mode() & 0o100 == 0 {
        return code(status::PERMISSION_DENIED);
    }
    let child = Command::new(passwd)
        .arg(user)
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return code(errno_status(&e)),
    };
    let mut stdin = child.stdin.take().expect("piped");
    let written = (|| -> std::io::Result<()> {
        stdin.write_all(password.as_bytes())?;
        stdin.write_all(b"\n")?;
        std::thread::sleep(Duration::from_millis(100));
        stdin.write_all(password.as_bytes())?;
        stdin.write_all(b"\n")
    })();
    // A rejected username can close the pipe before our second write. Child
    // does not reap on drop, so close stdin and wait on every post-spawn path.
    drop(stdin);
    let _ = child.wait();
    match written {
        Ok(()) => code(0),
        Err(error) => code(errno_status(&error)),
    }
}

pub enum Outcome {
    Now(Request, Reply),
    Deferred,
}

pub fn call(req: Request, ctx: &Ctx, deferrer: &Deferrer) -> Outcome {
    let exec_timeout_ms = ctx.exec_timeout_ms;
    let raw = &req.data;
    let reply = match req.method.as_str() {
        "packagelist" => packagelist(raw),
        "password_set" => password_set(raw),
        "upgrade_test" => {
            // ops->exec({"sysupgrade", "--test", "/tmp/firmware.bin"}): PATH lookup, deferred
            let Some(cmd) = file::exec_lookup("sysupgrade") else {
                return Outcome::Now(req, code(status::NOT_FOUND));
            };
            return match deferrer.defer(req, move || {
                let params = vec!["--test".to_owned(), "/tmp/firmware.bin".to_owned()];
                match file::run_command(&cmd, &params, &[], exec_timeout_ms) {
                    Ok(json) => Reply::one(status::OK, object_to_payload(&json)),
                    Err(c) => code(c),
                }
            }) {
                None => Outcome::Deferred,
                Some((req, reply)) => Outcome::Now(req, reply),
            };
        }
        "upgrade_start" => {
            let keep = arg(raw, "keep", MsgType::Int8)
                .and_then(|f| f.as_bool())
                .unwrap_or(false);
            if keep {
                ctx.delayed
                    .borrow_mut()
                    .exec(&["/sbin/sysupgrade", "/tmp/firmware.bin"]);
            } else {
                ctx.delayed
                    .borrow_mut()
                    .exec(&["/sbin/sysupgrade", "-n", "/tmp/firmware.bin"]);
            }
            code(0)
        }
        "upgrade_clean" => match fs::remove_file("/tmp/firmware.bin") {
            Ok(()) => code(0),
            Err(e) => code(errno_status(&e)),
        },
        "factory" => {
            ctx.delayed
                .borrow_mut()
                .exec(&["/sbin/jffs2reset", "-y", "-r"]);
            code(0)
        }
        "reboot" => {
            let pid = owrt_platform::rpcd::delayed_reboot();
            ctx.delayed.borrow_mut().track(pid);
            code(0)
        }
        _ => code(status::METHOD_NOT_FOUND),
    };
    Outcome::Now(req, reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_abi_field_preserves_the_previous_value() {
        let mut abi = Vec::new();
        parse_abi(b"g:openwrt:abiversion=2026\n", &mut abi);
        assert_eq!(abi, b"2026");
        for line in [b"g".as_slice(), b"g:", b"g:openwrt:abiversion="] {
            parse_abi(line, &mut abi);
            assert_eq!(abi, b"2026");
        }
    }

    #[test]
    fn world_match() {
        let w: Vec<&[u8]> = vec![b"luci\n", b"rpcd=1.0\n", b"uci~x\n", b"\0"];
        assert!(is_all_or_world(b"luci", Some(&w)));
        assert!(is_all_or_world(b"rpcd", Some(&w)));
        assert!(!is_all_or_world(b"rpc", Some(&w)));
        assert!(!is_all_or_world(b"lucix", Some(&w)));
        assert!(is_all_or_world(b"anything", None));
    }

    #[test]
    fn tokens_and_chunks() {
        assert_eq!(
            scan_token(b"P: libubox20260213\n").unwrap(),
            b"libubox20260213"
        );
        assert_eq!(scan_token(b"P:x y\n").unwrap(), b"x");
        assert!(scan_token(b"P:\n").is_none());
        let long = vec![b'a'; 600];
        let mut data = long.clone();
        data.push(b'\n');
        let chunks = fgets_chunks(&data);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 515);
    }
}
