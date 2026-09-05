//! The `file` object (rpcd file.c port): read/write/list/stat/lstat/md5/
//! remove/exec with session ACL checks through the original rpcd's
//! `session access` (scope `file`).

use crate::util;
use crate::Ctx;
use owrt_ubus::json::Json;
use owrt_ubus::status;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use owrt_ubus::sys::{poll_fds, PollFd, POLLIN};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const FILE_MIN_SIZE: u64 = 4096;
pub const FILE_MAX_SIZE: u64 = 4096 * 64;
const CMDLINE_MAX: usize = 1024;

pub fn signature() -> Vec<(&'static str, Vec<(&'static str, owrt_ubus::MsgType)>)> {
    use owrt_ubus::MsgType::*;
    vec![
        ("read", vec![("path", String), ("base64", Int8), ("ubus_rpc_session", String)]),
        ("write", vec![("path", String), ("data", String), ("append", Int8), ("mode", Int32), ("base64", Int8), ("ubus_rpc_session", String)]),
        ("list", vec![("path", String), ("ubus_rpc_session", String)]),
        ("lstat", vec![("path", String), ("ubus_rpc_session", String)]),
        ("stat", vec![("path", String), ("ubus_rpc_session", String)]),
        ("md5", vec![("path", String), ("ubus_rpc_session", String)]),
        ("remove", vec![("path", String), ("ubus_rpc_session", String)]),
        ("exec", vec![("command", String), ("params", Array), ("env", Table), ("ubus_rpc_session", String)]),
    ]
}

/// errno -> ubus status (file.c rpc_errno_status)
fn errno_status(e: &std::io::Error) -> i32 {
    match e.raw_os_error() {
        Some(13) => status::PERMISSION_DENIED,
        Some(20) => status::INVALID_ARGUMENT,
        Some(2) => status::NOT_FOUND,
        Some(22) => status::INVALID_ARGUMENT,
        _ => status::UNKNOWN_ERROR,
    }
}

fn arg_str<'a>(args: &'a Json, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Json::as_str)
}

fn arg_bool(args: &Json, key: &str) -> bool {
    matches!(args.get(key), Some(Json::Bool(true)))
}

fn add_stat(out: &mut Vec<(String, Json)>, m: &fs::Metadata) {
    let ty = if m.file_type().is_file() {
        "file"
    } else if m.file_type().is_dir() {
        "directory"
    } else if m.file_type().is_symlink() {
        "symlink"
    } else if m.file_type().is_char_device() {
        "char"
    } else if m.file_type().is_block_device() {
        "block"
    } else if m.file_type().is_fifo() {
        "fifo"
    } else if m.file_type().is_socket() {
        "socket"
    } else {
        "unknown"
    };
    out.push(("type".into(), Json::Str(ty.into())));
    out.push(("size".into(), Json::Int(m.size() as i64)));
    out.push(("mode".into(), Json::Int(m.mode() as i64)));
    out.push(("atime".into(), Json::Int(m.atime() as u32 as i64)));
    out.push(("mtime".into(), Json::Int(m.mtime() as u32 as i64)));
    out.push(("ctime".into(), Json::Int(m.ctime() as u32 as i64)));
    out.push(("inode".into(), Json::Int(m.ino() as u32 as i64)));
    out.push(("uid".into(), Json::Int(m.uid() as i64)));
    out.push(("gid".into(), Json::Int(m.gid() as i64)));
    if let Some(u) = util::user_name(m.uid()) {
        out.push(("user".into(), Json::Str(u)));
    }
    if let Some(g) = util::group_name(m.gid()) {
        out.push(("group".into(), Json::Str(g)));
    }
}

/// `rpc_check_path`: canonicalise, ACL-check, optionally stat.
fn check_path(ctx: &Ctx, args: &Json, perm: &str, want_stat: bool, use_lstat: bool) -> Result<(String, Option<fs::Metadata>), i32> {
    let Some(raw) = arg_str(args, "path") else { return Err(status::INVALID_ARGUMENT) };
    let Some(path) = util::canonicalize(raw) else { return Err(status::UNKNOWN_ERROR) };
    if !ctx.file_access(arg_str(args, "ubus_rpc_session"), &path, perm) {
        return Err(status::PERMISSION_DENIED);
    }
    if want_stat {
        let m = if use_lstat { fs::symlink_metadata(&path) } else { fs::metadata(&path) };
        match m {
            Ok(m) => Ok((path, Some(m))),
            Err(e) => Err(errno_status(&e)),
        }
    } else {
        Ok((path, None))
    }
}

pub fn read(ctx: &Ctx, args: &Json) -> Result<Option<Json>, i32> {
    let (path, m) = check_path(ctx, args, "read", true, false)?;
    let m = m.unwrap();
    if m.size() >= FILE_MAX_SIZE {
        return Err(status::NOT_SUPPORTED);
    }
    let mut f = fs::File::open(&path).map_err(|e| errno_status(&e))?;
    let want = if m.size() == 0 { FILE_MIN_SIZE } else { m.size() } as usize;
    let mut buf = vec![0u8; want];
    let n = f.read(&mut buf).map_err(|_| status::NO_DATA)?;
    if n == 0 {
        return Err(status::NO_DATA);
    }
    buf.truncate(n);
    let data = if arg_bool(args, "base64") {
        util::b64_encode(&buf)
    } else {
        String::from_utf8_lossy(&buf).into_owned()
    };
    Ok(Some(Json::Object(vec![("data".into(), Json::Str(data))])))
}

pub fn write(ctx: &Ctx, args: &Json) -> Result<Option<Json>, i32> {
    let (path, _) = check_path(ctx, args, "write", false, false)?;
    let Some(data) = arg_str(args, "data") else { return Err(status::INVALID_ARGUMENT) };
    let mode = match args.get("mode") {
        Some(Json::Int(m)) => *m as u32,
        _ => 0o666,
    };
    let mut opts = fs::OpenOptions::new();
    // rpc_file_write: umask(0) around open(path, O_CREAT | O_WRONLY | flag,
    // mode), where flag defaults to O_TRUNC and becomes O_APPEND only when
    // "append" is set.
    opts.create(true).write(true).mode(mode);
    if arg_bool(args, "append") {
        opts.append(true);
    } else {
        opts.truncate(true);
    }
    let prev_umask = util::umask_zero();
    let opened = opts.open(&path);
    util::umask_restore(prev_umask);
    let mut f = opened.map_err(|e| errno_status(&e))?;
    let bytes: Vec<u8> = if !data.is_empty() && arg_bool(args, "base64") {
        util::b64_decode(data.as_bytes()).ok_or(status::UNKNOWN_ERROR)?
    } else {
        data.as_bytes().to_vec()
    };
    let mut rv = Ok(());
    if f.write_all(&bytes).is_err() {
        rv = Err(status::UNKNOWN_ERROR);
    }
    if f.sync_all().is_err() {
        rv = Err(status::UNKNOWN_ERROR);
    }
    drop(f);
    util::sync_all();
    rv.map(|_| None)
}

pub fn md5(ctx: &Ctx, args: &Json) -> Result<Option<Json>, i32> {
    let (path, m) = check_path(ctx, args, "read", true, false)?;
    if !m.unwrap().is_file() {
        return Err(status::NOT_SUPPORTED);
    }
    let data = fs::read(&path).map_err(|e| errno_status(&e))?;
    Ok(Some(Json::Object(vec![("md5".into(), Json::Str(util::hex(&util::md5(&data))))])))
}

pub fn list(ctx: &Ctx, args: &Json) -> Result<Option<Json>, i32> {
    let (path, _) = check_path(ctx, args, "list", false, false)?;
    let rd = fs::read_dir(&path).map_err(|e| errno_status(&e))?;
    let mut entries = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let entrypath = format!("{path}/{name}");
        let Ok(m) = fs::symlink_metadata(&entrypath) else { continue };
        let mut o = vec![("name".into(), Json::Str(name))];
        add_stat(&mut o, &m);
        if m.file_type().is_symlink() {
            let mut t = Vec::new();
            if let Ok(link) = fs::read_link(&entrypath) {
                t.push(("name".into(), Json::Str(link.to_string_lossy().into_owned())));
            }
            match fs::metadata(&entrypath) {
                Ok(tm) => add_stat(&mut t, &tm),
                Err(_) => t.push(("type".into(), Json::Str("broken".into()))),
            }
            o.push(("target".into(), Json::Object(t)));
        }
        entries.push(Json::Object(o));
    }
    Ok(Some(Json::Object(vec![("entries".into(), Json::Array(entries))])))
}

pub fn stat(ctx: &Ctx, args: &Json, use_lstat: bool) -> Result<Option<Json>, i32> {
    let (path, m) = check_path(ctx, args, "list", true, use_lstat)?;
    let mut o = vec![("path".into(), Json::Str(path))];
    add_stat(&mut o, &m.unwrap());
    Ok(Some(Json::Object(o)))
}

fn remove_recursive(path: &str) -> Result<(), i32> {
    let rd = fs::read_dir(path).map_err(|e| errno_status(&e))?;
    for e in rd.flatten() {
        let entrypath = format!("{path}/{}", e.file_name().to_string_lossy());
        if let Ok(m) = fs::symlink_metadata(&entrypath) {
            if m.is_dir() {
                remove_recursive(&entrypath)?;
            } else {
                fs::remove_file(&entrypath).map_err(|e| errno_status(&e))?;
            }
        }
    }
    fs::remove_dir(path).map_err(|e| errno_status(&e))
}

pub fn remove(ctx: &Ctx, args: &Json) -> Result<Option<Json>, i32> {
    let (path, _) = check_path(ctx, args, "write", false, false)?;
    let m = fs::symlink_metadata(&path).map_err(|e| errno_status(&e))?;
    if m.is_dir() {
        remove_recursive(&path)?;
    } else {
        fs::remove_file(&path).map_err(|e| errno_status(&e))?;
    }
    Ok(None)
}

/// file.c `rpc_file_exec_lookup`: as given if a regular file, else PATH search.
pub fn exec_lookup(cmd: &str) -> Option<String> {
    if fs::metadata(cmd).map(|m| m.is_file()).unwrap_or(false) {
        return Some(cmd.to_owned());
    }
    let search = std::env::var("PATH").unwrap_or_else(|_| "/bin:/usr/bin:/sbin:/usr/sbin".into());
    for dir in search.split(':') {
        let p = format!("{dir}/{cmd}");
        if fs::metadata(&p).map(|m| m.is_file()).unwrap_or(false) {
            return Some(p);
        }
    }
    None
}

pub fn exec(ctx: &Ctx, args: &Json) -> Result<Option<Json>, i32> {
    let Some(cmd) = arg_str(args, "command") else { return Err(status::INVALID_ARGUMENT) };
    let sid = arg_str(args, "ubus_rpc_session");
    let params: Vec<String> = match args.get("params") {
        Some(Json::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect(),
        _ => Vec::new(),
    };
    let has_params = matches!(args.get("params"), Some(Json::Array(_)));
    let env: Vec<(String, String)> = match args.get("env") {
        Some(Json::Object(o)) => o.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned()))).collect(),
        _ => Vec::new(),
    };
    let has_env = matches!(args.get("env"), Some(Json::Object(_)));
    if sid.is_some() && has_env {
        return Err(status::PERMISSION_DENIED);
    }
    let Some(found) = exec_lookup(cmd) else { return Err(status::NOT_FOUND) };
    let Some(executable) = util::canonicalize(&found) else { return Err(status::UNKNOWN_ERROR) };
    if !ctx.file_access(sid, &executable, "exec") {
        if !has_params || executable.len() >= CMDLINE_MAX {
            return Err(status::PERMISSION_DENIED);
        }
        let mut cmdstr = executable.clone();
        let mut arglen = 2;
        for p in &params {
            if arglen == 255 || cmdstr.len() + p.len() >= CMDLINE_MAX {
                return Err(status::PERMISSION_DENIED);
            }
            cmdstr.push(' ');
            cmdstr.push_str(p);
            arglen += 1;
        }
        if !ctx.file_access(sid, &cmdstr, "exec") {
            return Err(status::PERMISSION_DENIED);
        }
    }
    // The forked child in rpc_file_exec_run hits arglen==255 and _exit(127)
    // once argv (executable + params + NULL) would exceed 255 entries.
    if params.len() > 253 {
        return Ok(Some(Json::Object(vec![("code".into(), Json::Int(127))])));
    }
    run_command(&executable, &params, &env, ctx.exec_timeout_ms).map(Some)
}

/// rpc_exec with the default callbacks (exec.c): run `executable` with
/// `params`, collect stdout/stderr (64 KiB cap each -> NOT_SUPPORTED), kill on
/// timeout (-> TIMEOUT), reply {code, stdout?, stderr?}. A failed exec in the
/// child is code 127.
pub fn run_command(executable: &str, params: &[String], env: &[(String, String)], timeout_ms: i32) -> Result<Json, i32> {
    let mut command = Command::new(executable);
    command.arg0(executable);
    command.args(params);
    for (k, v) in env {
        command.env(k, v);
    }
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // The child _exit(127)s if execv fails (non-executable, bad interpreter),
    // so a spawn failure after a successful lookup is reported as code 127,
    // not as a ubus status. Pre-fork failures (lookup/ACL) already returned.
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return Ok(Json::Object(vec![("code".into(), Json::Int(127))])),
    };
    let mut out = Pipe::new(fs::File::from(OwnedFd::from(child.stdout.take().unwrap())));
    let mut err = Pipe::new(fs::File::from(OwnedFd::from(child.stderr.take().unwrap())));
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(0) as u64);
    // exec.c drives both pipes from uloop and replies as soon as the direct
    // child exits (rpc_exec_process_cb: one last ustream_poll, then close) or
    // the timeout fires (rpc_exec_timeout_cb: SIGKILL, reply with whatever is
    // buffered). It never waits for a descendant that inherited the pipes --
    // and neither may we: `file exec` runs on the rpcd main loop, so blocking
    // on a daemonising command would stall every other request and timer.
    let mut exited = None;
    let mut timed_out = false;
    while out.open || err.open {
        if let Ok(Some(st)) = child.try_wait() {
            exited = Some(st);
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            timed_out = true;
            break;
        }
        let wait_ms = remaining.as_millis().min(EXEC_TICK_MS as u128) as i32;
        poll_pipes(&mut out, &mut err, wait_ms);
    }
    // Both pipes at EOF does not mean the child is gone; procwait bounds that
    // wait and SIGKILLs on expiry. A zero budget (we already timed out) kills
    // right away.
    let code = match exited {
        Some(st) => Ok(st),
        None => match crate::procwait::wait(&mut child, deadline.saturating_duration_since(Instant::now())) {
            Ok(crate::procwait::Outcome::Exited(st)) => Ok(st),
            Ok(crate::procwait::Outcome::TimedOut) => {
                timed_out = true;
                Err(status::TIMEOUT)
            }
            Err(_) => Err(status::UNKNOWN_ERROR),
        },
    };
    // ustream_poll() before the reply: take what is already in the pipes.
    while poll_pipes(&mut out, &mut err, 0) {}
    let code = if timed_out { Err(status::TIMEOUT) } else { code };
    let st = code?;
    if out.overflow || err.overflow {
        return Err(status::NOT_SUPPORTED);
    }
    // rpc_file_exec_write emits WEXITSTATUS(stat): the exit code for a normal
    // exit, and 0 when the child was killed by a signal (st.code() is None).
    let exit_code = st.code().unwrap_or(0) as u32 & 0xff;
    let mut o = vec![("code".into(), Json::Int(exit_code as i64))];
    if !out.data.is_empty() {
        o.push(("stdout".into(), Json::Str(String::from_utf8_lossy(&out.data).into_owned())));
    }
    if !err.data.is_empty() {
        o.push(("stderr".into(), Json::Str(String::from_utf8_lossy(&err.data).into_owned())));
    }
    Ok(Json::Object(o))
}

/// How long a poll(2) round may block before we re-check whether the direct
/// child exited; only reached when a descendant holds a pipe open.
const EXEC_TICK_MS: u64 = 50;

/// One capture pipe: `open` clears at EOF, on error, or once the 256 KiB cap
/// (`FILE_MAX_SIZE`, -> NOT_SUPPORTED) is hit.
struct Pipe {
    file: fs::File,
    data: Vec<u8>,
    open: bool,
    overflow: bool,
}

impl Pipe {
    fn new(file: fs::File) -> Self {
        Pipe { file, data: Vec::new(), open: true, overflow: false }
    }

    /// One bounded read; poll(2) already said the fd is ready, so it cannot block.
    fn read_ready(&mut self) {
        let mut chunk = [0u8; 4096];
        match self.file.read(&mut chunk) {
            Ok(0) => self.open = false,
            Ok(n) => {
                self.data.extend_from_slice(&chunk[..n]);
                if self.data.len() >= FILE_MAX_SIZE as usize {
                    self.overflow = true;
                    self.open = false;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => self.open = false,
        }
    }
}

/// Poll the still-open pipes and read the ready ones. Returns whether anything
/// was ready, so a 0 ms drain can loop until the pipes are quiet.
fn poll_pipes(out: &mut Pipe, err: &mut Pipe, timeout_ms: i32) -> bool {
    let (out_polled, err_polled) = (out.open, err.open);
    let mut fds: Vec<PollFd> = Vec::with_capacity(2);
    for pipe in [&*out, &*err] {
        if pipe.open {
            fds.push(PollFd { fd: pipe.file.as_raw_fd(), events: POLLIN, revents: 0 });
        }
    }
    if fds.is_empty() || poll_fds(&mut fds, timeout_ms).unwrap_or(0) == 0 {
        return false;
    }
    let mut i = 0;
    if out_polled {
        if fds[i].revents != 0 {
            out.read_ready();
        }
        i += 1;
    }
    if err_polled && fds[i].revents != 0 {
        err.read_ready();
    }
    true
}

/// Dispatch one `file` method.
pub fn call(ctx: &Ctx, method: &str, args: &Json) -> Result<Option<Json>, i32> {
    match method {
        "read" => read(ctx, args),
        "write" => write(ctx, args),
        "list" => list(ctx, args),
        "lstat" => stat(ctx, args, true),
        "stat" => stat(ctx, args, false),
        "md5" => md5(ctx, args),
        "remove" => remove(ctx, args),
        "exec" => exec(ctx, args),
        _ => Err(status::METHOD_NOT_FOUND),
    }
}

#[cfg(test)]
mod tests {
    use super::run_command;
    use owrt_ubus::status;
    use std::time::Instant;

    fn sh(script: &str, timeout_ms: i32) -> (Result<crate::Json, i32>, u128) {
        let started = Instant::now();
        let r = run_command("/bin/sh", &["-c".into(), script.into()], &[], timeout_ms);
        (r, started.elapsed().as_millis())
    }

    /// exec.c replies when the *direct* child exits; a descendant that
    /// inherited stdout/stderr must not hold the rpcd main loop hostage.
    #[test]
    fn descendant_holding_the_pipes_does_not_extend_the_call() {
        let (r, ms) = sh("sleep 5 & exit 0", 200);
        assert!(r.is_ok(), "expected a normal reply, got {r:?}");
        assert!(ms < 1000, "took {ms} ms, should return with the direct child");

        let (r, ms) = sh("sleep 5 & wait", 200);
        assert_eq!(r.unwrap_err(), status::TIMEOUT);
        assert!(ms < 1000, "took {ms} ms, should return at the timeout");
    }

    #[test]
    fn output_and_exit_code_still_come_back() {
        let (r, _) = sh("printf out; printf err >&2; exit 3", 5000);
        let Ok(crate::Json::Object(o)) = r else { panic!("unexpected reply: {r:?}") };
        let get = |k: &str| o.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert!(matches!(get("code"), Some(crate::Json::Int(3))));
        assert!(matches!(get("stdout"), Some(crate::Json::Str(ref s)) if s == "out"));
        assert!(matches!(get("stderr"), Some(crate::Json::Str(ref s)) if s == "err"));
    }
}
