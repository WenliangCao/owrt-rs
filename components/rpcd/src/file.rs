//! The `file` object (rpcd file.c port): read/write/list/stat/lstat/md5/
//! remove/exec with session ACL checks through the original rpcd's
//! `session access` (scope `file`).

use crate::session::Reply;
use crate::util;
use crate::{Ctx, Deferrer};
use owrt_ubus::convert::{fields_to_json, json_to_fields};
use owrt_ubus::blob::{self, MsgType};
use owrt_ubus::json::Json;
use owrt_ubus::{status, BlobBuf, Request};
use std::fs;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
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

fn add_stat(out: &mut BlobBuf, m: &fs::Metadata, names: &mut util::IdentityNames) {
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
    out.msg_string("type", ty);
    // Keep the existing JSON bridge's signed INT32/INT64 selection, without
    // allocating a tree or copying constant field names into Strings.
    for (name, value) in [
        ("size", m.size() as i64),
        ("mode", m.mode() as i64),
        ("atime", m.atime() as u32 as i64),
        ("mtime", m.mtime() as u32 as i64),
        ("ctime", m.ctime() as u32 as i64),
        ("inode", m.ino() as u32 as i64),
        ("uid", m.uid() as i64),
        ("gid", m.gid() as i64),
    ] {
        json_to_fields(out, name, &Json::Int(value));
    }
    if let Some(u) = names.user(m.uid()) {
        out.msg_string("user", u);
    }
    if let Some(g) = names.group(m.gid()) {
        out.msg_string("group", g);
    }
}

/// `rpc_check_path`: canonicalise, ACL-check, optionally stat.
fn check_path(ctx: &Ctx, args: &Json, perm: &str, want_stat: bool, use_lstat: bool) -> Result<(PathBuf, Option<fs::Metadata>), i32> {
    check_path_args(ctx, PathArgs::from_json(args), perm, want_stat, use_lstat)
}

#[derive(Debug, PartialEq, Eq)]
struct PathArgs<'a> {
    path: Option<&'a [u8]>,
    sid: Option<&'a str>,
}

impl<'a> PathArgs<'a> {
    fn from_json(args: &'a Json) -> Self {
        Self { path: args.get("path").and_then(Json::as_bytes), sid: arg_str(args, "ubus_rpc_session") }
    }

    fn from_blob(data: &'a [u8]) -> Self {
        let (mut path, mut sid) = (None, None);
        for field in blob::fields(data) {
            match field.name {
                "path" if path.is_none() => path = Some(field),
                "ubus_rpc_session" if sid.is_none() => sid = Some(field),
                _ => {}
            }
        }
        // JSON's get selects the first named field, even when its type is
        // wrong. A STRING without a NUL becomes empty in field_to_json.
        let string_bytes = |f: blob::Field<'a>| {
            (f.ty == MsgType::String as u32).then(|| f.as_bytes().unwrap_or(b""))
        };
        Self {
            path: path.and_then(string_bytes),
            sid: sid.and_then(string_bytes).and_then(|v| std::str::from_utf8(v).ok()),
        }
    }
}

fn check_path_args(ctx: &Ctx, args: PathArgs<'_>, perm: &str, want_stat: bool, use_lstat: bool) -> Result<(PathBuf, Option<fs::Metadata>), i32> {
    let Some(raw) = args.path else { return Err(status::INVALID_ARGUMENT) };
    let Some(path) = util::canonicalize_bytes(raw) else { return Err(status::UNKNOWN_ERROR) };
    if !ctx.file_access_bytes(args.sid, &path, perm) {
        return Err(status::PERMISSION_DENIED);
    }
    let path = PathBuf::from(OsString::from_vec(path));
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
        Json::Str(util::b64_encode(&buf))
    } else {
        Json::from_string_bytes(buf)
    };
    Ok(Some(Json::Object(vec![("data".into(), data)])))
}

pub fn write(ctx: &Ctx, args: &Json) -> Result<Option<Json>, i32> {
    let (path, _) = check_path(ctx, args, "write", false, false)?;
    let Some(data) = args.get("data").and_then(Json::as_bytes) else { return Err(status::INVALID_ARGUMENT) };
    let mode = match args.get("mode") {
        Some(Json::Int(m)) => *m as u32,
        _ => 0o666,
    };
    let mut f = open_for_write(&path, mode, arg_bool(args, "append")).map_err(|e| errno_status(&e))?;
    let bytes: Vec<u8> = if !data.is_empty() && arg_bool(args, "base64") {
        util::b64_decode(data).ok_or(status::UNKNOWN_ERROR)?
    } else {
        data.to_vec()
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

/// `rpc_file_write`'s open: `umask(0); open(path, O_CREAT | O_WRONLY | flag,
/// mode); umask(prev)`, where flag is O_TRUNC unless `append`. The umask is
/// process-global and the rc/uci/rpc-sys workers fork children from their own
/// threads, which would inherit the 0 mask for the length of the window, so a
/// new file is created with O_EXCL and fchmod'ed to `mode` instead. An
/// existing file keeps its own mode, exactly as in C -- open(2) ignores the
/// mode argument once it does not create the file.
fn open_for_write(path: impl AsRef<Path>, mode: u32, append: bool) -> std::io::Result<fs::File> {
    let path = path.as_ref();
    let mut opts = fs::OpenOptions::new();
    opts.write(true).mode(mode);
    if append {
        opts.append(true);
    } else {
        opts.truncate(true);
    }
    let mut created = true;
    let f = match opts.clone().create_new(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // A dangling symlink fails O_EXCL while the open below still
            // creates the target, so re-check before deciding to chmod.
            created = fs::metadata(path).is_err();
            opts.clone().create(true).open(path)?
        }
        Err(e) => return Err(e),
    };
    if created {
        f.set_permissions(fs::Permissions::from_mode(mode & 0o7777))?;
    }
    Ok(f)
}

pub fn md5(ctx: &Ctx, args: &Json) -> Result<Option<Json>, i32> {
    let (path, m) = check_path(ctx, args, "read", true, false)?;
    if !m.unwrap().is_file() {
        return Err(status::NOT_SUPPORTED);
    }
    let mut input = fs::File::open(&path).map_err(|e| errno_status(&e))?;
    let digest = owrt_ubus::digest::md5_reader(&mut input).map_err(|e| errno_status(&e))?;
    Ok(Some(Json::Object(vec![("md5".into(), Json::Str(util::hex(&digest)))])))
}

fn list(ctx: &Ctx, args: PathArgs<'_>) -> Result<Vec<u8>, i32> {
    let (mut path, _) = check_path_args(ctx, args, "list", false, false)?;
    let rd = fs::read_dir(&path).map_err(|e| errno_status(&e))?;
    let mut out = BlobBuf::with_capacity(256);
    let mut names = util::IdentityNames::default();
    let entries = out.msg_open_array("entries");
    for e in rd.flatten() {
        let name = e.file_name();
        // Reuse the path storage across entries. Keep full-path lstat rather
        // than DirEntry::metadata: if the parent is renamed while listing,
        // the C implementation also resolves the original pathname again.
        path.push(&name);
        let Ok(m) = fs::symlink_metadata(&path) else {
            path.pop();
            continue;
        };
        let entry = out.msg_open_table("");
        out.msg_string_bytes("name", name.as_bytes());
        add_stat(&mut out, &m, &mut names);
        if m.file_type().is_symlink() {
            let target = out.msg_open_table("target");
            if let Ok(link) = fs::read_link(&path) {
                out.msg_string_bytes("name", link.as_os_str().as_bytes());
            }
            match fs::metadata(&path) {
                Ok(tm) => add_stat(&mut out, &tm, &mut names),
                Err(_) => { out.msg_string("type", "broken"); },
            }
            out.msg_close(target);
        }
        out.msg_close(entry);
        path.pop();
    }
    out.msg_close(entries);
    Ok(out.into_payload())
}

fn stat(ctx: &Ctx, args: PathArgs<'_>, use_lstat: bool) -> Result<Vec<u8>, i32> {
    let (path, m) = check_path_args(ctx, args, "list", true, use_lstat)?;
    let mut out = BlobBuf::with_capacity(256);
    out.msg_string_bytes("path", path.as_os_str().as_bytes());
    add_stat(&mut out, &m.unwrap(), &mut util::IdentityNames::default());
    Ok(out.into_payload())
}

fn remove_recursive(path: &Path) -> Result<(), i32> {
    let rd = fs::read_dir(path).map_err(|e| errno_status(&e))?;
    for e in rd.flatten() {
        let entrypath = e.path();
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
    exec_lookup_os(OsStr::new(cmd))?.into_string().ok()
}

fn exec_lookup_os(cmd: &OsStr) -> Option<OsString> {
    if fs::metadata(cmd).map(|m| m.is_file()).unwrap_or(false) {
        return Some(cmd.to_owned());
    }
    let search = std::env::var_os("PATH").unwrap_or_else(|| "/bin:/usr/bin:/sbin:/usr/sbin".into());
    for dir in search.as_bytes().split(|&b| b == b':') {
        // C concatenates even when cmd starts with '/', unlike Path::join.
        let mut p = dir.to_vec();
        p.push(b'/');
        p.extend_from_slice(cmd.as_bytes());
        let p = OsString::from_vec(p);
        if fs::metadata(&p).map(|m| m.is_file()).unwrap_or(false) {
            return Some(p);
        }
    }
    None
}

/// The command line rpc_file_exec_run builds for its second ACL check: the
/// canonical executable plus every string parameter, space separated, inside a
/// 1024 byte buffer. None is C's PERMISSION_DENIED -- either
/// `strlen(executable) >= sizeof(cmdstr)`, or the 255th argv slot, or a
/// parameter that no longer fits: C tests
/// `p + blobmsg_data_len(cur) >= cmdstr + sizeof(cmdstr)` and a blobmsg
/// string's data length counts its NUL terminator, so the limit is one byte
/// tighter than the visible length suggests.
#[cfg(test)]
fn acl_cmdline(executable: &str, params: &[String]) -> Option<String> {
    let params: Vec<OsString> = params.iter().map(OsString::from).collect();
    acl_cmdline_os(OsStr::new(executable), &params)?.into_string().ok()
}

fn acl_cmdline_os(executable: &OsStr, params: &[OsString]) -> Option<OsString> {
    if executable.len() >= CMDLINE_MAX {
        return None;
    }
    let mut cmdstr = executable.to_owned();
    for (i, p) in params.iter().enumerate() {
        // C's arglen counts argv[0] and the NULL terminator, so it is 2 + i
        // here and the 254th parameter is the one that no longer fits.
        if i + 2 == 255 || cmdstr.len() + p.len() + 1 >= CMDLINE_MAX {
            return None;
        }
        cmdstr.push(" ");
        cmdstr.push(p);
    }
    Some(cmdstr)
}

/// Executable, argv tail and environment, as rpc_file_exec_run holds them at
/// the point where it forks.
type ExecPlan = (OsString, Vec<OsString>, Vec<(OsString, OsString)>);

/// Everything rpc_file_exec_run does before its fork: argument decoding, the
/// `sid`+`env` rejection, the PATH lookup and both ACL checks. Cheap and
/// non-blocking, so it stays on the request loop exactly as in C.
fn exec_prepare(ctx: &Ctx, args: &Json) -> Result<ExecPlan, i32> {
    let Some(cmd) = args.get("command").and_then(Json::as_bytes) else { return Err(status::INVALID_ARGUMENT) };
    let sid = arg_str(args, "ubus_rpc_session");
    let params: Vec<OsString> = match args.get("params") {
        Some(Json::Array(a)) => a.iter().filter_map(|v| v.as_bytes().map(|b| OsString::from_vec(b.to_vec()))).collect(),
        _ => Vec::new(),
    };
    let has_params = matches!(args.get("params"), Some(Json::Array(_)));
    let env: Vec<(OsString, OsString)> = match args.get("env") {
        Some(Json::Object(o)) => o.iter().filter_map(|(k, v)| v.as_bytes().map(|s| (OsString::from(k), OsString::from_vec(s.to_vec())))).collect(),
        _ => Vec::new(),
    };
    let has_env = matches!(args.get("env"), Some(Json::Object(_)));
    if sid.is_some() && has_env {
        return Err(status::PERMISSION_DENIED);
    }
    let Some(found) = exec_lookup_os(OsStr::from_bytes(cmd)) else { return Err(status::NOT_FOUND) };
    let Some(executable) = util::canonicalize_bytes(found.as_bytes()) else { return Err(status::UNKNOWN_ERROR) };
    let executable = OsString::from_vec(executable);
    if !ctx.file_access_bytes(sid, executable.as_bytes(), "exec") {
        if !has_params {
            return Err(status::PERMISSION_DENIED);
        }
        let Some(cmdstr) = acl_cmdline_os(&executable, &params) else {
            return Err(status::PERMISSION_DENIED);
        };
        if !ctx.file_access_bytes(sid, cmdstr.as_bytes(), "exec") {
            return Err(status::PERMISSION_DENIED);
        }
    }
    Ok((executable, params, env))
}

/// `file exec`: C forks the child, arms a uloop timeout and hands the request
/// to `ubus_defer_request`, so the request loop keeps answering while the
/// command runs. Here the child is watched from a worker thread and the reply
/// travels back through the `Deferrer`, which gives the same property: no
/// ordering guarantee against other requests (C has none either), one
/// independent exec timeout per call, and a reply that is simply dropped by
/// the socket if the caller is already gone.
pub fn exec(ctx: &Ctx, req: Request, args: &Json, deferrer: &Deferrer) -> Outcome {
    let (executable, params, env) = match exec_prepare(ctx, args) {
        Ok(v) => v,
        Err(code) => return Outcome::Now(req, crate::to_reply(Err(code))),
    };
    let timeout_ms = ctx.exec_timeout_ms;
    match deferrer.defer(req, move || {
        // The forked child in rpc_file_exec_run hits arglen==255 and
        // _exit(127) once argv (executable + params + NULL) would exceed 255
        // entries; C reports that through the deferred reply as well.
        let r = if params.len() > 253 {
            Ok(Json::Object(vec![("code".into(), Json::Int(127))]))
        } else {
            run_command_os(&executable, &params, &env, timeout_ms)
        };
        crate::to_reply(r.map(Some))
    }) {
        None => Outcome::Deferred,
        Some((req, reply)) => Outcome::Now(req, reply),
    }
}

/// rpc_exec with the default callbacks (exec.c): run `executable` with
/// `params`, collect stdout/stderr (256 KiB cap each -> NOT_SUPPORTED), kill on
/// timeout (-> TIMEOUT), reply {code, stdout?, stderr?}. A failed exec in the
/// child is code 127.
pub fn run_command(executable: &str, params: &[String], env: &[(String, String)], timeout_ms: i32) -> Result<Json, i32> {
    let params: Vec<OsString> = params.iter().map(OsString::from).collect();
    let env: Vec<(OsString, OsString)> = env.iter().map(|(k, v)| (k.into(), v.into())).collect();
    run_command_os(OsStr::new(executable), &params, &env, timeout_ms)
}

fn run_command_os(executable: &OsStr, params: &[OsString], env: &[(OsString, OsString)], timeout_ms: i32) -> Result<Json, i32> {
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
    while out.open() || err.open() {
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
        // Overflow ends the call on its own; the other pipe may never reach EOF
        // (a script that keeps producing on the one still open).
        if out.overflow || err.overflow {
            break;
        }
    }
    if out.overflow || err.overflow {
        out.file = None;
        err.file = None;
        // The read callbacks schedule NOT_SUPPORTED the moment
        // ustream_read_buf_full() trips. Close both capture fds, so the child gets
        // EPIPE rather than blocking on a pipe nobody drains; the grace here
        // only covers a child that ignores SIGPIPE.
        let _ = crate::procwait::wait(&mut child, Duration::from_millis(EXEC_TICK_MS));
        return Err(status::NOT_SUPPORTED);
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
    if out.overflow || err.overflow {
        return Err(status::NOT_SUPPORTED);
    }
    let code = if timed_out { Err(status::TIMEOUT) } else { code };
    let st = code?;
    // rpc_file_exec_write emits WEXITSTATUS(stat): the exit code for a normal
    // exit, and 0 when the child was killed by a signal (st.code() is None).
    let exit_code = st.code().unwrap_or(0) as u32 & 0xff;
    let mut o = vec![("code".into(), Json::Int(exit_code as i64))];
    if !out.data.is_empty() {
        o.push(("stdout".into(), Json::from_string_bytes(out.data)));
    }
    if !err.data.is_empty() {
        o.push(("stderr".into(), Json::from_string_bytes(err.data)));
    }
    Ok(Json::Object(o))
}

/// How long a poll(2) round may block before we re-check whether the direct
/// child exited; only reached when a descendant holds a pipe open.
const EXEC_TICK_MS: u64 = 50;

/// One capture pipe. Closing means dropping the `File`: a bool alone would
/// leave the write end open and block a child that keeps producing output.
struct Pipe {
    file: Option<fs::File>,
    data: Vec<u8>,
    overflow: bool,
}

impl Pipe {
    fn new(file: fs::File) -> Self {
        Pipe { file: Some(file), data: Vec::new(), overflow: false }
    }

    fn open(&self) -> bool {
        self.file.is_some()
    }

    /// One bounded read; poll(2) already said the fd is ready, so it cannot
    /// block. Hitting the 256 KiB cap (`FILE_MAX_SIZE`) closes the fd, which is
    /// what makes the child stop instead of filling a pipe nobody reads.
    fn read_ready(&mut self) {
        let mut chunk = [0u8; 4096];
        let Some(file) = self.file.as_mut() else { return };
        match file.read(&mut chunk) {
            Ok(0) => self.file = None,
            Ok(n) => {
                self.data.extend_from_slice(&chunk[..n]);
                if self.data.len() >= FILE_MAX_SIZE as usize {
                    self.overflow = true;
                    self.file = None;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => self.file = None,
        }
    }
}

/// Poll the still-open pipes and read the ready ones. Returns whether anything
/// was ready, so a 0 ms drain can loop until the pipes are quiet.
fn poll_pipes(out: &mut Pipe, err: &mut Pipe, timeout_ms: i32) -> bool {
    let (out_polled, err_polled) = (out.open(), err.open());
    let mut fds: Vec<PollFd> = Vec::with_capacity(2);
    for pipe in [&*out, &*err] {
        if let Some(file) = pipe.file.as_ref() {
            fds.push(PollFd { fd: file.as_raw_fd(), events: POLLIN, revents: 0 });
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

pub enum Outcome {
    Now(Request, Reply),
    Deferred,
}

/// Dispatch one `file` method. Only `exec` defers; everything else is a
/// bounded filesystem operation that C runs on the loop too.
pub fn call(ctx: &Ctx, req: Request, deferrer: &Deferrer) -> Outcome {
    let payload = match req.method.as_str() {
        "list" => Some(list(ctx, PathArgs::from_blob(&req.data))),
        "lstat" => Some(stat(ctx, PathArgs::from_blob(&req.data), true)),
        "stat" => Some(stat(ctx, PathArgs::from_blob(&req.data), false)),
        _ => None,
    };
    if let Some(payload) = payload {
        let reply = match payload {
            Ok(data) => Reply::one(status::OK, data),
            Err(code) => Reply::empty(code),
        };
        return Outcome::Now(req, reply);
    }
    let args = fields_to_json(&req.data);
    if req.method == "exec" {
        return exec(ctx, req, &args, deferrer);
    }
    let r = match req.method.as_str() {
        "read" => read(ctx, &args),
        "write" => write(ctx, &args),
        "md5" => md5(ctx, &args),
        "remove" => remove(ctx, &args),
        _ => Err(status::METHOD_NOT_FOUND),
    };
    Outcome::Now(req, crate::to_reply(r))
}

#[cfg(test)]
mod tests {
    use super::{acl_cmdline, open_for_write, run_command, PathArgs, CMDLINE_MAX};
    use owrt_ubus::{BlobBuf, MsgType};
    use owrt_ubus::status;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Instant;

    #[test]
    fn path_arguments_keep_first_fields_raw_bytes_and_empty_string_rules() {
        let mut b = BlobBuf::new();
        b.msg_string_bytes("path", b"/tmp/\xff");
        b.msg_string("path", "/second");
        b.msg_string("ubus_rpc_session", "first");
        b.msg_string("ubus_rpc_session", "second");
        let fields = b.into_payload();
        assert_eq!(PathArgs::from_blob(&fields), PathArgs { path: Some(b"/tmp/\xff"), sid: Some("first") });

        let mut b = BlobBuf::new();
        b.msg_u32("path", 1);
        b.msg_string("path", "/second");
        b.msg_string_bytes("ubus_rpc_session", b"\xff");
        b.msg_string("ubus_rpc_session", "second");
        let fields = b.into_payload();
        assert_eq!(PathArgs::from_blob(&fields), PathArgs { path: None, sid: None });

        let mut b = BlobBuf::new();
        b.msg_field(MsgType::String as u32, "path", b"no terminator");
        b.msg_field(MsgType::String as u32, "ubus_rpc_session", b"no terminator");
        let fields = b.into_payload();
        assert_eq!(PathArgs::from_blob(&fields), PathArgs { path: Some(b""), sid: Some("") });
        assert_eq!(PathArgs::from_blob(&[]), PathArgs { path: None, sid: None });
    }

    /// rpc_file_exec_run measures each parameter with blobmsg_data_len(), which
    /// counts the string's NUL terminator, so the last command line that still
    /// passes the ACL check is 1023 bytes long. Dropping that byte let a
    /// 1024 byte command line through a `file exec` ACL that never saw it.
    #[test]
    fn the_acl_command_line_stops_one_byte_before_the_c_buffer() {
        let exe = "/bin/x"; // 6 bytes
        let fits = "a".repeat(CMDLINE_MAX - exe.len() - 1 - 1);
        let cmdstr = acl_cmdline(exe, std::slice::from_ref(&fits)).expect("1023 bytes must still be checked");
        assert_eq!(cmdstr.len(), CMDLINE_MAX - 1);
        assert!(acl_cmdline(exe, &[format!("{fits}a")]).is_none(), "1024 bytes must be denied");
        // the same limit across several parameters
        let half = "b".repeat(500);
        assert!(acl_cmdline(exe, &[half.clone(), half.clone()]).is_some());
        assert!(acl_cmdline(exe, &[half.clone(), half.clone(), half]).is_none());
        // argv runs out at 255 entries (executable + 253 parameters + NULL)
        let many: Vec<String> = (0..253).map(|_| "c".to_owned()).collect();
        assert!(acl_cmdline(exe, &many).is_some());
        let many: Vec<String> = (0..254).map(|_| "c".to_owned()).collect();
        assert!(acl_cmdline(exe, &many).is_none());
    }

    /// C gets the exact mode out of `umask(0)` + open(); we must get it without
    /// touching the process umask, because the rc/uci/rpc-sys workers fork
    /// children on other threads that would inherit the 0 mask. An existing
    /// file keeps its own mode either way -- open(2) ignores `mode` then.
    #[test]
    fn write_creates_with_the_exact_mode_and_leaves_the_umask_alone() {
        let path = format!("{}/r83-mode-{}", std::env::temp_dir().display(), std::process::id());
        let _ = std::fs::remove_file(&path);
        let prev = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
        let mode_of = |p: &str| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        open_for_write(&path, 0o666, false).expect("create");
        assert_eq!(mode_of(&path), 0o666, "a new file must get the requested mode, not mode & ~umask");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        open_for_write(&path, 0o666, false).expect("reopen");
        assert_eq!(mode_of(&path), 0o600, "an existing file keeps its mode");
        let during = rustix::process::umask(prev).as_raw_mode();
        assert_eq!(during, 0o077, "the process umask must be untouched");
        let _ = std::fs::remove_file(&path);
    }

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

    /// The read callbacks reply NOT_SUPPORTED as soon as the capture buffer is
    /// full. Closing the fd is what stops the child; a bool alone left it
    /// blocked on a full pipe until the exec timeout, which then masked the
    /// real status.
    #[test]
    fn output_over_the_cap_reports_not_supported_without_burning_the_timeout() {
        for redirect in ["", " >&2"] {
            let (r, ms) = sh(&format!("head -c 1048576 /dev/zero{redirect}"), 2000);
            assert_eq!(r.unwrap_err(), status::NOT_SUPPORTED, "redirect {redirect:?}");
            assert!(ms < 1500, "took {ms} ms with redirect {redirect:?}");
        }
        // both pipes over the cap at once
        let (r, ms) = sh("head -c 1048576 /dev/zero; head -c 1048576 /dev/zero >&2", 2000);
        assert_eq!(r.unwrap_err(), status::NOT_SUPPORTED);
        assert!(ms < 1500, "took {ms} ms");
    }

    /// Just under the cap must still be delivered in full, not truncated.
    #[test]
    fn output_just_under_the_cap_is_returned_whole() {
        let n = super::FILE_MAX_SIZE - 1;
        let (r, _) = sh(&format!("head -c {n} /dev/zero | tr '\\0' 'a'"), 5000);
        let Ok(crate::Json::Object(o)) = r else { panic!("unexpected reply: {r:?}") };
        let Some((_, crate::Json::Str(s))) = o.iter().find(|(k, _)| k == "stdout") else {
            panic!("no stdout in {o:?}")
        };
        assert_eq!(s.len() as u64, n);
    }

    /// A script that keeps writing after its output is discarded must not hold
    /// the call open either.
    #[test]
    fn a_producer_that_ignores_sigpipe_still_ends_at_the_cap() {
        let (r, ms) = sh("trap '' PIPE; while :; do head -c 65536 /dev/zero; done", 2000);
        assert_eq!(r.unwrap_err(), status::NOT_SUPPORTED);
        assert!(ms < 1500, "took {ms} ms");
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
