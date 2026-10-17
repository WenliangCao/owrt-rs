//! Exec the startup-pinned image without depending on procfs or argv[0].
//! Only the fixed helper/resolver entry points use this process boundary.

use std::ffi::{c_char, c_int, c_long, CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::{Arc, OnceLock};

static SELF_EXECUTABLE: OnceLock<Arc<OwnedFd>> = OnceLock::new();
const HELPER_CHANNELS: &str = "DNSMASQ_TEST_HELPER_CHANNELS";
const LOOKUP_CHANNELS: &str = "DNSMASQ_TEST_LOOKUP_CHANNELS";

unsafe extern "C" {
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn signal(number: c_int, handler: usize) -> usize;
    fn close(fd: c_int) -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
    fn fexecve(fd: c_int, argv: *const *const c_char, envp: *const *const c_char) -> c_int;
}

/// Call once in ordinary main, before chdir, credential changes or serving.
/// Internal exec entries must dispatch first: their AT_EXECFN may be /dev/fd/N
/// with N already closed by CLOEXEC. The retained inode survives later pathname
/// replacement/unlink. Opening the initial AT_EXECFN path is the startup trust
/// boundary; it does not claim to recover an already-replaced executable.
pub fn initialize_self_executable() -> io::Result<()> {
    if SELF_EXECUTABLE.get().is_some() {
        return Ok(());
    }
    let path = rustix::param::linux_execfn();
    if path.to_bytes().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "kernel executable path is unavailable",
        ));
    }
    let image = open_image(path)?;
    // Concurrent unit tests may race initialization. The first retained inode
    // wins; every later temporary descriptor is dropped normally.
    let _ = SELF_EXECUTABLE.set(image);
    Ok(())
}

fn open_image(path: &CStr) -> io::Result<Arc<OwnedFd>> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let stat = rustix::fs::fstat(&fd)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "executable is not a regular file",
        ));
    }
    Ok(Arc::new(fd))
}

fn image_for_spawn(test_entry: bool) -> io::Result<Arc<OwnedFd>> {
    if test_entry {
        // libtest has no ordinary main hook. The caller explicitly selected
        // a test entry, and AT_EXECFN names the full test executable here.
        initialize_self_executable()?;
    }
    SELF_EXECUTABLE
        .get()
        .cloned()
        .ok_or_else(|| io::Error::other("self executable was not initialized before startup"))
}

pub fn spawn_helper(
    commands: OwnedFd,
    events: OwnedFd,
    test_entry: Option<&'static str>,
) -> io::Result<Child> {
    spawn_image(
        image_for_spawn(test_entry.is_some())?,
        commands,
        events,
        false,
        test_entry,
    )
}

pub fn spawn_lookup(request: OwnedFd, result: OwnedFd, test_entry: bool) -> io::Result<Child> {
    spawn_image(
        image_for_spawn(test_entry)?,
        request,
        result,
        true,
        test_entry.then_some("config::dns::lookup::tests::internal_lookup_entry"),
    )
}

/// Rust's new runtime ignores SIGPIPE during initialization. A resolver entry
/// restores the former fork child's fixed dispositions after that runtime step.
pub fn restore_lookup_signals() -> io::Result<()> {
    for number in [2, 13, 15] {
        // SAFETY: these fixed, valid signals receive the libc SIG_DFL sentinel;
        // no user handler or pointer crosses the boundary.
        if unsafe { signal(number, 0) } == usize::MAX {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Every pointer refers to an immutable CString owned by this same value, or
/// is the final null pointer. Moving the value leaves CString allocations in
/// place. No caller can mutate the strings or expose their pointers.
struct ExecTable {
    _strings: Vec<CString>,
    pointers: Vec<*const c_char>,
}
impl ExecTable {
    fn new(strings: Vec<CString>) -> Self {
        let mut pointers: Vec<_> = strings.iter().map(|value| value.as_ptr()).collect();
        pointers.push(std::ptr::null());
        Self {
            _strings: strings,
            pointers,
        }
    }
    fn as_ptr(&self) -> *const *const c_char {
        self.pointers.as_ptr()
    }
}
// SAFETY: the table owns all pointees, which are immutable byte strings; no
// nonowned pointer or mutation is possible. Command requires Send + Sync for
// its fixed pre_exec hook, including when a caller moves Command to a thread.
unsafe impl Send for ExecTable {}
// SAFETY: shared references expose only the immutable, self-owned pointer
// table; neither the strings nor pointers can be mutated through them.
unsafe impl Sync for ExecTable {}

fn cstring(bytes: Vec<u8>) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn spawn_image(
    image: Arc<OwnedFd>,
    commands: OwnedFd,
    events: OwnedFd,
    resolver: bool,
    test_entry: Option<&str>,
) -> io::Result<Child> {
    let descriptors = format!("{}:{}", commands.as_raw_fd(), events.as_raw_fd());
    let mut args = vec![CString::new("dnsmasq-rs").unwrap()];
    if let Some(entry) = test_entry {
        for arg in ["--exact", entry, "--nocapture", "--test-threads=1"] {
            args.push(cstring(arg.as_bytes().to_vec())?);
        }
    } else {
        args.push(
            CString::new(if resolver {
                "--dnsmasq-internal-lookup-v1"
            } else {
                "--dnsmasq-internal-helper-v1"
            })
            .unwrap(),
        );
        args.push(CString::new(descriptors.clone()).unwrap());
    }
    let key = if resolver {
        LOOKUP_CHANNELS
    } else {
        HELPER_CHANNELS
    };
    let mut env = Vec::new();
    for (name, value) in std::env::vars_os() {
        if test_entry.is_some() && name == key {
            continue;
        }
        let mut bytes = name.as_os_str().as_bytes().to_vec();
        bytes.push(b'=');
        bytes.extend_from_slice(value.as_os_str().as_bytes());
        env.push(cstring(bytes)?);
    }
    if test_entry.is_some() {
        env.push(CString::new(format!("{key}={descriptors}")).unwrap());
    }
    let args = ExecTable::new(args);
    let env = ExecTable::new(env);

    // Command supplies its proven fork/error-pipe ownership. This directory is
    // only a fail-closed placeholder: the hook either execs the retained image
    // or returns Err, so Command never attempts its pathname exec operation.
    let mut command = Command::new("/");
    command.env_clear(); // fexecve receives the explicit frozen table above.
                         // SAFETY: all strings/tables and descriptors are owned by this closure and
                         // fully built in the parent. After fork it calls only async-signal-safe
                         // syscalls and fexecve, never allocating, locking or invoking user code.
    unsafe {
        command.pre_exec(move || {
            // Fixed Linux64 __NR_close_range, with native long varargs in all six
            // argument slots. CLOEXEC preserves std's private exec-error pipe.
            if syscall(
                436,
                3 as c_long,
                u32::MAX as c_long,
                4 as c_long,
                0 as c_long,
                0 as c_long,
                0 as c_long,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            for fd in [commands.as_raw_fd(), events.as_raw_fd()] {
                if fcntl(fd, 2, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if resolver {
                restore_lookup_signals()?;
                for fd in [0, 1, 2] {
                    close(fd);
                }
            } else {
                for sig in [2, 13, 14, 15] {
                    signal(sig, 1);
                }
                signal(17, 0);
            }
            // The fixed Linux kernel implements execveat, used by musl fexecve for
            // O_PATH descriptors; no procfs pathname is required. CLOEXEC closes
            // this retained executable descriptor only after the image is loaded.
            fexecve(image.as_raw_fd(), args.as_ptr(), env.as_ptr());
            Err(io::Error::last_os_error())
        });
    }
    command.spawn()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn pinned_exec_entry() {
        if let Ok(channels) = std::env::var(HELPER_CHANNELS) {
            let (_, output) = channels.split_once(':').unwrap();
            let mut output = super::super::inherited_pipe(output.parse().unwrap(), false).unwrap();
            output.write_all(b"retained executable").unwrap();
            std::process::exit(0);
        }
    }

    #[test]
    fn lookup_sigpipe_entry() {
        if let Ok(channels) = std::env::var(LOOKUP_CHANNELS) {
            restore_lookup_signals().unwrap();
            let (_, output) = channels.split_once(':').unwrap();
            let mut output = super::super::inherited_pipe(output.parse().unwrap(), false).unwrap();
            let _ = output.write_all(b"closed reader");
            std::process::exit(1);
        }
    }

    #[test]
    fn lookup_restores_sigpipe_after_rust_runtime_initialization() {
        initialize_self_executable().unwrap();
        let (request, request_writer) =
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let (result, response) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        drop(result);
        let mut child = spawn_image(
            image_for_spawn(true).unwrap(),
            request,
            response,
            true,
            Some("process::exec::tests::lookup_sigpipe_entry"),
        )
        .unwrap();
        drop(request_writer);
        assert_eq!(child.wait().unwrap().signal(), Some(13));
    }

    #[test]
    fn retained_image_survives_path_replacement_and_unlink() {
        let directory = std::env::temp_dir().join(format!(
            "dnsmasq-self-exec-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("executable");
        let original = std::ffi::OsStr::from_bytes(rustix::param::linux_execfn().to_bytes());
        std::fs::copy(original, &path).unwrap();
        let image = open_image(&CString::new(path.as_os_str().as_bytes()).unwrap()).unwrap();
        let replacement = directory.join("replacement");
        std::fs::write(&replacement, b"not the retained executable").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        for unlink in [false, true] {
            if unlink {
                std::fs::remove_file(&path).unwrap();
            }
            let (request, request_writer) =
                rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
            let (result, response) =
                rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
            let mut child = spawn_image(
                Arc::clone(&image),
                request,
                response,
                false,
                Some("process::exec::tests::pinned_exec_entry"),
            )
            .unwrap();
            drop(request_writer);
            let mut bytes = Vec::new();
            File::from(result).read_to_end(&mut bytes).unwrap();
            assert!(child.wait().unwrap().success());
            assert_eq!(bytes, b"retained executable");
        }
        std::fs::remove_dir(&directory).unwrap();
    }
    #[test]
    fn invalid_retained_image_returns_its_exec_error() {
        let path = std::env::temp_dir().join(format!("dnsmasq-bad-exec-{}", std::process::id()));
        std::fs::write(&path, b"not an executable image").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let image = open_image(&CString::new(path.as_os_str().as_bytes()).unwrap()).unwrap();
        let (request, _request_writer) =
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let (_result, response) =
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let error = spawn_image(image, request, response, false, None).unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(8),
            "exec error must return through std's pipe, without executing its placeholder"
        );
        std::fs::remove_file(path).unwrap();
    }
}
