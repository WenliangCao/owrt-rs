use crate::{md5, trace::Trace, unix};
use owrt_uci::show::{self, Show};
use owrt_uci::Context;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
#[cfg(test)]
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

const MAX_CONFIG_ENTRIES: usize = 4096;
const MAX_BASELINE_BYTES: u64 = (MAX_CONFIG_ENTRIES * 320) as u64;

#[derive(Debug)]
pub enum Error {
    Io(&'static str, io::Error),
    InvalidInput(String),
    Cancelled,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(context, error) => write!(formatter, "{context}: {error}"),
            Self::InvalidInput(message) => write!(formatter, "invalid input: {message}"),
            Self::Cancelled => write!(formatter, "cancelled"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub root: PathBuf,
    pub timeout: Duration,
}

impl Settings {
    fn path(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }
}

#[derive(Debug)]
pub struct RunOutcome {
    pub delivery_failures: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BaselineEntry {
    digest: String,
    name: OsString,
}

struct RunLock {
    _file: File,
}

impl RunLock {
    /// The shell original takes no lock at all: two concurrent runs share and
    /// delete the same `/var/run/config.check`, deliver every event twice and
    /// leave the baseline to whichever `md5sum` wins. Blocking here serialises
    /// the runs instead, which keeps each caller's own changes dispatched --
    /// refusing the second caller (the earlier fail-closed behaviour) dropped
    /// its packages until a third run happened to notice them.
    fn acquire(path: &Path, cancelled: &AtomicBool) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| Error::Io("open run lock", error))?;
        if !unix::lock(&file, cancelled).map_err(|error| Error::Io("lock run lock", error))? {
            return Err(Error::Cancelled);
        }
        Ok(Self { _file: file })
    }
}

pub fn run<W: Write>(
    settings: &Settings,
    cancelled: &AtomicBool,
    trace: &mut Trace<W>,
) -> Result<RunOutcome, Error> {
    let run_dir = settings.path("/var/run");
    fs::create_dir_all(run_dir).map_err(|error| Error::Io("create /var/run", error))?;
    let _lock = RunLock::acquire(&settings.path("/var/run/reload-config-rs.lock"), cancelled)?;

    // The shell writes each `uci show` into /var/run/config.check/<name> and
    // hashes the files; the normalized bytes never need to touch the disk, so
    // there is no scratch directory here.  Only /var/run/config.md5 is a
    // contract output (C1-01 section 5).
    let names = scan_config_names(settings)?;
    let mut current = HashMap::with_capacity(names.len());
    // One uci context for the round, the way `uci show` with no argument walks
    // every package in one process.  Packages stay loaded until exit instead
    // of being freed after each one: the same bytes come out, and mallocng
    // stops handing whole groups back to the kernel between packages (the
    // per-package free/munmap/mmap churn was a third of the round's syscalls).
    let mut ctx = Context::new();
    ctx.set_confdir(&settings.path("/etc/config").to_string_lossy());
    ctx.set_conf2dir(&settings.path("/var/run/uci").to_string_lossy());
    let mut output = Vec::new();
    for name in &names {
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        ctx.set_io_budget(settings.timeout, cancelled);
        let status = normalize(&mut ctx, name, &mut output)?;
        if let Some(status) = status {
            trace
                .normalization(&name.to_string_lossy(), status)
                .map_err(|error| Error::Io("write normalization trace", error))?;
        }
        // md5sum printed `<digest>  /var/run/config.check/<name>`; a newline in
        // the name split that line and the entry was lost from the baseline.
        // The shell copies md5sum's broken output verbatim and keeps going,
        // so the entry is dropped here rather than failing the round.
        if name.as_bytes().contains(&b'\n') {
            trace
                .normalization(&name.to_string_lossy(), "no_digest")
                .map_err(|error| Error::Io("write normalization trace", error))?;
            continue;
        }
        current.insert(name.clone(), md5::hex(&output));
        // Reuse ordinary package output without retaining a large temporary
        // rendering for the rest of the round. This does not limit its size.
        if output.capacity() > 64 * 1024 {
            output = Vec::new();
        }
    }

    let baseline_path = settings.path("/var/run/config.md5");
    let previous = read_baseline(&baseline_path)?;
    let changed = changed_entries(&previous, &current);
    let changed_text: Vec<String> = changed
        .iter()
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    trace
        .comparison(previous.len(), &changed_text, current.len())
        .map_err(|error| Error::Io("write comparison trace", error))?;

    let mut failures = 0;
    let mut bus = None;
    for package in &changed {
        let name = package.to_string_lossy();
        match dispatch(settings, package, cancelled, &mut bus)? {
            Delivery::Success(code) => trace
                .delivery(&name, "success", Some(code))
                .map_err(|error| Error::Io("write delivery trace", error))?,
            Delivery::Exit(code) => {
                failures += 1;
                trace
                    .delivery(&name, "exit_nonzero", Some(code))
                    .map_err(|error| Error::Io("write delivery trace", error))?;
            }
            Delivery::Timeout => {
                failures += 1;
                trace
                    .delivery(&name, "timeout", None)
                    .map_err(|error| Error::Io("write delivery trace", error))?;
            }
        }
    }

    write_baseline(&baseline_path, &names, &current, cancelled)?;
    trace
        .complete(true, failures)
        .map_err(|error| Error::Io("write completion trace", error))?;
    Ok(RunOutcome {
        delivery_failures: failures,
    })
}

fn scan_config_names(settings: &Settings) -> Result<Vec<OsString>, Error> {
    let mut seen = HashSet::<OsString>::new();
    let mut names = Vec::<OsString>::new();
    for directory in [settings.path("/var/run/uci"), settings.path("/etc/config")] {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(Error::Io("read config directory", error)),
        };
        for entry in entries {
            let entry = entry.map_err(|error| Error::Io("read config entry", error))?;
            let name = entry.file_name();
            // The shell original iterates `/var/run/uci/* /etc/config/*`; a
            // shell glob never matches a leading dot, so editor swap files and
            // other dotfiles are outside the scanned set.
            if name.as_bytes().first() == Some(&b'.') || seen.contains(&name) {
                continue;
            }
            // Directory entry types avoid a stat for ordinary files. The
            // shell's -f follows symlinks, so resolve those as before; a type
            // lookup error also retains the previous metadata fallback.
            let is_file = match entry.file_type() {
                Ok(kind) if !kind.is_symlink() => kind.is_file(),
                _ => entry.path().is_file(),
            };
            if is_file {
                seen.insert(name.clone());
                // No size check: the shell hands any regular file to `uci show`
                // whatever its size, and a 1.4 MiB /etc/config file is dispatched
                // like any other. Refusing one used to abort the whole round.
                names.push(name);
                if names.len() > MAX_CONFIG_ENTRIES {
                    return Err(Error::InvalidInput(format!(
                        "more than {MAX_CONFIG_ENTRIES} config entries"
                    )));
                }
            }
        }
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(names)
}

/// The shell's `uci show "$file" > /var/run/config.check/$file 2>/dev/null`,
/// rendered in-process by the uci library: the same lookup and the same
/// printer the CLI uses, so the bytes are what `uci show <name>` prints
/// (contract C-06), including the empty output for a dotted name whose tuple
/// does not resolve (C-03).  Deltas under /tmp/.uci apply as in the CLI.  Any
/// failure is what `uci` exits 1 for, so the entry is empty and traced as
/// `exit_1`.
fn normalize(
    ctx: &mut Context,
    name: &OsStr,
    output: &mut Vec<u8>,
) -> Result<Option<&'static str>, Error> {
    output.clear();
    let result = show::tuple(ctx, name.as_bytes(), &mut Show::new(true, b" "), output);
    match ctx.check_io_budget().and(result) {
        Ok(()) => Ok(None),
        Err(owrt_uci::Error::Cancelled) => Err(Error::Cancelled),
        Err(owrt_uci::Error::TimedOut) => {
            // Never reuse a package whose base/delta load was interrupted.
            ctx.root.clear();
            // As with the old killed `uci show`, hash whatever was already
            // rendered. A timeout while loading/locking has produced no bytes.
            Ok(Some("timeout"))
        }
        Err(_) => Ok(Some("exit_1")),
    }
}

enum Delivery {
    Success(i32),
    Exit(i32),
    Timeout,
}

fn dispatch(
    settings: &Settings,
    package: &OsStr,
    cancelled: &AtomicBool,
    bus: &mut Option<owrt_ubus::Connection>,
) -> Result<Delivery, Error> {
    use owrt_ubus::{conn::error_status, status, BlobBuf, Connection};
    use std::time::Instant;

    if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let deadline = Instant::now() + settings.timeout;
    let reused = bus.is_some();
    let mut stage = 0; // connect, lookup, invoke: CLI exit mapping differs.
    let mut invoke_deadline = deadline;
    let result = (|| -> io::Result<i32> {
        if bus.is_none() {
            *bus = Some(Connection::connect_interruptible(
                None,
                deadline,
                crate::is_cancelled,
            )?);
        }
        stage = 1;
        // Resolve on every event: service may have been re-registered since
        // the previous invocation. A failed lookup on an old transport can
        // reconnect safely because no config.change has been sent yet.
        let id = match bus.as_mut().unwrap().lookup_id_until("service", deadline) {
            Ok(id) => id,
            Err(error)
                if reused
                    && error_status(&error).is_none()
                    && !matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                    ) =>
            {
                *bus = None;
                stage = 0;
                *bus = Some(Connection::connect_interruptible(
                    None,
                    deadline,
                    crate::is_cancelled,
                )?);
                stage = 1;
                bus.as_mut().unwrap().lookup_id_until("service", deadline)?
            }
            Err(error) => return Err(error),
        };
        let mut fields = BlobBuf::new();
        fields.msg_string("type", "config.change");
        let table = fields.msg_open_table("data");
        // This is the blobmsg string produced by the CLI JSON parser, including
        // non-UTF-8 bytes; no lossy conversion or second JSON parser is needed.
        fields.msg_string_bytes("package", package.as_bytes());
        fields.msg_close(table);
        stage = 2;
        // ubus CLI defaults to a 30 s invoke timeout inside the outer budget.
        invoke_deadline = deadline.min(Instant::now() + Duration::from_secs(30));
        bus.as_mut()
            .unwrap()
            .invoke_status_until(id, "event", fields.payload(), invoke_deadline)
    })();
    if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
        *bus = None;
        return Err(Error::Cancelled);
    }
    let delivery = match result {
        Ok(0) => return Ok(Delivery::Success(0)),
        // CLI stderr is /dev/null (not a tty), so ubus_cli_error returns -N
        // for an invoke failure, whereas lookup errors are returned as +N.
        Ok(code) => Delivery::Exit((-code) & 255),
        Err(error) if error.kind() == io::ErrorKind::TimedOut => {
            if stage == 2 && invoke_deadline < deadline {
                Delivery::Exit((-status::TIMEOUT) & 255)
            } else {
                Delivery::Timeout
            }
        }
        Err(error) => {
            let code = error_status(&error).unwrap_or_else(|| {
                if error.kind() == io::ErrorKind::BrokenPipe {
                    status::INVALID_ARGUMENT
                } else {
                    status::CONNECTION_FAILED
                }
            });
            Delivery::Exit(match stage {
                0 => 255,
                1 => code & 255,
                _ => (-code) & 255,
            })
        }
    };
    // A failed invoke may already have been delivered. Never retry it, and
    // discard the transport so late replies cannot enter a subsequent event.
    *bus = None;
    Ok(delivery)
}

/// The shell's `md5sum -c $MD5FILE 2>/dev/null | grep FAILED`. busybox skips a
/// line it cannot parse (the diagnostic goes to the discarded stderr) and
/// carries on with the rest, so a broken line -- which is what a config
/// filename containing a newline produces -- must not fail the round.
fn read_baseline(path: &Path) -> Result<Vec<BaselineEntry>, Error> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(Error::Io("read baseline", error)),
    };
    let size = file
        .metadata()
        .map_err(|error| Error::Io("stat baseline", error))?
        .len();
    if size > MAX_BASELINE_BYTES {
        return Err(Error::InvalidInput(format!(
            "baseline is {size} bytes; limit is {MAX_BASELINE_BYTES}"
        )));
    }
    let mut content = Vec::with_capacity(size as usize);
    // The open file can grow after metadata. Read through EOF (including
    // short reads/EINTR), but stop one byte past the limit to detect overflow
    // before any event is delivered or a replacement baseline is written.
    file.take(MAX_BASELINE_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(|error| Error::Io("read baseline", error))?;
    if content.len() as u64 > MAX_BASELINE_BYTES {
        return Err(Error::InvalidInput(format!(
            "baseline exceeds {MAX_BASELINE_BYTES} bytes"
        )));
    }
    let mut entries = Vec::new();
    for line in content.split(|&byte| byte == b'\n') {
        if line.len() < 35 || &line[32..34] != b"  " {
            continue;
        }
        let Ok(digest) = std::str::from_utf8(&line[..32]) else {
            continue;
        };
        if !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let Some(name) = Path::new(OsStr::from_bytes(&line[34..])).file_name() else {
            continue;
        };
        entries.push(BaselineEntry {
            digest: digest.to_ascii_lowercase(),
            name: name.to_os_string(),
        });
    }
    Ok(entries)
}

fn changed_entries(
    previous: &[BaselineEntry],
    current: &HashMap<OsString, String>,
) -> Vec<OsString> {
    previous
        .iter()
        .filter(|entry| current.get(&entry.name) != Some(&entry.digest))
        .map(|entry| entry.name.clone())
        .collect()
}

fn write_baseline(
    path: &Path,
    names: &[OsString],
    current: &HashMap<OsString, String>,
    cancelled: &AtomicBool,
) -> Result<(), Error> {
    if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let mut temporary_name = path
        .file_name()
        .unwrap_or_else(|| OsStr::new("config.md5"))
        .to_os_string();
    temporary_name.push(".reload-config-rs.tmp");
    let temporary = path.with_file_name(temporary_name);
    let result = (|| {
        let file = File::create(&temporary)
            .map_err(|error| Error::Io("create temporary baseline", error))?;
        let mut output = BufWriter::new(file);
        for name in names {
            // Names whose digest md5sum could not report are absent here, the
            // same entries the shell's own broken md5sum line loses.
            let Some(digest) = current.get(name) else {
                continue;
            };
            // The path bytes are md5sum's, so they are written as bytes.
            for bytes in [
                digest.as_bytes(),
                b"  /var/run/config.check/",
                name.as_bytes(),
                b"\n",
            ] {
                output
                    .write_all(bytes)
                    .map_err(|error| Error::Io("write temporary baseline", error))?;
            }
        }
        output
            .flush()
            .map_err(|error| Error::Io("write temporary baseline", error))?;
        output
            .get_ref()
            .sync_all()
            .map_err(|error| Error::Io("sync temporary baseline", error))?;
        drop(output);
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        fs::rename(&temporary, path).map_err(|error| Error::Io("commit temporary baseline", error))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{
        changed_entries, read_baseline, run, scan_config_names, write_baseline, BaselineEntry,
        Error, Settings, MAX_BASELINE_BYTES, MAX_CONFIG_ENTRIES,
    };
    use std::collections::HashMap;
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File};
    use std::os::unix::ffi::OsStrExt;
    use std::time::Duration;

    #[test]
    fn changed_entries_preserve_baseline_order_and_ignore_creation() {
        let previous = vec![
            BaselineEntry {
                name: "beta".into(),
                digest: "B".into(),
            },
            BaselineEntry {
                name: "alpha".into(),
                digest: "A".into(),
            },
        ];
        let current: HashMap<OsString, String> =
            HashMap::from([("alpha".into(), "A2".into()), ("new".into(), "N".into())]);
        assert_eq!(changed_entries(&previous, &current), ["beta", "alpha"]);
    }

    #[test]
    fn small_state_space_matches_contract_rule() {
        let states = [None, Some("A"), Some("B")];
        for before_a in states {
            for before_b in states {
                for after_a in states {
                    for after_b in states {
                        let previous: Vec<_> = [("a", before_a), ("b", before_b)]
                            .into_iter()
                            .filter_map(|(name, digest)| {
                                digest.map(|digest| BaselineEntry {
                                    name: name.into(),
                                    digest: digest.into(),
                                })
                            })
                            .collect();
                        let current: HashMap<OsString, String> = [("a", after_a), ("b", after_b)]
                            .into_iter()
                            .filter_map(|(name, digest)| {
                                digest.map(|digest| (name.into(), digest.into()))
                            })
                            .collect();
                        let expected: Vec<OsString> =
                            [("a", before_a, after_a), ("b", before_b, after_b)]
                                .into_iter()
                                .filter(|(_, before, after)| before.is_some() && before != after)
                                .map(|(name, _, _)| name.into())
                                .collect();
                        assert_eq!(changed_entries(&previous, &current), expected);
                    }
                }
            }
        }
    }

    #[test]
    fn baseline_parser_skips_malformed_lines_like_md5sum_c() {
        let directory =
            std::env::temp_dir().join(format!("reload-config-rs-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("baseline");
        // busybox `md5sum -c` reports a format error on stderr (discarded by
        // the shell's 2>/dev/null) and checks the remaining lines.
        fs::write(
            &path,
            format!(
                "not-a-baseline\n{}  /var/run/config.check/alpha\n",
                "a".repeat(32)
            ),
        )
        .unwrap();
        assert_eq!(
            read_baseline(&path).unwrap(),
            [BaselineEntry {
                digest: "a".repeat(32),
                name: "alpha".into(),
            }]
        );
        // a config filename with a newline splits md5sum's own line; the
        // fragment is skipped and the truncated name stays an entry
        fs::write(
            &path,
            format!("{}  /var/run/config.check/we\nird\n", "b".repeat(32)),
        )
        .unwrap();
        assert_eq!(
            read_baseline(&path).unwrap(),
            [BaselineEntry {
                digest: "b".repeat(32),
                name: "we".into(),
            }]
        );
        File::create(&path)
            .unwrap()
            .set_len(MAX_BASELINE_BYTES + 1)
            .unwrap();
        assert!(read_baseline(&path).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn baseline_limit_applies_when_metadata_understates_readable_bytes() {
        use std::io::Write;
        #[cfg(test)]
use std::os::fd::AsRawFd;
        let (reader, writer) = owrt_ubus::sys::pipe().unwrap();
        let path = format!("/proc/self/fd/{}", reader.as_raw_fd());
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        let sender = std::thread::spawn(move || {
            File::from(writer)
                .write_all(&vec![b'x'; MAX_BASELINE_BYTES as usize + 1])
                .unwrap();
        });
        assert!(matches!(
            read_baseline(std::path::Path::new(&path)),
            Err(Error::InvalidInput(_))
        ));
        sender.join().unwrap();
    }

    #[test]
    fn scanner_skips_dotfiles_like_the_shell_glob() {
        let root = std::env::temp_dir().join(format!(
            "reload-config-rs-dotfile-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let directory = root.join("etc/config");
        fs::create_dir_all(&directory).unwrap();
        for name in [".network.swp", "network", ".hidden", "dhcp.bak"] {
            File::create(directory.join(name)).unwrap();
        }
        let settings = Settings {
            root: root.clone(),
            timeout: Duration::from_secs(1),
        };
        assert_eq!(
            scan_config_names(&settings).unwrap(),
            ["dhcp.bak", "network"]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scanner_follows_only_symlinks_to_regular_files() {
        let root =
            std::env::temp_dir().join(format!("reload-config-scan-links-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let directory = root.join("etc/config");
        fs::create_dir_all(&directory).unwrap();
        fs::write(root.join("regular"), b"").unwrap();
        std::os::unix::fs::symlink(root.join("regular"), directory.join("file-link")).unwrap();
        std::os::unix::fs::symlink(root.join("missing"), directory.join("broken-link")).unwrap();
        std::os::unix::fs::symlink(&directory, directory.join("dir-link")).unwrap();
        let settings = Settings {
            root: root.clone(),
            timeout: Duration::from_secs(1),
        };
        assert_eq!(scan_config_names(&settings).unwrap(), ["file-link"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn config_limit_counts_unique_names_and_rejects_before_changing_baseline() {
        let root = std::env::temp_dir().join(format!(
            "reload-config-rs-limit-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let config = root.join("etc/config");
        let state = root.join("var/run/uci");
        fs::create_dir_all(&config).unwrap();
        fs::create_dir_all(&state).unwrap();
        for i in 0..MAX_CONFIG_ENTRIES {
            File::create(config.join(format!("package{i:04}"))).unwrap();
        }
        let settings = Settings {
            root: root.clone(),
            timeout: Duration::from_secs(1),
        };
        assert_eq!(
            scan_config_names(&settings).unwrap().len(),
            MAX_CONFIG_ENTRIES
        );
        File::create(state.join("package0000")).unwrap();
        File::create(config.join(".hidden")).unwrap();
        fs::create_dir(config.join("directory")).unwrap();
        assert_eq!(
            scan_config_names(&settings).unwrap().len(),
            MAX_CONFIG_ENTRIES
        );

        File::create(state.join("overflow")).unwrap();
        let baseline = root.join("var/run/config.md5");
        fs::write(&baseline, b"previous baseline\n").unwrap();
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let mut trace_bytes = Vec::new();
        let mut trace = crate::trace::Trace::new(&mut trace_bytes);
        assert!(matches!(
            run(&settings, &cancelled, &mut trace),
            Err(Error::InvalidInput(_))
        ));
        assert_eq!(fs::read(&baseline).unwrap(), b"previous baseline\n");
        assert!(trace_bytes.is_empty());
        assert!(!root.join("var/run/config.check").exists());
        assert!(!root
            .join("var/run/config.md5.reload-config-rs.tmp")
            .exists());
        fs::remove_dir_all(root).unwrap();
    }

    /// The shell hands any regular file to `uci show`. A 1.4 MiB
    /// /etc/config/big is scanned, hashed and dispatched (verified against the
    /// rootfs shell script); refusing it aborted the whole round.
    #[test]
    fn scanner_keeps_oversized_and_non_utf8_sources_like_the_shell() {
        let root =
            std::env::temp_dir().join(format!("reload-config-rs-scan-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let directory = root.join("etc/config");
        fs::create_dir_all(&directory).unwrap();
        File::create(directory.join("oversized"))
            .unwrap()
            .set_len(2 * 1024 * 1024)
            .unwrap();
        File::create(directory.join(OsStr::from_bytes(b"\xff\xfe"))).unwrap();
        File::create(directory.join("with space")).unwrap();
        let settings = Settings {
            root: root.clone(),
            timeout: Duration::from_secs(1),
        };
        assert_eq!(
            scan_config_names(&settings).unwrap(),
            [
                OsStr::from_bytes(b"oversized"),
                OsStr::from_bytes(b"with space"),
                OsStr::from_bytes(b"\xff\xfe"),
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_temporary_baseline_write_preserves_previous_bytes() {
        let directory = std::env::temp_dir().join(format!(
            "reload-config-rs-baseline-atomic-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("baseline");
        fs::write(&path, "previous baseline\n").unwrap();
        fs::create_dir(directory.join("baseline.reload-config-rs.tmp")).unwrap();
        let names = vec![OsString::from("alpha")];
        let current = HashMap::from([(OsString::from("alpha"), "a".repeat(32))]);

        assert!(write_baseline(
            &path,
            &names,
            &current,
            &std::sync::atomic::AtomicBool::new(false)
        )
        .is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "previous baseline\n");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn cancelled_dispatch_does_not_start_a_command() {
        let settings = Settings {
            root: "/".into(),
            timeout: Duration::from_secs(1),
        };
        let cancelled = std::sync::atomic::AtomicBool::new(true);
        assert!(matches!(
            super::dispatch(&settings, OsStr::new("alpha"), &cancelled, &mut None),
            Err(Error::Cancelled)
        ));
    }

    #[test]
    fn reused_normalization_buffer_discards_previous_package_on_failure() {
        let root = std::env::temp_dir().join(format!(
            "reload-config-normalize-reuse-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("alpha"),
            b"config test 's'\noption value 'first'\n",
        )
        .unwrap();
        let mut ctx = owrt_uci::Context::new();
        ctx.set_confdir(root.to_str().unwrap());
        ctx.set_conf2dir(root.join("missing").to_str().unwrap());
        let mut output = Vec::new();
        assert_eq!(
            super::normalize(&mut ctx, OsStr::new("alpha"), &mut output).unwrap(),
            None
        );
        assert_eq!(output, b"alpha.s=test\nalpha.s.value='first'\n");
        assert_eq!(
            super::normalize(&mut ctx, OsStr::new("alpha.absent"), &mut output).unwrap(),
            Some("exit_1")
        );
        assert!(output.is_empty());
        assert_eq!(
            super::normalize(&mut ctx, OsStr::new("alpha.s.value"), &mut output).unwrap(),
            None
        );
        assert_eq!(output, b"alpha.s.value='first'\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn buffered_baseline_preserves_all_bytes_across_flushes() {
        let root = std::env::temp_dir().join(format!(
            "reload-config-baseline-buffer-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let names: Vec<OsString> = (0..256).map(|i| format!("package{i:04}").into()).collect();
        let current: HashMap<_, _> = names
            .iter()
            .map(|name| (name.clone(), crate::md5::hex(name.as_bytes())))
            .collect();
        let mut expected = Vec::new();
        for name in &names {
            expected.extend_from_slice(current[name].as_bytes());
            expected.extend_from_slice(b"  /var/run/config.check/");
            expected.extend_from_slice(name.as_bytes());
            expected.push(b'\n');
        }
        assert!(expected.len() > 2 * 8192);
        let path = root.join("baseline");
        write_baseline(
            &path,
            &names,
            &current,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(fs::read(&path).unwrap(), expected);
        assert_eq!(read_baseline(&path).unwrap().len(), names.len());
        assert!(!root.join("baseline.reload-config-rs.tmp").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancellation_after_comparison_preserves_baseline_with_no_changes() {
        use std::io::{self, Write};
        use std::sync::atomic::{AtomicBool, Ordering};
        struct CancelOnWrite<'a>(&'a AtomicBool);
        impl Write for CancelOnWrite<'_> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.store(true, Ordering::Relaxed);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let root = std::env::temp_dir().join(format!(
            "reload-config-cancel-commit-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("etc/config")).unwrap();
        fs::create_dir_all(root.join("var/run")).unwrap();
        fs::write(root.join("etc/config/alpha"), b"").unwrap();
        let baseline = root.join("var/run/config.md5");
        // Same digest, but rewriting would change case and the recorded path.
        let previous = b"D41D8CD98F00B204E9800998ECF8427E  /old/alpha\n";
        fs::write(&baseline, previous).unwrap();
        let cancelled = AtomicBool::new(false);
        let mut trace = crate::trace::Trace::new(CancelOnWrite(&cancelled));
        let settings = Settings {
            root: root.clone(),
            timeout: Duration::from_secs(1),
        };
        assert!(matches!(
            run(&settings, &cancelled, &mut trace),
            Err(Error::Cancelled)
        ));
        assert_eq!(fs::read(&baseline).unwrap(), previous);
        assert!(!root
            .join("var/run/config.md5.reload-config-rs.tmp")
            .exists());
        fs::remove_dir_all(root).unwrap();
    }
}
