use crate::process::{self, WaitResult};
use crate::{trace::Trace, unix};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

const MAX_CONFIG_ENTRIES: usize = 4096;
const MAX_BASELINE_BYTES: u64 = (MAX_CONFIG_ENTRIES * 320) as u64;
/// md5sum prints one `<32 hex>  <path>` line per file, so its output is bounded
/// by the same budget as the baseline it becomes.
const MAX_COMMAND_OUTPUT_BYTES: usize = MAX_BASELINE_BYTES as usize;

#[derive(Debug)]
pub enum Error {
    Io(&'static str, io::Error),
    InvalidInput(String),
    Dependency(String),
    Timeout(String),
    Cancelled,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(context, error) => write!(formatter, "{context}: {error}"),
            Self::InvalidInput(message) => write!(formatter, "invalid input: {message}"),
            Self::Dependency(message) => write!(formatter, "dependency failure: {message}"),
            Self::Timeout(message) => write!(formatter, "dependency timeout: {message}"),
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

struct CheckDirectory {
    path: PathBuf,
}

impl Drop for CheckDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
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
        if !unix::lock(file.as_raw_fd(), cancelled).map_err(|error| Error::Io("lock run lock", error))? {
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

    let check_path = settings.path("/var/run/config.check");
    if check_path.exists() {
        fs::remove_dir_all(&check_path)
            .map_err(|error| Error::Io("remove stale config.check", error))?;
    }
    fs::create_dir_all(&check_path).map_err(|error| Error::Io("create config.check", error))?;
    let _check_guard = CheckDirectory {
        path: check_path.clone(),
    };

    let names = scan_config_names(settings)?;
    let mut current = HashMap::with_capacity(names.len());
    let mut normalized: Vec<(OsString, PathBuf)> = Vec::with_capacity(names.len());
    for name in &names {
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let output = check_path.join(name);
        if let Some(status) = normalize(settings, name, &output, cancelled)? {
            trace
                .normalization(&name.to_string_lossy(), &status)
                .map_err(|error| Error::Io("write normalization trace", error))?;
        }
        normalized.push((name.clone(), output));
    }
    // One md5sum over every normalized file, as the shell script does
    // (`md5sum /var/run/config.check/*`), instead of one process per package.
    let digests = md5_all(settings, &normalized, cancelled)?;
    for (name, output) in &normalized {
        // A digest can only be missing when the name breaks md5sum's line
        // format (a newline in a config filename). The shell copies md5sum's
        // broken output into the baseline verbatim and keeps going, so the
        // entry is dropped here rather than failing the round.
        match digests.get(output) {
            Some(digest) => {
                current.insert(name.clone(), digest.clone());
            }
            None => trace
                .normalization(&name.to_string_lossy(), "no_digest")
                .map_err(|error| Error::Io("write normalization trace", error))?,
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
    for package in &changed {
        let name = package.to_string_lossy();
        match dispatch(settings, package, cancelled)? {
            Delivery::Success(code) => trace
                .delivery(&name, "success", Some(code))
                .map_err(|error| Error::Io("write delivery trace", error))?,
            Delivery::Exit(code) => {
                failures += 1;
                trace
                    .delivery(&name, "exit_nonzero", Some(code))
                    .map_err(|error| Error::Io("write delivery trace", error))?;
            }
            Delivery::Spawn(error) => {
                failures += 1;
                trace
                    .delivery(&name, "spawn_error", None)
                    .map_err(|trace_error| Error::Io("write delivery trace", trace_error))?;
                let _ = error;
            }
            Delivery::Timeout => {
                failures += 1;
                trace
                    .delivery(&name, "timeout", None)
                    .map_err(|error| Error::Io("write delivery trace", error))?;
            }
        }
    }

    write_baseline(&baseline_path, &names, &current)?;
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
        let mut source_names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| Error::Io("read config entry", error))?;
            // The shell original iterates `/var/run/uci/* /etc/config/*`; a
            // shell glob never matches a leading dot, so editor swap files and
            // other dotfiles are outside the scanned set.
            if entry.file_name().as_bytes().first() == Some(&b'.') {
                continue;
            }
            if entry.path().is_file() {
                source_names.push(entry.file_name());
            }
        }
        source_names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        for name in source_names {
            if seen.insert(name.clone()) {
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

/// The shell's `uci show "$file" > /var/run/config.check/$file 2>/dev/null`:
/// the exit status is ignored and whatever landed in the file is what gets
/// hashed. Returns the status label for the trace, or None when uci succeeded.
fn normalize(
    settings: &Settings,
    name: &OsStr,
    output: &Path,
    cancelled: &AtomicBool,
) -> Result<Option<String>, Error> {
    let file =
        File::create(output).map_err(|error| Error::Io("create normalized output", error))?;
    let mut command = Command::new("uci");
    command
        .arg("-c")
        .arg(settings.path("/etc/config"))
        .arg("-C")
        .arg(settings.path("/var/run/uci"))
        .arg("show")
        .arg(name)
        .stdout(Stdio::from(file))
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|error| Error::Dependency(format!("spawn uci for {name:?}: {error}")))?;
    match process::wait(&mut child, settings.timeout, cancelled)
        .map_err(|error| Error::Io("wait for uci", error))?
    {
        WaitResult::Exited(status) if status.success() => Ok(None),
        WaitResult::Exited(status) => Ok(Some(format_exit(status.code()))),
        // The shell has no timeout and simply waits, so it dispatches the rest
        // of the round; aborting here left every later package without an
        // event and the baseline unwritten. The killed child is treated like
        // any other failing `uci show`: the partial file is what gets hashed.
        WaitResult::TimedOut => Ok(Some("timeout".into())),
        WaitResult::Cancelled => Err(Error::Cancelled),
    }
}

fn md5_all(
    settings: &Settings,
    files: &[(OsString, PathBuf)],
    cancelled: &AtomicBool,
) -> Result<BTreeMap<PathBuf, String>, Error> {
    let mut digests = BTreeMap::new();
    if files.is_empty() {
        return Ok(digests);
    }
    let mut command = Command::new("md5sum");
    for (_, path) in files {
        command.arg(path);
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| Error::Dependency(format!("spawn md5sum: {error}")))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Dependency("md5sum stdout unavailable".into()))?;
    // read while the child runs: 19 lines fit the pipe, larger sets must not deadlock
    let mut output = Vec::new();
    stdout
        .by_ref()
        .take((MAX_COMMAND_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut output)
        .map_err(|error| Error::Io("read md5sum output", error))?;
    let status = process::wait(&mut child, settings.timeout, cancelled)
        .map_err(|error| Error::Io("wait for md5sum", error))?;
    match status {
        WaitResult::TimedOut => return Err(Error::Timeout("md5sum".into())),
        WaitResult::Cancelled => return Err(Error::Cancelled),
        WaitResult::Exited(status) if !status.success() => {
            return Err(Error::Dependency(format!("md5sum exited {status}")))
        }
        WaitResult::Exited(_) => {}
    }
    if output.len() > MAX_COMMAND_OUTPUT_BYTES {
        return Err(Error::Dependency("md5sum output exceeded limit".into()));
    }
    // Paths are not UTF-8 in general, so the output is split on bytes. A path
    // containing a newline splits md5sum's own line, exactly as it does in the
    // shell's `md5sum ... > config.md5`; those fragments simply do not match a
    // digest and are skipped rather than failing the round.
    for line in output.split(|&byte| byte == b'\n') {
        if line.len() < 35 {
            continue;
        }
        let (digest, rest) = line.split_at(32);
        let Ok(digest) = std::str::from_utf8(digest) else {
            continue;
        };
        if !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let path = rest.strip_prefix(b"  ").unwrap_or(rest);
        let path = path.strip_prefix(b"*").unwrap_or(path);
        digests.insert(
            PathBuf::from(OsStr::from_bytes(path)),
            digest.to_ascii_lowercase(),
        );
    }
    Ok(digests)
}

enum Delivery {
    Success(i32),
    Exit(i32),
    Spawn(io::Error),
    Timeout,
}

fn dispatch(
    settings: &Settings,
    package: &OsStr,
    cancelled: &AtomicBool,
) -> Result<Delivery, Error> {
    // The shell interpolates `$(basename $c)` raw, so a package name that is
    // not UTF-8 reaches ubus as those exact bytes; the payload is built as
    // bytes and handed to execve as an OsStr for that reason.
    let mut payload = br#"{ "type": "config.change", "data": { "package": ""#.to_vec();
    payload.extend_from_slice(&crate::json::escape_bytes(package.as_bytes()));
    payload.extend_from_slice(br#"" } }"#);
    let payload = OsStr::from_bytes(&payload);
    let mut child = match Command::new("ubus")
        .arg("call")
        .arg("service")
        .arg("event")
        .arg(payload)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return Ok(Delivery::Spawn(error)),
    };
    match process::wait(&mut child, settings.timeout, cancelled)
        .map_err(|error| Error::Io("wait for ubus", error))?
    {
        WaitResult::Exited(status) => {
            let code = status.code().unwrap_or(128);
            if status.success() {
                Ok(Delivery::Success(code))
            } else {
                Ok(Delivery::Exit(code))
            }
        }
        // C-08: "a send failure affects neither later entries nor the baseline
        // rewrite". A timeout is a send failure, so the killed child is counted
        // and the round goes on; returning early used to skip the remaining
        // packages and leave the baseline unwritten, which then re-sent the
        // events that had already been delivered.
        WaitResult::TimedOut => Ok(Delivery::Timeout),
        WaitResult::Cancelled => Err(Error::Cancelled),
    }
}

/// The shell's `md5sum -c $MD5FILE 2>/dev/null | grep FAILED`. busybox skips a
/// line it cannot parse (the diagnostic goes to the discarded stderr) and
/// carries on with the rest, so a broken line -- which is what a config
/// filename containing a newline produces -- must not fail the round.
fn read_baseline(path: &Path) -> Result<Vec<BaselineEntry>, Error> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.len() > MAX_BASELINE_BYTES => {
            return Err(Error::InvalidInput(format!(
                "baseline is {} bytes; limit is {MAX_BASELINE_BYTES}",
                metadata.len()
            )))
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(Error::Io("stat baseline", error)),
    }
    let content = match fs::read(path) {
        Ok(content) => content,
        Err(error) => return Err(Error::Io("read baseline", error)),
    };
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
) -> Result<(), Error> {
    let mut temporary_name = path
        .file_name()
        .unwrap_or_else(|| OsStr::new("config.md5"))
        .to_os_string();
    temporary_name.push(".reload-config-rs.tmp");
    let temporary = path.with_file_name(temporary_name);
    let result = (|| {
        let mut output = File::create(&temporary)
            .map_err(|error| Error::Io("create temporary baseline", error))?;
        for name in names {
            // Names whose digest md5sum could not report are absent here, the
            // same entries the shell's own broken md5sum line loses.
            let Some(digest) = current.get(name) else {
                continue;
            };
            // The path bytes are md5sum's, so they are written as bytes.
            let mut line = format!("{digest}  /var/run/config.check/").into_bytes();
            line.extend_from_slice(name.as_bytes());
            line.push(b'\n');
            output
                .write_all(&line)
                .map_err(|error| Error::Io("write temporary baseline", error))?;
        }
        output
            .sync_all()
            .map_err(|error| Error::Io("sync temporary baseline", error))?;
        drop(output);
        fs::rename(&temporary, path).map_err(|error| Error::Io("commit temporary baseline", error))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}


fn format_exit(code: Option<i32>) -> String {
    code.map_or_else(|| "signal".into(), |value| format!("exit_{value}"))
}

#[cfg(test)]
mod tests {
    use super::{
        changed_entries, read_baseline, run, scan_config_names, write_baseline, BaselineEntry, Error,
        Settings, MAX_BASELINE_BYTES, MAX_CONFIG_ENTRIES,
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
    fn config_limit_counts_unique_names_and_rejects_before_changing_baseline() {
        let root = std::env::temp_dir().join(format!(
            "reload-config-rs-limit-test-{}", std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let config = root.join("etc/config");
        let state = root.join("var/run/uci");
        fs::create_dir_all(&config).unwrap();
        fs::create_dir_all(&state).unwrap();
        for i in 0..MAX_CONFIG_ENTRIES {
            File::create(config.join(format!("package{i:04}"))).unwrap();
        }
        let settings = Settings { root: root.clone(), timeout: Duration::from_secs(1) };
        assert_eq!(scan_config_names(&settings).unwrap().len(), MAX_CONFIG_ENTRIES);
        File::create(state.join("package0000")).unwrap();
        File::create(config.join(".hidden")).unwrap();
        fs::create_dir(config.join("directory")).unwrap();
        assert_eq!(scan_config_names(&settings).unwrap().len(), MAX_CONFIG_ENTRIES);

        File::create(state.join("overflow")).unwrap();
        let baseline = root.join("var/run/config.md5");
        fs::write(&baseline, b"previous baseline\n").unwrap();
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let mut trace_bytes = Vec::new();
        let mut trace = crate::trace::Trace::new(&mut trace_bytes);
        assert!(matches!(run(&settings, &cancelled, &mut trace), Err(Error::InvalidInput(_))));
        assert_eq!(fs::read(&baseline).unwrap(), b"previous baseline\n");
        assert!(trace_bytes.is_empty());
        assert!(!root.join("var/run/config.check").exists());
        assert!(!root.join("var/run/config.md5.reload-config-rs.tmp").exists());
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

        assert!(write_baseline(&path, &names, &current).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "previous baseline\n");
        fs::remove_dir_all(directory).unwrap();
    }
}
