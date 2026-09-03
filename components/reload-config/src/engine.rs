use crate::process::{self, WaitResult};
use crate::{trace::Trace, unix};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

const MAX_CONFIG_ENTRIES: usize = 4096;
const MAX_CONFIG_SOURCE_BYTES: u64 = 1024 * 1024;
const MAX_NORMALIZED_BYTES: u64 = 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_BASELINE_BYTES: u64 = (MAX_CONFIG_ENTRIES * 320) as u64;

#[derive(Debug)]
pub enum Error {
    Io(&'static str, io::Error),
    InvalidInput(String),
    Dependency(String),
    Timeout(String),
    Cancelled,
    ConcurrentRun,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(context, error) => write!(formatter, "{context}: {error}"),
            Self::InvalidInput(message) => write!(formatter, "invalid input: {message}"),
            Self::Dependency(message) => write!(formatter, "dependency failure: {message}"),
            Self::Timeout(message) => write!(formatter, "dependency timeout: {message}"),
            Self::Cancelled => write!(formatter, "cancelled"),
            Self::ConcurrentRun => write!(formatter, "another reload-config-rs run holds the lock"),
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
    name: String,
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
    fn acquire(path: &Path) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| Error::Io("open run lock", error))?;
        match unix::try_lock(file.as_raw_fd()) {
            Ok(true) => Ok(Self { _file: file }),
            Ok(false) => Err(Error::ConcurrentRun),
            Err(error) => Err(Error::Io("lock run lock", error)),
        }
    }
}

pub fn run<W: Write>(
    settings: &Settings,
    cancelled: &AtomicBool,
    trace: &mut Trace<W>,
) -> Result<RunOutcome, Error> {
    let run_dir = settings.path("/var/run");
    fs::create_dir_all(run_dir).map_err(|error| Error::Io("create /var/run", error))?;
    let _lock = RunLock::acquire(&settings.path("/var/run/reload-config-rs.lock"))?;

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
    let mut normalized: Vec<(String, PathBuf)> = Vec::with_capacity(names.len());
    for name in &names {
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let output = check_path.join(name);
        let status = normalize(settings, name, &output, cancelled)?;
        if !status.success() {
            trace
                .normalization(name, &format_exit(status.code()))
                .map_err(|error| Error::Io("write normalization trace", error))?;
        }
        let size = fs::metadata(&output)
            .map_err(|error| Error::Io("stat normalized config", error))?
            .len();
        if size > MAX_NORMALIZED_BYTES {
            return Err(Error::InvalidInput(format!(
                "normalized package {name:?} is {size} bytes; limit is {MAX_NORMALIZED_BYTES}"
            )));
        }
        normalized.push((name.clone(), output));
    }
    // One md5sum over every normalized file, as the shell script does
    // (`md5sum /var/run/config.check/*`), instead of one process per package.
    let digests = md5_all(settings, &normalized, cancelled)?;
    for (name, output) in &normalized {
        let digest = digests
            .get(output)
            .ok_or_else(|| Error::Dependency(format!("md5sum returned no digest for {name:?}")))?;
        current.insert(name.clone(), digest.clone());
    }

    let baseline_path = settings.path("/var/run/config.md5");
    let previous = read_baseline(&baseline_path)?;
    let changed = changed_entries(&previous, &current);
    trace
        .comparison(previous.len(), &changed, current.len())
        .map_err(|error| Error::Io("write comparison trace", error))?;

    let mut failures = 0;
    for package in &changed {
        match dispatch(settings, package, cancelled)? {
            Delivery::Success(code) => trace
                .delivery(package, "success", Some(code))
                .map_err(|error| Error::Io("write delivery trace", error))?,
            Delivery::Exit(code) => {
                failures += 1;
                trace
                    .delivery(package, "exit_nonzero", Some(code))
                    .map_err(|error| Error::Io("write delivery trace", error))?;
            }
            Delivery::Spawn(error) => {
                failures += 1;
                trace
                    .delivery(package, "spawn_error", None)
                    .map_err(|trace_error| Error::Io("write delivery trace", trace_error))?;
                let _ = error;
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

fn scan_config_names(settings: &Settings) -> Result<Vec<String>, Error> {
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
                let size = fs::metadata(directory.join(&name))
                    .map_err(|error| Error::Io("stat config entry", error))?
                    .len();
                if size > MAX_CONFIG_SOURCE_BYTES {
                    return Err(Error::InvalidInput(format!(
                        "config entry {name:?} is {size} bytes; limit is {MAX_CONFIG_SOURCE_BYTES}"
                    )));
                }
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
    names
        .into_iter()
        .map(|name| {
            let value = name
                .into_string()
                .map_err(|_| Error::InvalidInput("non-UTF-8 config filename".into()))?;
            if value.contains(['\n', '\r', '\0']) {
                return Err(Error::InvalidInput(format!(
                    "control character in config filename {value:?}"
                )));
            }
            Ok(value)
        })
        .collect()
}

fn normalize(
    settings: &Settings,
    name: &str,
    output: &Path,
    cancelled: &AtomicBool,
) -> Result<std::process::ExitStatus, Error> {
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
        WaitResult::Exited(status) => Ok(status),
        WaitResult::TimedOut => Err(Error::Timeout(format!("uci show {name:?}"))),
        WaitResult::Cancelled => Err(Error::Cancelled),
    }
}

fn md5_all(
    settings: &Settings,
    files: &[(String, PathBuf)],
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
    let text = std::str::from_utf8(&output)
        .map_err(|_| Error::Dependency("md5sum output was not UTF-8".into()))?;
    for line in text.lines() {
        let mut parts = line.splitn(2, ' ');
        let digest = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("").trim_start_matches([' ', '*']);
        if digest.len() != 32 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::Dependency(format!(
                "md5sum returned invalid digest {digest:?}"
            )));
        }
        digests.insert(PathBuf::from(path), digest.to_ascii_lowercase());
    }
    Ok(digests)
}

enum Delivery {
    Success(i32),
    Exit(i32),
    Spawn(io::Error),
}

fn dispatch(settings: &Settings, package: &str, cancelled: &AtomicBool) -> Result<Delivery, Error> {
    let payload = format!(
        "{{ \"type\": \"config.change\", \"data\": {{ \"package\": \"{}\" }} }}",
        json_escape(package)
    );
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
        WaitResult::TimedOut => Err(Error::Timeout(format!(
            "ubus service.event for {package:?}"
        ))),
        WaitResult::Cancelled => Err(Error::Cancelled),
    }
}

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
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) => return Err(Error::Io("read baseline", error)),
    };
    content
        .lines()
        .map(|line| {
            if line.len() < 35 || &line[32..34] != "  " {
                return Err(Error::InvalidInput(format!(
                    "malformed baseline line {line:?}"
                )));
            }
            let digest = &line[..32];
            if !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(Error::InvalidInput(format!(
                    "invalid baseline digest {digest:?}"
                )));
            }
            let name = Path::new(&line[34..])
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| Error::InvalidInput("baseline path has no UTF-8 basename".into()))?;
            Ok(BaselineEntry {
                digest: digest.to_ascii_lowercase(),
                name: name.to_owned(),
            })
        })
        .collect()
}

fn changed_entries(previous: &[BaselineEntry], current: &HashMap<String, String>) -> Vec<String> {
    previous
        .iter()
        .filter(|entry| current.get(&entry.name) != Some(&entry.digest))
        .map(|entry| entry.name.clone())
        .collect()
}

fn write_baseline(
    path: &Path,
    names: &[String],
    current: &HashMap<String, String>,
) -> Result<(), Error> {
    let mut temporary_name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("config.md5"))
        .to_os_string();
    temporary_name.push(".reload-config-rs.tmp");
    let temporary = path.with_file_name(temporary_name);
    let result = (|| {
        let mut output = File::create(&temporary)
            .map_err(|error| Error::Io("create temporary baseline", error))?;
        for name in names {
            let digest = current
                .get(name)
                .ok_or_else(|| Error::Dependency(format!("missing digest for {name:?}")))?;
            writeln!(output, "{digest}  /var/run/config.check/{name}")
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

fn json_escape(value: &str) -> String {
    crate::trace::escape(value)
}

fn format_exit(code: Option<i32>) -> String {
    code.map_or_else(|| "signal".into(), |value| format!("exit_{value}"))
}

#[cfg(test)]
mod tests {
    use super::{
        changed_entries, read_baseline, scan_config_names, write_baseline, BaselineEntry, Settings,
        MAX_BASELINE_BYTES, MAX_CONFIG_SOURCE_BYTES,
    };
    use std::collections::HashMap;
    use std::fs::{self, File};
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
        let current = HashMap::from([("alpha".into(), "A2".into()), ("new".into(), "N".into())]);
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
                        let current: HashMap<_, _> = [("a", after_a), ("b", after_b)]
                            .into_iter()
                            .filter_map(|(name, digest)| {
                                digest.map(|digest| (name.into(), digest.into()))
                            })
                            .collect();
                        let expected: Vec<_> = [("a", before_a, after_a), ("b", before_b, after_b)]
                            .into_iter()
                            .filter(|(_, before, after)| before.is_some() && before != after)
                            .map(|(name, _, _)| name.to_owned())
                            .collect();
                        assert_eq!(changed_entries(&previous, &current), expected);
                    }
                }
            }
        }
    }

    #[test]
    fn baseline_parser_rejects_malformed_lines() {
        let directory =
            std::env::temp_dir().join(format!("reload-config-rs-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("baseline");
        fs::write(&path, "not-a-baseline\n").unwrap();
        assert!(read_baseline(&path).is_err());
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
        assert_eq!(scan_config_names(&settings).unwrap(), ["dhcp.bak", "network"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scanner_rejects_oversized_source_before_uci() {
        let root =
            std::env::temp_dir().join(format!("reload-config-rs-scan-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let directory = root.join("etc/config");
        fs::create_dir_all(&directory).unwrap();
        File::create(directory.join("oversized"))
            .unwrap()
            .set_len(MAX_CONFIG_SOURCE_BYTES + 1)
            .unwrap();
        let settings = Settings {
            root: root.clone(),
            timeout: Duration::from_secs(1),
        };
        assert!(scan_config_names(&settings).is_err());
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
        let names = vec!["alpha".to_owned()];
        let current = HashMap::from([("alpha".to_owned(), "a".repeat(32))]);

        assert!(write_baseline(&path, &names, &current).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "previous baseline\n");
        fs::remove_dir_all(directory).unwrap();
    }
}
