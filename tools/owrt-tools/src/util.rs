//! Shared helpers: errors, hashing, files, child processes and JSON output.
//!
//! JSON is written in the exact layout of Python's `json.dumps` (ASCII-only
//! escapes, insertion order, `indent=2`), because evidence and release
//! manifests produced by earlier tooling are compared and hashed as bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;
use sha2::{Digest, Sha256};

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A failed check or operation, carrying a human-readable explanation.
#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

macro_rules! from_error {
    ($($source:ty),*) => {$(
        impl From<$source> for Error {
            fn from(error: $source) -> Self {
                Self::new(error.to_string())
            }
        }
    )*};
}
from_error!(io::Error, serde_json::Error, toml::de::Error, regex::Error,
            std::num::ParseIntError, std::string::FromUtf8Error);

/// Returns early with an [`Error`] built from a format string.
macro_rules! bail {
    ($($arg:tt)+) => { return Err($crate::util::Error::new(format!($($arg)+))) };
}

/// Returns early with an [`Error`] unless the condition holds.
macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition { $crate::util::bail!($($arg)+); }
    };
}

pub(crate) use {bail, ensure};

/// The repository root this binary was built from.
pub fn repo() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().and_then(Path::parent).expect("crate lives in tools/owrt-tools").to_path_buf()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn sha256_bytes(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|error| Error::new(format!("{}: {error}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1 << 20];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(hex(&hasher.finalize()));
        }
        hasher.update(&buffer[..read]);
    }
}

/// A 64-digit lowercase SHA-256 (or `length`-digit) hexadecimal string.
pub fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn read_text(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|error| Error::new(format!("{}: {error}", path.display())))
}

/// Reads text, replacing invalid UTF-8 like Python's `errors="replace"`.
pub fn read_lossy(path: &Path) -> Result<String> {
    let data = fs::read(path).map_err(|error| Error::new(format!("{}: {error}", path.display())))?;
    Ok(String::from_utf8_lossy(&data).into_owned())
}

/// Python `str.splitlines()`: also splits on lone `\r` (progress output),
/// form feeds and Unicode line separators.
pub fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        let boundary = matches!(character,
            '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}');
        if boundary {
            lines.push(&text[start..index]);
            let mut end = index + character.len_utf8();
            if character == '\r' {
                if let Some(&(next, '\n')) = chars.peek() {
                    chars.next();
                    end = next + 1;
                }
            }
            start = end;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

pub fn read_json(path: &Path) -> Result<Value> {
    serde_json::from_str(&read_text(path)?).map_err(|error| Error::new(format!("{}: {error}", path.display())))
}

/// Writes `value` as `json.dumps(value, indent=2) + "\n"`, creating parents.
pub fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, pretty_json(value) + "\n")?;
    Ok(())
}

/// Creates a new file exclusively (Python mode `"x"`) and writes JSON to it.
pub fn write_json_new(path: &Path, value: &Value) -> Result<()> {
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all((pretty_json(value) + "\n").as_bytes())?;
    Ok(())
}

pub fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// All paths below `root` in Python `sorted(root.rglob("*"))` order,
/// without following symlinked directories.
pub fn walk_sorted(root: &Path) -> Result<Vec<PathBuf>> {
    fn visit(directory: &Path, found: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let is_dir = fs::symlink_metadata(&path)?.is_dir();
            found.push(path.clone());
            if is_dir {
                visit(&path, found)?;
            }
        }
        Ok(())
    }
    let mut found = Vec::new();
    visit(root, &mut found)?;
    found.sort();
    Ok(found)
}

pub fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).map(|meta| meta.file_type().is_symlink()).unwrap_or(false)
}

/// Copies contents, permission bits and timestamps (Python `shutil.copy2`).
pub fn copy2(source: &Path, target: &Path) -> Result<()> {
    fs::copy(source, target).map_err(|error| {
        Error::new(format!("copy {} -> {}: {error}", source.display(), target.display()))
    })?;
    copy_times(source, target)
}

fn copy_times(source: &Path, target: &Path) -> Result<()> {
    let meta = fs::metadata(source)?;
    let times = fs::FileTimes::new().set_accessed(meta.accessed()?).set_modified(meta.modified()?);
    let file = File::options().write(true).open(target).or_else(|_| File::open(target))?;
    file.set_times(times)?;
    Ok(())
}

/// Recursively copies a directory tree with [`copy2`] (Python `copytree`).
pub fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir(target)?;
    for entry in fs::read_dir(source)? {
        let path = entry?.path();
        let destination = target.join(path.file_name().expect("directory entry has a name"));
        if path.is_dir() {
            copy_tree(&path, &destination)?;
        } else {
            copy2(&path, &destination)?;
        }
    }
    fs::set_permissions(target, fs::metadata(source)?.permissions())?;
    Ok(())
}

pub fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

pub fn mode(path: &Path) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::metadata(path)?.permissions().mode() & 0o7777)
}

/// A child environment: the variables a command will receive, in full.
pub type Env = BTreeMap<String, String>;

/// The current process environment (non-UTF-8 entries are not representable).
pub fn current_env() -> Env {
    std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

pub fn command(argv: &[String], cwd: Option<&Path>, env: Option<&Env>) -> Command {
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    if let Some(env) = env {
        command.env_clear().envs(env);
    }
    command
}

/// Runs a command with stdout and stderr in `log`; fails on a nonzero exit.
/// Returns the log text (Python `build_package.run`).
pub fn run_logged(argv: &[String], log: &Path, cwd: Option<&Path>, env: Option<&Env>) -> Result<String> {
    let code = run_to_log(argv, log, cwd, env)?;
    ensure!(code == 0, "command exited {code}; see {}", log.display());
    read_lossy(log)
}

/// Runs a command with stdout and stderr in `log` and returns its exit code.
pub fn run_to_log(argv: &[String], log: &Path, cwd: Option<&Path>, env: Option<&Env>) -> Result<i32> {
    let output = File::create(log)?;
    let errors = output.try_clone()?;
    let status = command(argv, cwd, env)
        .stdin(Stdio::null())
        .stdout(output)
        .stderr(errors)
        .status()
        .map_err(|error| Error::new(format!("{}: {error}", argv[0])))?;
    Ok(exit_code(status))
}

pub fn exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.code().unwrap_or_else(|| -status.signal().unwrap_or(1))
}

/// Runs a command, inheriting stdio, and fails unless it exits 0.
pub fn run_checked(argv: &[String], cwd: Option<&Path>, env: Option<&Env>) -> Result<()> {
    let status = command(argv, cwd, env)
        .status()
        .map_err(|error| Error::new(format!("{}: {error}", argv[0])))?;
    ensure!(status.success(), "command {:?} exited {}", argv, exit_code(status));
    Ok(())
}

/// Python `subprocess.check_output(..., text=True)`: stdout as text.
pub fn output(argv: &[String], cwd: Option<&Path>, env: Option<&Env>) -> Result<String> {
    let result = command(argv, cwd, env)
        .stderr(Stdio::inherit())
        .output()
        .map_err(|error| Error::new(format!("{}: {error}", argv[0])))?;
    ensure!(result.status.success(), "command {:?} exited {}", argv, exit_code(result.status));
    Ok(String::from_utf8_lossy(&result.stdout).into_owned())
}

pub fn strings<I, S>(items: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    items.into_iter().map(Into::into).collect()
}

pub fn git_head(repo: &Path) -> Result<String> {
    Ok(output(&strings(["git", "-C", &display(repo), "rev-parse", "HEAD"]), None, None)?.trim().to_owned())
}

pub fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

pub fn is_x86_64_linux() -> bool {
    cfg!(all(target_os = "linux", target_arch = "x86_64"))
}

pub fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

pub fn uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

pub fn gid() -> u32 {
    // SAFETY: getgid has no preconditions and cannot fail.
    unsafe { libc::getgid() }
}

/// An exclusive, non-blocking `flock` held until the value is dropped.
pub struct FileLock {
    _file: File,
}

impl FileLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        use std::os::fd::AsRawFd;
        let file = fs::OpenOptions::new().append(true).create(true).open(path)?;
        // SAFETY: the descriptor is owned by `file`, which outlives the lock.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        ensure!(result == 0, "{} is locked by another build: {}", path.display(), io::Error::last_os_error());
        Ok(Self { _file: file })
    }
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn record_interrupt(_signal: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// Records SIGINT/SIGTERM instead of terminating, so cleanup guards run.
/// The running child receives the same signal from its process group; the
/// caller checks [`check_interrupted`] after each step.
pub fn trap_interrupts() {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: the handler only stores to an atomic, which is
        // async-signal-safe, and it stays valid for the process lifetime.
        unsafe { libc::signal(signal, record_interrupt as *const () as libc::sighandler_t) };
    }
}

pub fn check_interrupted(what: &str) -> Result<()> {
    ensure!(!INTERRUPTED.load(Ordering::SeqCst), "{what} interrupted by signal");
    Ok(())
}

/// Minimal command-line parsing: declared value options and flags, plus
/// positionals. Values may be `--name value` or `--name=value`.
#[derive(Debug, Default)]
pub struct Args {
    positional: Vec<String>,
    values: BTreeMap<String, Vec<String>>,
    flags: BTreeSet<String>,
}

impl Args {
    pub fn parse(raw: &[String], value_options: &[&str], flag_options: &[&str]) -> Result<Self> {
        let mut args = Self::default();
        let mut items = raw.iter();
        while let Some(item) = items.next() {
            if item == "--" {
                args.positional.extend(items.by_ref().cloned());
                break;
            }
            if !item.starts_with("--") || item == "-" {
                args.positional.push(item.clone());
                continue;
            }
            let (name, inline) = match item.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None => (item.as_str(), None),
            };
            if flag_options.contains(&name) && inline.is_none() {
                args.flags.insert(name.to_owned());
            } else if value_options.contains(&name) {
                let value = match inline {
                    Some(value) => value,
                    None => items.next().cloned().ok_or_else(|| Error::new(format!("{name} needs a value")))?,
                };
                args.values.entry(name.to_owned()).or_default().push(value);
            } else {
                bail!("unknown option: {item}");
            }
        }
        Ok(args)
    }

    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).and_then(|values| values.last()).map(String::as_str)
    }

    pub fn values(&self, name: &str) -> &[String] {
        self.values.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn required(&self, name: &str) -> Result<&str> {
        self.value(name).ok_or_else(|| Error::new(format!("{name} is required")))
    }

    pub fn flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }

    pub fn positional(&self) -> &[String] {
        &self.positional
    }

    /// Exactly `names.len()` positionals, or a usage error naming them.
    pub fn exact(&self, names: &[&str]) -> Result<Vec<String>> {
        ensure!(self.positional.len() == names.len(), "usage: {}", names.join(" "));
        Ok(self.positional.clone())
    }
}

pub fn os_args() -> Vec<String> {
    std::env::args_os().map(|arg: OsString| arg.to_string_lossy().into_owned()).collect()
}

// ---------------------------------------------------------------- JSON

struct Style {
    indent: Option<usize>,
    sort_keys: bool,
    item: &'static str,
    key: &'static str,
}

/// `json.dumps(value, indent=2)`.
pub fn pretty_json(value: &Value) -> String {
    serialize(value, &Style { indent: Some(2), sort_keys: false, item: ",", key: ": " })
}

/// `json.dumps(value)`: one line with `", "` and `": "` separators.
pub fn line_json(value: &Value) -> String {
    serialize(value, &Style { indent: None, sort_keys: false, item: ", ", key: ": " })
}

/// `json.dumps(value, sort_keys=True, separators=(",", ":"))`, the input
/// form of every frozen source digest.
pub fn canonical_json(value: &Value) -> String {
    serialize(value, &Style { indent: None, sort_keys: true, item: ",", key: ":" })
}

/// SHA-256 of [`canonical_json`].
pub fn canonical_digest(value: &Value) -> String {
    sha256_bytes(canonical_json(value).as_bytes())
}

fn serialize(value: &Value, style: &Style) -> String {
    let mut out = String::new();
    write_value(&mut out, value, style, 0);
    out
}

fn newline(out: &mut String, style: &Style, depth: usize) {
    if let Some(indent) = style.indent {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', indent * depth));
    }
}

fn write_value(out: &mut String, value: &Value, style: &Style, depth: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => match number.as_f64() {
            Some(float) if !number.is_i64() && !number.is_u64() => out.push_str(&python_float(float)),
            _ => out.push_str(&number.to_string()),
        },
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(style.item);
                }
                newline(out, style, depth + 1);
                write_value(out, item, style, depth + 1);
            }
            newline(out, style, depth);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            if style.sort_keys {
                entries.sort_by(|left, right| left.0.cmp(right.0));
            }
            out.push('{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push_str(style.item);
                }
                newline(out, style, depth + 1);
                write_string(out, key);
                out.push_str(style.key);
                write_value(out, item, style, depth + 1);
            }
            newline(out, style, depth);
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(character),
            other => {
                let mut units = [0u16; 2];
                for unit in other.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

/// Python `repr(float)`: shortest round-trip digits, scientific notation
/// outside `1e-4 <= |x| < 1e16`.
pub fn python_float(value: f64) -> String {
    if value == 0.0 {
        return if value.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').expect("{:e} has an exponent");
    let exponent: i32 = exponent.parse().expect("{:e} exponent is an integer");
    if (-4..16).contains(&exponent) {
        let plain = format!("{value}");
        if plain.contains('.') { plain } else { plain + ".0" }
    } else {
        let sign = if exponent < 0 { '-' } else { '+' };
        format!("{mantissa}e{sign}{:02}", exponent.abs())
    }
}

/// Builds a JSON object from `(key, value)` pairs in order.
pub fn object<I, K>(pairs: I) -> Value
where
    I: IntoIterator<Item = (K, Value)>,
    K: Into<String>,
{
    Value::Object(pairs.into_iter().map(|(key, value)| (key.into(), value)).collect())
}

/// `{name: digest}` in the given order.
pub fn string_map(pairs: &[(String, String)]) -> Value {
    object(pairs.iter().map(|(key, value)| (key.clone(), Value::String(value.clone()))))
}

/// Field accessors that turn a missing or mistyped field into an [`Error`].
pub trait JsonExt {
    fn field(&self, key: &str) -> Result<&Value>;
    fn str_field(&self, key: &str) -> Result<&str>;
    fn u64_field(&self, key: &str) -> Result<u64>;
    fn obj_field(&self, key: &str) -> Result<&serde_json::Map<String, Value>>;
}

impl JsonExt for Value {
    fn field(&self, key: &str) -> Result<&Value> {
        self.get(key).ok_or_else(|| Error::new(format!("missing JSON field: {key}")))
    }

    fn str_field(&self, key: &str) -> Result<&str> {
        self.field(key)?.as_str().ok_or_else(|| Error::new(format!("JSON field is not a string: {key}")))
    }

    fn u64_field(&self, key: &str) -> Result<u64> {
        self.field(key)?.as_u64().ok_or_else(|| Error::new(format!("JSON field is not an integer: {key}")))
    }

    fn obj_field(&self, key: &str) -> Result<&serde_json::Map<String, Value>> {
        self.field(key)?.as_object().ok_or_else(|| Error::new(format!("JSON field is not an object: {key}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_layout_matches_python_dumps() {
        let value = json!({"b": [1, {"x": []}, {}], "a": "é\"\n", "f": 0.5, "g": 1e-5, "h": 1e16});
        assert_eq!(
            pretty_json(&value),
            "{\n  \"b\": [\n    1,\n    {\n      \"x\": []\n    },\n    {}\n  ],\n  \"a\": \"\\u00e9\\\"\\n\",\n  \
             \"f\": 0.5,\n  \"g\": 1e-05,\n  \"h\": 1e+16\n}"
        );
        assert_eq!(canonical_json(&value), "{\"a\":\"\\u00e9\\\"\\n\",\"b\":[1,{\"x\":[]},{}],\"f\":0.5,\"g\":1e-05,\"h\":1e+16}");
        assert_eq!(line_json(&json!({"a": [1, 2]})), "{\"a\": [1, 2]}");
        assert_eq!(python_float(2.0), "2.0");
        assert_eq!(python_float(123.456), "123.456");
        assert_eq!(python_float(1.5e-7), "1.5e-07");
        assert_eq!(write_string_for("\u{1f600}\u{7f}"), "\"\\ud83d\\ude00\\u007f\"");
    }

    fn write_string_for(text: &str) -> String {
        let mut out = String::new();
        write_string(&mut out, text);
        out
    }

    #[test]
    fn splitlines_matches_python() {
        assert_eq!(splitlines("a\r\nb\rc\n\nd\u{c}e\n"), ["a", "b", "c", "", "d", "e"]);
        assert_eq!(splitlines(""), Vec::<&str>::new());
        assert_eq!(splitlines("x"), ["x"]);
    }

    #[test]
    fn walk_order_compares_path_components() {
        let directory = TempDir::new("walk");
        for name in ["a/b", "a-c", "a/a"] {
            let path = directory.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "").unwrap();
        }
        let names: Vec<_> = walk_sorted(directory.path())
            .unwrap()
            .into_iter()
            .map(|path| path.strip_prefix(directory.path()).unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["a", "a/a", "a/b", "a-c"]);
    }

    #[test]
    fn args_accept_values_flags_and_reject_unknown_options() {
        let raw = strings(["work", "--spec=a", "--stage", "generate", "--benchmark"]);
        let args = Args::parse(&raw, &["--spec", "--stage"], &["--benchmark"]).unwrap();
        assert_eq!(args.positional(), ["work"]);
        assert_eq!(args.value("--spec"), Some("a"));
        assert_eq!(args.value("--stage"), Some("generate"));
        assert!(args.flag("--benchmark"));
        assert!(Args::parse(&strings(["--bogus"]), &[], &[]).is_err());
        assert!(Args::parse(&strings(["--spec"]), &["--spec"], &[]).is_err());
    }
}

/// A uniquely named temporary directory removed on drop (tests and tools).
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> Self {
        Self::try_new(prefix).expect("create temporary directory")
    }

    pub fn try_new(prefix: &str) -> Result<Self> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let base = std::env::temp_dir();
        loop {
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.subsec_nanos())
                .unwrap_or(0);
            let path = base.join(format!("{prefix}-{}-{unique}-{nanos}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Keeps the directory on disk and returns its path.
    pub fn keep(self) -> PathBuf {
        let path = self.path.clone();
        std::mem::forget(self);
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
