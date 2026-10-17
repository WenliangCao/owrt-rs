//! Startup input ordering and include ownership, from option.c:2057-2218,
//! 5471-5718 and 5952-6090. No sockets or daemon state are created here.

use super::{
    lex_line, lookup, validate_directive, Argument, Directive, EncodedArg, Error,
    OccurrenceTracker, OptionSpec, Origin, OPTIONS,
};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SHORT_OPTIONS: &[u8] = b"951yZDNLERKzowefnbvhdkqr:m:p:c:l:s:i:t:u:g:a:x:S:C:A:T:H:Q:I:B:F:G:O:M:X:V:U:j:P:J:W:Y:2:4:6:7:8:0:3:";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Run,
    Test,
    Version,
    Help,
    HelpDhcp,
}

#[derive(Clone, Debug)]
pub struct Location {
    pub file: Option<PathBuf>,
    pub line: Option<usize>,
    pub from_script: bool,
}

impl Location {
    fn command_line() -> Self {
        Self {
            file: None,
            line: None,
            from_script: false,
        }
    }
}

#[derive(Debug)]
pub struct LoadError {
    pub location: Location,
    pub exit_code: i32,
    pub message: String,
}

impl LoadError {
    fn new(location: &Location, exit_code: i32, message: impl Into<String>) -> Self {
        Self {
            location: location.clone(),
            exit_code,
            message: message.into(),
        }
    }

    // Keep the repeated path/error formatting out of the include loader's
    // success path. All callers use the same message structure.
    #[cold]
    #[inline(never)]
    fn path_io(
        location: &Location,
        exit_code: i32,
        action: &str,
        path: &Path,
        error: io::Error,
    ) -> Self {
        let mut description = error.to_string();
        if let Some(code) = error.raw_os_error() {
            let suffix = format!(" (os error {code})");
            if description.ends_with(&suffix) {
                description.truncate(description.len() - suffix.len());
            }
        }
        Self::new(
            location,
            exit_code,
            format!("{action} {}: {description}", path.display()),
        )
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if let Some(file) = &self.location.file {
            if self.location.from_script {
                write!(f, " in output from {}", file.display())?;
            } else if let Some(line) = self.location.line {
                write!(f, " at line {line} of {}", file.display())?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for LoadError {}

fn path_from_arg(argument: Option<&EncodedArg>) -> Option<PathBuf> {
    let bytes = argument?.decoded();
    (!bytes.is_empty()).then(|| PathBuf::from(OsString::from_vec(bytes)))
}

fn long_option(name: &[u8]) -> Result<&'static OptionSpec, Error> {
    if let Some(spec) = lookup(name) {
        return Ok(spec);
    }
    let mut matches = OPTIONS
        .iter()
        .filter(|spec| spec.name.as_bytes().starts_with(name));
    let first = matches.next().ok_or(Error("bad option"))?;
    // GNU long aliases with identical value and argument requirement are not
    // ambiguous; other abbreviated collisions are errors.
    if matches.any(|other| other.id != first.id || other.argument != first.argument) {
        return Err(Error("ambiguous option"));
    }
    Ok(first)
}

fn short_option(letter: u8) -> Result<(&'static OptionSpec, bool), Error> {
    let position = SHORT_OPTIONS
        .iter()
        .position(|&c| c == letter && c != b':')
        .ok_or(Error("bad option"))?;
    let name = match letter {
        b'l' => Some("dhcp-leasefile"),
        b's' => Some("domain"),
        _ => None,
    };
    let spec = if let Some(name) = name {
        lookup(name.as_bytes())
    } else {
        OPTIONS.iter().find(|spec| spec.short == Some(letter))
    }
    .ok_or(Error("bad option"))?;
    Ok((spec, SHORT_OPTIONS.get(position + 1) == Some(&b':')))
}

/// Load arguments excluding argv[0]. Each ordinary option is validated and
/// delivered immediately, preserving CLI/include ordering and failure order.
/// The callback must apply its semantics or return an error for unimplemented
/// options. A successful load alone therefore does not assert engine coverage.
///
/// `conf-script` deliberately executes /bin/sh as C popen does; callers must
/// only load trusted administrator configuration. Paths are relative to the
/// process working directory, including paths in nested configuration files.
/// Errors are startup-fatal. Script parse failures leave the command to finish
/// after the application reports the error and exits, matching C's die path.
pub fn load<F>(arguments: &[OsString], default_file: &Path, apply: F) -> Result<Action, LoadError>
where
    F: FnMut(&Directive, &Location) -> Result<(), Error>,
{
    let mut loader = Loader {
        apply,
        seen_files: HashSet::new(),
        read_stdin: false,
        occurrences: OccurrenceTracker::default(),
    };
    loader.arguments(arguments, default_file)
}

struct Loader<F> {
    apply: F,
    seen_files: HashSet<(u64, u64)>,
    read_stdin: bool,
    occurrences: OccurrenceTracker,
}

impl<F> Loader<F>
where
    F: FnMut(&Directive, &Location) -> Result<(), Error>,
{
    fn arguments(&mut self, args: &[OsString], default_file: &Path) -> Result<Action, LoadError> {
        let location = Location::command_line();
        let mut first_file = None;
        let mut action = Action::Run;
        let mut nonoptions = Vec::new();
        let mut index = 0;
        while index < args.len() {
            let bytes = args[index].as_bytes();
            if bytes == b"--" {
                nonoptions.extend(args[index + 1..].iter());
                break;
            }
            if bytes.len() < 2 || bytes[0] != b'-' {
                nonoptions.push(&args[index]);
                index += 1;
                continue;
            }
            if let Some(long) = bytes.strip_prefix(b"--") {
                let equal = long.iter().position(|&c| c == b'=');
                let (name, value) = match equal {
                    Some(pos) => (&long[..pos], Some(&long[pos + 1..])),
                    None => (long, None),
                };
                let spec = long_option(name).map_err(|_| {
                    LoadError::new(&location, 1, "bad command line options: try --help")
                })?;
                let value = match (spec.argument, value) {
                    (Argument::None, Some(_)) => {
                        return Err(LoadError::new(
                            &location,
                            1,
                            "bad command line options: try --help",
                        ))
                    }
                    (Argument::Required, None) => {
                        index += 1;
                        Some(
                            args.get(index)
                                .ok_or_else(|| {
                                    LoadError::new(
                                        &location,
                                        1,
                                        "bad command line options: try --help",
                                    )
                                })?
                                .as_bytes(),
                        )
                    }
                    (_, value) => value,
                };
                if let Some(early) = self.command_option(
                    spec,
                    value.map(EncodedArg::command_line),
                    &mut first_file,
                    &mut action,
                    args,
                    &location,
                )? {
                    return Ok(early);
                }
            } else {
                let mut cursor = 1;
                while cursor < bytes.len() {
                    let (spec, required) = short_option(bytes[cursor]).map_err(|_| {
                        LoadError::new(&location, 1, "bad command line options: try --help")
                    })?;
                    cursor += 1;
                    let value = if required {
                        let value = if cursor < bytes.len() {
                            &bytes[cursor..]
                        } else {
                            index += 1;
                            args.get(index)
                                .ok_or_else(|| {
                                    LoadError::new(
                                        &location,
                                        1,
                                        "bad command line options: try --help",
                                    )
                                })?
                                .as_bytes()
                        };
                        cursor = bytes.len();
                        Some(EncodedArg::command_line(value))
                    } else {
                        None
                    };
                    if let Some(early) = self.command_option(
                        spec,
                        value,
                        &mut first_file,
                        &mut action,
                        args,
                        &location,
                    )? {
                        return Ok(early);
                    }
                }
            }
            index += 1;
        }
        if nonoptions
            .iter()
            .any(|arg| arg.as_bytes().iter().any(|&c| !super::white(c)))
        {
            return Err(LoadError::new(&location, 1, "junk found in command line"));
        }
        if let Some(path) = first_file {
            self.file(&path, false, false)?;
        } else {
            self.file(default_file, true, false)?;
        }
        Ok(action)
    }

    fn command_option(
        &mut self,
        spec: &OptionSpec,
        argument: Option<EncodedArg>,
        first_file: &mut Option<PathBuf>,
        action: &mut Action,
        args: &[OsString],
        location: &Location,
    ) -> Result<Option<Action>, LoadError> {
        match spec.id {
            "LOPT_TEST" => *action = Action::Test,
            "'v'" => return Ok(Some(Action::Version)),
            "'w'" => {
                return Ok(Some(if args.len() == 2 && args[1] == "dhcp" {
                    Action::HelpDhcp
                } else {
                    Action::Help
                }))
            }
            "'C'" => {
                if first_file.is_none() {
                    *first_file = path_from_arg(argument.as_ref());
                } else if let Some(path) = path_from_arg(argument.as_ref()) {
                    self.file(&path, false, false)?;
                } else {
                    // C's NULL second conf-file is undefined (stat/fopen
                    // NULL); diagnose rather than reproduce a crash.
                    return Err(LoadError::new(location, 1, "empty additional conf-file"));
                }
            }
            _ => self.directive(
                Directive {
                    name: spec.name.as_bytes().to_vec(),
                    argument,
                },
                location,
                Origin::CommandLine,
            )?,
        }
        Ok(None)
    }

    fn directive(
        &mut self,
        directive: Directive,
        location: &Location,
        origin: Origin,
    ) -> Result<(), LoadError> {
        let spec = validate_directive(&directive).map_err(|e| LoadError::new(location, 1, e.0))?;
        if !self.occurrences.record(spec, origin).map_err(|e| {
            LoadError::new(
                location,
                1,
                if origin == Origin::CommandLine {
                    format!("bad command line options: {}", e.0)
                } else {
                    e.0.to_owned()
                },
            )
        })? {
            return Ok(());
        }
        match spec.id {
            "'C'" | "LOPT_CONF_SCRIPT" => {
                if let Some(path) = path_from_arg(directive.argument.as_ref()) {
                    self.file(&path, false, spec.id == "LOPT_CONF_SCRIPT")?;
                }
            }
            "'7'" => self.directory(directive.argument.as_ref().unwrap(), location)?,
            // C handles these commands only on argv; in a file they set bit 0
            // of the option flags, which has no runtime meaning.
            "'v'" | "'w'" | "LOPT_TEST" => {}
            _ => (self.apply)(&directive, location).map_err(|e| {
                LoadError::new(
                    location,
                    1,
                    if origin == Origin::CommandLine {
                        let message = if e.0 == "error" { "try --help" } else { e.0 };
                        format!("bad command line options: {message}")
                    } else {
                        e.0.to_owned()
                    },
                )
            })?,
        }
        Ok(())
    }

    fn read<R: BufRead>(
        &mut self,
        mut reader: R,
        path: &Path,
        script: bool,
    ) -> Result<(), LoadError> {
        let mut buffer = Vec::new();
        let mut location = Location {
            file: Some(path.to_owned()),
            line: Some(0),
            from_script: script,
        };
        loop {
            buffer.clear();
            // get_line_alloc treats a getc read error as EOF, but still
            // returns a partial final line. Opening the file failed earlier.
            let count = reader
                .read_until(b'\n', &mut buffer)
                .unwrap_or(buffer.len());
            if count == 0 {
                break;
            }
            // This reader created line=Some(0) above; no branch removes it.
            *location.line.as_mut().unwrap() += 1;
            if let Some(directive) =
                lex_line(&buffer).map_err(|e| LoadError::new(&location, 1, e.0))?
            {
                self.directive(directive, &location, Origin::File)?;
            }
        }
        Ok(())
    }

    fn file(&mut self, path: &Path, missing_ok: bool, script: bool) -> Result<(), LoadError> {
        let location = Location {
            file: Some(path.to_owned()),
            line: None,
            // Only parsing emitted lines adds "in output from". popen and
            // pclose failures themselves are ordinary startup diagnostics.
            from_script: false,
        };
        if !script && path == Path::new("-") {
            if self.read_stdin {
                return Ok(());
            }
            self.read_stdin = true;
            return self.read(io::stdin().lock(), Path::new("stdin"), false);
        }
        // stat follows symlinks; dev+inode handles hard links and recursive
        // includes without a string-path recursion limit.
        if let Ok(metadata) = fs::metadata(path) {
            if !self.seen_files.insert((metadata.dev(), metadata.ino())) {
                return Ok(());
            }
        }
        if script {
            let mut command = Command::new("/bin/sh");
            command
                .arg0("sh")
                .arg("-c")
                .arg(path.as_os_str())
                .stdin(Stdio::inherit())
                .stdout(Stdio::piped());
            // dnsmasq.c ignores SIGPIPE before read_opts(), and popen keeps
            // that disposition in its shell. Command resets it before exec;
            // restore the inherited contract using only an async-signal-safe
            // operation in the child.
            dnsmasq_platform::libc_format::preserve_ignored_sigpipe(&mut command);
            let mut child = command
                .spawn()
                .map_err(|e| LoadError::path_io(&location, 3, "cannot execute", path, e))?;
            // A parse error is startup-fatal: main exits just as C die does,
            // without killing or waiting for the script. Its remaining work
            // and closed-output-pipe handling continue after parent exit.
            // Successful spawn used Stdio::piped above and no other caller
            // took this ChildStdout; transfer that sole pipe owner to the reader.
            self.read(BufReader::new(child.stdout.take().unwrap()), path, true)?;
            let status = child
                .wait()
                .map_err(|e| LoadError::path_io(&location, 5, "error executing", path, e))?;
            if !status.success() {
                return Err(LoadError::new(
                    &location,
                    status.into_raw() + 10,
                    format!("{} returns non-zero error code", path.display()),
                ));
            }
            return Ok(());
        }
        match File::open(path) {
            Ok(file) => self.read(BufReader::new(file), path, false),
            Err(e) if missing_ok && e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(LoadError::path_io(&location, 3, "cannot read", path, e)),
        }
    }

    fn directory(&mut self, argument: &EncodedArg, location: &Location) -> Result<(), LoadError> {
        let parts = argument.split(b',');
        let Some(directory) = path_from_arg(parts.first()) else {
            return Ok(());
        };
        let mut include = Vec::new();
        let mut exclude = Vec::new();
        for part in &parts[1..] {
            let suffix = part.decoded();
            if suffix.is_empty() || suffix == b"*" {
                continue;
            }
            if suffix[0] == b'*' {
                include.push(suffix[1..].to_vec());
            } else {
                exclude.push(suffix);
            }
        }
        let entries = fs::read_dir(&directory).map_err(|e| {
            LoadError::path_io(location, 3, "cannot access directory", &directory, e)
        })?;
        let mut files = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| LoadError::new(location, 3, e.to_string()))?;
            let name = entry.file_name();
            let name = name.as_bytes();
            if name.is_empty()
                || name[0] == b'.'
                || name.last() == Some(&b'~')
                || (name[0] == b'#' && name.last() == Some(&b'#'))
            {
                continue;
            }
            let matches = |suffix: &Vec<u8>| name.len() > suffix.len() && name.ends_with(suffix);
            if (!include.is_empty() && !include.iter().any(matches)) || exclude.iter().any(matches)
            {
                continue;
            }
            let path = entry.path();
            let metadata = fs::metadata(&path)
                .map_err(|e| LoadError::path_io(location, 3, "cannot access", &path, e))?;
            if metadata.is_file() {
                files.push(path);
            }
        }
        // Same strcmp byte order; O(n log n) instead of C's insertion-list O(n²).
        crate::sorting::sort_by(&mut files, |a, b| {
            a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes())
        });
        for path in files {
            self.file(&path, false, false)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScalarConfig;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "dnsmasq-config-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn file(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, contents).unwrap();
            path
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn run(args: &[OsString], default: &Path) -> Result<(Action, ScalarConfig), LoadError> {
        let mut config = ScalarConfig::default();
        let action = load(args, default, |directive, _| {
            if config.apply(directive)? {
                Ok(())
            } else {
                Err(Error("unimplemented option"))
            }
        })?;
        Ok((action, config))
    }

    #[test]
    fn path_io_errors_preserve_text_and_location() {
        let location = Location {
            file: Some("main.conf".into()),
            line: Some(7),
            from_script: false,
        };
        for (action, code) in [
            ("cannot execute", 3),
            ("error executing", 5),
            ("cannot read", 3),
            ("cannot access directory", 3),
            ("cannot access", 3),
        ] {
            for (path, displayed) in [
                (b"/tmp/config file".as_slice(), "/tmp/config file"),
                (b"/tmp/non-utf8-\xff".as_slice(), "/tmp/non-utf8-\u{fffd}"),
            ] {
                let path = Path::new(std::ffi::OsStr::from_bytes(path));
                let error = LoadError::path_io(
                    &location,
                    code,
                    action,
                    path,
                    io::Error::other("test I/O failure"),
                );
                assert_eq!(error.exit_code, code);
                assert_eq!(
                    error.message,
                    format!("{action} {displayed}: test I/O failure")
                );
                assert_eq!(
                    error.to_string(),
                    format!("{action} {displayed}: test I/O failure at line 7 of main.conf")
                );
            }
        }
        for (code, text) in [(2, "No such file or directory"), (13, "Permission denied")] {
            let error = LoadError::path_io(
                &Location::command_line(),
                3,
                "cannot read",
                Path::new("missing.conf"),
                io::Error::from_raw_os_error(code),
            );
            assert_eq!(
                error.to_string(),
                format!("cannot read missing.conf: {text}")
            );
        }
    }

    #[test]
    fn cli_file_override_first_file_deferral_and_inline_order() {
        let temp = Temp::new();
        let file = temp.file("main", "port=1234\n");
        let (action, config) = run(
            &[
                "--test".into(),
                "-p53".into(),
                "-C".into(),
                file.clone().into(),
            ],
            &temp.0.join("absent"),
        )
        .unwrap();
        assert_eq!(action, Action::Test);
        assert_eq!(config.dns_port, 1234);
        let a = temp.file("a", "server=first\n");
        let b = temp.file("b", "server=second\n");
        let mut order = Vec::new();
        load(
            &["-C".into(), a.into(), "-C".into(), b.into()],
            &file,
            |d, _| {
                order.push(d.argument.as_ref().unwrap().decoded());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(order, [b"second".to_vec(), b"first".to_vec()]);
        // An extra -C is loaded immediately; a subsequent CLI scalar is
        // ignored by C's ARG_USED_FILE path and does not erase that value.
        let empty = temp.file("empty", "");
        let (_, config) = run(
            &[
                "-C".into(),
                empty.into(),
                "-C".into(),
                file.into(),
                "-p55".into(),
            ],
            &temp.0.join("absent"),
        )
        .unwrap();
        assert_eq!(config.dns_port, 1234);
    }

    #[test]
    fn includes_deduplicate_inode_before_recursion() {
        let temp = Temp::new();
        let a = temp.0.join("a");
        let b = temp.0.join("b");
        let alias = temp.0.join("alias");
        fs::write(
            &a,
            format!(
                "conf-file={}\nconf-file={}\nserver=a\n",
                b.display(),
                alias.display()
            ),
        )
        .unwrap();
        fs::write(&b, format!("conf-file={}\nserver=b\n", a.display())).unwrap();
        fs::hard_link(&b, &alias).unwrap();
        let mut order = Vec::new();
        load(&["-C".into(), a.into()], &temp.0.join("absent"), |d, _| {
            order.push(d.argument.as_ref().unwrap().decoded());
            Ok(())
        })
        .unwrap();
        assert_eq!(order, [b"b".to_vec(), b"a".to_vec()]);
    }

    #[test]
    fn directory_suffixes_backups_and_byte_order() {
        let temp = Temp::new();
        let directory = temp.0.join("directory");
        fs::create_dir(&directory).unwrap();
        for name in [
            "20.conf",
            "10.conf",
            ".hidden.conf",
            "backup.conf~",
            "#backup.conf#",
            "30.skip.conf",
            "other.txt",
        ] {
            fs::write(directory.join(name), format!("server={name}\n")).unwrap();
        }
        fs::create_dir(directory.join("directory.conf")).unwrap();
        let config = temp.file(
            "main",
            &format!("conf-dir={},*.conf,.skip.conf\n", directory.display()),
        );
        let mut order = Vec::new();
        load(
            &["-C".into(), config.into()],
            &temp.0.join("absent"),
            |d, _| {
                order.push(d.argument.as_ref().unwrap().decoded());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(order, [b"10.conf".to_vec(), b"20.conf".to_vec()]);
    }

    #[test]
    fn absent_default_is_optional_but_explicit_file_and_dangling_link_fail() {
        let temp = Temp::new();
        let absent = temp.0.join("absent");
        assert!(run(&[], &absent).is_ok());
        assert_eq!(
            run(&["-C".into(), absent.clone().into()], &absent)
                .unwrap_err()
                .exit_code,
            3
        );
        let directory = temp.0.join("directory");
        fs::create_dir(&directory).unwrap();
        std::os::unix::fs::symlink(&absent, directory.join("bad")).unwrap();
        let config = temp.file("main", &format!("conf-dir={}\n", directory.display()));
        assert_eq!(
            run(&["-C".into(), config.into()], &absent)
                .unwrap_err()
                .exit_code,
            3
        );
    }

    #[test]
    fn special_commands_and_short_long_arity_are_distinct() {
        let temp = Temp::new();
        let absent = temp.0.join("absent");
        assert_eq!(run(&["-v?".into()], &absent).unwrap().0, Action::Version);
        assert_eq!(
            run(&["--help".into(), "dhcp".into()], &absent).unwrap().0,
            Action::HelpDhcp
        );
        assert!(run(&["--port=bad".into(), "--help".into()], &absent).is_err());
        assert!(run(&["--cache-size".into(), "123".into()], &absent).is_err());
        assert_eq!(run(&["-c123".into()], &absent).unwrap().1.cache_size, 123);
        assert!(run(&["--por=53".into()], &absent).is_err());
        assert_eq!(
            run(&["--max-tcp-c=123".into()], &absent)
                .unwrap()
                .1
                .max_tcp_connections,
            123
        );
        assert!(run(&["--".into(), "--test".into()], &absent).is_err());
    }

    #[test]
    fn config_script_exit_status_location_and_file_commands() {
        let temp = Temp::new();
        let config = temp.file(
            "main",
            "conf-script=printf 'port=1234\\n'\nhelp\nversion\ntest\n",
        );
        let (action, state) = run(&["-C".into(), config.into()], &temp.0.join("absent")).unwrap();
        assert_eq!(action, Action::Run);
        assert_eq!(state.dns_port, 1234);
        let config = temp.file("bad", "conf-script=printf 'port=bad\\n'\n");
        let error = run(&["-C".into(), config.into()], &temp.0.join("absent")).unwrap_err();
        assert!(error.location.from_script);
        assert_eq!(error.exit_code, 1);
        let config = temp.file("exit", "conf-script=exit 3\n");
        assert_eq!(
            run(&["-C".into(), config.into()], &temp.0.join("absent"))
                .unwrap_err()
                .exit_code,
            (3 << 8) + 10
        );
    }

    #[test]
    #[ignore = "requires DNSMASQ_C_REFERENCE pointing to exact C 2.93 build"]
    fn cli_include_acceptance_matches_c() {
        let reference = std::env::var_os("DNSMASQ_C_REFERENCE").expect("DNSMASQ_C_REFERENCE");
        let temp = Temp::new();
        let empty = temp.file("empty", "");
        let scalar = temp.file("scalar", "port=1234\n");
        let recursive = temp.0.join("recursive");
        fs::write(
            &recursive,
            format!("conf-file={}\nport=1234\n", recursive.display()),
        )
        .unwrap();
        let alias = temp.0.join("alias");
        fs::hard_link(&scalar, &alias).unwrap();
        let double = temp.file(
            "double",
            &format!(
                "conf-file={}\nconf-file={}\n",
                scalar.display(),
                alias.display()
            ),
        );
        let duplicate = temp.file(
            "duplicate",
            &format!("conf-file={}\nport=55\n", scalar.display()),
        );
        let directory = temp.0.join("dir");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("10.conf"), "port=1234\n").unwrap();
        fs::write(directory.join("20.skip.conf"), "port=5678\n").unwrap();
        fs::write(directory.join(".hidden.conf"), "invalid\n").unwrap();
        let sorted = temp.file(
            "sorted",
            &format!("conf-dir={},*.conf,.skip.conf\n", directory.display()),
        );
        let script = temp.file("script", "conf-script=printf 'port=1234\\n'\n");
        let script_bad = temp.file("script-bad", "conf-script=printf 'port=bad\\n'\n");
        let as_os = |items: &[&str]| items.iter().map(OsString::from).collect::<Vec<_>>();
        let mut cases: Vec<Vec<OsString>> = [
            vec!["--port=53"],
            vec!["-p53"],
            vec!["-p", "53"],
            vec!["--port"],
            vec!["--cache-size", "123"],
            vec!["-c123"],
            vec!["--por=53"],
            vec!["--max-tcp-c=123"],
            vec!["--version", "--bad"],
            vec!["-v?"],
            vec!["--port=bad", "--help"],
            vec!["--help", "dhcp"],
            vec!["--", "--test"],
            vec!["--port=53", "--port=54"],
            vec!["--port", "  "],
            vec!["--fast-dns-retry"],
        ]
        .iter()
        .map(|args| as_os(args))
        .collect();
        for path in [
            &recursive,
            &double,
            &duplicate,
            &sorted,
            &script,
            &script_bad,
        ] {
            cases.push(vec!["-C".into(), path.as_os_str().to_owned()]);
        }
        cases.push(vec!["-C".into(), scalar.into(), "-p55".into()]);
        let mut successes = 0;
        let mut failures = 0;
        for case in cases {
            let mut args = vec!["--test".into(), "-C".into(), empty.as_os_str().to_owned()];
            args.extend(case);
            let rust = run(&args, &temp.0.join("absent"));
            let c = Command::new(&reference).args(&args).output().unwrap();
            assert_eq!(
                rust.is_ok(),
                c.status.success(),
                "args {args:?}, Rust {rust:?}, C {}",
                String::from_utf8_lossy(&c.stderr)
            );
            if rust.is_ok() {
                successes += 1;
            } else {
                failures += 1;
            }
        }
        assert!(successes >= 10 && failures >= 5);
        eprintln!(
            "CLI/include C differential: {successes} accepted, {failures} rejected, {} matched",
            successes + failures
        );
    }
}
