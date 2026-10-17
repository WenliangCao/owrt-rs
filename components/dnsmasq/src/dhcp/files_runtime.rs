//! Staged DHCP host/option banks. File work is owned by the existing poll loop;
//! only completed generations are returned for publication to packet consumers.

use super::filewatch::{self, DirectoryScan, DirectoryWatch, ScanError, WatchStep};
use crate::config::dhcp::{
    DhcpOption, DynamicFileDirectory, DynamicFileKind, FilePlanStep, HostConfig, HostFileError,
    HostFileErrorKind, HostFiles,
};
use crate::config::lex_argument_line;
use dnsmasq_platform::poll::PollFd;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::PathBuf;

#[derive(Debug)]
pub enum FileDiagnostic {
    File(HostFileError),
    StaticDirectory { path: PathBuf, error: io::Error },
    BadDirectory { path: PathBuf, error: io::Error },
    DirectoryWatch { path: PathBuf, error: io::Error },
    WatchRead(io::Error),
    Read(PathBuf),
    Modified(PathBuf),
}

impl std::fmt::Display for FileDiagnostic {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn message(error: &io::Error) -> String {
            let mut value = error.to_string();
            if let Some(code) = error.raw_os_error() {
                if let Some(prefix) = value.strip_suffix(&format!(" (os error {code})")) {
                    value.truncate(prefix.len());
                }
            }
            value
        }
        match self {
            Self::File(HostFileError { path, line, kind }) => match kind {
                HostFileErrorKind::Io(error) => {
                    write!(output, "cannot read {}: {}", path.display(), message(error))
                }
                HostFileErrorKind::Line(error) | HostFileErrorKind::Unsupported(error) => write!(
                    output,
                    "{error} at line {} of {}",
                    line.unwrap_or(0),
                    path.display()
                ),
            },
            Self::StaticDirectory { path, error } => write!(
                output,
                "cannot access directory {}: {}",
                path.display(),
                message(error)
            ),
            Self::BadDirectory { path, error } => write!(
                output,
                "bad dynamic directory {}: {}",
                path.display(),
                if error.raw_os_error() == Some(20) {
                    "not a directory".to_owned()
                } else {
                    message(error)
                }
            ),
            Self::DirectoryWatch { path, error } => write!(
                output,
                "failed to create inotify for {}: {}",
                path.display(),
                message(error)
            ),
            Self::WatchRead(error) => write!(output, "inotify read: {}", message(error)),
            Self::Read(path) => write!(output, "read {}", path.display()),
            Self::Modified(path) => write!(output, "inotify: {} new or modified", path.display()),
        }
    }
}

#[derive(Debug)]
pub struct BankUpdate {
    /// Full reload removes all old bank rows; a directory event prepends only.
    pub replacement: bool,
    /// Bank rows only, newest first. Inline/ethers rows remain caller-owned.
    pub hosts: Vec<HostConfig>,
    /// Bank rows only, newest first; never forced or PXE-only.
    pub options: Vec<DhcpOption>,
    /// Full reload, or a live host file which successfully opened. C refreshes
    /// host/lease/DNS state even when that file contained no successful rows.
    pub refresh_hosts: bool,
}

#[derive(Debug, Default)]
pub struct FileStep {
    pub update: Option<BankUpdate>,
    pub diagnostics: Vec<FileDiagnostic>,
    /// More bounded work is immediately available. False while a FIFO waits.
    pub runnable: bool,
}

struct Generation {
    replacement: bool,
    hosts: Vec<HostConfig>,
    base_hosts: usize,
    options: Vec<DhcpOption>,
    refresh_hosts: bool,
}

impl Generation {
    fn new(base: &[HostConfig], replacement: bool) -> Self {
        Self {
            replacement,
            hosts: base.to_vec(),
            base_hosts: base.len(),
            options: Vec::new(),
            refresh_hosts: replacement,
        }
    }

    fn complete(mut self) -> BankUpdate {
        self.hosts.truncate(self.hosts.len() - self.base_hosts);
        BankUpdate {
            replacement: self.replacement,
            hosts: self.hosts,
            options: self.options,
            refresh_hosts: self.refresh_hosts,
        }
    }
}

struct ReadJob {
    path: PathBuf,
    kind: DynamicFileKind,
    file: File,
    wait_readiness: bool,
    line: Vec<u8>,
    line_number: usize,
}

impl ReadJob {
    fn line(&mut self, generation: &mut Generation, diagnostics: &mut Vec<FileDiagnostic>) {
        self.line_number += 1;
        let parsed = lex_argument_line(&self.line).and_then(|argument| {
            if let Some(argument) = argument {
                match self.kind {
                    DynamicFileKind::Hosts => generation
                        .hosts
                        .insert(0, HostFiles::parse_row(&argument, &generation.hosts)?),
                    DynamicFileKind::Options => generation
                        .options
                        .insert(0, DhcpOption::parse(&argument, false)?),
                }
            }
            Ok(())
        });
        if let Err(error) = parsed {
            diagnostics.push(FileDiagnostic::File(HostFileError {
                path: self.path.clone(),
                line: Some(self.line_number),
                kind: HostFileErrorKind::Line(error),
            }));
        }
        self.line.clear();
    }

    fn step(&mut self, generation: &mut Generation, diagnostics: &mut Vec<FileDiagnostic>) -> bool {
        if self.wait_readiness {
            let mut fds = [PollFd {
                fd: self.file.as_raw_fd(),
                events: 1,
                revents: 0,
            }];
            match dnsmasq_platform::poll::poll_fds(&mut fds, 0) {
                Ok(0) => return false,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => return false,
                Err(_) => {
                    if !self.line.is_empty() {
                        self.line(generation, diagnostics);
                    }
                    return true;
                }
                Ok(_) => {}
            }
        }
        let mut bytes = [0; 4096];
        let length = match self.file.read(&mut bytes) {
            Ok(length) => length,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return false
            }
            // C get_line_alloc treats errors as EOF and parses a partial line.
            Err(_) => 0,
        };
        for byte in &bytes[..length] {
            if *byte == b'\n' {
                self.line(generation, diagnostics);
            } else {
                self.line.push(*byte);
            }
        }
        if length == 0 && !self.line.is_empty() {
            self.line(generation, diagnostics);
        }
        length == 0
    }
}

enum Phase {
    Idle,
    StaticHosts,
    StaticOptions,
    Directories(usize),
    Live,
}

pub struct DhcpFiles {
    hosts: HostFiles,
    options: HostFiles,
    watch: Option<DirectoryWatch>,
    phase: Phase,
    generation: Option<Generation>,
    scan: Option<DirectoryScan>,
    job: Option<ReadJob>,
}

impl DhcpFiles {
    /// All lists are already in C's reverse directive order. Dynamic hosts and
    /// options must remain interleaved in their single declaration-order list.
    pub fn new(
        host_files: &[Vec<u8>],
        option_files: &[Vec<u8>],
        directories: &[DynamicFileDirectory],
    ) -> io::Result<Self> {
        Ok(Self {
            hosts: HostFiles::new(host_files),
            options: HostFiles::new(option_files),
            watch: (!directories.is_empty())
                .then(|| DirectoryWatch::new(directories))
                .transpose()?,
            phase: Phase::Idle,
            generation: None,
            scan: None,
            job: None,
        })
    }

    /// False asks the owner to retain its pending reload trigger until the
    /// previous update has been published. It never discards an active job.
    pub fn begin_reload(&mut self, nonbank_hosts: &[HostConfig]) -> bool {
        if self.busy() {
            return false;
        }
        self.generation = Some(Generation::new(nonbank_hosts, true));
        self.hosts.begin_plan();
        self.phase = Phase::StaticHosts;
        true
    }

    /// While true, the owner defers DHCP admission until a complete bank update
    /// can be applied. DNS/TFTP/helper service continues through the same owner.
    pub fn busy(&self) -> bool {
        self.generation.is_some()
    }

    /// Current work the next file turn can actually consume. A queued reload
    /// or buffered watch event cannot run ahead of an active blocked FIFO.
    pub fn runnable(&self) -> bool {
        if let Some(job) = &self.job {
            return !job.wait_readiness;
        }
        self.busy() || self.watch.as_ref().is_some_and(DirectoryWatch::runnable)
    }

    pub fn watch_fd(&self) -> Option<std::os::fd::RawFd> {
        self.watch.as_ref().map(DirectoryWatch::raw_fd)
    }

    pub fn append_poll_fds(&self, fds: &mut Vec<PollFd>) {
        if !self.busy() {
            if let Some(watch) = &self.watch {
                watch.append_poll_fds(fds);
            }
        }
        if let Some(job) = self.job.as_ref().filter(|job| job.wait_readiness) {
            fds.push(PollFd {
                fd: job.file.as_raw_fd(),
                events: 1,
                revents: 0,
            });
        }
    }

    fn open(
        &mut self,
        kind: DynamicFileKind,
        path: PathBuf,
        dynamic: bool,
        diagnostics: &mut Vec<FileDiagnostic>,
    ) {
        // option_read_dynfile announces the attempt; static reread_dhcp logs
        // only after an open/read succeeded.
        if dynamic {
            diagnostics.push(FileDiagnostic::Read(path.clone()));
        }
        match OpenOptions::new()
            .read(true)
            .custom_flags(0o4000)
            .open(&path)
        {
            Ok(file) => {
                let wait_readiness = file.metadata().is_ok_and(|metadata| {
                    metadata.file_type().is_fifo() || metadata.file_type().is_char_device()
                });
                if kind == DynamicFileKind::Hosts {
                    self.generation.as_mut().unwrap().refresh_hosts = true;
                }
                self.job = Some(ReadJob {
                    path,
                    kind,
                    file,
                    wait_readiness,
                    line: Vec::new(),
                    line_number: 0,
                });
            }
            Err(error) => diagnostics.push(FileDiagnostic::File(HostFileError {
                path,
                line: None,
                kind: HostFileErrorKind::Io(error),
            })),
        }
    }

    /// Call again only after applying any returned update. This snapshots the
    /// caller's current host bank before each individual live file is parsed.
    pub fn step(&mut self, current_hosts: &[HostConfig]) -> FileStep {
        self.step_with_watch_readiness(current_hosts, true)
    }

    /// Buffered watch events and active file generations remain runnable
    /// independently of the kernel descriptor's next POLLIN notification.
    pub fn step_with_watch_readiness(&mut self, current_hosts: &[HostConfig], watch_ready: bool) -> FileStep {
        let mut result = FileStep::default();
        if let Some(job) = &mut self.job {
            if job.step(self.generation.as_mut().unwrap(), &mut result.diagnostics) {
                let job = self.job.take().unwrap();
                if matches!(self.phase, Phase::StaticHosts | Phase::StaticOptions) {
                    result.diagnostics.push(FileDiagnostic::Read(job.path));
                }
                if matches!(self.phase, Phase::Live) {
                    self.finish(&mut result);
                }
            }
        } else if let Some(scan) = &mut self.scan {
            match scan.entries.next() {
                Some(Ok(entry)) => {
                    use std::os::unix::ffi::OsStrExt;
                    let name = entry.file_name();
                    if filewatch::accepted_name(name.as_bytes()) {
                        let path = filewatch::literal_join(&scan.path, name.as_bytes());
                        if fs::metadata(&path).is_ok_and(|metadata| metadata.is_file()) {
                            let kind = scan.kind.clone();
                            self.open(kind, path, true, &mut result.diagnostics);
                        }
                    }
                }
                // C treats readdir error like EOF; the prior files survive.
                Some(Err(_)) | None => self.scan = None,
            }
        } else {
            match self.phase {
                Phase::StaticHosts | Phase::StaticOptions => {
                    let host = matches!(self.phase, Phase::StaticHosts);
                    let mut errors = Vec::new();
                    let step = if host {
                        self.hosts.step_plan(&mut errors)
                    } else {
                        self.options.step_plan(&mut errors)
                    };
                    result
                        .diagnostics
                        .extend(errors.into_iter().map(|error| match error {
                            HostFileError {
                                path,
                                kind: HostFileErrorKind::Io(error),
                                ..
                            } => FileDiagnostic::StaticDirectory { path, error },
                            error => FileDiagnostic::File(error),
                        }));
                    match step {
                        FilePlanStep::Pending => {}
                        FilePlanStep::File(path) => self.open(
                            if host {
                                DynamicFileKind::Hosts
                            } else {
                                DynamicFileKind::Options
                            },
                            path,
                            false,
                            &mut result.diagnostics,
                        ),
                        FilePlanStep::Done if host => {
                            self.options.begin_plan();
                            self.phase = Phase::StaticOptions;
                        }
                        FilePlanStep::Done => self.phase = Phase::Directories(0),
                    }
                }
                Phase::Directories(index) => {
                    if let Some(watch) = &mut self.watch {
                        if index < watch.len() {
                            self.phase = Phase::Directories(index + 1);
                            match watch.scan(index) {
                                Ok(scan) => self.scan = Some(scan),
                                Err(ScanError::Bad(path, error)) => result
                                    .diagnostics
                                    .push(FileDiagnostic::BadDirectory { path, error }),
                                Err(ScanError::Watch(path, error)) => result
                                    .diagnostics
                                    .push(FileDiagnostic::DirectoryWatch { path, error }),
                            }
                        } else {
                            self.finish(&mut result);
                        }
                    } else {
                        self.finish(&mut result);
                    }
                }
                Phase::Idle => {
                    if let Some(watch) = &mut self.watch {
                        match watch.step_with_readiness(watch_ready) {
                            Ok(WatchStep::File(kind, path)) => {
                                self.phase = Phase::Live;
                                self.generation = Some(Generation::new(current_hosts, false));
                                result
                                    .diagnostics
                                    .push(FileDiagnostic::Modified(path.clone()));
                                self.open(kind, path, true, &mut result.diagnostics);
                                if self.job.is_none() {
                                    self.finish(&mut result);
                                }
                            }
                            Ok(WatchStep::Pending) => result.runnable = true,
                            Ok(WatchStep::Idle) => {}
                            Err(error) => result.diagnostics.push(FileDiagnostic::WatchRead(error)),
                        }
                    }
                }
                Phase::Live => self.finish(&mut result),
            }
        }
        result.runnable |= self.runnable();
        result
    }

    fn finish(&mut self, result: &mut FileStep) {
        result.update = self.generation.take().map(Generation::complete);
        self.phase = Phase::Idle;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::dhcp::OptionValue;
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "dhcp-files-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
        fn bytes(&self, name: &str) -> Vec<u8> {
            self.path(name).as_os_str().as_bytes().to_vec()
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn complete(
        owner: &mut DhcpFiles,
        current: &[HostConfig],
    ) -> (BankUpdate, Vec<FileDiagnostic>) {
        let mut diagnostics = Vec::new();
        for _ in 0..100_000 {
            let step = owner.step(current);
            diagnostics.extend(step.diagnostics);
            if let Some(update) = step.update {
                return (update, diagnostics);
            }
        }
        panic!("file generation did not complete");
    }

    fn drain(
        owner: &mut DhcpFiles,
        hosts: &mut Vec<HostConfig>,
        options: &mut Vec<DhcpOption>,
    ) -> usize {
        let mut updates = 0;
        for _ in 0..100_000 {
            let step = owner.step(hosts);
            if let Some(mut update) = step.update {
                assert!(!update.replacement);
                update.hosts.append(hosts);
                *hosts = update.hosts;
                update.options.append(options);
                *options = update.options;
                updates += 1;
            }
            if !step.runnable {
                return updates;
            }
        }
        panic!("watch did not drain");
    }

    fn host(line: &[u8]) -> HostConfig {
        HostFiles::parse_row(&lex_argument_line(line).unwrap().unwrap(), &[]).unwrap()
    }
    fn option_values(options: &[DhcpOption]) -> Vec<Vec<u8>> {
        options
            .iter()
            .map(|option| option.value.bytes(None, false))
            .collect()
    }

    #[test]
    fn full_generation_keeps_valid_rows_and_replaces_banks_after_open_failure() {
        let directory = Directory::new();
        fs::write(directory.path("hosts"), b"02:00:00:00:00:01,192.0.2.10\n02:00:00:00:00:02,192.0.2.10\n\"\n02:00:00:00:00:03,192.0.2.11").unwrap();
        fs::write(
            directory.path("opts"),
            b"option:domain-name,first\ninvalid option\noption:domain-name,second\n",
        )
        .unwrap();
        let mut owner =
            DhcpFiles::new(&[directory.bytes("hosts")], &[directory.bytes("opts")], &[]).unwrap();
        let base = vec![host(b"02:00:00:00:00:ff,192.0.2.2")];
        assert!(owner.begin_reload(&base));
        assert!(!owner.begin_reload(&base));
        let (update, diagnostics) = complete(&mut owner, &base);
        assert!(update.replacement && update.refresh_hosts);
        assert_eq!(update.hosts.len(), 2);
        assert_eq!(update.hosts[0].address.unwrap().octets(), [192, 0, 2, 11]);
        assert_eq!(
            option_values(&update.options),
            [b"second".to_vec(), b"first".to_vec()]
        );
        assert!(update
            .options
            .iter()
            .all(|option| !option.force && !option.pxe_only));
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| matches!(diagnostic, FileDiagnostic::File(_)))
                .count(),
            3
        );
        fs::remove_file(directory.path("hosts")).unwrap();
        fs::write(directory.path("opts"), b"").unwrap();
        assert!(owner.begin_reload(&base));
        let (update, diagnostics) = complete(&mut owner, &base);
        assert!(update.hosts.is_empty() && update.options.is_empty());
        assert!(matches!(
            &diagnostics[0],
            FileDiagnostic::File(HostFileError {
                kind: HostFileErrorKind::Io(_),
                ..
            })
        ));
    }

    #[test]
    fn static_directories_are_sorted_and_dynamic_directories_append_after_them() {
        let directory = Directory::new();
        fs::create_dir(directory.path("static")).unwrap();
        fs::create_dir(directory.path("dynamic")).unwrap();
        for (name, contents) in [
            ("static/z", "option:domain-name,last-static"),
            ("static/a", "option:domain-name,first-static"),
            ("static/.ignored", "option:domain-name,hidden"),
            ("dynamic/one", "option:domain-name,dynamic"),
        ] {
            fs::write(directory.path(name), contents).unwrap();
        }
        symlink("z", directory.path("static/b")).unwrap();
        fs::create_dir(directory.path("static/subdir")).unwrap();
        let mut owner = DhcpFiles::new(
            &[],
            &[directory.bytes("static")],
            &[DynamicFileDirectory {
                kind: DynamicFileKind::Options,
                path: directory.bytes("dynamic"),
            }],
        )
        .unwrap();
        assert!(owner.begin_reload(&[]));
        let (update, _) = complete(&mut owner, &[]);
        assert_eq!(
            option_values(&update.options),
            [
                b"dynamic".to_vec(),
                b"last-static".to_vec(),
                b"last-static".to_vec(),
                b"first-static".to_vec()
            ]
        );
    }

    #[test]
    fn dynamic_host_rows_append_without_replacement_until_full_reload() {
        let directory = Directory::new();
        let mut owner = DhcpFiles::new(
            &[],
            &[],
            &[DynamicFileDirectory {
                kind: DynamicFileKind::Hosts,
                path: directory.bytes(""),
            }],
        )
        .unwrap();
        assert!(owner.begin_reload(&[]));
        assert!(complete(&mut owner, &[]).0.hosts.is_empty());
        let mut hosts = Vec::new();
        let mut options = Vec::new();
        let path = directory.path("hosts");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"02:00:00:00:00:01,192.0.2.10\n").unwrap();
        assert_eq!(drain(&mut owner, &mut hosts, &mut options), 0);
        drop(file);
        assert_eq!(drain(&mut owner, &mut hosts, &mut options), 1);
        assert_eq!(hosts.len(), 1);
        fs::write(
            &path,
            b"02:00:00:00:00:02,192.0.2.10\n02:00:00:00:00:01,192.0.2.11\n",
        )
        .unwrap();
        assert_eq!(drain(&mut owner, &mut hosts, &mut options), 1);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].address.unwrap().octets(), [192, 0, 2, 11]);
        fs::remove_file(&path).unwrap();
        assert_eq!(drain(&mut owner, &mut hosts, &mut options), 0);
        assert_eq!(hosts.len(), 2);
        assert!(owner.begin_reload(&[]));
        let (update, _) = complete(&mut owner, &hosts);
        assert!(update.replacement && update.hosts.is_empty());
    }

    #[test]
    fn dynamic_option_updates_keep_old_options_and_do_not_refresh_hosts() {
        let directory = Directory::new();
        let mut owner = DhcpFiles::new(
            &[],
            &[],
            &[DynamicFileDirectory {
                kind: DynamicFileKind::Options,
                path: directory.bytes(""),
            }],
        )
        .unwrap();
        owner.begin_reload(&[]);
        complete(&mut owner, &[]);
        fs::write(directory.path("new"), b"option:domain-name,first\n").unwrap();
        let (first, _) = complete(&mut owner, &[]);
        assert!(!first.refresh_hosts && !first.replacement);
        fs::write(directory.path("new"), b"option:domain-name,second\n").unwrap();
        let (second, _) = complete(&mut owner, &[]);
        assert_eq!(
            second.options[0].value,
            OptionValue::String(b"second".to_vec())
        );
        assert!(!second.refresh_hosts);
        fs::write(directory.path("new"), b"").unwrap();
        let (empty, _) = complete(&mut owner, &[]);
        assert!(empty.options.is_empty() && !empty.refresh_hosts && !empty.replacement);
    }

    #[test]
    fn renamed_directory_watch_reads_configured_path_without_reattaching() {
        let directory = Directory::new();
        fs::create_dir(directory.path("watched")).unwrap();
        let mut owner = DhcpFiles::new(
            &[],
            &[],
            &[DynamicFileDirectory {
                kind: DynamicFileKind::Options,
                path: directory.bytes("watched"),
            }],
        )
        .unwrap();
        owner.begin_reload(&[]);
        complete(&mut owner, &[]);
        fs::rename(directory.path("watched"), directory.path("old")).unwrap();
        fs::create_dir(directory.path("watched")).unwrap();
        fs::write(
            directory.path("watched/options"),
            b"option:domain-name,replacement\n",
        )
        .unwrap();
        assert_eq!(drain(&mut owner, &mut Vec::new(), &mut Vec::new()), 0);
        owner.begin_reload(&[]);
        let (reloaded, _) = complete(&mut owner, &[]);
        assert_eq!(option_values(&reloaded.options), [b"replacement".to_vec()]);
        fs::write(
            directory.path("old/options"),
            b"option:domain-name,old-inode\n",
        )
        .unwrap();
        let (event, _) = complete(&mut owner, &[]);
        assert_eq!(option_values(&event.options), [b"replacement".to_vec()]);
    }

    #[test]
    fn missing_dynamic_directory_can_be_watched_on_later_reload() {
        let directory = Directory::new();
        let mut owner = DhcpFiles::new(
            &[],
            &[],
            &[DynamicFileDirectory {
                kind: DynamicFileKind::Hosts,
                path: directory.bytes("missing"),
            }],
        )
        .unwrap();
        owner.begin_reload(&[]);
        let (_, errors) = complete(&mut owner, &[]);
        assert!(errors
            .iter()
            .any(|error| matches!(error, FileDiagnostic::BadDirectory { .. })));
        fs::create_dir(directory.path("missing")).unwrap();
        fs::write(
            directory.path("missing/host"),
            b"02:00:00:00:00:01,192.0.2.10\n",
        )
        .unwrap();
        owner.begin_reload(&[]);
        let (update, _) = complete(&mut owner, &[]);
        assert_eq!(update.hosts.len(), 1);
    }

    #[test]
    fn watch_input_waits_for_its_fd_but_buffered_events_continue_without_readiness() {
        let directory = Directory::new();
        fs::create_dir(directory.path("live")).unwrap();
        let mut owner = DhcpFiles::new(&[], &[], &[DynamicFileDirectory {
            kind: DynamicFileKind::Hosts, path: directory.bytes("live"),
        }]).unwrap();
        owner.begin_reload(&[]);
        let initial = (0..100).find_map(|_| owner.step_with_watch_readiness(&[], false).update).unwrap();
        assert!(initial.hosts.is_empty());
        fs::write(directory.path("live/host"), b"02:00:00:00:00:01,192.0.2.10\n").unwrap();
        for _ in 0..3 {
            let step = owner.step_with_watch_readiness(&[], false);
            assert!(step.update.is_none() && !step.runnable);
        }
        // The first readable turn buffers a kernel batch; subsequent events
        // must finish even after its fd no longer reports POLLIN.
        assert!(owner.step_with_watch_readiness(&[], true).runnable);
        assert!(owner.runnable(), "the kernel batch is now owned logical work");
        let update = (0..100).find_map(|_| owner.step_with_watch_readiness(&[], false).update).unwrap();
        assert_eq!(update.hosts.len(), 1);
        assert_eq!(update.hosts[0].address, Some("192.0.2.10".parse().unwrap()));
    }

    #[test]
    fn static_bank_plan_finishes_from_logical_turns_without_watch_or_network_fd() {
        let directory = Directory::new();
        fs::write(directory.path("opts"), b"option:domain-name,logical\n").unwrap();
        let mut owner = DhcpFiles::new(&[], &[directory.bytes("opts")], &[]).unwrap();
        assert!(!owner.runnable());
        owner.begin_reload(&[]);
        let mut update = None;
        for _ in 0..16 {
            assert!(owner.runnable(), "the next bounded plan/read turn needs no new event");
            let mut fds = Vec::new();
            owner.append_poll_fds(&mut fds);
            assert!(fds.is_empty());
            let step = owner.step_with_watch_readiness(&[], false);
            if step.update.is_some() { update = step.update; break; }
        }
        assert_eq!(option_values(&update.unwrap().options), [b"logical".to_vec()]);
        assert!(!owner.runnable());
        assert!(!owner.busy());
    }

    #[test]
    fn fifo_waits_without_owner_work_and_parses_partial_line_at_eof() {
        let directory = Directory::new();
        let path = directory.path("fifo");
        rustix::fs::mkfifoat(rustix::fs::CWD, &path,
                            rustix::fs::Mode::from_raw_mode(0o600)).unwrap();
        let mut owner = DhcpFiles::new(&[], &[directory.bytes("fifo")], &[]).unwrap();
        owner.begin_reload(&[]);
        for _ in 0..100 {
            let step = owner.step(&[]);
            assert!(step.update.is_none());
            if !step.runnable {
                break;
            }
        }
        assert!(owner.busy());
        assert!(!owner.runnable());
        assert!(!owner.step(&[]).runnable);
        let mut writer = OpenOptions::new()
            .write(true)
            .custom_flags(0o4000)
            .open(path)
            .unwrap();
        writer.write_all(b"option:domain-name,partial").unwrap();
        let step = owner.step(&[]);
        assert!(step.update.is_none());
        assert!(!step.runnable);
        drop(writer);
        let (update, _) = complete(&mut owner, &[]);
        assert_eq!(option_values(&update.options), [b"partial".to_vec()]);
        assert!(!owner.busy());
        assert!(!owner.runnable());
    }
}
