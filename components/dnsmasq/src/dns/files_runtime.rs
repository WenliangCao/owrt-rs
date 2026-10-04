//! Bounded local-file jobs and triggers; no DNS resolver or thread is hidden
//! here. The caller publishes each completed source in its existing owner.

use super::{resolver_line, server_line, FileStamp, ResolverSelection, Source, SourceRule};
use crate::config::dns::{RuleTarget, ServerHost};
use crate::config::dns_lookup::EndpointLookup;
use crate::config::{dns::DnsConfig, Error};
use crate::dns::filewatch::{FileWatch, WatchError};
use owrt_ubus::sys::PollFd;
use std::collections::VecDeque;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

extern "C" {
    fn if_nametoindex(name: *const std::ffi::c_char) -> u32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReloadReason {
    Init,
    Notify,
    Signal,
    Route,
}

#[derive(Debug)]
pub enum FileDiagnostic {
    Access {
        path: PathBuf,
        error: io::Error,
    },
    Open {
        path: PathBuf,
        source: Source,
        error: io::Error,
    },
    Line {
        path: PathBuf,
        line: usize,
        error: Error,
    },
    EmptyResolvers(PathBuf),
    ReadingResolvers(PathBuf),
    Watch(io::Error),
    ResolverChild {
        path: PathBuf,
        error: String,
    },
}

impl std::fmt::Display for FileDiagnostic {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::dns::filewatch::os_message;
        match self {
            Self::Access { path, error } => write!(
                out,
                "failed to access {}: {}",
                path.display(),
                os_message(error)
            ),
            Self::Open {
                path,
                source,
                error,
            } => write!(
                out,
                "{} {}: {}",
                if *source == Source::Resolv {
                    "failed to read"
                } else {
                    "cannot read"
                },
                path.display(),
                os_message(error)
            ),
            Self::Line { path, line, error } => {
                write!(out, "{error} at line {line} of {}", path.display())
            }
            Self::EmptyResolvers(path) => {
                write!(out, "no servers found in {}, will retry", path.display())
            }
            Self::ReadingResolvers(path) => write!(out, "reading {}", path.display()),
            Self::Watch(error) => write!(out, "inotify read: {}", os_message(error)),
            Self::ResolverChild { path, error } => write!(
                out,
                "cannot resolve endpoints in {}: {}",
                path.display(),
                error
            ),
        }
    }
}

#[derive(Debug)]
pub struct SourceUpdate {
    pub source: Source,
    pub path: PathBuf,
    pub rows: Vec<SourceRule>,
    /// Run the existing full hosts/cache/DHCP reload hook once after applying
    /// this update. Its server-file bank is deliberately not reread by that hook.
    pub full_reload: bool,
}

#[derive(Debug, Default)]
pub struct FileStep {
    pub update: Option<SourceUpdate>,
    pub diagnostics: Vec<FileDiagnostic>,
    /// EVENT_RELOAD rerun_scripts belongs after that signal's file reads,
    /// even if a later inotify/route trigger is already queued.
    pub signal_complete: bool,
    /// Local parse work remains. Poll the owner without a long sleep; special
    /// stream inputs waiting for readiness do not set this bit.
    pub runnable: bool,
}

struct ReadRequest {
    source: Source,
    path: PathBuf,
    resolver_index: Option<usize>,
    reload: bool,
}

struct ReadJob {
    request: ReadRequest,
    file: File,
    wait_readiness: bool,
    line: Vec<u8>,
    line_number: usize,
    rows: Vec<SourceRule>,
}

impl ReadJob {
    fn consume_line(&mut self, diagnostics: &mut Vec<FileDiagnostic>) {
        self.line_number += 1;
        if self.request.source == Source::Resolv {
            if let Some(address) = resolver_line(&self.line, |name| {
                let Ok(name) = CString::new(name) else {
                    return 0;
                };
                // SAFETY: interface lookup takes this live C string, performs
                // no network name resolution, and returns zero for unknown names.
                unsafe { if_nametoindex(name.as_ptr()) }
            }) {
                self.rows
                    .push(SourceRule::resolver(address, self.line_number));
            }
        } else {
            match super::server_line_with_origin(&self.line) {
                Ok((rules, reverse)) => {
                    self.rows.extend(rules.into_iter().map(|rule| {
                        SourceRule::configured_reverse(rule, self.line_number, reverse)
                    }))
                }
                Err(error) => diagnostics.push(FileDiagnostic::Line {
                    path: self.request.path.clone(),
                    line: self.line_number,
                    error,
                }),
            }
        }
        self.line.clear();
    }

    /// One fixed-size read, followed by parsing only the bytes just read.
    /// An incomplete line is retained, including a partial last line on error.
    fn step(&mut self, diagnostics: &mut Vec<FileDiagnostic>) -> io::Result<bool> {
        if self.wait_readiness {
            let mut fds = [PollFd {
                fd: self.file.as_raw_fd(),
                events: 1,
                revents: 0,
            }];
            if owrt_ubus::sys::poll_fds(&mut fds, 0)? == 0 {
                return Ok(false);
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
                return Ok(false)
            }
            // get_line_alloc treats stream failure like EOF, including a
            // partial final row. Only fopen failures generate file diagnostics.
            Err(_) => 0,
        };
        for byte in &bytes[..length] {
            if *byte == b'\n' {
                self.consume_line(diagnostics);
            } else {
                self.line.push(*byte);
            }
        }
        if length == 0 {
            if !self.line.is_empty() {
                self.consume_line(diagnostics);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub struct DnsFiles {
    watch: Option<FileWatch>,
    resolvers: ResolverSelection,
    servers_file: Option<PathBuf>,
    no_poll: bool,
    clear_on_reload: bool,
    triggers: VecDeque<ReloadReason>,
    requests: VecDeque<ReadRequest>,
    job: Option<ReadJob>,
    warned_empty: bool,
    initializing: bool,
    active_reason: Option<ReloadReason>,
    notify_seen: bool,
    endpoint_lookup: Option<EndpointLookup>,
    endpoint_update: Option<SourceUpdate>,
}

impl DnsFiles {
    pub fn new(
        config: &DnsConfig,
        dns_enabled: bool,
        clear_on_reload: bool,
    ) -> Result<Self, WatchError> {
        let resolver_enabled = dns_enabled && !config.no_resolv;
        let paths = if resolver_enabled {
            &config.resolv_files[..]
        } else {
            &[]
        };
        Ok(Self {
            watch: resolver_enabled
                .then(|| FileWatch::new(paths))
                .transpose()?,
            resolvers: ResolverSelection::new(paths),
            servers_file: dns_enabled.then(|| config.servers_file.clone()).flatten(),
            no_poll: config.no_poll,
            clear_on_reload,
            triggers: VecDeque::new(),
            requests: VecDeque::new(),
            job: None,
            warned_empty: false,
            initializing: false,
            active_reason: None,
            notify_seen: false,
            endpoint_lookup: None,
            endpoint_update: None,
        })
    }

    /// Initial owner calls Init once; SIGHUP calls Signal after its existing
    /// full reload. Route is the qualifying EVENT_NEWROUTE, not every netlink event.
    pub fn request(&mut self, reason: ReloadReason) {
        if reason == ReloadReason::Init {
            self.initializing = true;
        }
        if !self.triggers.contains(&reason) {
            self.triggers.push_back(reason);
        }
    }

    pub fn append_poll_fds(&self, fds: &mut Vec<PollFd>) {
        if let Some(lookup) = &self.endpoint_lookup {
            lookup.append_poll_fds(fds);
        }
        if let Some(watch) = &self.watch {
            fds.push(PollFd {
                fd: watch.raw_fd(),
                events: 1,
                revents: 0,
            });
        }
        if let Some(job) = &self.job {
            if job.wait_readiness {
                fds.push(PollFd {
                    fd: job.file.as_raw_fd(),
                    events: 1,
                    revents: 0,
                });
            }
        }
    }

    /// Cancel a hostname resolver child without waiting. The owner must call
    /// `step()` until `has_work()` becomes false before dropping the daemon.
    pub fn begin_shutdown(&mut self) {
        if let Some(lookup) = &mut self.endpoint_lookup {
            lookup.cancel();
        }
        self.endpoint_update = None;
        self.requests.clear();
        self.triggers.clear();
        self.job = None;
    }

    pub fn has_work(&self) -> bool {
        self.endpoint_lookup.is_some()
            || self.job.is_some()
            || !self.requests.is_empty()
            || !self.triggers.is_empty()
            || self.notify_seen
    }

    /// The PID/listeners may already exist, as in C, but queued DNS requests
    /// must not receive a transient no-server answer before the initial file
    /// reads finish. Other owner duties can continue while this is true.
    pub fn initializing(&self) -> bool {
        self.initializing
    }

    fn schedule(&mut self, reason: ReloadReason, diagnostics: &mut Vec<FileDiagnostic>) {
        let select = match reason {
            ReloadReason::Init | ReloadReason::Signal if self.no_poll => {
                self.resolvers.paths().next().map(|_| 0)
            }
            ReloadReason::Init | ReloadReason::Notify | ReloadReason::Route if !self.no_poll => {
                let metadata: Vec<_> = self.resolvers.paths().map(fs::metadata).collect();
                let stamps: Vec<_> = metadata
                    .iter()
                    .map(|result| {
                        result.as_ref().ok().map(|meta| FileStamp {
                            modified: meta.mtime(),
                            inode: meta.ino(),
                        })
                    })
                    .collect();
                let selection = self
                    .resolvers
                    .select(reason != ReloadReason::Route, &stamps);
                for index in selection.warn_missing {
                    if let Err(error) = &metadata[index] {
                        diagnostics.push(FileDiagnostic::Access {
                            path: self.resolvers.path(index).to_owned(),
                            error: io::Error::from_raw_os_error(error.raw_os_error().unwrap_or(5)),
                        });
                    }
                }
                selection.selected
            }
            _ => None,
        };
        if let Some(index) = select {
            self.requests.push_back(ReadRequest {
                source: Source::Resolv,
                path: self.resolvers.path(index).to_owned(),
                resolver_index: Some(index),
                reload: reason != ReloadReason::Init,
            });
        }
        if matches!(reason, ReloadReason::Init | ReloadReason::Signal) {
            if let Some(path) = &self.servers_file {
                self.requests.push_back(ReadRequest {
                    source: Source::ServersFile,
                    path: path.clone(),
                    resolver_index: None,
                    reload: false,
                });
            }
        }
    }

    fn resolver_failed(&mut self, request: &ReadRequest, diagnostics: &mut Vec<FileDiagnostic>) {
        if let Some(index) = request.resolver_index {
            self.resolvers.retry_on_next_trigger(index);
            // no-poll calls reload_servers directly, outside poll_resolv's
            // one-time empty warning and retry bookkeeping.
            if !self.no_poll && !self.warned_empty {
                diagnostics.push(FileDiagnostic::EmptyResolvers(request.path.clone()));
                self.warned_empty = true;
            }
        }
    }

    pub fn step(&mut self) -> FileStep {
        let mut result = FileStep::default();
        if let Some(lookup) = &mut self.endpoint_lookup {
            if let Some(done) = lookup.step() {
                self.endpoint_lookup = None;
                if let Some(error) = done.error {
                    result.diagnostics.push(FileDiagnostic::ResolverChild {
                        path: self
                            .endpoint_update
                            .as_ref()
                            .map(|u| u.path.clone())
                            .unwrap_or_default(),
                        error,
                    });
                    self.endpoint_update = None;
                } else if let Some(mut update) = self.endpoint_update.take() {
                    update.rows = done
                        .rules
                        .into_iter()
                        .map(|rule| SourceRule::configured(rule, 0))
                        .collect();
                    result.update = Some(update);
                }
            }
            result.runnable = self.endpoint_lookup.is_some();
            return result;
        }
        let mut watch_more = false;
        if let Some(watch) = &mut self.watch {
            match watch.read_events() {
                Ok(true) => self.notify_seen = true,
                Ok(false) => {}
                Err(error) => result.diagnostics.push(FileDiagnostic::Watch(error)),
            }
            watch_more = watch.pending().unwrap_or(false);
        }
        // C drains inotify_check and emits one hit for the entire ready burst.
        // Yield between batches while retaining that coalescing boundary.
        if self.notify_seen && !watch_more {
            self.notify_seen = false;
            self.request(ReloadReason::Notify);
        }
        if self.job.is_none() && self.requests.is_empty() && !watch_more {
            if let Some(reason) = self.triggers.pop_front() {
                self.active_reason = Some(reason);
                self.schedule(reason, &mut result.diagnostics);
            }
        }
        if self.job.is_none() {
            if let Some(request) = self.requests.pop_front() {
                match OpenOptions::new()
                    .read(true)
                    .custom_flags(0o4000 | 0o2000000)
                    .open(&request.path)
                {
                    Ok(file) => {
                        // Nonblocking FIFO opens are kept pending until a
                        // writer/data/EOF event, without stalling other services.
                        let wait_readiness =
                            file.metadata().is_ok_and(|meta| meta.file_type().is_fifo());
                        self.job = Some(ReadJob {
                            request,
                            file,
                            wait_readiness,
                            line: Vec::new(),
                            line_number: 0,
                            rows: Vec::new(),
                        });
                    }
                    Err(error) => {
                        result.diagnostics.push(FileDiagnostic::Open {
                            path: request.path.clone(),
                            source: request.source,
                            error,
                        });
                        self.resolver_failed(&request, &mut result.diagnostics);
                    }
                }
            }
        }
        if let Some(mut job) = self.job.take() {
            // poll failures are transient like read errors; no source change
            // occurs while its input is still awaiting a later owner turn.
            if job.step(&mut result.diagnostics).unwrap_or(false) {
                let successful_resolv =
                    job.request.source == Source::Resolv && !job.rows.is_empty();
                if job.request.source == Source::Resolv {
                    if successful_resolv {
                        self.warned_empty = false;
                        // poll_resolv logs only after a successful read, before
                        // check_servers and any clear-on-reload side effects.
                        // no-poll calls reload_servers directly, without this.
                        if !self.no_poll {
                            result
                                .diagnostics
                                .push(FileDiagnostic::ReadingResolvers(job.request.path.clone()));
                        }
                    } else {
                        self.resolver_failed(&job.request, &mut result.diagnostics);
                    }
                }
                let update = SourceUpdate {
                    source: job.request.source,
                    path: job.request.path,
                    rows: job.rows,
                    full_reload: successful_resolv
                        && !self.no_poll
                        && job.request.reload
                        && self.clear_on_reload,
                };
                let needs_lookup = update.source == Source::ServersFile && update.rows.iter().any(|row| {
                    matches!(row.rule.target, RuleTarget::Upstream(ref endpoint) if matches!(endpoint.host, ServerHost::Name(_)))
                });
                if needs_lookup {
                    let reverse = update.rows.iter().any(|row| row.reverse);
                    let rules = update.rows.iter().map(|row| row.rule.clone()).collect();
                    match EndpointLookup::start(rules, reverse) {
                        Ok(lookup) => {
                            self.endpoint_lookup = Some(lookup);
                            self.endpoint_update = Some(update);
                        }
                        Err(error) => result.diagnostics.push(FileDiagnostic::Watch(error)),
                    }
                } else {
                    result.update = Some(update);
                }
            } else {
                self.job = Some(job);
            }
        }
        if self.job.is_none() && self.requests.is_empty() {
            result.signal_complete = self.active_reason.take() == Some(ReloadReason::Signal);
        }
        if self.initializing
            && self.job.is_none()
            && self.requests.is_empty()
            && !self.triggers.contains(&ReloadReason::Init)
        {
            self.initializing = false;
        }
        result.runnable = self.job.as_ref().map_or(
            !self.requests.is_empty() || !self.triggers.is_empty(),
            |job| !job.wait_readiness,
        );
        result.runnable |= watch_more;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "dns-files-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn config(&self) -> DnsConfig {
            let mut config = DnsConfig::default();
            config.resolv_files = vec![self.0.join("resolv")];
            config
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn drain(files: &mut DnsFiles) -> (Vec<SourceUpdate>, Vec<FileDiagnostic>) {
        let mut updates = Vec::new();
        let mut diagnostics = Vec::new();
        for _ in 0..100 {
            let step = files.step();
            updates.extend(step.update);
            diagnostics.extend(step.diagnostics);
            if !files.has_work() {
                return (updates, diagnostics);
            }
        }
        panic!("small regular-file job failed to complete");
    }

    #[test]
    fn inotify_replaces_opened_empty_files_but_deletion_does_not_reload() {
        let dir = Directory::new();
        let config = dir.config();
        let path = &config.resolv_files[0];
        fs::write(path, b"nameserver 192.0.2.1\n").unwrap();
        let mut files = DnsFiles::new(&config, true, true).unwrap();
        files.request(ReloadReason::Init);
        let (updates, _) = drain(&mut files);
        assert_eq!(updates.len(), 1);
        assert!(!updates[0].full_reload);
        assert_eq!(
            updates[0].rows[0].address,
            Some("192.0.2.1:53".parse().unwrap())
        );
        fs::write(path, b"nameserver 192.0.2.2\n").unwrap();
        let (updates, _) = drain(&mut files);
        assert!(updates[0].full_reload);
        fs::write(path, b"").unwrap();
        let (updates, diagnostics) = drain(&mut files);
        assert!(updates[0].rows.is_empty());
        assert!(!updates[0].full_reload);
        assert!(matches!(diagnostics[0], FileDiagnostic::EmptyResolvers(_)));
        fs::remove_file(path).unwrap();
        assert!(drain(&mut files).0.is_empty());
        fs::write(path, b"server 192.0.2.3").unwrap();
        assert_eq!(
            drain(&mut files).0[0].rows[0].address,
            Some("192.0.2.3:53".parse().unwrap())
        );
    }

    #[test]
    fn no_poll_and_servers_file_wait_for_signal_and_keep_partial_valid_rows() {
        let dir = Directory::new();
        let mut config = dir.config();
        config.no_poll = true;
        config.servers_file = Some(dir.0.join("servers"));
        let resolv = &config.resolv_files[0];
        let servers = config.servers_file.as_ref().unwrap();
        fs::write(resolv, b"nameserver 192.0.2.1").unwrap();
        fs::write(
            servers,
            b"server=/one/192.0.2.2\naddress=/bad/192.0.2.3\nserver=/two/192.0.2.4",
        )
        .unwrap();
        let mut files = DnsFiles::new(&config, true, true).unwrap();
        files.request(ReloadReason::Init);
        let (updates, diagnostics) = drain(&mut files);
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[1].rows.len(), 2);
        assert!(matches!(
            &diagnostics[0],
            FileDiagnostic::Line {
                line: 2,
                error: Error("illegal option"),
                ..
            }
        ));
        fs::write(resolv, b"nameserver 192.0.2.9").unwrap();
        fs::write(servers, b"").unwrap();
        assert!(drain(&mut files).0.is_empty());
        files.request(ReloadReason::Route);
        assert!(drain(&mut files).0.is_empty());
        files.request(ReloadReason::Signal);
        let (updates, _) = drain(&mut files);
        assert_eq!(
            updates[0].rows[0].address,
            Some("192.0.2.9:53".parse().unwrap())
        );
        assert!(!updates[0].full_reload);
        assert!(updates[1].rows.is_empty());
        fs::remove_file(servers).unwrap();
        files.request(ReloadReason::Signal);
        let (updates, diagnostics) = drain(&mut files);
        assert_eq!(updates.len(), 1); // Failed open produces no bank replacement.
        assert!(matches!(
            diagnostics[0],
            FileDiagnostic::Open {
                source: Source::ServersFile,
                ..
            }
        ));
    }

    #[test]
    fn signal_completion_is_after_its_reads_not_after_later_notifications() {
        let dir = Directory::new();
        let mut config = dir.config();
        config.no_resolv = true;
        config.servers_file = Some(dir.0.join("servers"));
        let mut bytes = vec![b'#'];
        bytes.extend(std::iter::repeat_n(b'x', 9000));
        bytes.extend_from_slice(b"\nserver=/test/127.0.0.2\n");
        fs::write(config.servers_file.as_ref().unwrap(), bytes).unwrap();
        let mut files = DnsFiles::new(&config, true, true).unwrap();
        files.request(ReloadReason::Signal);
        files.request(ReloadReason::Notify);
        let first = files.step();
        assert!(!first.signal_complete && first.update.is_none());
        let mut completions = 0;
        for _ in 0..10 {
            let step = files.step();
            if step.signal_complete {
                completions += 1;
                assert_eq!(step.update.unwrap().source, Source::ServersFile);
                assert!(files.has_work()); // A later Notify still remains.
            }
            if !files.has_work() {
                break;
            }
        }
        assert_eq!(completions, 1);
        assert!(!files.step().signal_complete);
    }

    #[test]
    fn a_ready_event_burst_produces_one_resolver_reload_across_read_budgets() {
        let dir = Directory::new();
        let config = dir.config();
        let resolv = &config.resolv_files[0];
        fs::write(resolv, b"nameserver 192.0.2.1\n").unwrap();
        let mut files = DnsFiles::new(&config, true, true).unwrap();
        files.request(ReloadReason::Init);
        drain(&mut files);
        let neighbor = dir.0.join("unrelated".repeat(20));
        for _ in 0..100 {
            fs::write(resolv, b"nameserver 192.0.2.2\n").unwrap();
            fs::write(&neighbor, b"ignore").unwrap();
        }
        let mut updates = Vec::new();
        for _ in 0..100 {
            let step = files.step();
            let runnable = step.runnable;
            updates.extend(step.update);
            if !runnable && !files.has_work() {
                break;
            }
        }
        assert_eq!(updates.len(), 1);
        assert!(updates[0].full_reload);
    }

    #[test]
    fn watch_parent_and_symlink_limit_follow_the_image() {
        let dir = Directory::new();
        let mut config = dir.config();
        config.no_poll = true;
        assert!(DnsFiles::new(&config, true, false).is_ok()); // Missing leaf, existing parent.
        config.resolv_files = vec![dir.0.join("missing-parent/resolv")];
        assert!(matches!(
            DnsFiles::new(&config, true, false),
            Err(WatchError::MissingParent(_))
        ));
        config.no_resolv = true;
        assert!(DnsFiles::new(&config, true, false).is_ok());
        config.no_resolv = false;
        fs::write(dir.0.join("target"), b"nameserver 192.0.2.1").unwrap();
        let mut target = PathBuf::from("target");
        for n in 0..21 {
            let name = format!("link{n}");
            symlink(&target, dir.0.join(&name)).unwrap();
            target = name.into();
            if n == 19 {
                config.resolv_files = vec![dir.0.join(&target)];
                assert!(DnsFiles::new(&config, true, false).is_ok());
            }
        }
        config.resolv_files = vec![dir.0.join(target)];
        assert!(matches!(
            DnsFiles::new(&config, true, false),
            Err(WatchError::TooManyLinks(_))
        ));
    }

    #[test]
    fn large_regular_input_yields_and_fifo_does_not_busy_poll_the_owner() {
        let dir = Directory::new();
        let mut config = dir.config();
        config.no_poll = true;
        let path = &config.resolv_files[0];
        let mut content = vec![b' '; 9000];
        content.extend_from_slice(b"nameserver 192.0.2.1");
        fs::write(path, content).unwrap();
        let mut files = DnsFiles::new(&config, true, false).unwrap();
        files.request(ReloadReason::Init);
        assert!(files.step().update.is_none());
        assert!(files.initializing());
        let (updates, _) = drain(&mut files);
        assert!(!files.initializing());
        assert_eq!(updates[0].rows.len(), 1);
        drop(files);
        fs::remove_file(path).unwrap();
        extern "C" {
            fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
        }
        let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: live NUL-terminated temporary test path.
        assert_eq!(unsafe { mkfifo(cpath.as_ptr(), 0o600) }, 0);
        let mut files = DnsFiles::new(&config, true, false).unwrap();
        files.request(ReloadReason::Init);
        assert!(!files.step().runnable);
        files.request(ReloadReason::Signal);
        let step = files.step();
        assert!(step.update.is_none() && !step.runnable);
        let mut fds = Vec::new();
        files.append_poll_fds(&mut fds);
        assert_eq!(fds.len(), 2); // Watch descriptor plus waiting FIFO.
    }
}
