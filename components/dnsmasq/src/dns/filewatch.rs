//! Linux inotify boundary from the exact image's inotify.c. Resolver watches
//! attach to startup-resolved parent directories, never to an open leaf fd.

use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

const IN_NONBLOCK: i32 = 0o4000;
const IN_CLOEXEC: i32 = 0o2000000;
const IN_CLOSE_WRITE: u32 = 0x8;
const IN_MOVED_TO: u32 = 0x80;
// Pinned AArch64 musl sys/param.h; C allows 20 traversals, rejects the 21st.
const MAX_SYMLINKS: usize = 20;

extern "C" {
    fn inotify_init1(flags: i32) -> i32;
    fn inotify_add_watch(fd: i32, path: *const std::ffi::c_char, mask: u32) -> i32;
}

#[derive(Debug)]
pub enum WatchError {
    Init(io::Error),
    Link { path: PathBuf, error: io::Error },
    TooManyLinks(PathBuf),
    MissingParent(PathBuf),
    Add { path: PathBuf, error: io::Error },
}

impl std::fmt::Display for WatchError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init(error) => write!(out, "failed to create inotify: {}", os_message(error)),
            Self::Link { path, error } => {
                write!(
                    out,
                    "cannot access path {}: {}",
                    path.display(),
                    os_message(error)
                )
            }
            Self::TooManyLinks(path) => {
                write!(out, "too many symlinks following {}", path.display())
            }
            Self::MissingParent(path) => write!(
                out,
                "directory {} for resolv-file is missing, cannot poll",
                path.display()
            ),
            Self::Add { path, error } => write!(
                out,
                "failed to create inotify for {}: {}",
                path.display(),
                os_message(error)
            ),
        }
    }
}

impl std::error::Error for WatchError {}

pub(super) fn os_message(error: &io::Error) -> String {
    let mut message = error.to_string();
    if let Some(code) = error.raw_os_error() {
        if let Some(text) = message.strip_suffix(&format!(" (os error {code})")) {
            message.truncate(text.len());
        }
    }
    message
}

struct WatchedFile {
    descriptor: i32,
    name: Vec<u8>,
}

pub struct FileWatch {
    fd: File,
    files: Vec<WatchedFile>,
}

impl FileWatch {
    /// Empty paths still create the descriptor when the caller enables the
    /// resolver subsystem. no-poll deliberately does not suppress watches.
    pub fn new(paths: impl IntoIterator<Item = impl AsRef<Path>>) -> Result<Self, WatchError> {
        // SAFETY: inotify_init1 has no pointer inputs; successful fd is owned.
        let fd = unsafe { inotify_init1(IN_NONBLOCK | IN_CLOEXEC) };
        if fd < 0 {
            return Err(WatchError::Init(io::Error::last_os_error()));
        }
        let mut watch = Self {
            // SAFETY: fresh descriptor, transferred exactly once to File.
            fd: unsafe { File::from_raw_fd(fd) },
            files: Vec::new(),
        };
        for original in paths {
            let original = original.as_ref();
            let (path, last_error) = follow_links(original)?;
            let bytes = path.as_os_str().as_bytes();
            let Some(slash) = bytes.iter().rposition(|byte| *byte == b'/') else {
                return Err(WatchError::Add {
                    path: original.to_owned(),
                    error: last_error,
                });
            };
            let parent = CString::new(&bytes[..slash]).map_err(|_| WatchError::Add {
                path: original.to_owned(),
                error: io::Error::from_raw_os_error(22),
            })?;
            // SAFETY: live NUL-terminated path and owned inotify descriptor.
            let descriptor =
                unsafe { inotify_add_watch(fd, parent.as_ptr(), IN_CLOSE_WRITE | IN_MOVED_TO) };
            if descriptor < 0 {
                let error = io::Error::last_os_error();
                return Err(if error.raw_os_error() == Some(2) {
                    WatchError::MissingParent(original.to_owned())
                } else {
                    WatchError::Add {
                        path: original.to_owned(),
                        error,
                    }
                });
            }
            watch.files.push(WatchedFile {
                descriptor,
                name: bytes[slash + 1..].to_vec(),
            });
        }
        Ok(watch)
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Consume one bounded kernel batch. Remaining events keep POLLIN set and
    /// are drained on the next owner turn; no read-to-empty busy loop.
    pub fn read_events(&mut self) -> io::Result<bool> {
        let mut bytes = [0u8; 4096];
        match self.fd.read(&mut bytes) {
            Ok(length) => Ok(self.contains_resolver_event(&bytes[..length])),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn contains_resolver_event(&self, mut bytes: &[u8]) -> bool {
        while bytes.len() >= 16 {
            let descriptor = i32::from_ne_bytes(bytes[..4].try_into().unwrap());
            let length = u32::from_ne_bytes(bytes[12..16].try_into().unwrap()) as usize;
            let Some(name) = bytes.get(16..16usize.saturating_add(length)) else {
                break;
            };
            let name = name.split(|byte| *byte == 0).next().unwrap_or_default();
            if watched_name(name)
                && self
                    .files
                    .iter()
                    .any(|file| file.descriptor == descriptor && file.name == name)
            {
                return true;
            }
            bytes = &bytes[16 + length..];
        }
        false
    }
}

fn watched_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name[0] != b'.'
        && !name.ends_with(b"~")
        && !(name.starts_with(b"#") && name.ends_with(b"#"))
}

fn follow_links(original: &Path) -> Result<(PathBuf, io::Error), WatchError> {
    let mut path = original.to_owned();
    for depth in 0.. {
        match fs::read_link(&path) {
            Ok(target) => {
                if depth >= MAX_SYMLINKS {
                    return Err(WatchError::TooManyLinks(original.to_owned()));
                }
                let mut bytes = path.as_os_str().as_bytes().to_vec();
                let target = target.as_os_str().as_bytes();
                if !target.starts_with(b"/") {
                    if let Some(slash) = bytes.iter().rposition(|byte| *byte == b'/') {
                        bytes.truncate(slash + 1);
                        bytes.extend_from_slice(target);
                        path = OsString::from_vec(bytes).into();
                        continue;
                    }
                }
                path = OsString::from_vec(target.to_vec()).into();
            }
            Err(error) if matches!(error.raw_os_error(), Some(2 | 22)) => return Ok((path, error)),
            Err(error) => return Err(WatchError::Link { path, error }),
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_scanner_observes_file_names_and_global_filters() {
        let mut watch = FileWatch::new(std::iter::empty::<&Path>()).unwrap();
        for name in [b"resolv".as_slice(), b".hidden", b"backup~", b"#temp#"] {
            watch.files.push(WatchedFile {
                descriptor: 7,
                name: name.to_vec(),
            });
            let mut event = Vec::new();
            event.extend_from_slice(&7i32.to_ne_bytes());
            event.extend_from_slice(&IN_CLOSE_WRITE.to_ne_bytes());
            event.extend_from_slice(&0u32.to_ne_bytes());
            event.extend_from_slice(&((name.len() + 1) as u32).to_ne_bytes());
            event.extend_from_slice(name);
            event.push(0);
            assert_eq!(watch.contains_resolver_event(&event), name == b"resolv");
            assert!(!watch.contains_resolver_event(&event[..15]));
        }
    }
}
