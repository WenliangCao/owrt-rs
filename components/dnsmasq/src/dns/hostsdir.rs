//! inotify.c dynamic hosts directories: stable source IDs and incremental
//! events. The existing file owner performs reads and publishes host changes.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
#[path = "hostsdir_runtime.rs"]
mod runtime;
#[cfg(target_os = "linux")]
pub use runtime::{HostsLoad, HostsRead};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostSource {
    pub path: PathBuf,
    pub uid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEvent {
    pub directory: usize,
    pub name: Vec<u8>,
    pub deleted: bool,
}

#[derive(Clone, Debug)]
pub struct HostChange {
    pub source: HostSource,
    pub deleted: bool,
}

struct Directory {
    path: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    watch_attempted: bool,
    #[cfg(target_os = "linux")]
    watch_ok: bool,
    #[cfg(target_os = "linux")]
    watch_errno: i32,
    files: HashMap<Vec<u8>, HostSource>,
}

pub struct HostsDirectories {
    directories: Vec<Directory>,
    next_uid: u32,
}

impl HostsDirectories {
    /// Caller reserves a source-ID range separate from ordinary hosts inputs.
    /// Repeated directory declarations retain distinct per-path source IDs.
    pub fn new(paths: &[Option<PathBuf>], first_uid: u32) -> Self {
        Self {
            directories: paths
                .iter()
                .map(|path| Directory {
                    path: path.clone(),
                    #[cfg(target_os = "linux")]
                    watch_attempted: false,
                    #[cfg(target_os = "linux")]
                    watch_ok: false,
                    #[cfg(target_os = "linux")]
                    watch_errno: 22,
                    files: HashMap::new(),
                })
                .collect(),
            next_uid: first_uid,
        }
    }

    fn source(&mut self, directory: usize, name: &[u8]) -> Option<HostSource> {
        let entry = self.directories.get_mut(directory)?;
        if !watched_name(name) {
            return None;
        }
        if let Some(source) = entry.files.get(name) {
            return Some(source.clone());
        }
        let path = entry.path.as_ref()?;
        let uid = self.next_uid;
        // u32::MAX belongs to configured host records in the current loader.
        self.next_uid = uid.checked_add(1).filter(|next| *next != u32::MAX)?;
        #[cfg(unix)]
        let path = {
            use std::os::unix::ffi::{OsStrExt, OsStringExt};
            let mut bytes = path.as_os_str().as_bytes().to_vec();
            bytes.push(b'/');
            bytes.extend_from_slice(name);
            PathBuf::from(OsString::from_vec(bytes))
        };
        #[cfg(not(unix))]
        let path = path.join(OsString::from(String::from_utf8_lossy(name).into_owned()));
        let source = HostSource { path, uid };
        entry.files.insert(name.to_vec(), source.clone());
        Some(source)
    }

    pub fn changes(&mut self, events: impl IntoIterator<Item = DirectoryEvent>) -> Vec<HostChange> {
        events
            .into_iter()
            .filter_map(|event| {
                Some(HostChange {
                    source: self.source(event.directory, &event.name)?,
                    deleted: event.deleted,
                })
            })
            .collect()
    }
}

pub(crate) fn watched_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name[0] != b'.'
        && !name.ends_with(b"~")
        && !(name.starts_with(b"#") && name.ends_with(b"#"))
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub enum DirectoryDiagnostic {
    Bad {
        path: Option<PathBuf>,
        error: std::io::Error,
    },
    NotDirectory(PathBuf),
    Watch {
        path: PathBuf,
        error: std::io::Error,
    },
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for DirectoryDiagnostic {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use super::filewatch::os_message;
        match self {
            Self::Bad { path, error } => write!(
                output,
                "bad dynamic directory {}: {}",
                path.as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "(null)".into()),
                os_message(error)
            ),
            Self::NotDirectory(path) => write!(
                output,
                "bad dynamic directory {}: not a directory",
                path.display()
            ),
            Self::Watch { path, error } => write!(
                output,
                "failed to create inotify for {}: {}",
                path.display(),
                os_message(error)
            ),
        }
    }
}

#[cfg(target_os = "linux")]
impl HostsDirectories {
    /// Watch before reading entries; HUP scans use the same stable path IDs and
    /// do not reattach a watch which was already attempted, even if it failed.
    pub fn scan(
        &mut self,
        watch: &mut super::filewatch::FileWatch,
    ) -> (Vec<HostSource>, Vec<DirectoryDiagnostic>) {
        use std::os::unix::ffi::OsStrExt;
        let mut sources = Vec::new();
        let mut diagnostics = Vec::new();
        for index in 0..self.directories.len() {
            let Some(path) = self.directories[index].path.clone() else {
                diagnostics.push(DirectoryDiagnostic::Bad {
                    path: None,
                    error: std::io::Error::from_raw_os_error(14),
                });
                continue;
            };
            match std::fs::metadata(&path) {
                Err(error) => {
                    diagnostics.push(DirectoryDiagnostic::Bad {
                        path: Some(path),
                        error,
                    });
                    continue;
                }
                Ok(metadata) if !metadata.is_dir() => {
                    diagnostics.push(DirectoryDiagnostic::NotDirectory(path));
                    continue;
                }
                Ok(_) => {}
            }
            let entry = &mut self.directories[index];
            if !entry.watch_attempted {
                entry.watch_attempted = true;
                match watch.add_hosts_directory(index, &path) {
                    Ok(()) => entry.watch_ok = true,
                    Err(error) => {
                        entry.watch_errno = error.raw_os_error().unwrap_or(22);
                        diagnostics.push(DirectoryDiagnostic::Watch { path, error });
                        continue;
                    }
                }
            }
            if !entry.watch_ok {
                diagnostics.push(DirectoryDiagnostic::Watch {
                    path,
                    error: std::io::Error::from_raw_os_error(entry.watch_errno),
                });
                continue;
            }
            let entries = match std::fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(error) => {
                    diagnostics.push(DirectoryDiagnostic::Watch { path, error });
                    continue;
                }
            };
            // Match readdir order. Do not sort dynamic directory contents.
            for entry in entries.flatten() {
                let Some(source) = self.source(index, entry.file_name().as_bytes()) else {
                    continue;
                };
                // stat follows regular-file symlinks. Nonregular names still
                // reserve a stable UID, but only runtime events attempt reads.
                if std::fs::metadata(&source.path).is_ok_and(|metadata| metadata.is_file()) {
                    sources.push(source);
                }
            }
        }
        (sources, diagnostics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_uid_survives_delete_recreate_and_repeated_directory_declarations() {
        let mut registry =
            HostsDirectories::new(&[Some("/hosts/".into()), Some("/hosts/".into())], 100);
        let make = |directory, deleted| DirectoryEvent {
            directory,
            name: b"one".to_vec(),
            deleted,
        };
        let first = registry.changes([
            make(0, false),
            make(0, true),
            make(0, false),
            make(1, false),
        ]);
        assert_eq!(
            first
                .iter()
                .map(|event| event.source.uid)
                .collect::<Vec<_>>(),
            [100, 100, 100, 101]
        );
        assert_eq!(first[0].source.path, PathBuf::from("/hosts//one"));
        assert!(registry
            .changes([DirectoryEvent {
                directory: 0,
                name: b".hidden".to_vec(),
                deleted: false
            }])
            .is_empty());
    }
}
