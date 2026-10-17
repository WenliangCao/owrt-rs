//! option.c expand_filelist/reread_dhcp. File entries retain their list position
//! across reloads; only configuration rules loaded from files are replaced.

use super::HostConfig;
use crate::config::{lex_argument_line, Error};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, ReadDir};
use std::io::{self, BufRead, BufReader};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

#[derive(Debug)]
pub enum HostFileErrorKind {
    Io(io::Error),
    Line(Error),
    /// C accepts this selector, but the Rust caller cannot safely serve a
    /// configuration with it dropped. This is not a skippable C syntax error.
    Unsupported(Error),
}

#[derive(Debug)]
pub struct HostFileError {
    pub path: PathBuf,
    pub line: Option<usize>,
    pub kind: HostFileErrorKind,
}

#[derive(Debug)]
pub struct HostReload {
    /// Complete newest-first list: file rules followed by unchanged main rules.
    pub hosts: Vec<HostConfig>,
    pub errors: Vec<HostFileError>,
}

impl HostReload {
    pub fn ready(&self) -> bool {
        !self
            .errors
            .iter()
            .any(|error| matches!(error.kind, HostFileErrorKind::Unsupported(_)))
    }
}

#[derive(Debug)]
struct Entry {
    path: PathBuf,
    from_directory: bool,
    inactive: bool,
}

#[derive(Debug)]
pub struct HostFiles {
    entries: Vec<Entry>,
    order: Vec<usize>,
    expansion: Option<Expansion>,
    read_position: usize,
}

#[derive(Debug)]
enum Expansion {
    Entry(Option<usize>),
    Scan {
        parent: usize,
        path: PathBuf,
        entries: ReadDir,
        names: BTreeSet<OsString>,
    },
    Append {
        parent: usize,
        path: PathBuf,
        names: std::collections::btree_set::IntoIter<OsString>,
    },
}

/// One bounded directory-plan turn. Files are yielded only after all static
/// directory expansion completes, preserving expand_filelist's global order.
#[derive(Debug, Eq, PartialEq)]
pub enum FilePlanStep {
    Pending,
    File(PathBuf),
    Done,
}

impl HostFiles {
    /// Reuse the qualified bank grammar outside the configuration module;
    /// `existing` includes every row visible to C's duplicate-address check.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub(crate) fn parse_row(
        argument: &crate::config::EncodedArg,
        existing: &[HostConfig],
    ) -> Result<HostConfig, Error> {
        HostConfig::parse(argument, existing)
    }

    /// Paths must already be in C's last-directive-first order.
    pub fn new(paths: &[Vec<u8>]) -> Self {
        Self {
            entries: paths
                .iter()
                .map(|path| Entry {
                    path: PathBuf::from(OsString::from_vec(path.clone())),
                    from_directory: false,
                    inactive: false,
                })
                .collect(),
            order: (0..paths.len()).collect(),
            expansion: None,
            read_position: 0,
        }
    }

    pub fn begin_plan(&mut self) {
        for entry in &mut self.entries {
            entry.inactive = entry.from_directory;
        }
        self.expansion = Some(Expansion::Entry(self.order.first().copied()));
        self.read_position = 0;
    }

    fn next_entry(&self, id: usize) -> Option<usize> {
        self.order
            .iter()
            .position(|&candidate| candidate == id)
            .and_then(|position| self.order.get(position + 1).copied())
    }

    fn append_child(&mut self, path: &PathBuf, name: OsString) {
        // C compares a literal slash join, including an explicit duplicate path.
        let mut full = path.as_os_str().as_bytes().to_vec();
        full.push(b'/');
        full.extend_from_slice(name.as_bytes());
        let full = PathBuf::from(OsString::from_vec(full));
        let child = if let Some(position) = self.order.iter().position(|&index| {
            self.entries[index].path.as_os_str().as_bytes() == full.as_os_str().as_bytes()
        }) {
            let found = self.order.remove(position);
            self.entries[found].inactive = false;
            found
        } else {
            let found = self.entries.len();
            self.entries.push(Entry {
                path: full,
                from_directory: true,
                inactive: false,
            });
            found
        };
        self.order.push(child);
        if self.entries[child].from_directory
            && fs::metadata(&self.entries[child].path).is_ok_and(|meta| !meta.is_file())
        {
            self.entries[child].inactive = true;
        }
    }

    /// Visit one directory entry or one planned path, without reading file
    /// contents. Incremental ordered insertion avoids a whole-directory sort
    /// in a live owner turn; the pinned image uses C-locale byte ordering.
    pub fn step_plan(&mut self, errors: &mut Vec<HostFileError>) -> FilePlanStep {
        let Some(expansion) = self.expansion.take() else {
            let Some(&id) = self.order.get(self.read_position) else {
                return FilePlanStep::Done;
            };
            self.read_position += 1;
            return if self.entries[id].inactive {
                FilePlanStep::Pending
            } else {
                FilePlanStep::File(self.entries[id].path.clone())
            };
        };
        self.expansion = match expansion {
            Expansion::Entry(None) => None,
            Expansion::Entry(Some(parent)) => {
                let path = self.entries[parent].path.clone();
                if !self.entries[parent].inactive
                    && fs::metadata(&path).is_ok_and(|meta| meta.is_dir())
                {
                    self.entries[parent].inactive = true;
                    match fs::read_dir(&path) {
                        Ok(entries) => Some(Expansion::Scan {
                            parent,
                            path,
                            entries,
                            names: BTreeSet::new(),
                        }),
                        Err(error) => {
                            errors.push(HostFileError {
                                path,
                                line: None,
                                kind: HostFileErrorKind::Io(error),
                            });
                            Some(Expansion::Entry(self.next_entry(parent)))
                        }
                    }
                } else {
                    Some(Expansion::Entry(self.next_entry(parent)))
                }
            }
            Expansion::Scan {
                parent,
                path,
                mut entries,
                mut names,
            } => match entries.next() {
                Some(Ok(child)) => {
                    let name = child.file_name();
                    if accepted_name(name.as_bytes()) {
                        names.insert(name);
                    }
                    Some(Expansion::Scan {
                        parent,
                        path,
                        entries,
                        names,
                    })
                }
                Some(Err(error)) => {
                    // scandir failure discards the incomplete directory list.
                    errors.push(HostFileError {
                        path,
                        line: None,
                        kind: HostFileErrorKind::Io(error),
                    });
                    Some(Expansion::Entry(self.next_entry(parent)))
                }
                None => Some(Expansion::Append {
                    parent,
                    path,
                    names: names.into_iter(),
                }),
            },
            Expansion::Append {
                parent,
                path,
                mut names,
            } => {
                if let Some(name) = names.next() {
                    self.append_child(&path, name);
                    Some(Expansion::Append {
                        parent,
                        path,
                        names,
                    })
                } else {
                    Some(Expansion::Entry(self.next_entry(parent)))
                }
            }
        };
        FilePlanStep::Pending
    }

    pub fn reload(&mut self, main_hosts: &[HostConfig]) -> HostReload {
        let mut report = HostReload {
            hosts: main_hosts.to_vec(),
            errors: Vec::new(),
        };
        self.begin_plan();
        loop {
            let path = match self.step_plan(&mut report.errors) {
                FilePlanStep::Pending => continue,
                FilePlanStep::Done => break,
                FilePlanStep::File(path) => path,
            };
            let file = match File::open(&path) {
                Ok(file) => file,
                Err(error) => {
                    report.errors.push(HostFileError {
                        path: path.clone(),
                        line: None,
                        kind: HostFileErrorKind::Io(error),
                    });
                    continue;
                }
            };
            let mut reader = BufReader::new(file);
            let mut line = Vec::new();
            let mut lineno = 0;
            loop {
                line.clear();
                // C get_line_alloc treats stream errors as EOF, with any partial
                // last row still parsed. Open errors above are reported.
                if reader.read_until(b'\n', &mut line).unwrap_or(line.len()) == 0 {
                    break;
                }
                lineno += 1;
                let result = lex_argument_line(&line).and_then(|argument| {
                    argument
                        .map(|argument| HostConfig::parse(&argument, &report.hosts))
                        .transpose()
                });
                match result {
                    Ok(Some(host)) => report.hosts.insert(0, host),
                    Ok(None) => {}
                    Err(error) => report.errors.push(HostFileError {
                        path: path.clone(),
                        line: Some(lineno),
                        kind: if super::host::unsupported(&error) {
                            HostFileErrorKind::Unsupported(error)
                        } else {
                            HostFileErrorKind::Line(error)
                        },
                    }),
                }
            }
        }
        report
    }
}

fn accepted_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name[0] != b'.'
        && !name.ends_with(b"~")
        && !(name.starts_with(b"#") && name.ends_with(b"#"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn planned_directory_order_retains_explicit_paths_and_retires_missing_children() {
        let folder = std::env::temp_dir().join(format!(
            "dhcp-file-plan-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&folder).unwrap();
        for name in ["z", "a", ".hidden", "backup~", "#autosave#"] {
            fs::write(folder.join(name), b"").unwrap();
        }
        fs::create_dir(folder.join("nested")).unwrap();
        let mut plan = HostFiles::new(&[
            folder.join("z").as_os_str().as_bytes().to_vec(),
            folder.as_os_str().as_bytes().to_vec(),
        ]);
        let collect = |plan: &mut HostFiles| {
            plan.begin_plan();
            let mut paths = Vec::new();
            let mut errors = Vec::new();
            loop {
                match plan.step_plan(&mut errors) {
                    FilePlanStep::Pending => {}
                    FilePlanStep::File(path) => paths.push(path),
                    FilePlanStep::Done => break,
                }
            }
            assert!(errors.is_empty());
            paths
        };
        assert_eq!(collect(&mut plan), [folder.join("a"), folder.join("z")]);
        fs::remove_file(folder.join("a")).unwrap();
        fs::remove_file(folder.join("z")).unwrap();
        // The derived child disappears; an explicit missing path still gets
        // its own nonfatal open error at the later read stage, as C does.
        assert_eq!(collect(&mut plan), [folder.join("z")]);
        fs::remove_dir_all(folder).unwrap();
    }

    #[test]
    fn reload_preserves_selectors_and_skips_only_invalid_lines() {
        let folder = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../private/dnsmasq-rewrite/hostfile-unit")
            .join(format!(
                "{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        fs::create_dir_all(&folder).unwrap();
        let path = folder.join("hosts");
        fs::write(&path, b"02:00:00:00:00:01,tag:known,ignore\n").unwrap();
        let mut files = HostFiles::new(&[path.as_os_str().as_bytes().to_vec()]);
        let report = files.reload(&[]);
        assert!(report.ready());
        assert!(report.errors.is_empty());
        assert!(report.hosts[0].filter.matches_with(&[b"known"], false));
        assert!(!report.hosts[0].filter.matches_with(&[], false));
        fs::write(&path, b"bad:hex\n02:00:00:00:00:01,192.0.2.10,valid\n").unwrap();
        let report = files.reload(&[]);
        assert!(report.ready());
        assert_eq!(report.hosts.len(), 1);
        assert!(matches!(report.errors[0].kind, HostFileErrorKind::Line(_)));
        assert_eq!(report.errors[0].line, Some(1));
        fs::remove_dir_all(folder).unwrap();
    }
}
