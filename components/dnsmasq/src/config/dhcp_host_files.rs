//! option.c expand_filelist/reread_dhcp. File entries retain their list position
//! across reloads; only configuration rules loaded from files are replaced.

use super::HostConfig;
use crate::config::{lex_argument_line, Error};
use std::ffi::OsString;
use std::fs::{self, File};
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
}

impl HostFiles {
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
        }
    }

    fn expand(&mut self, errors: &mut Vec<HostFileError>) {
        for entry in &mut self.entries {
            entry.inactive = entry.from_directory;
        }
        let mut current = self.order.first().copied();
        while let Some(id) = current {
            let path = self.entries[id].path.clone();
            if !self.entries[id].inactive && fs::metadata(&path).is_ok_and(|meta| meta.is_dir()) {
                self.entries[id].inactive = true;
                match fs::read_dir(&path).and_then(|dir| dir.collect::<Result<Vec<_>, _>>()) {
                    Err(error) => errors.push(HostFileError {
                        path,
                        line: None,
                        kind: HostFileErrorKind::Io(error),
                    }),
                    Ok(mut children) => {
                        // The pinned no-IDN/no-NLS target keeps the C locale.
                        crate::sorting::sort_by(&mut children, |a, b| {
                            a.file_name().cmp(&b.file_name())
                        });
                        for child in children {
                            let name = child.file_name();
                            let bytes = name.as_bytes();
                            if bytes.is_empty()
                                || bytes[0] == b'.'
                                || bytes.last() == Some(&b'~')
                                || (bytes[0] == b'#' && bytes.last() == Some(&b'#'))
                            {
                                continue;
                            }
                            // Preserve C's literal slash join rather than normalizing
                            // names, since explicit-path overlap compares raw bytes.
                            let mut full = path.as_os_str().as_bytes().to_vec();
                            full.push(b'/');
                            full.extend_from_slice(bytes);
                            let full = PathBuf::from(OsString::from_vec(full));
                            let child_id = if let Some(position) =
                                self.order.iter().position(|&index| {
                                    self.entries[index].path.as_os_str().as_bytes()
                                        == full.as_os_str().as_bytes()
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
                            self.order.push(child_id);
                            if self.entries[child_id].from_directory
                                && fs::metadata(&self.entries[child_id].path)
                                    .is_ok_and(|meta| !meta.is_file())
                            {
                                self.entries[child_id].inactive = true;
                            }
                        }
                    }
                }
            }
            let position = self
                .order
                .iter()
                .position(|&index| index == id)
                .expect("directory entry remains in list");
            current = self.order.get(position + 1).copied();
        }
    }

    pub fn reload(&mut self, main_hosts: &[HostConfig]) -> HostReload {
        let mut report = HostReload {
            hosts: main_hosts.to_vec(),
            errors: Vec::new(),
        };
        self.expand(&mut report.errors);
        for &id in &self.order {
            let entry = &self.entries[id];
            if entry.inactive {
                continue;
            }
            let file = match File::open(&entry.path) {
                Ok(file) => file,
                Err(error) => {
                    report.errors.push(HostFileError {
                        path: entry.path.clone(),
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
                        path: entry.path.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

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
