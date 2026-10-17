//! DHCP dynamic-directory watches follow inotify.c, including persistent watch
//! attempts, inode lifetime, readdir order and append-only close-write events.

use crate::config::dhcp::{DynamicFileDirectory, DynamicFileKind};
use rustix::fs::inotify::{self, CreateFlags, WatchFlags};
use std::ffi::{CString, OsString};
use std::fs::{self, File, ReadDir};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

const CLOSE_WRITE: u32 = 0x8;
const MOVED_TO: u32 = 0x80;
const DELETE: u32 = 0x200;

pub(super) fn accepted_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name[0] != b'.'
        && !name.ends_with(b"~")
        && !(name.starts_with(b"#") && name.ends_with(b"#"))
        && !name.contains(&b'/')
}

struct Directory {
    path: PathBuf,
    kind: DynamicFileKind,
    attempted: bool,
    descriptor: i32,
    watch_error: Option<i32>,
}

pub(super) enum ScanError {
    Bad(PathBuf, io::Error),
    Watch(PathBuf, io::Error),
}

pub(super) struct DirectoryScan {
    pub kind: DynamicFileKind,
    pub path: PathBuf,
    pub entries: ReadDir,
}

struct Event {
    descriptor: i32,
    name: Vec<u8>,
    directory: usize,
}

pub(super) enum WatchStep {
    Idle,
    Pending,
    File(DynamicFileKind, PathBuf),
}

pub(super) struct DirectoryWatch {
    fd: File,
    directories: Vec<Directory>,
    bytes: [u8; 4096],
    length: usize,
    position: usize,
    event: Option<Event>,
}

impl DirectoryWatch {
    pub fn new(directories: &[DynamicFileDirectory]) -> io::Result<Self> {
        let fd = inotify::init(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC)?;
        Ok(Self {
            fd: File::from(fd),
            directories: directories
                .iter()
                .map(|directory| Directory {
                    path: PathBuf::from(OsString::from_vec(directory.path.clone())),
                    kind: directory.kind.clone(),
                    attempted: false,
                    descriptor: -1,
                    watch_error: None,
                })
                .collect(),
            bytes: [0; 4096],
            length: 0,
            position: 0,
            event: None,
        })
    }

    pub fn len(&self) -> usize {
        self.directories.len()
    }

    pub fn raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }

    pub fn append_poll_fds(&self, fds: &mut Vec<dnsmasq_platform::poll::PollFd>) {
        fds.push(dnsmasq_platform::poll::PollFd {
            fd: self.fd.as_raw_fd(),
            events: 1,
            revents: 0,
        });
    }

    /// Watch before opendir; a failed watch remains attempted on later HUP.
    /// Missing/non-directory paths never set AH_WD_DONE and may recover on HUP.
    pub fn scan(&mut self, index: usize) -> Result<DirectoryScan, ScanError> {
        let directory = &mut self.directories[index];
        let metadata = fs::metadata(&directory.path)
            .map_err(|error| ScanError::Bad(directory.path.clone(), error))?;
        if !metadata.is_dir() {
            return Err(ScanError::Bad(
                directory.path.clone(),
                io::Error::from_raw_os_error(20),
            ));
        }
        if !directory.attempted {
            directory.attempted = true;
            let path = CString::new(directory.path.as_os_str().as_bytes()).map_err(|_| {
                ScanError::Watch(directory.path.clone(), io::Error::from_raw_os_error(22))
            })?;
            directory.descriptor = match inotify::add_watch(
                &self.fd,
                path.as_c_str(),
                WatchFlags::CLOSE_WRITE | WatchFlags::MOVED_TO | WatchFlags::DELETE,
            ) {
                Ok(descriptor) => descriptor,
                Err(error) => {
                    let error = io::Error::from(error);
                    directory.watch_error = error.raw_os_error();
                    return Err(ScanError::Watch(directory.path.clone(), error));
                }
            };
        }
        if directory.descriptor < 0 {
            return Err(ScanError::Watch(
                directory.path.clone(),
                io::Error::from_raw_os_error(directory.watch_error.unwrap_or(22)),
            ));
        }
        let entries = fs::read_dir(&directory.path)
            .map_err(|error| ScanError::Watch(directory.path.clone(), error))?;
        Ok(DirectoryScan {
            kind: directory.kind.clone(),
            path: directory.path.clone(),
            entries,
        })
    }

    pub fn runnable(&self) -> bool {
        self.event.is_some() || self.position < self.length
    }

    /// One buffered event, one directory match, or one <=4096 byte read.
    /// Duplicate declarations sharing a watch descriptor each receive the event.
    pub fn step_with_readiness(&mut self, readable: bool) -> io::Result<WatchStep> {
        if let Some(event) = self.event.as_mut() {
            if let Some(directory) = self.directories.get(event.directory) {
                event.directory += 1;
                if directory.descriptor == event.descriptor {
                    return Ok(WatchStep::File(
                        directory.kind.clone(),
                        literal_join(&directory.path, &event.name),
                    ));
                }
            } else {
                self.event = None;
            }
            return Ok(WatchStep::Pending);
        }
        if self.position < self.length {
            let bytes = &self.bytes[self.position..self.length];
            let Some((length, event)) = decode_event(bytes) else {
                self.position = self.length;
                return Ok(WatchStep::Pending);
            };
            self.position += length;
            self.event = event;
            return Ok(WatchStep::Pending);
        }
        if !readable {
            return Ok(WatchStep::Idle);
        }
        match self.fd.read(&mut self.bytes) {
            Ok(0) => Ok(WatchStep::Idle),
            Ok(length) => {
                self.length = length;
                self.position = 0;
                Ok(WatchStep::Pending)
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(WatchStep::Pending),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(WatchStep::Idle),
            Err(error) => Err(error),
        }
    }
}

pub(super) fn literal_join(path: &std::path::Path, name: &[u8]) -> PathBuf {
    let mut bytes = path.as_os_str().as_bytes().to_vec();
    bytes.push(b'/');
    bytes.extend_from_slice(name);
    PathBuf::from(OsString::from_vec(bytes))
}

fn decode_event(bytes: &[u8]) -> Option<(usize, Option<Event>)> {
    let header = bytes.get(..16)?;
    let length =
        16usize.checked_add(u32::from_ne_bytes(header[12..16].try_into().ok()?) as usize)?;
    let record = bytes.get(..length)?;
    let mask = u32::from_ne_bytes(header[4..8].try_into().ok()?);
    let name = &record[16..];
    let Some(nul) = name.iter().position(|byte| *byte == 0) else {
        return Some((length, None));
    };
    let name = &name[..nul];
    let event = (mask & (CLOSE_WRITE | MOVED_TO) != 0 && mask & DELETE == 0 && accepted_name(name))
        .then(|| Event {
            descriptor: i32::from_ne_bytes(header[..4].try_into().unwrap()),
            name: name.to_vec(),
            directory: 0,
        });
    Some((length, event))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_decoder_rejects_truncated_nameless_and_delete_records() {
        let make = |mask: u32, name: &[u8]| {
            let mut out = Vec::new();
            out.extend_from_slice(&7i32.to_ne_bytes());
            out.extend_from_slice(&mask.to_ne_bytes());
            out.extend_from_slice(&0u32.to_ne_bytes());
            out.extend_from_slice(&(name.len() as u32).to_ne_bytes());
            out.extend_from_slice(name);
            out
        };
        let bytes = make(CLOSE_WRITE, b"hosts\0\0\0");
        assert_eq!(decode_event(&bytes).unwrap().1.unwrap().name, b"hosts");
        assert!(decode_event(&bytes[..bytes.len() - 1]).is_none());
        for (mask, name) in [
            (DELETE, &b"hosts\0"[..]),
            (CLOSE_WRITE, b""),
            (CLOSE_WRITE, b"hosts"),
            (MOVED_TO, b".hidden\0"),
            (CLOSE_WRITE, b"../hosts\0"),
            (0x8000, b"hosts\0"),
        ] {
            assert!(decode_event(&make(mask, name)).unwrap().1.is_none());
        }
    }
}
