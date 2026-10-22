//! file.c backend: uci_open_stream, uci_config_path, uci_file_load,
//! uci_file_commit, uci_list_config_files.

use crate::context::{Context, FILEMODE};
use crate::delta;
use crate::error::{Error, Result};
use crate::export;
use crate::parse;
use crate::sys;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// uci_open_stream(ctx, filename, NULL, pos, write, create)
pub fn open_stream(
    ctx: &Context,
    filename: &str,
    seek_end: bool,
    write: bool,
    create: bool,
) -> Result<File> {
    ctx.check_io_budget()?;
    let mut mode = FILEMODE;
    if create {
        let filename2 = format!("{}/{}", ctx.confdir, basename(filename));
        if let Ok(md) = fs::metadata(&filename2) {
            mode = md.mode();
        }
    }
    if !write {
        match fs::metadata(filename) {
            Ok(md) if md.file_type().is_file() => {}
            _ => return Err(Error::NotFound),
        }
    }
    let mut oo = OpenOptions::new();
    oo.read(true);
    if write {
        oo.write(true);
    }
    if create {
        oo.create(true).mode(mode & 0o7777);
    }
    let mut f = oo.open(filename).map_err(|_| Error::Io)?;
    ctx.lock_file(&f, if write { sys::LOCK_EX } else { sys::LOCK_SH })?;
    // a freshly opened descriptor is already at offset 0
    if seek_end && f.seek(SeekFrom::End(0)).is_err() {
        sys::unlock(&f);
        return Err(Error::Io);
    }
    Ok(f)
}

/// Read through EOF from the current offset. Metadata is only an allocation
/// hint: a successful short read need not mean EOF, even for a regular file.
pub(crate) fn read_whole(ctx: &Context, mut f: &File) -> Result<Vec<u8>> {
    let hint = f.metadata().map(|m| m.len() as usize).unwrap_or(0);
    read_all(ctx, &mut f, hint)
}

fn read_all(ctx: &Context, reader: impl Read, hint: usize) -> Result<Vec<u8>> {
    read_into(ctx, reader, hint, Vec::new())
}

fn read_into(
    ctx: &Context,
    mut reader: impl Read,
    hint: usize,
    mut data: Vec<u8>,
) -> Result<Vec<u8>> {
    data.resize(hint.saturating_add(1).min(64 * 1024), 0);
    let mut filled: usize = 0;
    loop {
        ctx.check_io_budget()?;
        let end = filled.saturating_add(64 * 1024).min(data.len());
        match reader.read(&mut data[filled..end]) {
            Ok(0) => break,
            Ok(n) => {
                filled += n;
                if filled == data.len() {
                    let size = data.len().checked_mul(2).ok_or(Error::Mem)?;
                    data.resize(size, 0);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Io),
        }
    }
    data.truncate(filled);
    Ok(data)
}

#[cfg(test)]
mod read_tests {
    use super::*;
    use std::io::{self, Cursor};

    struct Fragmented<'a> {
        bytes: Cursor<&'a [u8]>,
        chunk: usize,
        interrupt: bool,
    }

    impl Read for Fragmented<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if std::mem::take(&mut self.interrupt) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let len = out.len().min(self.chunk);
            self.bytes.read(&mut out[..len])
        }
    }

    #[test]
    fn short_reads_and_interrupted_reads_preserve_every_byte() {
        let bytes = b"config test 's'\n option v 'visible'\n option tail 'retained'\n";
        for chunk in [1, 7, 16, bytes.len()] {
            for hint in [0, 3, bytes.len(), bytes.len() + 128] {
                for buffer in [Vec::new(), vec![0xa5; 4096]] {
                    let reader = Fragmented {
                        bytes: Cursor::new(&bytes[..]),
                        chunk,
                        interrupt: true,
                    };
                    assert_eq!(
                        read_into(&Context::new(), reader, hint, buffer).unwrap(),
                        bytes
                    );
                }
            }
        }
    }

    #[test]
    fn read_errors_never_return_a_partial_or_reused_buffer() {
        struct FailAfter<'a>(&'a [u8]);
        impl Read for FailAfter<'_> {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    return Err(io::ErrorKind::Other.into());
                }
                self.0.read(out)
            }
        }
        for buffer in [Vec::new(), vec![0xa5; 4096]] {
            assert_eq!(
                read_into(&Context::new(), FailAfter(b"prefix"), 6, buffer),
                Err(Error::Io)
            );
        }
    }

    #[test]
    fn reads_only_the_remaining_bytes_after_a_seek() {
        let bytes = b"old prefix\nremaining delta\n";
        let mut reader = Cursor::new(&bytes[..]);
        reader.set_position(11);
        assert_eq!(
            read_all(&Context::new(), reader, bytes.len()).unwrap(),
            b"remaining delta\n"
        );
    }
}

/// uci_config_path: None when the (conf2) directory is disabled.
fn config_path(ctx: &Context, name: &str, conf2: bool) -> Result<Option<String>> {
    if !crate::ops::validate_package(name) {
        return Err(Error::Inval);
    }
    let dir = if conf2 {
        ctx.conf2dir.as_deref()
    } else {
        Some(ctx.confdir.as_str())
    };
    Ok(dir.map(|d| format!("{d}/{name}")))
}

/// uci_file_load: returns the index of the loaded package in ctx.root.
pub fn load(ctx: &mut Context, name: &str) -> Result<usize> {
    load_impl(ctx, name, None)
}

/// Read and lock current files as usual, reusing only an identical base parse.
/// Delta paths are resolved and replayed on every call, including cache hits.
pub fn load_cached(ctx: &mut Context, name: &str, cache: &mut crate::ReadCache) -> Result<usize> {
    load_impl(ctx, name, Some(cache))
}

fn load_impl(
    ctx: &mut Context,
    name: &str,
    mut cache: Option<&mut crate::ReadCache>,
) -> Result<usize> {
    let (filename, pkgname, confdir, conf2) = match name.as_bytes().first() {
        Some(b'.') if name.as_bytes().get(1) != Some(&b'/') => return Err(Error::NotFound),
        Some(b'.') | Some(b'/') => {
            let base = name.rsplit('/').next().unwrap_or(name).to_owned();
            (name.to_owned(), base, false, false)
        }
        _ => {
            let mut conf2 = true;
            let mut filename = config_path(ctx, name, true)?;
            if filename.as_ref().is_none_or(|f| fs::metadata(f).is_err()) {
                conf2 = false;
                filename = config_path(ctx, name, false)?;
            }
            (filename.unwrap_or_default(), name.to_owned(), true, conf2)
        }
    };
    let file = open_stream(ctx, &filename, false, false, false)?;
    ctx.err = None;
    // The owner keeps the shared lock alive while the whole file is read once.
    let read_result = match cache.as_deref_mut() {
        Some(cache) => {
            let hint = file.metadata().map(|m| m.len() as usize).unwrap_or(0);
            read_into(ctx, &file, hint, cache.take_buffer())
        }
        None => read_whole(ctx, &file),
    };
    let data = match read_result {
        Ok(d) => d,
        Err(e) => {
            sys::unlock(&file);
            return Err(e);
        }
    };
    let result = match cache {
        Some(cache) => cache.import(ctx, data, &pkgname),
        None => parse::import(ctx, &mut data.as_slice(), Some(&pkgname), None, true),
    };
    let pidx = match result {
        Ok(Some(i)) => i,
        Ok(None) => {
            sys::unlock(&file);
            return Err(Error::NotFound);
        }
        Err(e) => {
            sys::unlock(&file);
            return Err(e);
        }
    };
    {
        let p = &mut ctx.root[pidx];
        p.uses_conf2 = conf2;
        p.path = Some(filename);
        p.has_delta = confdir;
    }
    let r = delta::load_delta(ctx, pidx, false);
    sys::unlock(&file);
    if let Err(error @ (Error::TimedOut | Error::Cancelled)) = r {
        // A timed-out delta load is not a successfully cached base package.
        ctx.root.remove(pidx);
        return ctx.fail(error);
    }
    r?;
    Ok(pidx)
}

/// uci_file_commit
pub fn commit(ctx: &mut Context, pidx: usize, overwrite: bool) -> Result<()> {
    let name = ctx.root[pidx].name.clone();
    if ctx.root[pidx].path.is_none() && overwrite {
        let uses_conf2 = ctx.root[pidx].uses_conf2;
        ctx.root[pidx].path = config_path(ctx, &name, uses_conf2)?;
    }
    let Some(path) = ctx.root[pidx].path.clone() else {
        return Err(Error::Inval);
    };
    let confdir = if ctx.root[pidx].uses_conf2 {
        ctx.conf2dir.clone().unwrap_or_default()
    } else {
        ctx.confdir.clone()
    };
    let template = format!("{confdir}/.{name}.uci-XXXXXX");

    // open the config file for writing now, so that it is locked
    let f1 = open_stream(ctx, &path, false, true, true)?;

    let mut do_rename = false;
    let mut tmpname: Option<String> = None;
    let mut saved_delta = None;
    let body: Result<()> = (|| {
        if ctx.root[pidx].has_delta {
            if !overwrite {
                // dump our own changes to the delta file
                if !ctx.root[pidx].delta.is_empty() {
                    delta::save(ctx, pidx)?;
                }
                // other processes might have modified the config as well:
                // dump and reload from the locked stream
                ctx.root.remove(pidx);
                let mut stream = &f1;
                stream.seek(SeekFrom::Start(0)).map_err(|_| Error::Io)?;
                let data = read_whole(ctx, stream)?;
                let mut reader: &[u8] = &data;
                let newidx = match parse::import(ctx, &mut reader, Some(&name), None, true)? {
                    Some(i) => i,
                    None => return Err(Error::NotFound),
                };
                if newidx != pidx {
                    let p = ctx.root.remove(newidx);
                    ctx.root.insert(pidx, p);
                }
                let p = &mut ctx.root[pidx];
                p.path = Some(path.clone());
                p.has_delta = true;
            }
            let (changes, stream) = delta::prepare_commit(ctx, pidx)?;
            saved_delta = stream;
            if changes == 0 {
                return Ok(());
            }
        }
        let (f2, tmp) = sys::mkstemp(&template).map_err(|_| Error::Io)?;
        tmpname = Some(tmp);
        sys::lock(&f2, sys::LOCK_EX).map_err(|_| Error::Io)?;
        // uci_export writes through stdio and only then fflush/fsync; a bare
        // File would emit a write(2) per token of every option
        let mut w = std::io::BufWriter::new(&f2);
        export::export_package(&mut w, ctx.flags, &ctx.root[pidx], false).map_err(|_| Error::Io)?;
        w.flush().map_err(|_| Error::Io)?;
        drop(w);
        f2.sync_all().map_err(|_| Error::Io)?;
        sys::unlock(&f2);
        do_rename = true;
        Ok(())
    })();

    if do_rename {
        let tmp = tmpname.clone().unwrap_or_default();
        let mut backup = None;
        let installed = (|| -> std::io::Result<std::path::PathBuf> {
            let real = fs::canonicalize(&path)?;
            let md = fs::metadata(&real)?;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(md.mode() & 0o7777))?;
            if saved_delta.is_some() {
                // Retain the old inode until draft cleanup also succeeds.
                // A failed truncate must not turn a retry into a second list-add.
                let parent = real
                    .parent()
                    .ok_or_else(|| std::io::Error::other("config has no parent"))?;
                let template = parent.join(format!(".{name}.uci-backup-XXXXXX"));
                let (placeholder, old) = sys::mkstemp(&template.to_string_lossy())?;
                drop(placeholder);
                fs::remove_file(&old)?;
                fs::hard_link(&real, &old)?;
                backup = Some(old);
            }
            fs::rename(&tmp, &real)?;
            Ok(real)
        })();
        let real = match installed {
            Ok(real) => real,
            Err(_) => {
                let _ = fs::remove_file(&tmp);
                if let Some(old) = backup {
                    let _ = fs::remove_file(old);
                }
                return Err(Error::Io);
            }
        };
        if let Some(stream) = saved_delta {
            if stream.set_len(0).is_err() {
                if let Some(old) = backup {
                    if fs::rename(&old, &real).is_err() {
                        // Both operations failed: keep the original backup for
                        // recovery and distinguish an uncertain commit from a
                        // restored, retryable I/O failure.
                        return Err(Error::Unknown);
                    }
                }
                return Err(Error::Io);
            }
        }
        if let Some(old) = backup {
            let _ = fs::remove_file(old);
        }
    } else if let Some(tmp) = &tmpname {
        let _ = fs::remove_file(tmp);
    }
    sys::unlock(&f1);
    body
}

/// uci_list_config_files: glob(confdir/*, GLOB_MARK), skipping directories,
/// names containing '.', and invalid package names. No match at all is
/// UCI_ERR_NOTFOUND.
pub fn list_config_files(ctx: &Context) -> Result<Vec<String>> {
    list_config_files_in(&ctx.confdir)
}

/// The listing itself depends only on confdir, not a parser or delta context.
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64")
)))]
pub fn list_config_files_in(confdir: &str) -> Result<Vec<String>> {
    let entries = match fs::read_dir(confdir) {
        Ok(e) => e,
        Err(_) => return Err(Error::NotFound),
    };
    let mut matched = false;
    let mut out = Vec::new();
    for e in entries.flatten() {
        let raw = e.file_name();
        let bytes = std::os::unix::ffi::OsStrExt::as_bytes(raw.as_os_str());
        if bytes.first() == Some(&b'.') {
            continue; // glob("*") never matches a leading dot
        }
        // A glob match still counts when every matched name is later excluded.
        matched = true;
        if bytes.contains(&b'.') {
            continue;
        }
        let Ok(name) = raw.into_string() else {
            continue;
        };
        if !crate::ops::validate_package(&name) {
            continue;
        }
        // read_dir already provides the type on normal Linux filesystems.
        // GLOB_MARK follows symlinks, so inspect their current target each
        // time; unknown/error cases retain the previous metadata fallback.
        let is_dir = match e.file_type() {
            Ok(ty) if !ty.is_symlink() => ty.is_dir(),
            _ => fs::metadata(e.path()).map(|m| m.is_dir()).unwrap_or(false),
        };
        if !is_dir {
            out.push(name);
        }
    }
    if !matched {
        return Err(Error::NotFound);
    }
    out.sort_unstable();
    Ok(out)
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub fn list_config_files_in(confdir: &str) -> Result<Vec<String>> {
    directory::list(confdir)
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
mod directory {
    use super::*;

    pub fn list(confdir: &str) -> Result<Vec<String>> {
        let mut matched = false;
        let mut out = Vec::new();
        owrt_platform::directory::entries(confdir, |name, ty| {
            if name.first() == Some(&b'.') {
                return;
            }
            matched = true;
            if name.contains(&b'.') {
                return;
            }
            let Ok(name) = std::str::from_utf8(name) else {
                return;
            };
            if !crate::ops::validate_package(name) {
                return;
            }
            let is_dir = match ty {
                0 | 10 => fs::metadata(std::path::Path::new(confdir).join(name))
                    .map(|m| m.is_dir())
                    .unwrap_or(false),
                _ => ty == 4,
            };
            if !is_dir {
                out.push(name.to_owned());
            }
        })
        .map_err(|_| Error::NotFound)?;
        if !matched {
            return Err(Error::NotFound);
        }
        out.sort_unstable();
        Ok(out)
    }
}
