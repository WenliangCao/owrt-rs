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
pub fn open_stream(ctx: &Context, filename: &str, seek_end: bool, write: bool, create: bool) -> Result<File> {
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
    if sys::lock(&f, if write { sys::LOCK_EX } else { sys::LOCK_SH }).is_err() {
        return Err(Error::Io);
    }
    // a freshly opened descriptor is already at offset 0
    if seek_end && f.seek(SeekFrom::End(0)).is_err() {
        sys::unlock(&f);
        return Err(Error::Io);
    }
    Ok(f)
}

/// The rest of `f` from its current offset.  Sized from fstat so a config
/// file is normally fetched by one read(2): a regular file that returns
/// fewer bytes than asked is at EOF, and only a file that grew underneath
/// the lock is read on to EOF.  Replaces an 8 KiB BufReader (a fresh
/// mallocng group, mmap and munmap) plus its trailing zero-length read.
pub(crate) fn read_whole(mut f: &File) -> Result<Vec<u8>> {
    let hint = f.metadata().map(|m| m.len() as usize).unwrap_or(0);
    let mut data = vec![0u8; hint + 1];
    let mut filled = 0;
    loop {
        match f.read(&mut data[filled..]) {
            Ok(0) => break,
            Ok(n) => {
                filled += n;
                if filled < data.len() {
                    break;
                }
                data.resize(data.len() * 2, 0);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Io),
        }
    }
    data.truncate(filled);
    Ok(data)
}

/// uci_config_path: None when the (conf2) directory is disabled.
fn config_path(ctx: &Context, name: &str, conf2: bool) -> Result<Option<String>> {
    if !crate::ops::validate_package(name) {
        return Err(Error::Inval);
    }
    let dir = if conf2 { ctx.conf2dir.as_deref() } else { Some(ctx.confdir.as_str()) };
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

fn load_impl(ctx: &mut Context, name: &str, cache: Option<&mut crate::ReadCache>) -> Result<usize> {
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
    let data = match read_whole(&file) {
        Ok(d) => d,
        Err(e) => {
            sys::unlock(&file);
            return Err(e);
        }
    };
    let mut reader: &[u8] = &data;
    let result = match cache {
        Some(cache) => cache.import(ctx, &mut reader, &pkgname),
        None => parse::import(ctx, &mut reader, Some(&pkgname), None, true),
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
                let data = read_whole(stream)?;
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
            // flush delta
            if delta::load_delta(ctx, pidx, true)? == 0 {
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
        let _ = f2.sync_all();
        sys::unlock(&f2);
        do_rename = true;
        Ok(())
    })();

    sys::unlock(&f1);
    drop(f1);
    if do_rename {
        let tmp = tmpname.clone().unwrap_or_default();
        let renamed = (|| -> std::io::Result<()> {
            let real = fs::canonicalize(&path)?;
            let md = fs::metadata(&real)?;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(md.mode() & 0o7777))?;
            fs::rename(&tmp, &real)
        })();
        if renamed.is_err() {
            let _ = fs::remove_file(&tmp);
            return Err(Error::Io);
        }
    } else if let Some(tmp) = &tmpname {
        let _ = fs::remove_file(tmp);
    }
    body
}

/// uci_list_config_files: glob(confdir/*, GLOB_MARK), skipping directories,
/// names containing '.', and invalid package names. No match at all is
/// UCI_ERR_NOTFOUND.
pub fn list_config_files(ctx: &Context) -> Result<Vec<String>> {
    list_config_files_in(&ctx.confdir)
}

/// The listing itself depends only on confdir, not a parser or delta context.
#[cfg(not(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64"))))]
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
        let Ok(name) = raw.into_string() else { continue };
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

#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub fn list_config_files_in(confdir: &str) -> Result<Vec<String>> {
    directory::list(confdir)
}

#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64")))]
mod directory {
    use super::*;
    use std::ffi::{c_char, c_void, CStr, CString};
    use std::ptr::NonNull;

    // Linux aarch64/x86_64 dirent; verified against the image SDK by check_abi.
    #[repr(C)]
    struct Dirent { ino: u64, off: i64, reclen: u16, ty: u8, name: [c_char; 256] }
    extern "C" {
        fn opendir(path: *const c_char) -> *mut c_void;
        fn readdir(dir: *mut c_void) -> *mut Dirent;
        fn closedir(dir: *mut c_void) -> i32;
    }
    struct Directory(NonNull<c_void>);
    impl Drop for Directory {
        fn drop(&mut self) {
            // SAFETY: this object owns the successful opendir result.
            unsafe { closedir(self.0.as_ptr()); }
        }
    }

    pub fn list(confdir: &str) -> Result<Vec<String>> {
        let path = CString::new(confdir).map_err(|_| Error::NotFound)?;
        // SAFETY: path is NUL terminated and remains live through the call.
        let dir = Directory(NonNull::new(unsafe { opendir(path.as_ptr()) }).ok_or(Error::NotFound)?);
        let mut matched = false;
        let mut out = Vec::new();
        loop {
            // SAFETY: dir is open and exclusively used here. Each borrowed
            // entry/name is consumed before the next readdir or closedir.
            let entry = unsafe { readdir(dir.0.as_ptr()) };
            if entry.is_null() { break; }
            // SAFETY: libc returns a valid dirent with a NUL-terminated name;
            // do not form a reference to the possibly shorter trailing array.
            let (name, ty) = unsafe {
                (CStr::from_ptr(std::ptr::addr_of!((*entry).name).cast()).to_bytes(), (*entry).ty)
            };
            if name.first() == Some(&b'.') { continue; }
            matched = true;
            if name.contains(&b'.') { continue; }
            let Ok(name) = std::str::from_utf8(name) else { continue };
            if !crate::ops::validate_package(name) { continue; }
            // DT_UNKNOWN and symlinks need the current followed metadata, as
            // before. All other d_type values can only exclude DT_DIR (4).
            let is_dir = match ty {
                0 | 10 => fs::metadata(std::path::Path::new(confdir).join(name))
                    .map(|m| m.is_dir()).unwrap_or(false),
                _ => ty == 4,
            };
            if !is_dir { out.push(name.to_owned()); }
        }
        if !matched { return Err(Error::NotFound); }
        out.sort_unstable();
        Ok(out)
    }

    #[test]
    fn dirent_layout_matches_linux_sdk() {
        assert_eq!(std::mem::size_of::<Dirent>(), 280);
        assert_eq!(std::mem::offset_of!(Dirent, ty), 18);
        assert_eq!(std::mem::offset_of!(Dirent, name), 19);
    }
}
