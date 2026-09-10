//! file.c backend: uci_open_stream, uci_config_path, uci_file_load,
//! uci_file_commit, uci_list_config_files.

use crate::context::{Context, FILEMODE};
use crate::delta;
use crate::error::{Error, Result};
use crate::export;
use crate::parse;
use crate::sys;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Seek, SeekFrom, Write};
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
    let seek = if seek_end { SeekFrom::End(0) } else { SeekFrom::Start(0) };
    if f.seek(seek).is_err() {
        sys::unlock(&f);
        return Err(Error::Io);
    }
    Ok(f)
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
    let mut reader = BufReader::new(file.try_clone().map_err(|_| Error::Io)?);
    let result = parse::import(ctx, &mut reader, Some(&pkgname), None, true);
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
                let mut dup = f1.try_clone().map_err(|_| Error::Io)?;
                dup.seek(SeekFrom::Start(0)).map_err(|_| Error::Io)?;
                let mut reader = BufReader::new(dup);
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
    let entries = match fs::read_dir(&ctx.confdir) {
        Ok(e) => e,
        Err(_) => return Err(Error::NotFound),
    };
    let mut names: Vec<(Vec<u8>, bool)> = Vec::new();
    for e in entries.flatten() {
        let raw = e.file_name();
        let bytes = std::os::unix::ffi::OsStrExt::as_bytes(raw.as_os_str()).to_vec();
        if bytes.first() == Some(&b'.') {
            continue; // glob("*") never matches a leading dot
        }
        let is_dir = fs::metadata(e.path()).map(|m| m.is_dir()).unwrap_or(false);
        names.push((bytes, is_dir));
    }
    if names.is_empty() {
        return Err(Error::NotFound);
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = Vec::new();
    for (bytes, is_dir) in names {
        if is_dir || bytes.contains(&b'.') {
            continue;
        }
        let Ok(s) = String::from_utf8(bytes) else { continue };
        if !crate::ops::validate_package(&s) {
            continue;
        }
        out.push(s);
    }
    Ok(out)
}
