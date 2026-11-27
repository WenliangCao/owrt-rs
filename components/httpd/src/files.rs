//! Static file serving with uhttpd's path lookup, index files, directory
//! listing, conditional requests and MIME table.

use crate::http::{self, Method, Request, Response};
use rustix::fs::{Mode, OFlags, RawDir, ResolveFlags};
use std::borrow::Cow;
use std::cell::RefCell;
use std::fs;
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

/// Anchored directory descriptor for the HTTP document root. All path lookups
/// and file opens go through `dirfd` with `openat2(RESOLVE_BENEATH)` so no
/// symlink or race can escape the document root.
#[derive(Clone)]
pub struct Docroot {
    path: Arc<str>,
    dirfd: Arc<OwnedFd>,
}

impl Docroot {
    /// Open `path` and probe `openat2(RESOLVE_BENEATH)` at startup. Fails
    /// explicitly if `openat2` returns `ENOSYS` or `EPERM`.
    pub fn open(path: &str) -> io::Result<Self> {
        let dirfd = rustix::fs::openat(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        check_openat2_probe(rustix::fs::openat2(
            &dirfd,
            c".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH,
        ))?;
        Ok(Self {
            path: Arc::from(path),
            dirfd: Arc::new(dirfd),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.path
    }
}

fn check_openat2_probe(probe: Result<OwnedFd, rustix::io::Errno>) -> io::Result<()> {
    match probe {
        Ok(_fd) => Ok(()),
        Err(errno) if matches!(errno, rustix::io::Errno::NOSYS | rustix::io::Errno::PERM) => {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("openat2(RESOLVE_BENEATH) unsupported or blocked: {errno}"),
            ))
        }
        Err(errno) => Err(errno.into()),
    }
}

fn open_beneath(
    dirfd: &OwnedFd,
    rel: &str,
    oflags: OFlags,
    no_symlinks: bool,
) -> Result<OwnedFd, rustix::io::Errno> {
    let target = if rel.is_empty() { "." } else { rel };
    let mut resolve = ResolveFlags::BENEATH;
    if no_symlinks {
        resolve |= ResolveFlags::NO_SYMLINKS;
    }
    rustix::fs::openat2(dirfd, target, oflags, Mode::empty(), resolve)
}

pub struct PathInfo {
    /// Canonical physical path (valid UTF-8: built from the docroot and the
    /// decoded URL).
    pub phys: String,
    /// Where the docroot-relative name starts inside `phys`.
    name_start: usize,
    /// A directory listing is named with a trailing slash the physical
    /// path does not carry; every other name is a suffix of `phys`.
    dir_name: Option<String>,
    pub info: Option<String>,
    pub query: Option<String>,
    pub meta: fs::Metadata,
    docroot: Option<Docroot>,
    rel: String,
    no_symlinks: bool,
}

impl PathInfo {
    /// Path relative to docroot, starting with '/'.
    pub fn name(&self) -> &str {
        if let Some(dir) = &self.dir_name {
            return dir;
        }
        let name = &self.phys[self.name_start..];
        if name.is_empty() {
            "/"
        } else {
            name
        }
    }

    pub fn path(&self) -> &Path {
        Path::new(&self.phys)
    }

    /// A regular file whose name starts `name_start` bytes into `phys`.
    #[cfg(test)]
    pub fn for_test(phys: String, name_start: usize, meta: fs::Metadata) -> Self {
        let rel = phys[name_start..].trim_start_matches('/').to_owned();
        PathInfo {
            phys,
            name_start,
            dir_name: None,
            info: None,
            query: None,
            meta,
            docroot: None,
            rel,
            no_symlinks: false,
        }
    }

    fn mime_type(&self) -> &'static str {
        match &self.docroot {
            Some(docroot) => file_mime_type_at(docroot, &self.rel, &self.phys),
            None => file_mime_type(&self.phys),
        }
    }
}

/// `Found` carries the whole record by value: boxing it cost one allocation
/// per static request, and the record is moved once.
#[allow(clippy::large_enum_variant)]
pub enum Lookup {
    Found(PathInfo),
    /// Directory requested without trailing slash: redirect.
    Redirect(String),
    NotFound,
}

/// `canonpath` on a path that starts with '/', rewriting it in place: the
/// canonical form is never longer than such an input. The hot path of
/// `lookup` canonicalizes the full docroot+URL string this way instead of
/// allocating a second copy.
fn canonpath_in_place(path: &mut String) {
    if !path.starts_with('/') {
        *path = canonpath(path);
        return;
    }
    let mut bytes = std::mem::take(path).into_bytes();
    let n = bytes.len();
    let (mut r, mut w) = (0usize, 0usize);
    while r < n {
        let e = bytes[r..]
            .iter()
            .position(|&b| b == b'/')
            .map_or(n, |p| r + p);
        match &bytes[r..e] {
            b"" | b"." => {}
            b".." => {
                if let Some(slash) = bytes[..w].iter().rposition(|&b| b == b'/') {
                    w = slash;
                }
            }
            _ => {
                // w <= r - 1 here: the byte at w is a consumed '/' or already
                // written output, never part of this segment.
                bytes[w] = b'/';
                bytes.copy_within(r..e, w + 1);
                w += 1 + (e - r);
            }
        }
        r = e + 1;
    }
    if w == 0 {
        bytes.clear();
        bytes.push(b'/');
        w = 1;
    }
    bytes.truncate(w);
    // Segments were moved whole, so the bytes are still the input's UTF-8.
    *path = String::from_utf8(bytes)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
}

fn canonpath(path: &str) -> String {
    let mut out = String::with_capacity(path.len().max(1));
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if let Some(slash) = out.rfind('/') {
                    out.truncate(slash);
                }
            }
            s => {
                out.push('/');
                out.push_str(s);
            }
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// uhttpd's `uh_path_lookup`: longest existing prefix wins, rest is PATH_INFO.
/// All resolution is anchored on `docroot`'s dirfd via `openat2(RESOLVE_BENEATH)`.
pub fn lookup(docroot: &Docroot, url: &str, no_symlinks: bool, indexes: &[String]) -> Lookup {
    let (path_part, query) = match url.split_once('?') {
        Some((p, q)) => (
            p,
            if q.is_empty() {
                None
            } else {
                Some(q.to_owned())
            },
        ),
        None => (url, None),
    };
    // Unescaped paths already have the required UTF-8 representation. For
    // escaped bytes retain the same malformed-escape and lossy-UTF-8 rules.
    let bytes;
    let decoded = if path_part.contains('%') {
        let Some(decoded) = http::url_decode(path_part) else {
            return Lookup::NotFound;
        };
        bytes = decoded;
        String::from_utf8_lossy(&bytes)
    } else {
        Cow::Borrowed(path_part)
    };
    let trailing_slash = decoded.ends_with('/');
    let mut canonical = decoded.into_owned();
    canonpath_in_place(&mut canonical);

    let mut found: Option<(&str, &str, fs::Metadata)> = None;
    let bytes = canonical.as_bytes();
    let mut i = bytes.len();
    loop {
        if i == bytes.len() || bytes[i] == b'/' {
            let prefix = &canonical[..i];
            let rel = prefix.strip_prefix('/').unwrap_or(prefix);
            match open_beneath(
                &docroot.dirfd,
                rel,
                OFlags::PATH | OFlags::CLOEXEC,
                no_symlinks,
            ) {
                Ok(fd) => {
                    if let Ok(meta) = fs::File::from(fd).metadata() {
                        found = Some((prefix, &canonical[i..], meta));
                        break;
                    }
                }
                Err(rustix::io::Errno::XDEV | rustix::io::Errno::LOOP) => {
                    return Lookup::NotFound;
                }
                Err(_) => {}
            }
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    let Some((prefix, info, meta)) = found else {
        return Lookup::NotFound;
    };
    let rel = prefix.strip_prefix('/').unwrap_or(prefix);
    let root_prefix = if docroot.as_str() == "/" {
        ""
    } else {
        docroot.as_str()
    };
    let name_start = root_prefix.len();
    let phys = if prefix.is_empty() {
        docroot.as_str().to_owned()
    } else {
        format!("{root_prefix}{prefix}")
    };
    if meta.is_file() {
        return Lookup::Found(PathInfo {
            phys,
            name_start,
            dir_name: None,
            info: if info.is_empty() {
                None
            } else {
                Some(info.to_owned())
            },
            query,
            meta,
            docroot: Some(docroot.clone()),
            rel: rel.to_owned(),
            no_symlinks,
        });
    }
    if !meta.is_dir() || !info.is_empty() {
        return Lookup::NotFound;
    }
    let name = &phys[name_start..];
    let dir_name = if name.ends_with('/') {
        name.to_owned()
    } else {
        format!("{name}/")
    };
    if !trailing_slash {
        let location = match &query {
            Some(q) => format!("{dir_name}?{q}"),
            None => dir_name,
        };
        return Lookup::Redirect(location);
    }
    for index in indexes {
        let idx_rel = if rel.is_empty() {
            index.clone()
        } else {
            format!("{rel}/{index}")
        };
        if let Ok(fd) = open_beneath(
            &docroot.dirfd,
            &idx_rel,
            OFlags::PATH | OFlags::CLOEXEC,
            no_symlinks,
        ) {
            if let Ok(m) = fs::File::from(fd).metadata() {
                if m.is_file() {
                    let idx_phys = if phys.ends_with('/') {
                        format!("{phys}{index}")
                    } else {
                        format!("{phys}/{index}")
                    };
                    return Lookup::Found(PathInfo {
                        phys: idx_phys,
                        name_start,
                        dir_name: None,
                        info: None,
                        query,
                        meta: m,
                        docroot: Some(docroot.clone()),
                        rel: idx_rel,
                        no_symlinks,
                    });
                }
            }
        }
    }
    Lookup::Found(PathInfo {
        phys,
        name_start,
        dir_name: Some(dir_name),
        info: None,
        query,
        meta,
        docroot: Some(docroot.clone()),
        rel: rel.to_owned(),
        no_symlinks,
    })
}

pub fn mime_type(path: &str) -> &'static str {
    const TABLE: &[(&str, &str)] = &[
        // Verbatim from uhttpd mimetypes.h (uh_mime_types), same order.
        // Match case-insensitively at a `.`/`/` boundary anchored to the end.
        // Order matters for compound suffixes such as tar.gz before gz.
        ("txt", "text/plain"),
        ("log", "text/plain"),
        ("js", "text/javascript"),
        ("css", "text/css"),
        ("htm", "text/html"),
        ("html", "text/html"),
        ("diff", "text/x-patch"),
        ("patch", "text/x-patch"),
        ("c", "text/x-csrc"),
        ("h", "text/x-chdr"),
        ("o", "text/x-object"),
        ("ko", "text/x-object"),
        ("bmp", "image/bmp"),
        ("gif", "image/gif"),
        ("png", "image/png"),
        ("jpg", "image/jpeg"),
        ("jpeg", "image/jpeg"),
        ("svg", "image/svg+xml"),
        ("json", "application/json"),
        ("jsonp", "application/javascript"),
        ("zip", "application/zip"),
        ("pdf", "application/pdf"),
        ("xml", "application/xml"),
        ("xsl", "application/xml"),
        ("doc", "application/msword"),
        ("ppt", "application/vnd.ms-powerpoint"),
        ("xls", "application/vnd.ms-excel"),
        ("odt", "application/vnd.oasis.opendocument.text"),
        ("odp", "application/vnd.oasis.opendocument.presentation"),
        ("pl", "application/x-perl"),
        ("sh", "application/x-shellscript"),
        ("php", "application/x-php"),
        ("deb", "application/x-deb"),
        ("iso", "application/x-cd-image"),
        ("tar.gz", "application/x-compressed-tar"),
        ("tgz", "application/x-compressed-tar"),
        ("gz", "application/x-gzip"),
        ("tar.bz2", "application/x-bzip-compressed-tar"),
        ("tbz", "application/x-bzip-compressed-tar"),
        ("bz2", "application/x-bzip"),
        ("tar", "application/x-tar"),
        ("rar", "application/x-rar-compressed"),
        ("mp3", "audio/mpeg"),
        ("ogg", "audio/x-vorbis+ogg"),
        ("wav", "audio/x-wav"),
        ("aac", "audio/aac"),
        ("mpg", "video/mpeg"),
        ("mpeg", "video/mpeg"),
        ("avi", "video/x-msvideo"),
        ("mov", "video/quicktime"),
        ("mp4", "video/mp4"),
        ("readme", "text/plain"),
        ("cfg", "text/plain"),
        ("conf", "text/plain"),
        ("pac", "application/x-ns-proxy-autoconfig"),
        ("wpad.dat", "application/x-ns-proxy-autoconfig"),
        ("appcache", "text/cache-manifest"),
        ("manifest", "text/cache-manifest"),
    ];
    let path = path.as_bytes();
    for (ext, mime) in TABLE {
        let ext = ext.as_bytes();
        if path.len() > ext.len()
            && matches!(path[path.len() - ext.len() - 1], b'.' | b'/')
            && path[path.len() - ext.len()..].eq_ignore_ascii_case(ext)
        {
            return mime;
        }
    }
    "application/octet-stream"
}

/// OpenWrt 25.12.6 uses a symlink's immediate target name for MIME lookup.
/// Read only one link: following a chain would change the upstream behavior.
fn file_mime_type(path: &str) -> &'static str {
    match fs::read_link(path) {
        Ok(target) => mime_type(&target.to_string_lossy()),
        Err(_) => mime_type(path),
    }
}

fn file_mime_type_at(docroot: &Docroot, rel: &str, phys: &str) -> &'static str {
    if !rel.is_empty() {
        if let Ok(target) = rustix::fs::readlinkat(&docroot.dirfd, rel, Vec::new()) {
            return mime_type(&target.to_string_lossy());
        }
    }
    mime_type(phys)
}

#[cfg(test)]
mod tests {
    use super::{canonpath, mime_type};

    #[test]
    fn canonical_paths_preserve_root_and_segment_boundaries() {
        for (path, expected) in [
            ("", "/"),
            ("/", "/"),
            ("////", "/"),
            ("relative/file", "/relative/file"),
            ("/a//b/./c/", "/a/b/c"),
            ("/a/b/../c", "/a/c"),
            ("/../../a/../..", "/"),
            ("/doc/../doc-other/file", "/doc-other/file"),
            ("/a/.../.hidden", "/a/.../.hidden"),
            ("/目录/页面/../文件", "/目录/文件"),
        ] {
            assert_eq!(canonpath(path), expected, "{path}");
        }
    }

    #[test]
    fn in_place_canonpath_matches_canonpath_for_rooted_paths() {
        for path in [
            "/",
            "////",
            "/a//b/./c/",
            "/a/b/../c",
            "/../../a/../..",
            "/doc/../doc-other/file",
            "/a/.../.hidden",
            "/目录/页面/../文件",
            "/www/static.dat",
            "/www/./a/../b/c/..",
            "/..",
            "/a/..",
        ] {
            let mut rewritten = path.to_owned();
            super::canonpath_in_place(&mut rewritten);
            assert_eq!(rewritten, super::canonpath(path), "{path}");
        }
        let mut relative = "relative/file".to_owned();
        super::canonpath_in_place(&mut relative);
        assert_eq!(relative, "/relative/file");
    }

    #[test]
    fn reused_open_file_never_serves_a_replaced_or_rewritten_file() {
        use std::io::{Read as _, Write as _};
        let dir = std::env::temp_dir().join(format!("httpd-reuse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let docroot = super::Docroot::open(dir.to_str().unwrap()).unwrap();
        std::fs::write(dir.join("f.txt"), b"first").unwrap();
        let body = |expect: &[u8]| {
            let super::Lookup::Found(pi) = super::lookup(&docroot, "/f.txt", false, &[]) else {
                panic!("lookup")
            };
            assert_eq!(pi.name(), "/f.txt");
            let opened = super::OpenFile::acquire(&pi, true).expect("open");
            let mut got = Vec::new();
            super::ReadAt {
                file: &opened.file,
                pos: 0,
            }
            .read_to_end(&mut got)
            .unwrap();
            opened.release(true);
            assert_eq!(got, expect);
        };
        body(b"first");
        body(b"first");
        // Same inode rewritten: ctime moves, the descriptor is replaced.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(dir.join("f.txt"))
            .unwrap();
        file.write_all(b"second, longer").unwrap();
        drop(file);
        body(b"second, longer");
        // Replaced by rename: different inode.
        std::fs::write(dir.join("g.txt"), b"third").unwrap();
        std::fs::rename(dir.join("g.txt"), dir.join("f.txt")).unwrap();
        body(b"third");
        // Not reusing leaves nothing behind for the thread.
        let super::Lookup::Found(pi) = super::lookup(&docroot, "/f.txt", false, &[]) else {
            panic!()
        };
        super::OpenFile::acquire(&pi, false).unwrap().release(false);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_readonly_reads_files_and_reports_missing_ones() {
        use std::io::Read;
        let dir = std::env::temp_dir().join(format!("httpd-open-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("f.txt");
        std::fs::write(&file, b"payload").unwrap();
        let mut text = String::new();
        super::open_readonly(&file)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "payload");
        assert_eq!(
            super::open_readonly(&dir.join("missing"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        // Past the stack buffer: the std fallback answers, with the same kind.
        let long = dir.join("a/".repeat(140)).join("f.txt");
        assert!(long.as_os_str().len() > 256);
        assert_eq!(
            super::open_readonly(&long).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn mime_preserves_case_boundaries_and_compound_suffix_priority() {
        for (path, expected) in [
            ("/static.dat", "application/octet-stream"),
            ("/site.CSS", "text/css"),
            ("/目录/页面.HtMl", "text/html"),
            ("/README", "text/plain"),
            ("/readme.txt", "text/plain"),
            ("/archive.TAR.Gz", "application/x-compressed-tar"),
            ("/archive.gz", "application/x-gzip"),
            ("/archive.TAR.BZ2", "application/x-bzip-compressed-tar"),
            ("/archive.bz2", "application/x-bzip"),
            ("/WPAD.DAT", "application/x-ns-proxy-autoconfig"),
            ("/tar.gz", "application/x-compressed-tar"),
            ("/css", "text/css"),
            ("css", "application/octet-stream"),
            ("/mycss", "application/octet-stream"),
            ("/x.css/unknown", "application/octet-stream"),
            ("/x.css.", "application/octet-stream"),
            ("/é", "application/octet-stream"),
            ("", "application/octet-stream"),
        ] {
            assert_eq!(mime_type(path), expected, "{path}");
        }
    }

    #[test]
    fn symlink_mime_uses_the_immediate_target_name() {
        use std::os::unix::fs::symlink;
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("httpd-mime-{}-{unique}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let fixture = Fixture(dir);
        let dir = &fixture.0;
        let docroot = super::Docroot::open(dir.to_str().unwrap()).unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("actual.css"), b"body {}").unwrap();
        symlink("actual.css", dir.join("alias.dat")).unwrap();
        symlink("../actual.css", dir.join("sub/rel.dat")).unwrap();
        symlink(dir.join("actual.css"), dir.join("absolute.dat")).unwrap();
        symlink("alias.dat", dir.join("chain.txt")).unwrap();
        for (url, expected) in [
            ("/actual.css", "text/css"),
            ("/alias.dat", "text/css"),
            ("/sub/rel.dat", "text/css"),
            ("/chain.txt", "application/octet-stream"),
        ] {
            let super::Lookup::Found(pi) = super::lookup(&docroot, url, false, &[]) else {
                panic!("file lookup failed for {url}");
            };
            assert_eq!(pi.mime_type(), expected, "{url}");
        }
        assert!(matches!(
            super::lookup(&docroot, "/absolute.dat", false, &[]),
            super::Lookup::NotFound
        ));
    }

    #[test]
    fn openat2_probe_fails_explicitly_on_enosys_and_eperm() {
        for errno in [rustix::io::Errno::NOSYS, rustix::io::Errno::PERM] {
            let err = super::check_openat2_probe(Err(errno)).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
            assert!(err.to_string().contains("openat2(RESOLVE_BENEATH)"));
        }
        assert!(super::Docroot::open("/nonexistent-docroot-path-for-test").is_err());
    }

    #[test]
    fn lookup_blocks_docroot_escapes_and_preserves_internal_symlinks() {
        use std::os::unix::fs::symlink;
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("httpd-escape-{}-{unique}", std::process::id()));
        let docroot_dir = base.join("www");
        let outside = base.join("outside");
        std::fs::create_dir_all(docroot_dir.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let _fixture = Fixture(base);

        std::fs::write(outside.join("secret.txt"), b"secret").unwrap();
        std::fs::write(docroot_dir.join("real.txt"), b"public").unwrap();
        symlink("real.txt", docroot_dir.join("internal.txt")).unwrap();
        symlink("../real.txt", docroot_dir.join("sub/up.txt")).unwrap();
        symlink("../outside/secret.txt", docroot_dir.join("escape_rel.txt")).unwrap();
        symlink("../outside", docroot_dir.join("escape_dir")).unwrap();
        symlink(
            outside.join("secret.txt"),
            docroot_dir.join("escape_abs.txt"),
        )
        .unwrap();

        let docroot = super::Docroot::open(docroot_dir.to_str().unwrap()).unwrap();
        for url in [
            "/escape_rel.txt",
            "/escape_dir/secret.txt",
            "/escape_abs.txt",
            "/../outside/secret.txt",
        ] {
            assert!(
                matches!(
                    super::lookup(&docroot, url, false, &[]),
                    super::Lookup::NotFound
                ),
                "escape path {url} must return NotFound"
            );
        }
        assert!(matches!(
            super::lookup(&docroot, "/internal.txt", false, &[]),
            super::Lookup::Found(_)
        ));
        assert!(matches!(
            super::lookup(&docroot, "/sub/up.txt", false, &[]),
            super::Lookup::Found(_)
        ));
        assert!(matches!(
            super::lookup(&docroot, "/internal.txt", true, &[]),
            super::Lookup::NotFound
        ));
    }

    #[test]
    fn open_file_acquire_rejects_toctou_swap_and_escape() {
        use std::os::unix::fs::symlink;
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("httpd-toctou-{}-{unique}", std::process::id()));
        let docroot_dir = base.join("www");
        let outside = base.join("outside");
        std::fs::create_dir_all(&docroot_dir).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let _fixture = Fixture(base);

        std::fs::write(outside.join("secret.txt"), b"secret").unwrap();
        std::fs::write(docroot_dir.join("target.txt"), b"original").unwrap();
        std::fs::write(docroot_dir.join("other.txt"), b"other").unwrap();
        let docroot = super::Docroot::open(docroot_dir.to_str().unwrap()).unwrap();

        // Replace with a different inode inside docroot after lookup.
        let super::Lookup::Found(pi) = super::lookup(&docroot, "/target.txt", false, &[]) else {
            panic!("lookup");
        };
        std::fs::rename(
            docroot_dir.join("other.txt"),
            docroot_dir.join("target.txt"),
        )
        .unwrap();
        assert!(
            super::OpenFile::acquire(&pi, false).is_none(),
            "swapped inode must be rejected"
        );

        // Replace with an escaping symlink after lookup.
        let super::Lookup::Found(pi) = super::lookup(&docroot, "/target.txt", false, &[]) else {
            panic!("lookup");
        };
        std::fs::remove_file(docroot_dir.join("target.txt")).unwrap();
        symlink("../outside/secret.txt", docroot_dir.join("target.txt")).unwrap();
        assert!(
            super::OpenFile::acquire(&pi, false).is_none(),
            "escaping symlink swap must be rejected"
        );
    }
}

/// Open a regular file for reading. musl's `open()` wrapper, which std's
/// `File::open` reaches through `open64`, follows every O_CLOEXEC open with a
/// second syscall, `fcntl(F_SETFD, FD_CLOEXEC)`, for kernels that predate the
/// flag; its `openat()` wrapper does not. That fcntl was one of the ten
/// syscalls every static response paid. Long paths fall back to std.
fn open_readonly(path: &Path) -> io::Result<fs::File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        let mut cpath = [0u8; 256];
        if bytes.len() < cpath.len() && !bytes.contains(&0) {
            cpath[..bytes.len()].copy_from_slice(bytes);
            let cpath = std::ffi::CStr::from_bytes_with_nul(&cpath[..bytes.len() + 1])
                .map_err(|_| io::ErrorKind::InvalidInput)?;
            let fd = rustix::fs::openat(
                rustix::fs::CWD,
                cpath,
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?;
            return Ok(fs::File::from(fd));
        }
    }
    fs::File::open(path)
}

/// The file a connection thread served last, kept open across requests.
/// `lookup` stats the path afresh every time; the descriptor is reused only
/// when that stat names exactly the object it was opened on -- same device,
/// inode and ctime -- so a replaced, rewritten, truncated, re-permissioned
/// or deleted-and-recreated file always reopens. Reuse saves the openat and
/// close a keep-alive client otherwise pays on every static response. The
/// entry dies with its thread, so idle and closed connections hold no file.
struct OpenFile {
    file: fs::File,
    dev: u64,
    ino: u64,
    ctime: (i64, i64),
}

thread_local! {
    static LAST_OPEN: RefCell<Option<OpenFile>> = const { RefCell::new(None) };
}

impl OpenFile {
    fn matches(&self, meta: &fs::Metadata) -> bool {
        self.dev == meta.dev()
            && self.ino == meta.ino()
            && self.ctime == (meta.ctime(), meta.ctime_nsec())
    }

    /// Reuse the thread's open file when it is the object `pi` names, else
    /// open it via the anchored docroot dirfd and verify `fstat` matches `pi.meta`.
    fn acquire(pi: &PathInfo, reuse: bool) -> Option<OpenFile> {
        if reuse {
            if let Some(last) = LAST_OPEN.with(|slot| slot.borrow_mut().take()) {
                if last.matches(&pi.meta) {
                    return Some(last);
                }
            }
        }
        let file = open_file_for_read(pi).ok()?;
        let meta = file.metadata().ok()?;
        Some(OpenFile {
            file,
            dev: meta.dev(),
            ino: meta.ino(),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        })
    }

    fn release(self, reuse: bool) {
        if reuse {
            LAST_OPEN.with(|slot| *slot.borrow_mut() = Some(self));
        }
    }
}

fn open_file_for_read(pi: &PathInfo) -> io::Result<fs::File> {
    let Some(docroot) = &pi.docroot else {
        return open_readonly(pi.path());
    };
    let fd = open_beneath(
        &docroot.dirfd,
        &pi.rel,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        pi.no_symlinks,
    )?;
    let file = fs::File::from(fd);
    let meta = file.metadata()?;
    if meta.dev() != pi.meta.dev()
        || meta.ino() != pi.meta.ino()
        || (meta.ctime(), meta.ctime_nsec()) != (pi.meta.ctime(), pi.meta.ctime_nsec())
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "file changed between lookup and open",
        ));
    }
    Ok(file)
}

/// Positional reads leave the shared descriptor's offset alone, so a reused
/// file starts at zero for every response.
struct ReadAt<'a> {
    file: &'a fs::File,
    pos: u64,
}

impl Read for ReadAt<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read_at(buf, self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

fn etag(meta: &fs::Metadata) -> String {
    format!("\"{:x}-{:x}-{:x}\"", meta.ino(), meta.size(), meta.mtime())
}

fn ok_headers<W: Write>(resp: &mut Response<W>, meta: Option<&fs::Metadata>) -> io::Result<()> {
    if let Some(meta) = meta {
        resp.header(
            "ETag",
            format_args!("\"{:x}-{:x}-{:x}\"", meta.ino(), meta.size(), meta.mtime()),
        )?;
        resp.header("Last-Modified", http::HttpDate(meta.mtime()))?;
    }
    resp.header("Date", http::HttpDate(http::now_unix()))
}

fn tag_matches(header: &str, tag: &str) -> bool {
    header
        .split([' ', ','])
        .filter(|t| !t.is_empty())
        .any(|t| t == "*" || t == tag)
}

/// Returns false when a precondition response was already sent.
fn preconditions<W: Write>(
    request: &Request,
    resp: &mut Response<W>,
    meta: &fs::Metadata,
) -> io::Result<bool> {
    // uhttpd parses If-Modified-Since / If-Unmodified-Since with strptime
    // "%a, %d %b %Y %H:%M:%S %Z"; musl rejects %Z, so on the target both
    // headers never match. Mirror that: only the ETag preconditions apply.
    let _ = http::parse_http_date;
    if let Some(h) = request.header("if-match") {
        if !tag_matches(h, &etag(meta)) {
            resp.status(412, "Precondition Failed")?;
            resp.end_headers()?;
            resp.finish()?;
            return Ok(false);
        }
    }
    // uh_file_if_range: any If-Range header is answered with 412, the value
    // is never compared (uhttpd does not implement ranges).
    if request.header("if-range").is_some() {
        resp.status(412, "Precondition Failed")?;
        resp.end_headers()?;
        resp.finish()?;
        return Ok(false);
    }
    if let Some(h) = request.header("if-none-match") {
        if tag_matches(h, &etag(meta)) {
            if matches!(request.method, Method::Get | Method::Head) {
                resp.status(304, "Not Modified")?;
                ok_headers(resp, Some(meta))?;
            } else {
                resp.status(412, "Precondition Failed")?;
            }
            resp.end_headers()?;
            resp.finish()?;
            return Ok(false);
        }
    }
    Ok(true)
}

pub enum Served {
    Complete,
    Forbidden,
}

/// A forbidden file has not written a response yet: the caller may dispatch
/// the configured error handler with REDIRECT_STATUS=403.
pub fn serve<W: http::Sink>(
    request: &Request,
    resp: &mut Response<W>,
    pi: &PathInfo,
    no_dirlists: bool,
    charset: &str,
    reuse_open: bool,
) -> io::Result<Served> {
    if !matches!(
        request.method,
        Method::Get | Method::Post | Method::Head | Method::Options
    ) {
        resp.status(405, "Method Not Allowed")?;
        resp.end_headers()?;
        resp.finish()?;
        return Ok(Served::Complete);
    }
    if pi.meta.permissions().mode() & 0o004 == 0 {
        return Ok(Served::Forbidden);
    }
    if pi.meta.is_file() {
        let Some(opened) = OpenFile::acquire(pi, reuse_open) else {
            return Ok(Served::Forbidden);
        };
        resp.disable_chunked();
        if !preconditions(request, resp, &pi.meta)? {
            opened.release(reuse_open);
            return Ok(Served::Complete);
        }
        resp.status(200, "OK")?;
        ok_headers(resp, Some(&pi.meta))?;
        resp.header("Content-Type", pi.mime_type())?;
        resp.header("Content-Length", pi.meta.size())?;
        resp.end_headers()?;
        let mut body = ReadAt {
            file: &opened.file,
            pos: 0,
        };
        let copied = resp.copy_unchunked(&mut body, pi.meta.size());
        opened.release(reuse_open);
        copied?;
        resp.finish()?;
        return Ok(Served::Complete);
    }
    if pi.meta.is_dir() {
        if no_dirlists {
            return Ok(Served::Forbidden);
        }
        dirlist(resp, pi, charset)?;
        return Ok(Served::Complete);
    }
    Ok(Served::Forbidden)
}

/// uh_client_error gives up on keep-alive when the request declared a body the
/// handler never read, because the unread suffix would be parsed as the next
/// request (client.c:157-164). Note the order: uh_http_header has already
/// written the `Connection` header by then, so the response still advertises
/// Keep-Alive and only the connection is dropped afterwards.
fn client_error<W: Write>(
    resp: &mut Response<W>,
    request: &Request,
    code: u16,
    summary: &str,
    detail: &str,
) -> io::Result<()> {
    resp.error(code, summary, Some(detail))?;
    if request.transfer_chunked || request.content_length.is_some_and(|n| n > 0) {
        resp.force_close();
    }
    Ok(())
}

/// file.c:715-719 / cgi.c:79-83. `url` is the request target as sent, not the
/// resolved path: uhttpd escapes what the client asked for, query included.
pub fn forbidden<W: Write>(resp: &mut Response<W>, request: &Request, url: &str) -> io::Result<()> {
    client_error(
        resp,
        request,
        403,
        "Forbidden",
        &format!(
            "You don't have permission to access {} on this server.",
            http::html_escape(url)
        ),
    )
}

/// file.c:1002-1005, same rule for the request target.
pub fn not_found<W: Write>(resp: &mut Response<W>, request: &Request, url: &str) -> io::Result<()> {
    client_error(
        resp,
        request,
        404,
        "Not Found",
        &format!(
            "The requested URL {} was not found on this server.",
            http::html_escape(url)
        ),
    )
}

fn dirlist<W: Write>(resp: &mut Response<W>, pi: &PathInfo, charset: &str) -> io::Result<()> {
    let escaped = http::html_escape(pi.name());
    resp.status(200, "OK")?;
    ok_headers(resp, None)?;
    resp.header("Content-Type", format!("text/html; charset={charset}"))?;
    resp.end_headers()?;
    resp.body(format!("<html><head><title>Index of {escaped}</title></head><body><h1>Index of {escaped}</h1><hr /><ol>").as_bytes())?;
    // (name, is_dir from d_type without following symlinks, stat following)
    let mut entries: Vec<(String, bool, fs::Metadata)> = Vec::new();
    if let Some(docroot) = &pi.docroot {
        if let Ok(dir_fd) = open_beneath(
            &docroot.dirfd,
            &pi.rel,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            pi.no_symlinks,
        ) {
            let mut buf = [MaybeUninit::<u8>::uninit(); 4096];
            let mut names: Vec<(String, bool)> = Vec::new();
            let mut iter = RawDir::new(&dir_fd, &mut buf);
            while let Some(Ok(entry)) = iter.next() {
                let fname = entry.file_name();
                if fname == c"." || fname == c".." {
                    continue;
                }
                let name = fname.to_string_lossy().into_owned();
                let is_dir = entry.file_type() == rustix::fs::FileType::Directory;
                names.push((name, is_dir));
            }
            for (name, is_dir) in names {
                let entry_rel = if pi.rel.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{name}", pi.rel)
                };
                if let Ok(entry_fd) = open_beneath(
                    &docroot.dirfd,
                    &entry_rel,
                    OFlags::PATH | OFlags::CLOEXEC,
                    pi.no_symlinks,
                ) {
                    if let Ok(meta) = fs::File::from(entry_fd).metadata() {
                        entries.push((name, is_dir, meta));
                    }
                }
            }
            if let Ok(parent_fd) = rustix::fs::openat(
                &dir_fd,
                c"..",
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                if let Ok(parent) = fs::File::from(parent_fd).metadata() {
                    entries.push(("..".to_owned(), true, parent));
                }
            }
        }
    } else if let Ok(read) = fs::read_dir(pi.path()) {
        for entry in read.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if let Ok(meta) = fs::metadata(entry.path()) {
                entries.push((name, is_dir, meta));
            }
        }
        if let Ok(parent) = fs::metadata(pi.path().join("..")) {
            entries.push(("..".to_owned(), true, parent));
        }
    }
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (name, is_dir, meta) in entries {
        let required = if is_dir { 0o001 } else { 0o004 };
        if meta.permissions().mode() & required == 0 {
            continue;
        }
        let escaped_name = http::html_escape(&name);
        let modified = http::http_date(meta.mtime());
        if is_dir {
            resp.body(format!(
                "<li><strong><a href='{escaped}{escaped_name}/'>{escaped_name}</a>/</strong><br /><small>modified: {modified}<br />directory - {:.2} kbyte<br /><br /></small></li>",
                meta.size() as f64 / 1024.0
            ).as_bytes())?;
        } else {
            let mime = match &pi.docroot {
                Some(docroot) => {
                    let entry_rel = if pi.rel.is_empty() {
                        name.clone()
                    } else {
                        format!("{}/{name}", pi.rel)
                    };
                    file_mime_type_at(docroot, &entry_rel, &name)
                }
                None => file_mime_type(&format!("{}/{name}", pi.phys)),
            };
            resp.body(format!(
                "<li><strong><a href='{escaped}{escaped_name}'>{escaped_name}</a></strong><br /><small>modified: {modified}<br />{mime} - {:.2} kbyte<br /><br /></small></li>",
                meta.size() as f64 / 1024.0
            ).as_bytes())?;
        }
    }
    resp.body(b"</ol><hr /></body></html>")?;
    resp.finish()
}
