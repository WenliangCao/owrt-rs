//! Static file serving with uhttpd's path lookup, index files, directory
//! listing, conditional requests and MIME table.

use crate::http::{self, Method, Request, Response};
use std::borrow::Cow;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub struct PathInfo {
    pub phys: PathBuf,
    /// Path relative to docroot, starting with '/'.
    pub name: String,
    pub info: Option<String>,
    pub query: Option<String>,
    pub meta: fs::Metadata,
}

pub enum Lookup {
    Found(Box<PathInfo>),
    /// Directory requested without trailing slash: redirect.
    Redirect(String),
    NotFound,
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
pub fn lookup(docroot: &str, url: &str, no_symlinks: bool, indexes: &[String]) -> Lookup {
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
    let mut full = String::with_capacity(docroot.len() + decoded.len());
    full.push_str(docroot);
    full.push_str(&decoded);
    // try progressively shorter prefixes ending at '/' boundaries
    let mut found: Option<(String, String, fs::Metadata)> = None;
    let bytes = full.as_bytes();
    let mut i = bytes.len();
    loop {
        if i == bytes.len() || bytes[i] == b'/' {
            let candidate = if no_symlinks {
                fs::canonicalize(&full[..i]).ok().map(|p| p.to_string_lossy().into_owned())
            } else {
                Some(canonpath(&full[..i]))
            };
            if let Some(candidate) = candidate {
                if let Ok(meta) = fs::metadata(&candidate) {
                    found = Some((candidate, full[i..].to_owned(), meta));
                    break;
                }
            }
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    let Some((phys, info, meta)) = found else {
        return Lookup::NotFound;
    };
    if !(phys == docroot || phys.strip_prefix(docroot).is_some_and(|tail| tail.starts_with('/'))) {
        return Lookup::NotFound;
    }
    let name = phys[docroot.len()..].to_owned();
    if meta.is_file() {
        return Lookup::Found(Box::new(PathInfo {
            phys: PathBuf::from(phys),
            name: if name.is_empty() { "/".into() } else { name },
            info: if info.is_empty() { None } else { Some(info) },
            query,
            meta,
        }));
    }
    if !meta.is_dir() || !info.is_empty() {
        return Lookup::NotFound;
    }
    let dir_name = if name.ends_with('/') {
        name
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
        let candidate = format!("{phys}/{index}");
        if let Ok(m) = fs::metadata(&candidate) {
            if m.is_file() {
                return Lookup::Found(Box::new(PathInfo {
                    phys: PathBuf::from(candidate),
                    name: format!("{dir_name}{index}"),
                    info: None,
                    query,
                    meta: m,
                }));
            }
        }
    }
    Lookup::Found(Box::new(PathInfo {
        phys: PathBuf::from(phys),
        name: dir_name,
        info: None,
        query,
        meta,
    }))
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
}

fn etag(meta: &fs::Metadata) -> String {
    format!("\"{:x}-{:x}-{:x}\"", meta.ino(), meta.size(), meta.mtime())
}

fn ok_headers<W: Write>(resp: &mut Response<W>, meta: Option<&fs::Metadata>) -> io::Result<()> {
    if let Some(meta) = meta {
        resp.header("ETag", format_args!("\"{:x}-{:x}-{:x}\"", meta.ino(), meta.size(), meta.mtime()))?;
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
        let Ok(mut file) = fs::File::open(&pi.phys) else {
            return Ok(Served::Forbidden);
        };
        resp.disable_chunked();
        if !preconditions(request, resp, &pi.meta)? {
            return Ok(Served::Complete);
        }
        resp.status(200, "OK")?;
        ok_headers(resp, Some(&pi.meta))?;
        resp.header("Content-Type", mime_type(&pi.name))?;
        resp.header("Content-Length", pi.meta.size())?;
        resp.end_headers()?;
        resp.copy_unchunked(&mut file, pi.meta.size())?;
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
    let escaped = http::html_escape(&pi.name);
    resp.status(200, "OK")?;
    ok_headers(resp, None)?;
    resp.header("Content-Type", &format!("text/html; charset={charset}"))?;
    resp.end_headers()?;
    resp.body(format!("<html><head><title>Index of {escaped}</title></head><body><h1>Index of {escaped}</h1><hr /><ol>").as_bytes())?;
    // (name, is_dir from d_type without following symlinks, stat following)
    let mut entries: Vec<(String, bool, fs::Metadata)> = Vec::new();
    if let Ok(read) = fs::read_dir(&pi.phys) {
        for entry in read.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if let Ok(meta) = fs::metadata(entry.path()) {
                entries.push((name, is_dir, meta));
            }
        }
    }
    if let Ok(parent) = fs::metadata(Path::new(&pi.phys).join("..")) {
        entries.push(("..".to_owned(), true, parent));
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
            resp.body(format!(
                "<li><strong><a href='{escaped}{escaped_name}'>{escaped_name}</a></strong><br /><small>modified: {modified}<br />{} - {:.2} kbyte<br /><br /></small></li>",
                mime_type(&name),
                meta.size() as f64 / 1024.0
            ).as_bytes())?;
        }
    }
    resp.body(b"</ol><hr /></body></html>")?;
    resp.finish()
}
