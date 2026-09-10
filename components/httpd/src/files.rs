//! Static file serving with uhttpd's path lookup, index files, directory
//! listing, conditional requests and MIME table.

use crate::http::{self, Method, Request, Response};
use std::fs;
use std::io::{self, Read, Write};
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
    let mut out: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let joined = format!("/{}", out.join("/"));
    joined
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
    let Some(decoded) = http::url_decode(path_part) else {
        return Lookup::NotFound;
    };
    let decoded = String::from_utf8_lossy(&decoded).into_owned();
    let trailing_slash = decoded.ends_with('/');
    let full = format!("{docroot}{decoded}");
    // try progressively shorter prefixes ending at '/' boundaries
    let mut found: Option<(String, String)> = None;
    let bytes = full.as_bytes();
    let mut i = bytes.len();
    loop {
        if i == bytes.len() || bytes[i] == b'/' {
            let candidate = if no_symlinks {
                fs::canonicalize(&full[..i]).ok().map(|p| p.to_string_lossy().into_owned())
            } else {
                Some(canonpath(&full[..i]))
            };
            if let Some(candidate) = candidate.filter(|p| fs::metadata(p).is_ok()) {
                found = Some((candidate, full[i..].to_owned()));
                break;
            }
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    let Some((phys, info)) = found else {
        return Lookup::NotFound;
    };
    if !(phys == docroot || phys.starts_with(&format!("{docroot}/"))) {
        return Lookup::NotFound;
    }
    let Ok(meta) = fs::metadata(&phys) else {
        return Lookup::NotFound;
    };
    let name = phys[docroot.len()..].to_owned();
    if meta.is_file() {
        return Lookup::Found(Box::new(PathInfo {
            phys: PathBuf::from(&phys),
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
        phys: PathBuf::from(&phys),
        name: dir_name,
        info: None,
        query,
        meta,
    }))
}

pub fn mime_type(path: &str) -> &'static str {
    const TABLE: &[(&str, &str)] = &[
        // Verbatim from uhttpd mimetypes.h (uh_mime_types), same order.
        // C matches case-insensitively at any `.`/`/` boundary anchored to
        // the end, which equals ends_with(".ext")/ends_with("/ext"); the
        // path is lowercased before lookup, so entries are lowercase.
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
    let lower = path.to_ascii_lowercase();
    for (ext, mime) in TABLE {
        if lower.ends_with(&format!(".{ext}")) || lower.ends_with(&format!("/{ext}")) {
            return mime;
        }
    }
    "application/octet-stream"
}

fn etag(meta: &fs::Metadata) -> String {
    format!("\"{:x}-{:x}-{:x}\"", meta.ino(), meta.size(), meta.mtime())
}

fn ok_headers<W: Write>(resp: &mut Response<W>, meta: Option<&fs::Metadata>) -> io::Result<()> {
    if let Some(meta) = meta {
        resp.header("ETag", &etag(meta))?;
        resp.header("Last-Modified", &http::http_date(meta.mtime()))?;
    }
    resp.header("Date", &http::http_date(http::now_unix()))
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
    let tag = etag(meta);
    if let Some(h) = request.header("if-match") {
        if !tag_matches(h, &tag) {
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
        if tag_matches(h, &tag) {
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

pub fn serve<W: Write>(
    request: &Request,
    resp: &mut Response<W>,
    pi: &PathInfo,
    no_dirlists: bool,
    charset: &str,
) -> io::Result<()> {
    if !matches!(
        request.method,
        Method::Get | Method::Post | Method::Head | Method::Options
    ) {
        resp.status(405, "Method Not Allowed")?;
        resp.end_headers()?;
        return resp.finish();
    }
    if pi.meta.permissions().mode() & 0o004 == 0 {
        return forbidden(resp, request, &request.url);
    }
    if pi.meta.is_file() {
        let Ok(mut file) = fs::File::open(&pi.phys) else {
            return forbidden(resp, request, &request.url);
        };
        resp.disable_chunked();
        if !preconditions(request, resp, &pi.meta)? {
            return Ok(());
        }
        resp.status(200, "OK")?;
        ok_headers(resp, Some(&pi.meta))?;
        resp.header("Content-Type", mime_type(&pi.name))?;
        resp.header("Content-Length", &pi.meta.size().to_string())?;
        resp.end_headers()?;
        if !resp.is_head() {
            let mut buf = [0u8; 16384];
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                resp.body(&buf[..n])?;
            }
        }
        return resp.finish();
    }
    if pi.meta.is_dir() {
        if no_dirlists {
            return forbidden(resp, request, &request.url);
        }
        return dirlist(resp, pi, charset);
    }
    forbidden(resp, request, &request.url)
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
