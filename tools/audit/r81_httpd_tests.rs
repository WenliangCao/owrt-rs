//! R81 cold-audit demonstration tests for components/httpd (NOT RUN: no cargo on
//! the audit host). The crate is a binary with private modules, so these cannot
//! link from outside. To run, append the `http_ua` module to the end of
//! components/httpd/src/http.rs and the `cgi_status` module to the end of
//! components/httpd/src/cgi.rs (both inside `#[cfg(test)]`), then `cargo test`.
//! Each test encodes uhttpd's behaviour; on the current code they are expected
//! to FAIL, which is the demonstration.

#[cfg(test)]
mod http_ua {
    use super::*;

    /// client.c:419-447 classifies the UA in order Opera, MSIE, Chrome/,
    /// Safari/+Mac OS X, Gecko/, Konqueror. Chrome-on-macOS contains both
    /// "Chrome/" and "Safari/ ... Mac OS X" and is UH_UA_CHROME: keep-alive
    /// stays on. http.rs:249 only tests the Safari/Mac substrings.
    #[test]
    fn chrome_on_mac_keeps_the_connection_alive() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let raw = format!("GET /cgi-bin/luci HTTP/1.1\r\nHost: x\r\nUser-Agent: {ua}\r\n\r\n");
        let mut input = io::Cursor::new(raw.into_bytes());
        let ParseOutcome::Request(r) = read_request(&mut input, true).unwrap() else { panic!() };
        assert!(!r.connection_close, "uhttpd keeps Chrome-on-Mac connections alive");
        // the genuine Safari case must still close
        let raw = "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15\r\n\r\n";
        let mut input = io::Cursor::new(raw.as_bytes().to_vec());
        let ParseOutcome::Request(r) = read_request(&mut input, true).unwrap() else { panic!() };
        assert!(r.connection_close);
    }
}

#[cfg(test)]
mod cgi_status {
    use super::tests::run_script;

    /// proc.c:192-201 proc_handle_close: when the relay closes and the header
    /// block was never completed, uhttpd answers 502 Bad Gateway
    /// "The process did not produce any response". cgi.rs:339-356 answers 200.
    #[test]
    fn script_that_exits_without_headers_is_502() {
        let (out, _) = run_script("exit 1\n", 5);
        assert!(out.starts_with("HTTP/1.0 502 Bad Gateway"), "{out:?}");
        let (out, _) = run_script("printf 'Content-Type: text/plain\\r\\n'\nexit 0\n", 5);
        assert!(out.starts_with("HTTP/1.0 502 Bad Gateway"), "partial header block: {out:?}");
    }

    /// proc.c:322-328 proc_timeout_cb -> uh_relay_kill -> relay_close_if_done ->
    /// proc_handle_close: a script killed at the deadline before finishing its
    /// headers also gets 502 (uhttpd has no 504 anywhere). cgi.rs:341 sends 504.
    #[test]
    fn script_timeout_before_headers_is_502() {
        let (out, _) = run_script("sleep 5\n", 1);
        assert!(out.starts_with("HTTP/1.0 502 Bad Gateway"), "{out:?}");
    }

    /// relay.c:101-104 + proc.c:195: a header line without ':' aborts the relay
    /// and the close callback answers 502, not 500 (cgi.rs:442).
    #[test]
    fn malformed_cgi_header_is_502() {
        let (out, _) = run_script("printf 'invalid\\r\\n'\n", 5);
        assert!(out.starts_with("HTTP/1.0 502 Bad Gateway"), "{out:?}");
    }
}
