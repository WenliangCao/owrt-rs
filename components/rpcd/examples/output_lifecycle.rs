//! Fault fixture: the direct child closes both capture pipes and stays alive.
//! No shell redirection backups or descendants may keep a pipe open.
use std::io::Write;

unsafe extern "C" {
    fn close(fd: i32) -> i32;
}

fn main() {
    std::fs::write("/tmp/out/child", std::process::id().to_string()).unwrap();
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "closed" {
        while !std::path::Path::new("/tmp/close-output").exists() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    if mode == "overflow" {
        // Rust ignores SIGPIPE; continue after the receiver closes its end.
        let _ = std::io::stdout().write_all(&vec![b'x'; 300 * 1024]);
    } else if mode != "empty" {
        std::io::stdout().write_all(b"x").unwrap();
        std::io::stdout().flush().unwrap();
        std::io::stderr().write_all(b"y").unwrap();
    }
    // SAFETY: this test child deliberately closes its own stdout/stderr.
    unsafe {
        close(1);
        close(2);
    }
    std::fs::write("/tmp/out/closed", b"closed").unwrap();
    std::thread::sleep(std::time::Duration::from_secs(30));
}
