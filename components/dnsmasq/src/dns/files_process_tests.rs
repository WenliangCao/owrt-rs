//! Hostname file reload contracts run in a standalone single-threaded process.
use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "dns-files-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self) -> DnsConfig {
        let mut config = DnsConfig::default();
        config.resolv_files = vec![self.0.join("resolv")];
        config
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) fn run() {
    server_file_keeps_distinct_lines_partial_errors_and_reverse_origin();
    eprintln!(
        "process test: files::server_file_keeps_distinct_lines_partial_errors_and_reverse_origin"
    );
}
fn server_file_keeps_distinct_lines_partial_errors_and_reverse_origin() {
    let directory = Directory::new();
    let path = directory.0.join("servers");
    fs::write(&path, b"server=/first/127.0.0.2\nserver=/named/127.1\nserver=/bad/::1%missing_endpoint_if\nrev-server=192.0.2.0/24,127.1\nserver=/last/127.0.0.3\n").unwrap();
    let mut config = directory.config();
    config.no_resolv = true;
    config.servers_file = Some(path);
    let mut files = DnsFiles::new(&config, true, false).unwrap();
    files.request(ReloadReason::Init);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let update = loop {
        // SAFETY: the standalone runner has one thread, private memory, no held locks or atfork hooks.
        let result = unsafe { files.step() };
        if let Some(update) = result.update {
            break update;
        }
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(1));
    };
    assert_eq!(
        update.rows.iter().map(|row| row.line).collect::<Vec<_>>(),
        [1, 2, 4, 5]
    );
    assert!(update.rows[2].reverse);
    assert!(!update.rows[1].reverse);
    assert!(
        matches!(&update.rows[3].rule.target, RuleTarget::Upstream(endpoint) if endpoint.host == ServerHost::Address("127.0.0.3".parse().unwrap()))
    );
}
