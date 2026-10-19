//! Line-oriented syslog sink for the JSONL trace.
//!
//! The original `/sbin/reload_config` is silent on stderr, so the default trace
//! destination is the local syslog socket. Each complete JSONL line becomes one
//! RFC 3164 datagram tagged `reload_config`. When the socket is unavailable,
//! ordinary lines are dropped and only fatal lines fall back to stderr.

use std::io::{self, Write};
use std::os::unix::net::UnixDatagram;

const SYSLOG_PATH: &str = "/dev/log";
const TAG: &str = "reload_config";
/// facility daemon (3 << 3) | severity info (6)
const PRI_DAEMON_INFO: u8 = 30;
/// facility daemon (3 << 3) | severity err (3)
const PRI_DAEMON_ERR: u8 = 27;

pub struct SyslogWriter {
    socket: Option<UnixDatagram>,
    pending: Vec<u8>,
}

impl SyslogWriter {
    pub fn open() -> Self {
        let socket = UnixDatagram::unbound()
            .ok()
            // Trace delivery must not hold the run lock while logd is stalled.
            // A full queue drops this diagnostic just like an unavailable logd.
            .filter(|socket| socket.set_nonblocking(true).is_ok())
            .filter(|socket| socket.connect(SYSLOG_PATH).is_ok());
        Self {
            socket,
            pending: Vec::new(),
        }
    }

    fn emit(&mut self, line: &[u8]) {
        let priority = priority_for(line);
        let mut message = format!("<{priority}>{TAG}[{}]: ", std::process::id()).into_bytes();
        message.extend_from_slice(line);
        let delivered = self
            .socket
            .as_ref()
            .map(|socket| socket.send(&message).is_ok())
            .unwrap_or(false);
        if !delivered && priority == PRI_DAEMON_ERR {
            let mut stderr = io::stderr();
            let _ = stderr.write_all(line);
            let _ = stderr.write_all(b"\n");
        }
    }
}

fn priority_for(line: &[u8]) -> u8 {
    const FATAL_MARKER: &[u8] = b"\"kind\":\"fatal\"";
    if line
        .windows(FATAL_MARKER.len())
        .any(|window| window == FATAL_MARKER)
    {
        PRI_DAEMON_ERR
    } else {
        PRI_DAEMON_INFO
    }
}

impl Write for SyslogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buf);
        while let Some(position) = self.pending.iter().position(|&byte| byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=position).collect();
            self.emit(&line[..line.len() - 1]);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            let line = std::mem::take(&mut self.pending);
            self.emit(&line);
        }
        Ok(())
    }
}

impl Drop for SyslogWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fatal_lines_use_error_priority() {
        assert_eq!(
            priority_for(br#"{"schema":1,"kind":"fatal","class":"dependency","message":"x"}"#),
            PRI_DAEMON_ERR
        );
        assert_eq!(
            priority_for(br#"{"schema":1,"kind":"complete","baseline_rewritten":true}"#),
            PRI_DAEMON_INFO
        );
    }

    #[test]
    fn partial_writes_are_assembled_into_lines() {
        let mut writer = SyslogWriter {
            socket: None,
            pending: Vec::new(),
        };
        writer.write_all(b"{\"a\":1").unwrap();
        assert_eq!(writer.pending, b"{\"a\":1");
        writer.write_all(b"}\n{\"b\":2}\n{\"c\"").unwrap();
        assert_eq!(writer.pending, b"{\"c\"");
        writer.flush().unwrap();
        assert!(writer.pending.is_empty());
    }
}
