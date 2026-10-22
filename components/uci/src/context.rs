//! struct uci_context (uci.h) and the context-level API from libuci.c.

use crate::error::{Error, Result};
use crate::model::Package;
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const CONFDIR: &str = "/etc/config";
pub const SAVEDIR: &str = "/tmp/.uci";
pub const CONF2DIR: &str = "/var/run/uci";
pub const DIRMODE: u32 = 0o700;
pub const FILEMODE: u32 = 0o600;

/// enum uci_flags
pub const FLAG_STRICT: u32 = 1 << 0;
pub const FLAG_PERROR: u32 = 1 << 1;
pub const FLAG_EXPORT_NAME: u32 = 1 << 2;
pub const FLAG_SAVED_DELTA: u32 = 1 << 3;

/// The parse-context fields uci_perror reads (`pctx->reason/line/byte`).
/// Present only while a parser context is alive in the C sense: after a
/// failed import (the longjmp skips uci_cleanup) and until the next cleanup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseInfo {
    pub reason: Option<&'static str>,
    pub line: i32,
    pub byte: usize,
}

struct IoBudget<'a> {
    deadline: Instant,
    cancelled: &'a AtomicBool,
}

pub struct Context<'a> {
    /// ctx->root: loaded packages, in load order.
    pub root: Vec<Package>,
    pub flags: u32,
    pub confdir: String,
    /// NULL when disabled via `-C ''`.
    pub conf2dir: Option<String>,
    pub savedir: String,
    /// ctx->delta_path, savedir kept as the last entry.
    pub delta_path: Vec<String>,
    /// ctx->err of the last failed public call (0 => None).
    pub err: Option<Error>,
    /// ctx->pctx, error-reporting view only.
    pub pctx: Option<ParseInfo>,
    // Opt-in for callers that cannot wait indefinitely. Ordinary libuci/CLI
    // users retain their existing blocking behavior and error codes.
    io_budget: Option<IoBudget<'a>>,
}

impl std::fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("packages", &self.root.len())
            .field("flags", &self.flags)
            .field("err", &self.err)
            .field("pctx", &self.pctx)
            .field("budgeted", &self.io_budget.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for Context<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Context<'a> {
    /// uci_alloc_context
    pub fn new() -> Self {
        Context {
            root: Vec::new(),
            flags: FLAG_STRICT | FLAG_SAVED_DELTA,
            confdir: CONFDIR.to_owned(),
            conf2dir: Some(CONF2DIR.to_owned()),
            savedir: SAVEDIR.to_owned(),
            delta_path: vec![SAVEDIR.to_owned()],
            err: None,
            pctx: None,
            io_budget: None,
        }
    }

    /// Start one cooperative load budget, shared by base and delta file locks,
    /// reads and parsing. It does not preempt a kernel filesystem operation.
    pub fn set_io_budget(&mut self, timeout: Duration, cancelled: &'a AtomicBool) {
        self.io_budget = Some(IoBudget {
            deadline: Instant::now() + timeout,
            cancelled,
        });
    }

    pub fn check_io_budget(&self) -> Result<()> {
        if let Some(budget) = &self.io_budget {
            if budget.cancelled.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            if Instant::now() >= budget.deadline {
                return Err(Error::TimedOut);
            }
        }
        Ok(())
    }

    pub(crate) fn lock_file(&self, file: &File, operation: i32) -> Result<()> {
        let Some(budget) = &self.io_budget else {
            return crate::sys::lock(file, operation).map_err(|_| Error::Io);
        };
        loop {
            self.check_io_budget()?;
            match crate::sys::lock(file, operation | crate::sys::LOCK_NB) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err(Error::Io),
            }
            // Only a contended lock sleeps; uncontended loads do not poll.
            std::thread::sleep(
                Duration::from_millis(10)
                    .min(budget.deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    /// uci_set_confdir
    pub fn set_confdir(&mut self, dir: &str) {
        self.confdir = dir.to_owned();
    }

    /// uci_set_conf2dir: empty disables the override directory.
    pub fn set_conf2dir(&mut self, dir: &str) {
        self.conf2dir = if dir.is_empty() {
            None
        } else {
            Some(dir.to_owned())
        };
    }

    /// uci_lookup_list(&ctx->root, name)
    pub fn find_package(&self, name: &str) -> Option<usize> {
        self.root.iter().position(|p| p.name == name)
    }

    /// uci_unload
    pub fn unload(&mut self, idx: usize) {
        if idx < self.root.len() {
            self.root.remove(idx);
        }
    }

    /// uci_cleanup: drop the parser context (error info included).
    pub fn cleanup(&mut self) {
        self.pctx = None;
    }

    /// Record a failure the way UCI_HANDLE_ERR does (`ctx->err = __val`).
    pub fn fail<T>(&mut self, e: Error) -> Result<T> {
        self.err = Some(e);
        Err(e)
    }

    /// uci_get_errorstr with dest == NULL, sans the static `error_info`
    /// buffer, which lives in the CLI (see bin/uci-rs.rs) because that is the
    /// only place where its cross-call persistence is observable.
    pub fn error_string(&self, prefix: Option<&str>, error_info: &str) -> String {
        let err = self.err.unwrap_or(Error::Inval);
        format!(
            "{}{}{}{}",
            prefix.unwrap_or(""),
            if prefix.is_some() { ": " } else { "" },
            err.strerror(),
            error_info
        )
    }

    /// The ` (reason) at line N, byte M` suffix uci_get_errorstr produces for
    /// a parse error while a parser context exists; None otherwise.
    pub fn parse_error_info(&self) -> Option<String> {
        match (&self.pctx, self.err) {
            (Some(p), Some(Error::Parse)) => Some(format!(
                " ({}) at line {}, byte {}",
                p.reason.unwrap_or("unknown"),
                p.line,
                p.byte
            )),
            _ => None,
        }
    }
}
