//! struct uci_context (uci.h) and the context-level API from libuci.c.

use crate::error::{Error, Result};
use crate::model::Package;

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseInfo {
    pub reason: Option<&'static str>,
    pub line: i32,
    pub byte: usize,
}

pub struct Context {
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
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    /// uci_alloc_context
    pub fn new() -> Context {
        Context {
            root: Vec::new(),
            flags: FLAG_STRICT | FLAG_SAVED_DELTA,
            confdir: CONFDIR.to_owned(),
            conf2dir: Some(CONF2DIR.to_owned()),
            savedir: SAVEDIR.to_owned(),
            delta_path: vec![SAVEDIR.to_owned()],
            err: None,
            pctx: None,
        }
    }

    /// uci_set_confdir
    pub fn set_confdir(&mut self, dir: &str) {
        self.confdir = dir.to_owned();
    }

    /// uci_set_conf2dir: empty disables the override directory.
    pub fn set_conf2dir(&mut self, dir: &str) {
        self.conf2dir = if dir.is_empty() { None } else { Some(dir.to_owned()) };
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
