#![forbid(unsafe_code)]
//! libuci semantics in Rust (contract C6). Module names follow the C units:
//! `parse` = file.c parser, `export` = file.c export, `file` = file.c backend
//! (load/commit/list), `delta` = delta.c, `ops` = list.c + util.c lookup.

#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod context;
pub mod delta;
pub mod error;
pub mod export;
pub mod file;
pub mod model;
pub mod ops;
pub mod parse;
mod read_cache;
pub mod show;
pub mod sys;

#[doc(inline)]
pub use context::Context;
#[doc(inline)]
pub use error::{Error, Result};
#[doc(inline)]
pub use model::{Cmd, Delta, Opt, OptionValue, Package, Ptr, Section};
#[doc(inline)]
pub use read_cache::ReadCache;

#[doc(hidden)]
pub mod cli;
